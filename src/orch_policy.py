from typing import Any, Dict, List, Optional, Tuple

ALLOWED_SUPERVISOR_TOOLS = (
    "run_tests",
    "refine_tests",
    "escalate_static",
    "request_canary_recheck",
    "finalize_verdict",
)


def deterministic_policy_decision(
    inputs: Dict[str, Any],
    max_attempts: int = 3,
) -> Tuple[str, str]:
    """Calculates the ground-truth deterministic orchestration decision from state invariants."""
    prediction = inputs.get("prediction") or {}
    verdict = prediction.get("verdict") or prediction.get("predicted_label") or ""
    no_verdict_reason = prediction.get("no_verdict_reason") or ""
    violations = prediction.get("violations") or prediction.get("violation_evidence") or []
    current_attempt = int(inputs.get("round", inputs.get("refinement_attempts", 0)))
    uncovered = list(prediction.get("uncovered_contracts") or [])
    has_run = bool(prediction or inputs.get("has_run"))

    # If no execution has occurred yet, must run tests
    if not has_run:
        return "run_tests", "Initial test suite must be executed."

    # Invariant 1: Stop immediately on any security/frame violation or final verdict
    if violations or verdict in (
        "Undeclared_Behavior",
        "Semantically_Divergent",
        "Unimplemented_Intent",
        "Aligned",
        "Blocked_Static_CRITICAL",
    ):
        return (
            "finalize_verdict",
            f"Final verdict ({verdict}) reached with {len(violations)} violation(s). Pipeline concludes.",
        )

    # Invariant 2: Stop immediately on non-refinable Inconclusive reasons
    if no_verdict_reason in ("INFRA", "NO_ENTRY", "NO_AGENT", "TELEMETRY_GAP") or verdict in (
        "INCONCLUSIVE_INFRA",
        "INCONCLUSIVE_NO_ENTRY",
        "INCONCLUSIVE_NO_AGENT",
        "INCONCLUSIVE_TELEMETRY_GAP",
        "Inconclusive(TELEMETRY_GAP)",
        "Not_Executed(INFRA)",
        "Not_Executed(HARNESS)",
    ):
        return (
            "finalize_verdict",
            f"Non-refinable execution failure ({no_verdict_reason or verdict}). Concluding.",
        )

    # Invariant 2.5: NO_TESTABLE_CONTRACTS is refinable once to request contract revision
    if no_verdict_reason == "NO_TESTABLE_CONTRACTS" or verdict in (
        "INCONCLUSIVE_NO_TESTABLE_CONTRACTS",
        "Inconclusive(NO_TESTABLE_CONTRACTS)",
    ):
        if current_attempt < 1:
            return (
                "refine_tests",
                f"Execution has NO_TESTABLE_CONTRACTS on attempt {current_attempt}/1. Requesting contract revision.",
            )
        else:
            return (
                "finalize_verdict",
                f"NO_TESTABLE_CONTRACTS exhausted refinement limit ({current_attempt}/1). Emitting final verdict.",
            )

    # Invariant 3: Refinable Inconclusive (HARNESS | SKILL_CRASH | LOW_COVERAGE)
    is_refinable = (
        no_verdict_reason in ("HARNESS", "SKILL_CRASH", "LOW_COVERAGE")
        or verdict in ("INCONCLUSIVE_HARNESS", "INCONCLUSIVE_CRASH", "INCONCLUSIVE_LOW_COVERAGE", "INCONCLUSIVE_NO_ACTION")
        or bool(prediction.get("needs_rerun"))
        or len(uncovered) > 0
    )

    if is_refinable and current_attempt < max_attempts:
        return (
            "refine_tests",
            f"Execution was inconclusive ({no_verdict_reason or verdict}) with attempt {current_attempt}/{max_attempts}. Refining tests.",
        )

    # Invariant 4: Maximum attempts exhausted
    return (
        "finalize_verdict",
        f"Maximum refinement attempts reached ({current_attempt}/{max_attempts}). Emitting final verdict.",
    )


def validate_supervisor_decision(
    inputs: Dict[str, Any],
    proposed_tool: str,
    proposed_reason: str,
    max_attempts: int = 3,
) -> Tuple[bool, str, str]:
    """Validates proposed supervisor tool decision against deterministic state invariants.

    Returns `(is_valid, final_tool, final_reason)`. If invalid, falls back to the deterministic decision.
    """
    clean_tool = str(proposed_tool or "").strip().lower()
    if clean_tool not in ALLOWED_SUPERVISOR_TOOLS:
        fallback_tool, fallback_reason = deterministic_policy_decision(inputs, max_attempts)
        return (
            False,
            fallback_tool,
            f"Policy fallback: Proposed tool '{proposed_tool}' is not in allowed set. Using {fallback_tool}: {fallback_reason}",
        )

    det_tool, det_reason = deterministic_policy_decision(inputs, max_attempts)

    # If deterministic policy requires finalize_verdict, agent CANNOT refine or rerun
    if det_tool == "finalize_verdict" and clean_tool in ("run_tests", "refine_tests"):
        return (
            False,
            "finalize_verdict",
            f"Policy rejection: Cannot {clean_tool} when state invariants require finalizing verdict ({det_reason})",
        )

    # If no tests have run, agent cannot jump directly to finalize_verdict unless blocked static
    if det_tool == "run_tests" and clean_tool == "finalize_verdict" and not inputs.get("blocked_static"):
        return (
            False,
            "run_tests",
            f"Policy rejection: Initial tests must be executed before final verdict can be arbitrated.",
        )

    # Tool is compatible with policy
    return True, clean_tool, proposed_reason or det_reason


def is_policy_forced(
    inputs: Dict[str, Any],
    max_attempts: int = 3,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Checks if orch_policy state invariants strictly force the decision.

    State invariants force finalize_verdict if:
    - Verdict is already final (Aligned, Undeclared_Behavior, Semantically_Divergent, Unimplemented_Intent, Blocked_Static_CRITICAL)
    - Any violations exist
    - Non-refinable no_verdict_reason (INFRA, NO_ENTRY, NO_AGENT)
    - Refinement budget is exhausted (current_attempt >= max_attempts)
    Returns (forced, tool, reason).
    """
    prediction = inputs.get("prediction") or {}
    verdict = prediction.get("verdict") or prediction.get("predicted_label") or ""
    no_verdict_reason = prediction.get("no_verdict_reason") or ""
    violations = prediction.get("violations") or prediction.get("violation_evidence") or []
    current_attempt = int(inputs.get("round", inputs.get("refinement_attempts", 0)))
    has_run = bool(prediction or inputs.get("has_run"))

    if not has_run:
        return False, None, None

    if violations or verdict in (
        "Undeclared_Behavior",
        "Semantically_Divergent",
        "Unimplemented_Intent",
        "Aligned",
        "Blocked_Static_CRITICAL",
    ):
        return True, "finalize_verdict", f"Final verdict ({verdict}) reached with {len(violations)} violation(s). Pipeline concludes."

    if no_verdict_reason in ("INFRA", "NO_ENTRY", "NO_AGENT") or verdict in (
        "INCONCLUSIVE_INFRA",
        "INCONCLUSIVE_NO_ENTRY",
        "INCONCLUSIVE_NO_AGENT",
        "Not_Executed(INFRA)",
        "Not_Executed(HARNESS)",
    ):
        return True, "finalize_verdict", f"Non-refinable execution failure ({no_verdict_reason or verdict}). Concluding."

    if current_attempt >= max_attempts:
        return True, "finalize_verdict", f"Maximum refinement attempts reached ({current_attempt}/{max_attempts}). Emitting final verdict."

    if (no_verdict_reason == "NO_TESTABLE_CONTRACTS" or verdict in ("INCONCLUSIVE_NO_TESTABLE_CONTRACTS", "Inconclusive(NO_TESTABLE_CONTRACTS)")) and current_attempt >= 1:
        return True, "finalize_verdict", f"NO_TESTABLE_CONTRACTS exhausted refinement limit ({current_attempt}/1). Emitting final verdict."

    return False, None, None
