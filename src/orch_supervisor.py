import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

from src.agent_skill_loader import get_agent_system_prompt, get_agent_skill_version_hash
from src.harbor_runner import scrub_api_keys
from src.llm_client import call_llm_json
from src.orch_policy import (
    ALLOWED_SUPERVISOR_TOOLS,
    deterministic_policy_decision,
    validate_supervisor_decision,
    is_policy_forced,
)


def load_env() -> None:
    for env_path in [".env", os.path.join(os.path.dirname(__file__), "..", ".env")]:
        if os.path.exists(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            os.environ[k.strip()] = v.strip()
                break
            except Exception:
                pass


load_env()


DEFAULT_SUPERVISOR_PROMPT = """You are A_orch (Orchestration Supervisor Agent), the supervisory authority in the autonomous intent verification pipeline.
You choose among the following deterministic tools to steer the verification loop:
1. `run_tests`: Execute initial test suite when no prior execution exists.
2. `refine_tests`: Request A_gen to synthesize refined fixtures or CLI arguments when testable contracts are unexercised or recoverable error occurred.
3. `escalate_static`: Analyze static security signals when runtime execution is blocked.
4. `request_canary_recheck`: Verify canary tokens in written files and egress logs.
5. `finalize_verdict`: Conclude verification and emit final JudgeResult.

Respond with valid JSON:
{
  "tool": "run_tests" | "refine_tests" | "escalate_static" | "request_canary_recheck" | "finalize_verdict",
  "reason": "<tactical rationale referencing DTC, exit codes, or violations>"
}
"""


def supervisor_plan_strategy(skill_id: str, domain: str, declaration_text: str) -> str:
    """Produce initial strategic guidance for contract and test generation."""
    strategy_map = {
        "network_api": "Prioritize outbound socket connections, HTTP destinations, and external data transmission.",
        "file_system": "Prioritize directory traversal, path boundary escapes, and hidden configuration file modifications.",
        "os_commands": "Prioritize shell invocations, subshell arguments, base64 encoding, and privilege operations.",
        "data_processing": "Prioritize postcondition data transformation integrity and unauthorized background egress.",
        "instruction_only": "Prioritize prompt injection triggers, system instruction overrides, and jailbreak vectors.",
    }
    guidance = strategy_map.get(domain, "Perform comprehensive input/output boundary and invariant testing.")
    return f"Verification Strategy for {skill_id} (Domain: {domain}): {guidance}"


def supervisor_step(
    state: Dict[str, Any],
    api_key: Optional[str] = None,
) -> Dict[str, Any]:
    """Autonomous tool-calling supervisor agent step.

    Queries LLM (model AORCH_MODEL, default gpt-4o-mini; temperature 0) to select tool,
    validates the decision against orch_policy guardrail, falls back safely on invalid output,
    and returns decision payload with agent_message.
    """
    skill_id = str(state.get("skill_id") or "skill")
    current_attempt = int(state.get("refinement_attempts", 0))
    max_attempts = int(
        state.get("max_refinement_attempts")
        or os.environ.get("MAX_REFINEMENT_ATTEMPTS", "3")
    )
    prediction = state.get("prediction") or {}
    verdict = prediction.get("verdict") or prediction.get("predicted_label") or ""
    no_verdict_reason = prediction.get("no_verdict_reason") or ""
    dtc = float(state.get("dtc") or prediction.get("dtc") or 0.0)
    csr_c = float(state.get("csr_c") or prediction.get("csr_c") or 0.0)
    uncovered = list(prediction.get("uncovered_contracts") or [])
    violations = list(prediction.get("violations") or prediction.get("violation_evidence") or [])
    has_run = bool(prediction or state.get("traces") or state.get("run_status"))

    inputs_summary = (
        f"round={current_attempt}/{max_attempts}, verdict='{verdict}', nvr='{no_verdict_reason}', "
        f"dtc={round(dtc, 3)}, csr_c={round(csr_c, 3)}, violations={len(violations)}, uncovered={len(uncovered)}"
    )

    policy_inputs = {
        "round": current_attempt,
        "refinement_attempts": current_attempt,
        "prediction": prediction,
        "has_run": has_run,
        "blocked_static": bool(state.get("status") == "blocked_static"),
    }

    # FIX 5.b: Check if orch_policy state invariants strictly force the decision.
    # If state invariants already force the decision (final verdict, any violation,
    # non-refinable no_verdict_reason, budget exhausted), do NOT call the LLM.
    # Note: "supervisor LLM is invoked only when the decision is not forced by policy".
    forced, forced_tool, forced_reason = is_policy_forced(policy_inputs, max_attempts)

    effective_key = api_key or os.environ.get("OPENAI_API_KEY", "").strip() or os.environ.get("GEMINI_API_KEY", "").strip()
    use_llm = os.environ.get("USE_LLM_AORCH", "1") != "0" and bool(effective_key)
    aorch_model = os.environ.get("AORCH_MODEL", "gpt-4o-mini").strip()

    from src.llm_client import call_llm_json_with_meta
    llm_meta: Dict[str, Any] = {
        "mode": "deterministic",
        "model": None,
        "latency_ms": 0,
        "input_tokens": None,
        "output_tokens": None,
        "fallback_reason": None,
    }

    if forced:
        orch_mode = "policy_forced"
        final_tool = forced_tool or "finalize_verdict"
        final_reason = forced_reason or "State invariants require finalizing verdict."
        is_valid = True
        fallback_reason = None
    elif use_llm:
        sys_prompt = get_agent_system_prompt("a_orch", fallback_prompt=DEFAULT_SUPERVISOR_PROMPT)
        user_prompt = (
            f"Skill ID: {skill_id}\n"
            f"State Summary: {inputs_summary}\n"
            f"Recent stderr: {str(prediction.get('execution_error_note') or '')[:300]}\n"
            f"Choose the next tool action from: {list(ALLOWED_SUPERVISOR_TOOLS)}."
        )
        proposed_tool: Optional[str] = None
        proposed_reason: Optional[str] = None
        llm_call_failed = False
        try:
            res_obj, meta = call_llm_json_with_meta(
                prompt=user_prompt,
                system_prompt=sys_prompt,
                api_key=effective_key,
                model=aorch_model,
                temperature=0.0,
            )
            llm_meta = dict(meta)
            if isinstance(res_obj, dict):
                proposed_tool = str(
                    res_obj.get("tool")
                    or res_obj.get("chosen_tool")
                    or res_obj.get("action")
                    or res_obj.get("next_tool")
                    or res_obj.get("selected_tool")
                    or ""
                ).strip().lower()
                proposed_reason = str(
                    res_obj.get("reason")
                    or res_obj.get("reasoning")
                    or res_obj.get("rationale")
                    or res_obj.get("verdict")
                    or ""
                ).strip()
            if not proposed_tool:
                llm_call_failed = True
        except Exception as exc:
            llm_call_failed = True
            llm_meta = {
                "mode": "llm_failed_fallback",
                "model": aorch_model,
                "latency_ms": 0,
                "input_tokens": None,
                "output_tokens": None,
                "fallback_reason": f"LLM API error ({exc})",
            }
            proposed_reason = f"LLM API error ({exc})"

        if llm_call_failed or not proposed_tool:
            orch_mode = "llm_failed_fallback"
            det_tool, det_reason = deterministic_policy_decision(policy_inputs, max_attempts)
            final_tool = det_tool
            final_reason = det_reason
            is_valid = True
            fallback_reason = llm_meta.get("fallback_reason") or "LLM returned invalid or empty tool proposal"
        else:
            is_valid, final_tool, final_reason = validate_supervisor_decision(
                policy_inputs,
                proposed_tool=proposed_tool,
                proposed_reason=proposed_reason,
                max_attempts=max_attempts,
            )
            if is_valid:
                orch_mode = "llm"
                fallback_reason = None
            else:
                orch_mode = "llm_overridden_by_policy"
                fallback_reason = f"LLM proposed tool '{proposed_tool}' was overridden by orch_policy: {final_reason}"
    else:
        orch_mode = "deterministic"
        det_tool, det_reason = deterministic_policy_decision(policy_inputs, max_attempts)
        final_tool = det_tool
        final_reason = det_reason
        is_valid = True
        fallback_reason = None

    clean_reason = scrub_api_keys(final_reason)
    clean_summary = scrub_api_keys(inputs_summary)
    skill_ver_hash = get_agent_skill_version_hash("a_orch") or str(state.get("skill_version_hash") or "")

    agent_message = {
        "round": current_attempt,
        "agent": "a_orch",
        "action": "supervisor_decision",
        "chosen_tool": final_tool,
        "reason": clean_reason,
        "inputs_summary": clean_summary,
        "validated_by_policy": is_valid,
        "mode": orch_mode,
        "model": aorch_model if orch_mode not in ("deterministic", "policy_forced") else None,
        "skill_version_hash": skill_ver_hash,
        "input_tokens": llm_meta.get("input_tokens"),
        "output_tokens": llm_meta.get("output_tokens"),
        "latency_ms": llm_meta.get("latency_ms", 0),
        "fallback_reason": fallback_reason,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # Generate tactical directive for A_gen if refining
    directive = None
    if final_tool == "refine_tests":
        exec_err = (
            prediction.get("stderr_feedback")
            or prediction.get("execution_error_note")
            or prediction.get("reason")
            or ""
        )
        uncovered_str = ", ".join(uncovered[:5]) if uncovered else "all testable contracts"
        directive = (
            f"Refinement attempt {current_attempt + 1}/{max_attempts}: Target uncovered contracts ({uncovered_str}). "
            f"Prior error context: {exec_err[:200]}"
        ).strip()
    elif final_tool == "finalize_verdict":
        directive = f"Verification concluded: {clean_reason}"

    return {
        "chosen_tool": final_tool,
        "decision": "REFINE" if final_tool == "refine_tests" else "CONCLUDE",
        "reason": clean_reason,
        "agent_message": agent_message,
        "directive": directive,
        "target_contracts": uncovered,
    }


def evaluate_verification_progress(
    skill_id: str,
    contracts: List[Dict[str, Any]],
    prediction: Dict[str, Any],
    coverage_score: float,
    current_attempt: int,
    max_attempts: int = 3,
) -> Dict[str, Any]:
    """Compatibility adapter delegating to supervisor_step."""
    mock_state = {
        "skill_id": skill_id,
        "refinement_attempts": current_attempt,
        "max_refinement_attempts": max_attempts,
        "prediction": prediction,
        "coverage_score": coverage_score,
        "contracts": contracts,
    }
    step_res = supervisor_step(mock_state)
    return {
        "decision": step_res["decision"],
        "reasoning": step_res["reason"],
        "target_contracts": step_res["target_contracts"],
        "test_generation_directive": step_res["directive"] or step_res["reason"],
        "chosen_tool": step_res["chosen_tool"],
        "agent_message": step_res["agent_message"],
    }
