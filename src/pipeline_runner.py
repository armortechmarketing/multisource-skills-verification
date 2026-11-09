import os
import sys
import json
import time
import logging
from collections import Counter
from typing import Dict, Any, List, Optional, Callable

logger = logging.getLogger(__name__)

sys.path.append(os.path.abspath("."))
try:
    from graph import run_skill
    _DEFAULT_RUN_SKILL = run_skill
except Exception:
    _DEFAULT_RUN_SKILL = None


def derive_gating_status(
    l1_risk: str,
    run_status: str,
    verdict: Optional[str],
    no_verdict_reason: Optional[str],
    explicit_gating_status: Optional[str] = None
) -> str:
    """
    Single authoritative function deriving gating_status from the result (P1).
    No loop-carried variables or mutable state.
    """
    if l1_risk == "CRITICAL" or verdict == "Blocked_Static_CRITICAL" or explicit_gating_status == "SKIPPED_LEVEL1_CRITICAL":
        return "SKIPPED_LEVEL1_CRITICAL"

    if no_verdict_reason:
        reason_map = {
            "HARNESS": "INCONCLUSIVE_HARNESS",
            "INFRA": "INCONCLUSIVE_INFRA",
            "NO_ENTRY": "INCONCLUSIVE_NO_ENTRY",
            "NO_AGENT": "INCONCLUSIVE_NO_AGENT",
            "SKILL_CRASH": "INCONCLUSIVE_CRASH",
            "LOW_COVERAGE": "INCONCLUSIVE_LOW_COVERAGE",
            "NO_TESTABLE_CONTRACTS": "INCONCLUSIVE_NO_TESTABLE_CONTRACTS",
            "TELEMETRY_GAP": "INCONCLUSIVE_TELEMETRY_GAP",
        }
        if no_verdict_reason in reason_map:
            return reason_map[no_verdict_reason]

    if explicit_gating_status and explicit_gating_status not in ("INVOKED", "NOT_INVOKED"):
        return explicit_gating_status

    if verdict in ("Aligned", "Undeclared_Behavior", "Unimplemented_Intent", "Semantically_Divergent"):
        return "INVOKED"

    if run_status in ("INVOKED_SUCCEEDED", "INVOKED_FAILED", "RAN"):
        if explicit_gating_status:
            return explicit_gating_status
        return "INVOKED"
    if run_status == "INFRA_FAILURE":
        return "INCONCLUSIVE_INFRA"

    return explicit_gating_status or "NOT_INVOKED"


def _infer_no_verdict_reason(
    verdict: Optional[str],
    gating_status: str,
    pred: Dict[str, Any],
    state: Dict[str, Any]
) -> Optional[str]:
    """Extracts canonical no_verdict_reason in {HARNESS, INFRA, NO_ENTRY, NO_AGENT, SKILL_CRASH, LOW_COVERAGE, NO_TESTABLE_CONTRACTS, TELEMETRY_GAP}."""
    explicit = pred.get("no_verdict_reason") or state.get("no_verdict_reason")
    if explicit:
        return str(explicit)

    for candidate in (verdict or "", gating_status or ""):
        if candidate == "INCONCLUSIVE_HARNESS":
            return "HARNESS"
        if candidate == "INCONCLUSIVE_INFRA":
            return "INFRA"
        if candidate == "INCONCLUSIVE_NO_ENTRY":
            return "NO_ENTRY"
        if candidate == "INCONCLUSIVE_NO_AGENT":
            return "NO_AGENT"
        if candidate == "INCONCLUSIVE_CRASH":
            return "SKILL_CRASH"
        if candidate in ("INCONCLUSIVE_LOW_COVERAGE", "INCONCLUSIVE_NO_ACTION"):
            return "LOW_COVERAGE"
        if candidate in ("INCONCLUSIVE_NO_TESTABLE_CONTRACTS", "Inconclusive(NO_TESTABLE_CONTRACTS)"):
            return "NO_TESTABLE_CONTRACTS"
        if candidate in ("INCONCLUSIVE_TELEMETRY_GAP", "Inconclusive(TELEMETRY_GAP)"):
            return "TELEMETRY_GAP"
    return None


def build_skill_record(skill_entry: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pure function constructing a single skill record from the execution/judge result (P1, P2).
    Never reads or mutates outer loop variables.
    """
    s_id = skill_entry["skill_id"]
    s_domain = skill_entry.get("domain", "data_processing")
    is_known_mal = bool(skill_entry.get("known_malicious", False))

    pred = dict(state.get("prediction") or {})
    l1_rep = dict(state.get("level1_report") or {})
    l1_risk = str(l1_rep.get("risk_level") or state.get("level1_risk") or "LOW")
    l1_reason = l1_rep.get("reason", "No static security patterns triggered.")

    raw_r_status = state.get("run_status") or pred.get("run_status") or "NOT_INVOKED"
    raw_g_status = state.get("gating_status") or pred.get("gating_status")

    if l1_risk == "CRITICAL" or raw_g_status == "SKIPPED_LEVEL1_CRITICAL":
        verdict = "Blocked_Static_CRITICAL"
        l2_verdict = None
        no_verdict_reason = None
        g_status = "SKIPPED_LEVEL1_CRITICAL"
        r_status = "NOT_INVOKED"
        l2_reason = "Not executed — blocked at Level-1 static security gate (see level1_reason)."
        dtc_val = 0.0
        csr_c_val = 0.0
        contract_status = []
        violations = []
        behavior_units = []
        intent_to_behavior: Dict[str, List[str]] = {}
        execution_error_note = None
        clean_cvs = [
            {
                "contract_id": cv.get("contract_id"),
                "verdict": cv.get("verdict", "Blocked_Static_CRITICAL"),
                "exercised": False,
                "violation_evidence": cv.get("violation_evidence", [])
            }
            for cv in pred.get("contract_verdicts", [])
        ]
        return {
            "skill_id": s_id,
            "domain": s_domain,
            "known_malicious": is_known_mal,
            "level1_risk": l1_risk,
            "level1_reason": l1_reason,
            "gating_status": g_status,
            "level2_verdict": l2_verdict,
            "level2_reason": l2_reason,
            "verdict": verdict,
            "run_status": r_status,
            "dtc": dtc_val,
            "csr_c": csr_c_val,
            "contract_verdicts": clean_cvs,
            "execution_error_sublabel": None,
            "backend": state.get("backend", "harbor_docker"),
            "valid_for_paper": bool(state.get("valid_for_paper", True)),
            "contracts_total": len(clean_cvs),
            "contracts_testable": sum(1 for cv in clean_cvs if cv.get("testable", True)),
            "contracts_non_testable": sum(1 for cv in clean_cvs if not cv.get("testable", True)),
            # New P2 fields
            "no_verdict_reason": no_verdict_reason,
            "contract_status": contract_status,
            "violations": violations,
            "behavior_units": behavior_units,
            "intent_to_behavior": intent_to_behavior,
            "execution_error_note": execution_error_note,
            "chunks_total": pred.get("chunks_total", state.get("chunks_total", 1)),
            "chunks_processed": pred.get("chunks_processed", state.get("chunks_processed", 1)),
            "chunks_skipped": pred.get("chunks_skipped", state.get("chunks_skipped", 0)),
            "truncated": pred.get("truncated", state.get("truncated", False)),
            "attribution": [],
        }

    # Non-CRITICAL path: derive fields purely from pred and state
    raw_pred_verdict = pred.get("verdict") or pred.get("predicted_label")
    no_verdict_reason = _infer_no_verdict_reason(raw_pred_verdict, raw_g_status or "", pred, state)

    g_status = derive_gating_status(
        l1_risk=l1_risk,
        run_status=raw_r_status,
        verdict=raw_pred_verdict,
        no_verdict_reason=no_verdict_reason,
        explicit_gating_status=raw_g_status,
    )

    if raw_pred_verdict in ("Aligned", "Undeclared_Behavior", "Unimplemented_Intent", "Semantically_Divergent"):
        l2_verdict: Optional[str] = raw_pred_verdict
        verdict = raw_pred_verdict
    elif no_verdict_reason:
        l2_verdict = None
        verdict = f"Inconclusive({no_verdict_reason})" if str(raw_pred_verdict).startswith("Inconclusive") else (raw_pred_verdict or g_status)
    else:
        l2_verdict = pred.get("predicted_label") if g_status == "INVOKED" else None
        verdict = l2_verdict or raw_pred_verdict or g_status or "NOT_INVOKED"

    # Re-check no_verdict_reason if verdict resolved to an Inconclusive variant
    if not no_verdict_reason:
        no_verdict_reason = _infer_no_verdict_reason(verdict, g_status, pred, state)

    # Formulate Level-2 reason
    goal_drift = pred.get("goal_drift_audit") or {}
    if pred.get("explanation") and isinstance(pred["explanation"], dict) and pred["explanation"].get("headline"):
        l2_reason = pred["explanation"]["headline"]
    elif pred.get("reasoning"):
        l2_reason = str(pred["reasoning"])
    elif goal_drift.get("drift_detected"):
        l2_reason = f"Undeclared_Behavior: {goal_drift.get('reason')}"
    elif l2_verdict == "Aligned":
        n_c = len(pred.get("contract_verdicts", []))
        l2_reason = f"All {n_c} behavioral contracts verified and passed execution in sandbox without invariant violations."
    elif l2_verdict == "Undeclared_Behavior":
        viols = pred.get("violation_evidence", [])
        viols_str = "; ".join(str(v) for v in viols) if viols else "Undeclared runtime behavior detected during execution."
        l2_reason = f"Execution invariant violated: {viols_str}"
    elif l2_verdict == "Unimplemented_Intent":
        sub = pred.get("execution_error_sublabel") or pred.get("failure_type") or "Stub/Unimplemented"
        l2_reason = f"Intent unimplemented in codebase: {sub}."
    elif l2_verdict == "Semantically_Divergent":
        l2_reason = "Observed outputs diverged from contract postconditions despite clean execution."
    elif no_verdict_reason == "INFRA":
        sub = pred.get("execution_error_sublabel") or state.get("execution_error_sublabel") or "Missing dependency"
        l2_reason = f"Execution blocked by infrastructure/environment failure: {sub}."
    elif no_verdict_reason == "NO_ENTRY":
        l2_reason = "No runnable entry point found in skill package."
    elif no_verdict_reason == "NO_AGENT":
        l2_reason = "Instruction-only skill requires agent API credentials (NO_AGENT)."
    elif no_verdict_reason == "HARNESS":
        sub = pred.get("execution_error_sublabel") or "test harness / precondition error"
        l2_reason = f"Execution blocked by test harness or unmet precondition: {sub}."
    elif no_verdict_reason == "TELEMETRY_GAP":
        l2_reason = "Agent/instruction-only run reported trajectory but zero trajectory units (TELEMETRY_GAP)."
    else:
        l2_reason = f"Trial concluded with gating status: {g_status}."

    coverage = float(
        pred.get("coverage")
        if pred.get("coverage") is not None
        else (state.get("coverage_score") or pred.get("coverage_score") or 0.0)
    )

    clean_cvs = []
    for cv in pred.get("contract_verdicts", []):
        clean_cvs.append({
            "contract_id": cv.get("contract_id"),
            "verdict": cv.get("verdict"),
            "exercised": bool(cv.get("exercised", False)),
            "violation_evidence": cv.get("violation_evidence", [])
        })

    contract_status = list(pred.get("contract_status") or [
        {
            "contract_id": cv.get("contract_id"),
            "status": "PASS" if cv.get("verdict") == "Aligned" and cv.get("exercised") else (
                "CONTRADICTED" if cv.get("verdict") == "Semantically_Divergent" else (
                    "STUB" if cv.get("verdict") == "Unimplemented_Intent" else "NOT_EXERCISED"
                )
            ),
            "reason": "; ".join(cv.get("violation_evidence", [])) if cv.get("violation_evidence") else str(cv.get("verdict", "")),
        }
        for cv in clean_cvs
    ])
    violations = list(pred.get("violations") or [])
    behavior_units = list(pred.get("behavior_units") or state.get("behavior_units") or [])
    intent_to_behavior = dict(pred.get("intent_to_behavior") or {})
    execution_error_note = pred.get("execution_error_note") or pred.get("execution_error_sublabel") or state.get("execution_error_sublabel")

    dtc_val = float(pred.get("dtc") if pred.get("dtc") is not None else (state.get("dtc") or coverage))
    csr_c_val = float(pred.get("csr_c") if pred.get("csr_c") is not None else (state.get("csr_c") or 0.0))

    return {
        "skill_id": s_id,
        "domain": s_domain,
        "known_malicious": is_known_mal,
        "level1_risk": l1_risk,
        "level1_reason": l1_reason,
        "gating_status": g_status,
        "level2_verdict": l2_verdict,
        "level2_reason": l2_reason,
        "verdict": verdict,
        "run_status": raw_r_status,
        "dtc": dtc_val,
        "csr_c": csr_c_val,
        "contract_verdicts": clean_cvs,
        "execution_error_sublabel": pred.get("execution_error_sublabel") or state.get("execution_error_sublabel"),
        "backend": state.get("backend", "harbor_docker"),
        "valid_for_paper": bool(state.get("valid_for_paper", True)),
        "contracts_total": int(pred.get("contracts_total", len(clean_cvs))),
        "contracts_testable": int(pred.get("contracts_testable", sum(1 for cv in clean_cvs if cv.get("testable", True)))),
        "contracts_non_testable": int(pred.get("contracts_non_testable", sum(1 for cv in clean_cvs if not cv.get("testable", True)))),
        # New P2 fields
        "no_verdict_reason": no_verdict_reason,
        "contract_status": contract_status,
        "violations": violations,
        "behavior_units": behavior_units,
        "intent_to_behavior": intent_to_behavior,
        "execution_error_note": execution_error_note,
        "attribution": pred.get("attribution") or [],
        "chunks_total": pred.get("chunks_total", state.get("chunks_total", 1)),
        "chunks_processed": pred.get("chunks_processed", state.get("chunks_processed", 1)),
        "chunks_skipped": pred.get("chunks_skipped", state.get("chunks_skipped", 0)),
        "truncated": pred.get("truncated", state.get("truncated", False)),
        "explanation": pred.get("explanation"),
        "agent_messages": state.get("agent_messages") or [],
        "failure_class": pred.get("failure_class") or state.get("failure_class"),
        "failure_symptom": pred.get("failure_symptom") or state.get("failure_symptom"),
        "strong_pass_count": pred.get("strong_pass_count"),
        "weak_pass_count": pred.get("weak_pass_count"),
    }


def build_error_skill_record(skill_entry: Dict[str, Any], err: Exception) -> Dict[str, Any]:
    """Constructs an immutable error record if an unexpected exception escapes run_skill."""
    s_id = skill_entry["skill_id"]
    s_domain = skill_entry.get("domain", "data_processing")
    is_known_mal = bool(skill_entry.get("known_malicious", False))
    err_str = str(err)
    return {
        "skill_id": s_id,
        "domain": s_domain,
        "known_malicious": is_known_mal,
        "level1_risk": "ERROR",
        "level1_reason": f"Execution error: {err_str}",
        "gating_status": "INCONCLUSIVE_INFRA",
        "level2_verdict": None,
        "level2_reason": f"Fatal pipeline error: {err_str}",
        "verdict": "ERROR",
        "run_status": "NOT_INVOKED",
        "dtc": 0.0,
        "csr_c": 0.0,
        "contract_verdicts": [],
        "execution_error_sublabel": err_str,
        "backend": "none",
        "valid_for_paper": False,
        "no_verdict_reason": "INFRA",
        "contract_status": [],
        "violations": [],
        "behavior_units": [],
        "intent_to_behavior": {},
        "execution_error_note": err_str,
        "attribution": [],
    }


def summarize_report_records(
    manifest_path: str,
    manifest_data: Dict[str, Any],
    results: List[Dict[str, Any]],
    total_skills: int,
    elapsed_sec: float
) -> Dict[str, Any]:
    """
    Aggregates distributions purely from the list of immutable skill records (P1, P3).
    Asserts sum(verdict_distribution.values()) == len(results).
    """
    level1_risks: Counter = Counter()
    gating_statuses: Counter = Counter()
    run_statuses: Counter = Counter()
    canonical_verdicts: Counter = Counter()
    backend_counts: Counter = Counter()
    no_verdict_by_reason: Counter = Counter()
    skipped_l1 = 0
    total_coverage = 0.0
    total_dtc = 0.0
    total_csr_c = 0.0

    for r in results:
        l1_risk = r.get("level1_risk", "LOW")
        level1_risks[l1_risk] += 1

        g_status = r.get("gating_status", "NOT_INVOKED")
        gating_statuses[g_status] += 1

        r_status = r.get("run_status", "NOT_INVOKED")
        if g_status == "SKIPPED_LEVEL1_CRITICAL" or r.get("verdict") == "Blocked_Static_CRITICAL":
            skipped_l1 += 1
        elif r_status != "NOT_INVOKED":
            # P3: run_status_distribution counts only executed skills
            run_statuses[r_status] += 1

        nvr = r.get("no_verdict_reason")
        if nvr:
            no_verdict_by_reason[nvr] += 1

        tally_label = r.get("verdict") or r.get("level2_verdict") or g_status or "UNKNOWN"
        canonical_verdicts[tally_label] += 1

        backend_counts[r.get("backend", "harbor_docker")] += 1
        total_dtc += float(r.get("dtc", 0.0) or 0.0)
        total_csr_c += float(r.get("csr_c", 0.0) or 0.0)

    assert sum(canonical_verdicts.values()) == len(results), (
        f"Verdict distribution sum mismatch: {sum(canonical_verdicts.values())} != {len(results)}"
    )

    # Attribution coverage metrics
    total_violations = 0
    attributed_violations = 0
    total_divergences = 0
    attributed_divergences = 0
    total_unimplemented = 0
    attributed_unimplemented = 0

    for r in results:
        attrs = r.get("attribution") or []
        v_label = r.get("verdict")
        if v_label == "Undeclared_Behavior":
            n_v = len(r.get("violations", [])) or len(attrs) or 1
            total_violations += n_v
            attr_count = sum(1 for a in attrs if a.get("code_sites"))
            attributed_violations += attr_count
        elif v_label == "Semantically_Divergent":
            total_divergences += 1
            if any(a.get("code_sites") for a in attrs):
                attributed_divergences += 1
        elif v_label == "Unimplemented_Intent":
            total_unimplemented += 1
            if any(a.get("code_sites") or a.get("absence") for a in attrs):
                attributed_unimplemented += 1

    denom = len(results) if len(results) > 0 else 1
    avg_dtc = round(total_dtc / denom, 3) if results else 0.0
    avg_csr_c = round(total_csr_c / denom, 3) if results else 0.0
    active_skills = [r for r in results if r.get("gating_status") not in ("SKIPPED_LEVEL1_CRITICAL", "NOT_INVOKED")]
    is_paper_valid = all(r.get("valid_for_paper", False) for r in active_skills) if active_skills else True

    # Run-level agent execution summary (Fix 5.e)
    agent_execution_summary = {
        "a_syn": {"llm": 0, "deterministic": 0, "llm_failed_fallback": 0},
        "a_gen": {"llm": 0, "deterministic": 0, "llm_failed_fallback": 0},
        "a_orch": {
            "llm": 0,
            "deterministic": 0,
            "policy_forced": 0,
            "llm_overridden_by_policy": 0,
            "llm_failed_fallback": 0,
        },
        "a_adj": {"llm": 0, "deterministic": 0, "llm_failed_fallback": 0},
    }
    for r in results:
        for msg in r.get("agent_messages") or []:
            ag = msg.get("agent")
            m = msg.get("mode")
            if ag in agent_execution_summary and m in agent_execution_summary[ag]:
                agent_execution_summary[ag][m] += 1

    return {
        "manifest_path": manifest_path,
        "run_id": manifest_data.get("run_id", "unknown"),
        "total_skills": total_skills,
        "completed_skills": len(results),
        "is_completed": len(results) >= total_skills,
        "blocked_static_count": skipped_l1,
        "skipped_l1": skipped_l1,
        "proceeded_to_level2": len(results) - skipped_l1,
        "average_dtc": avg_dtc,
        "average_csr_c": avg_csr_c,
        "contracts_total": sum(int(r.get("contracts_total", 0) or 0) for r in results),
        "contracts_testable": sum(int(r.get("contracts_testable", 0) or 0) for r in results),
        "contracts_non_testable": sum(int(r.get("contracts_non_testable", 0) or 0) for r in results),
        "total_time_seconds": round(elapsed_sec, 2),
        "valid_for_paper": is_paper_valid,
        "backend_distribution": dict(backend_counts),
        "level1_risk_distribution": dict(level1_risks),
        "gating_status_distribution": dict(gating_statuses),
        "run_status_distribution": dict(run_statuses),
        "no_verdict_by_reason": dict(no_verdict_by_reason),
        "verdict_distribution": dict(canonical_verdicts),
        "attribution_coverage": {
            "total_violations": total_violations,
            "attributed_violations": attributed_violations,
            "total_divergences": total_divergences,
            "attributed_divergences": attributed_divergences,
            "total_unimplemented": total_unimplemented,
            "attributed_unimplemented": attributed_unimplemented,
        },
        "agent_execution_summary": agent_execution_summary,
        "results": results,
    }


def _build_initial_skill_state(
    skill_entry: Dict[str, Any],
    *,
    force_refresh: bool = False,
    max_refinement_attempts: int = int(os.environ.get("MAX_REFINEMENT_ATTEMPTS", "3")),
) -> Dict[str, Any]:
    """Constructs a fresh, isolated PipelineState for a single skill entry."""
    s_id = skill_entry["skill_id"]
    skill_path = os.path.abspath(skill_entry.get("path", ""))
    skill_md_path = os.path.join(skill_path, "SKILL.md")
    declaration_text = ""
    if os.path.exists(skill_md_path):
        with open(skill_md_path, "r", encoding="utf-8", errors="ignore") as f:
            declaration_text = f.read()

    return {
        "skill_id": s_id,
        "skill_path": skill_path,
        "domain": skill_entry.get("domain", "data_processing"),
        "declaration_text": declaration_text,
        "contracts": None,
        "test_cases": None,
        "traces": None,
        "coverage_score": None,
        "refinement_attempts": 0,
        "max_refinement_attempts": max_refinement_attempts,
        "prediction": None,
        "supervisor_directive": None,
        "supervisor_decision": None,
        "force_refresh": force_refresh,
        "status": "in_progress",
        "run_status": None,
        "entry_point_reached": False,
        "activation": None,
        "script_execution": None,
        "failure_type": None,
        "execution_error_sublabel": None,
        "needs_rerun": False,
        "harbor_task_dir": None,
        "harbor_trial_dir": None,
        "contract_executions": None,
        "auto_installed_packages": [],
        "gating_status": None,
        "level1_report": None,
        "agent_messages": [],
    }


def _execute_manifest_batch_waves(
    pending_items: List[tuple[int, Dict[str, Any]]],
    *,
    force_refresh: bool,
    max_refinement_attempts: int = int(os.environ.get("MAX_REFINEMENT_ATTEMPTS", "3")),
) -> Dict[str, Dict[str, Any]]:
    """
    Executes all pending skills in Harbor batch waves (W4 + W7 Supervisor refinement loop).
    Returns a map of skill_id -> immutable skill record.
    """
    from src.adapters.skills_adapter import SkillHarborAdapter
    from src.harbor_runner import execute_harbor_batch
    from src.nodes import (
        adjudicate_node,
        apply_trial_result_to_state,
        contract_synth_node,
        finalize_node,
        supervisor_eval_node,
        supervisor_init_node,
        test_gen_node,
    )

    records_by_id: Dict[str, Dict[str, Any]] = {}
    states_by_id: Dict[str, Dict[str, Any]] = {}
    entries_by_id: Dict[str, Dict[str, Any]] = {}
    active_ids: List[str] = []

    for _, s in pending_items:
        s_id = s["skill_id"]
        entries_by_id[s_id] = s
        try:
            st = _build_initial_skill_state(
                s,
                force_refresh=force_refresh,
                max_refinement_attempts=max_refinement_attempts,
            )
            st.update(supervisor_init_node(st))
            st.update(contract_synth_node(st))
            if st.get("gating_status") == "SKIPPED_LEVEL1_CRITICAL":
                st.update(finalize_node(st))
                records_by_id[s_id] = build_skill_record(s, st)
            else:
                states_by_id[s_id] = st
                active_ids.append(s_id)
        except Exception as e:
            records_by_id[s_id] = build_error_skill_record(s, e)

    n_concurrent = int(os.environ.get("HARBOR_BATCH_CONCURRENCY", "4"))
    prev_test_cases_sig: Dict[str, str] = {}

    for wave in range(max_refinement_attempts + 1):
        if not active_ids:
            break

        wave_dir = os.path.abspath(os.path.join("harbor_tasks", f"batch_wave_{wave}_{int(time.time())}"))
        os.makedirs(wave_dir, exist_ok=True)
        adapter = SkillHarborAdapter(base_output_dir=wave_dir)

        batch_tasks: List[Dict[str, Any]] = []
        wave_task_dirs: Dict[str, str] = {}
        still_active_ids: List[str] = []

        for s_id in active_ids:
            st = states_by_id[s_id]
            s_entry = entries_by_id[s_id]
            try:
                st.update(test_gen_node(st))
                tcs = st.get("test_cases") or []
                tc_sig = json.dumps(
                    [
                        (
                            tc.get("entry_point"),
                            tc.get("cli_args"),
                            tc.get("mock_files"),
                            tc.get("env_vars"),
                        )
                        for tc in tcs
                    ],
                    sort_keys=True,
                    default=str,
                )
                if wave > 0 and prev_test_cases_sig.get(s_id) == tc_sig:
                    # Refinement generated identical test cases; conclude immediately
                    st.update(finalize_node(st))
                    records_by_id[s_id] = build_skill_record(s_entry, st)
                    continue
                prev_test_cases_sig[s_id] = tc_sig

                t_dir = adapter.scaffold_task(
                    skill_id=s_id,
                    skill_dir=st["skill_path"],
                    declaration_text=st.get("declaration_text", ""),
                    contracts=st.get("contracts") or [],
                )
                wave_task_dirs[s_id] = t_dir
                batch_tasks.append({
                    "skill_id": s_id,
                    "task_dir": t_dir,
                    "skill_dir": st["skill_path"],
                    "test_cases": tcs,
                    "contracts": st.get("contracts") or [],
                    "refinement_attempt": wave,
                })
                still_active_ids.append(s_id)
            except Exception as e:
                records_by_id[s_id] = build_error_skill_record(s_entry, e)

        if not batch_tasks:
            break

        batch_results = execute_harbor_batch(
            batch_tasks,
            batch_parent_dir=wave_dir,
            n_concurrent=n_concurrent,
            timeout_sec=1200,
        )

        next_wave_ids: List[str] = []
        for s_id in still_active_ids:
            st = states_by_id[s_id]
            s_entry = entries_by_id[s_id]
            try:
                trial_res = batch_results.get(s_id) or {
                    "run_status": "INFRA_FAILURE",
                    "failure_type": "HARBOR_TRIAL_MISSING",
                    "execution_error_sublabel": "Missing trial result from Harbor batch",
                }
                st.update(apply_trial_result_to_state(st, wave_task_dirs[s_id], trial_res))
                st.update(adjudicate_node(st))
                st.update(supervisor_eval_node(st))

                if st.get("supervisor_decision") == "REFINE" and wave < max_refinement_attempts:
                    next_wave_ids.append(s_id)
                else:
                    st.update(finalize_node(st))
                    records_by_id[s_id] = build_skill_record(s_entry, st)
            except Exception as e:
                records_by_id[s_id] = build_error_skill_record(s_entry, e)

        active_ids = next_wave_ids

    for s_id in active_ids:
        st = states_by_id[s_id]
        s_entry = entries_by_id[s_id]
        if s_id not in records_by_id:
            records_by_id[s_id] = build_skill_record(s_entry, st)

    return records_by_id


def execute_manifest_pipeline(
    manifest_path: str,
    output_report_path: Optional[str] = None,
    force_refresh: bool = True,
    resume: bool = True,
    on_skill_complete: Optional[Callable[[int, int, Dict[str, Any]], None]] = None,
    on_skill_start: Optional[Callable[[int, int, str], None]] = None
) -> Dict[str, Any]:
    """
    Executes the multi-agent verification pipeline across any arbitrary skill manifest.
    Builds every skill record from an isolated, immutable transformation without loop-carried state (P1).
    """
    if not os.path.exists(manifest_path):
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)

    skills = manifest_data.get("skills", [])
    total_skills = len(skills)

    # Phase 4 Batch Preflight: Run calibration controls C1-C11; abort batch if any fail
    try:
        from tests.controls.test_calibration_controls import run_calibration_controls
        run_calibration_controls()
    except Exception as e:
        raise RuntimeError(f"Pipeline batch preflight aborted due to calibration control failure: {e}")

    if output_report_path is None:
        manifest_dir = os.path.dirname(os.path.abspath(manifest_path))
        output_report_path = os.path.join(manifest_dir, "report.json")

    results: List[Dict[str, Any]] = []
    processed_ids = set()
    prev_results_by_id: Dict[str, Dict[str, Any]] = {}

    if resume and os.path.exists(output_report_path):
        try:
            with open(output_report_path, "r", encoding="utf-8") as f:
                prev_report = json.load(f)
            for r in prev_report.get("results", []):
                sid = r.get("skill_id")
                if sid and sid not in prev_results_by_id:
                    prev_results_by_id[sid] = r
        except Exception:
            prev_results_by_id = {}

    start_time = time.time()

    use_batch_harbor = (
        run_skill is _DEFAULT_RUN_SKILL
        and os.environ.get("EXEC_BACKEND", "harbor").lower() != "legacy"
        and os.environ.get("USE_HARBOR_BATCH", "1") == "1"
    )

    if use_batch_harbor:
        pending_items: List[tuple[int, Dict[str, Any]]] = []
        for idx, s in enumerate(skills, 1):
            s_id = s["skill_id"]
            if resume and s_id in prev_results_by_id:
                skill_res = prev_results_by_id[s_id]
                results.append(skill_res)
                processed_ids.add(s_id)
                if on_skill_complete:
                    try:
                        on_skill_complete(idx, total_skills, skill_res)
                    except Exception:
                        pass
                continue
            pending_items.append((idx, s))

        if pending_items:
            chunk_size = max(1, int(os.environ.get("HARBOR_WAVE_CHUNK_SIZE", "5")))
            for c_start in range(0, len(pending_items), chunk_size):
                chunk = pending_items[c_start : c_start + chunk_size]
                first_idx, first_s = chunk[0]
                first_sid = first_s["skill_id"]
                if on_skill_start:
                    try:
                        label = f"{first_sid} (+{len(chunk) - 1} in parallel batch)" if len(chunk) > 1 else first_sid
                        on_skill_start(first_idx, total_skills, label)
                    except Exception:
                        pass

                batch_records = _execute_manifest_batch_waves(
                    chunk,
                    force_refresh=force_refresh,
                    max_refinement_attempts=int(os.environ.get("MAX_REFINEMENT_ATTEMPTS", "3")),
                )
                for idx, s in chunk:
                    s_id = s["skill_id"]
                    skill_res = batch_records[s_id]
                    results.append(skill_res)
                    processed_ids.add(s_id)
                    prev_results_by_id[s_id] = skill_res
                    if on_skill_complete:
                        try:
                            on_skill_complete(idx, total_skills, skill_res)
                        except Exception:
                            pass

                checkpoint_report = summarize_report_records(
                    manifest_path=manifest_path,
                    manifest_data=manifest_data,
                    results=results,
                    total_skills=total_skills,
                    elapsed_sec=time.time() - start_time,
                )
                try:
                    tmp_checkpoint = output_report_path + ".tmp"
                    with open(tmp_checkpoint, "w", encoding="utf-8") as f:
                        json.dump(checkpoint_report, f, indent=2)
                    os.replace(tmp_checkpoint, output_report_path)
                except Exception:
                    try:
                        with open(output_report_path, "w", encoding="utf-8") as f:
                            json.dump(checkpoint_report, f, indent=2)
                    except Exception:
                        pass
    else:
        for idx, s in enumerate(skills, 1):
            s_id = s["skill_id"]

            if resume and s_id in prev_results_by_id:
                skill_res = prev_results_by_id[s_id]
                results.append(skill_res)
                processed_ids.add(s_id)
                if on_skill_complete:
                    try:
                        on_skill_complete(idx, total_skills, skill_res)
                    except Exception:
                        pass
                continue

            if on_skill_start:
                try:
                    on_skill_start(idx, total_skills, s_id)
                except Exception:
                    pass

            try:
                state = run_skill(s_id, manifest_file=manifest_path, force_refresh=force_refresh)
                skill_res = build_skill_record(s, state)
            except Exception as e:
                skill_res = build_error_skill_record(s, e)

            results.append(skill_res)
            processed_ids.add(s_id)
            prev_results_by_id[s_id] = skill_res

            checkpoint_report = summarize_report_records(
                manifest_path=manifest_path,
                manifest_data=manifest_data,
                results=results,
                total_skills=total_skills,
                elapsed_sec=time.time() - start_time,
            )
            try:
                tmp_checkpoint = output_report_path + ".tmp"
                with open(tmp_checkpoint, "w", encoding="utf-8") as f:
                    json.dump(checkpoint_report, f, indent=2)
                os.replace(tmp_checkpoint, output_report_path)
            except Exception:
                try:
                    with open(output_report_path, "w", encoding="utf-8") as f:
                        json.dump(checkpoint_report, f, indent=2)
                except Exception:
                    pass

            if on_skill_complete:
                try:
                    on_skill_complete(idx, total_skills, skill_res)
                except Exception:
                    pass

    report = summarize_report_records(
        manifest_path=manifest_path,
        manifest_data=manifest_data,
        results=results,
        total_skills=total_skills,
        elapsed_sec=time.time() - start_time,
    )
    assert sum(report["verdict_distribution"].values()) == total_skills, (
        f"Final verdict distribution sum {sum(report['verdict_distribution'].values())} != total_skills {total_skills}"
    )

    try:
        tmp_final = output_report_path + ".tmp"
        with open(tmp_final, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        os.replace(tmp_final, output_report_path)
    except Exception:
        try:
            with open(output_report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
        except Exception:
            pass

    return report


