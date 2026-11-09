import json
import os
import shutil
import time
from typing import Any, Dict, List

from src.a_gen_test_generator import generate_test_cases
from src.a_orch_supervisor import (
    evaluate_verification_progress,
    load_env,
    supervisor_plan_strategy,
    supervisor_step,
)
from src.a_syn_contract_synthesizer import (
    CURRENT_ASYN_VERSION,
    compute_skill_version_hash,
    extract_contracts_for_skill,
    runtime_bias_guard,
    scan_skill_for_level1_security,
    synthesize_contracts_with_security,
)
from src.adapters.skills_adapter import SkillHarborAdapter
from src.harbor_runner import execute_harbor_trial
from src.judge import (
    BehaviorUnit,
    Check,
    CheckResult,
    Contract,
    Evidence,
    JudgeConfig,
    RunStatusInfo,
    judge,
    parse_contract_from_dict,
)
from src.sandbox_runner import execute_skill_test
from src.state import PipelineState
from src.telemetry_parser import build_evidence_from_artifacts

load_env()


def supervisor_init_node(state: PipelineState) -> Dict[str, Any]:
    """
    Node 0: A_orch (Supervisor Strategy Initiation)
    Analyzes skill domain and declaration to set the verification directive.
    """
    skill_id = state["skill_id"]
    domain = state.get("domain") or "data_processing"
    declaration_text = state.get("declaration_text", "")

    directive = supervisor_plan_strategy(skill_id, domain, declaration_text)
    from src.agent_skill_loader import get_agent_skill_version_hash
    aorch_hash = get_agent_skill_version_hash("a_orch")
    prior_messages = list(state.get("agent_messages") or [])
    init_msg = {
        "round": 0,
        "agent": "a_orch",
        "action": "plan_strategy",
        "directive": directive,
        "mode": "deterministic",
        "model": None,
        "skill_version_hash": aorch_hash,
        "input_tokens": None,
        "output_tokens": None,
        "latency_ms": 0,
        "fallback_reason": None,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    return {
        "supervisor_directive": directive,
        "agent_messages": prior_messages + [init_msg],
        "status": "in_progress",
    }


def contract_synth_node(state: PipelineState) -> Dict[str, Any]:
    """
    Node 1: A_syn (Contract Synthesizer & Security Gate Agent)
    Synthesizes formal behavioral contracts and performs static security inspection
    in a unified pass as A_syn reads the skill declaration and package.
    Applies A_orch pre-filter gating: CRITICAL -> skips Level-2 execution.
    """
    skill_path = state["skill_path"]
    skill_id = state["skill_id"]
    contracts_file = os.path.join(skill_path, "contracts.json")
    declaration_text = state.get("declaration_text", "")
    current_hash = compute_skill_version_hash(skill_path, declaration_text=declaration_text)
    syn_model = os.environ.get("ASYN_MODEL", os.environ.get("OPENAI_MODEL", "gpt-4o-mini"))

    force_synth = os.environ.get("FORCE_SYNTHESIZE_CONTRACTS", "0") == "1"
    contracts = None
    l1_report = None
    loaded_from_cache = False

    # Re-use cached contracts if present on disk (unless FORCE_SYNTHESIZE_CONTRACTS=1)
    candidate_files = [contracts_file, os.path.join("skills_dataset", skill_id, "contracts.json")]
    if not force_synth:
        for c_file in candidate_files:
            if os.path.exists(c_file):
                try:
                    with open(c_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    cached_hash = data.get("skill_version_hash") if isinstance(data, dict) else None
                    cached_model = data.get("model") if isinstance(data, dict) else None
                    cached_asyn_ver = data.get("asyn_version") if isinstance(data, dict) else None
                    # If hash is present and doesn't match current, invalidate cache
                    if cached_hash and cached_hash != current_hash:
                        continue
                    if cached_model and cached_model != syn_model:
                        continue
                    # Amendment B5: Invalidate old cached contracts lacking or with outdated asyn_version
                    if not cached_asyn_ver or cached_asyn_ver != CURRENT_ASYN_VERSION:
                        continue
                    loaded_contracts = data.get("contracts", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
                    if loaded_contracts:
                        if c_file != contracts_file:
                            try:
                                shutil.copy2(c_file, contracts_file)
                            except Exception:
                                pass
                        contracts = [dict(c) for c in loaded_contracts]
                        loaded_from_cache = True
                        syn_meta = {
                            "chunks_total": data.get("chunks_total", 1),
                            "chunks_processed": data.get("chunks_processed", 1),
                            "chunks_skipped": data.get("chunks_skipped", 0),
                            "truncated": data.get("truncated", False),
                        }
                        break
                except Exception:
                    pass

    # If contracts are not cached or forced, A_syn performs unified contract synthesis + security scan
    effective_api_key = os.environ.get("OPENAI_API_KEY", "").strip() or os.environ.get("GEMINI_API_KEY", "").strip()
    syn_meta = syn_meta if loaded_from_cache else {}
    if contracts is None:
        contracts, l1_report, syn_meta = synthesize_contracts_with_security(
            skill_dir=skill_path,
            skill_id=skill_id,
            api_key=effective_api_key,
            declaration_text=declaration_text,
        )

        contract_output = {
            "skill_id": skill_id,
            "skill_version_hash": current_hash,
            "asyn_version": CURRENT_ASYN_VERSION,
            "model": syn_model,
            "declaration_source": "SKILL.md",
            "total_contracts": len(contracts),
            "chunks_total": syn_meta.get("chunks_total", 1),
            "chunks_processed": syn_meta.get("chunks_processed", 1),
            "chunks_skipped": syn_meta.get("chunks_skipped", 0),
            "truncated": syn_meta.get("truncated", False),
            "synthesized_by": "A_syn (Contract Synthesizer & Level-1 Security Gate)",
            "contracts": contracts,
            "level1_report": l1_report,
        }
        try:
            with open(contracts_file, "w", encoding="utf-8") as f:
                json.dump(contract_output, f, indent=2)
        except Exception:
            pass
    else:
        l1_report = scan_skill_for_level1_security(skill_path, declaration_text=declaration_text)

    contracts = contracts or []
    risk_level = l1_report.get("risk_level", "LOW")

    from src.agent_skill_loader import get_agent_skill_version_hash
    asyn_hash = get_agent_skill_version_hash("a_syn")

    if loaded_from_cache:
        synth_mode = "deterministic"
        synth_fallback = "Loaded pre-synthesized contracts from cache"
    elif syn_meta.get("mode"):
        synth_mode = syn_meta.get("mode", "deterministic")
        synth_fallback = syn_meta.get("fallback_reason")
    elif effective_api_key:
        synth_mode = "llm"
        synth_fallback = None
    else:
        synth_mode = "deterministic"
        synth_fallback = "No API key configured"

    prior_messages = list(state.get("agent_messages") or [])
    synth_msg = {
        "round": state.get("refinement_attempts", 0),
        "agent": "a_syn",
        "action": "synthesize_contracts",
        "total_contracts": len(contracts),
        "level1_risk": risk_level,
        "mode": synth_mode,
        "model": syn_meta.get("model") or (syn_model if synth_mode == "llm" else None),
        "skill_version_hash": asyn_hash,
        "input_tokens": syn_meta.get("input_tokens"),
        "output_tokens": syn_meta.get("output_tokens"),
        "latency_ms": syn_meta.get("latency_ms", 0),
        "fallback_reason": synth_fallback,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    updated_msgs = prior_messages + [synth_msg]

    if risk_level == "CRITICAL":
        # A_orch Gating Rule: SKIP test generation and Harbor execution entirely
        pred = {
            "predicted_label": "Blocked_Static_CRITICAL",
            "verdict": "Blocked_Static_CRITICAL",
            "no_verdict_reason": None,
            "gating_status": "SKIPPED_LEVEL1_CRITICAL",
            "run_status": "NOT_INVOKED",
            "execution_error_sublabel": None,
            "execution_error_note": None,
            "violation_evidence": [r["evidence"] for r in l1_report.get("triggered_rules", [])],
            "violations": [
                {
                    "rule_id": r.get("rule_id", "L1_CRITICAL"),
                    "behavior_unit_id": "static_l1",
                    "evidence_ref": "SKILL.md",
                    "kind": "forbidden",
                    "detail": r.get("evidence", ""),
                }
                for r in l1_report.get("triggered_rules", [])
            ],
            "behavior_units": [],
            "contract_status": [
                {
                    "contract_id": c.get("contract_id", f"C_{idx+1:02d}"),
                    "status": "NOT_EXERCISED",
                    "reason": "Skipped Level-2 execution due to Level-1 CRITICAL finding",
                    "cited_unit_ids": [],
                }
                for idx, c in enumerate(contracts or [{"contract_id": "C_01"}])
            ],
            "intent_to_behavior": {},
            "coverage": 1.0,
            "coverage_score": 1.0,
            "threat_category": l1_report.get("threat_category"),
            "reason": l1_report.get("reason"),
            "contract_verdicts": [
                {
                    "contract_id": c.get("contract_id", f"C_{idx+1:02d}"),
                    "verdict": "Blocked_Static_CRITICAL",
                    "exercised": False,
                    "violation_evidence": [r["evidence"] for r in l1_report.get("triggered_rules", [])],
                }
                for idx, c in enumerate(contracts or [{"contract_id": "C_01"}])
            ],
        }
        return {
            "contracts": contracts,
            "level1_report": l1_report,
            "gating_status": "SKIPPED_LEVEL1_CRITICAL",
            "prediction": pred,
            "run_status": "NOT_INVOKED",
            "coverage_score": 1.0,
            "agent_messages": updated_msgs,
            "chunks_total": syn_meta.get("chunks_total", 1),
            "chunks_processed": syn_meta.get("chunks_processed", 1),
            "chunks_skipped": syn_meta.get("chunks_skipped", 0),
            "truncated": syn_meta.get("truncated", False),
            "status": "in_progress",
        }

    elif risk_level == "HIGH":
        for c in contracts:
            for rule in l1_report.get("triggered_rules", []):
                inv_text = f"MUST NOT violate {rule['rule_id']}: {rule['evidence']}"
                if inv_text not in c.get("forbidden_invariants", []):
                    c.setdefault("forbidden_invariants", []).append(inv_text)
        return {
            "contracts": contracts,
            "level1_report": l1_report,
            "chunks_total": syn_meta.get("chunks_total", 1),
            "chunks_processed": syn_meta.get("chunks_processed", 1),
            "chunks_skipped": syn_meta.get("chunks_skipped", 0),
            "truncated": syn_meta.get("truncated", False),
            "agent_messages": updated_msgs,
            "status": "in_progress",
        }

    elif risk_level == "MEDIUM":
        sup_dir = state.get("supervisor_directive") or ""
        threat_cat = l1_report.get("threat_category", "Suspicious Signal")
        return {
            "contracts": contracts,
            "level1_report": l1_report,
            "chunks_total": syn_meta.get("chunks_total", 1),
            "chunks_processed": syn_meta.get("chunks_processed", 1),
            "chunks_skipped": syn_meta.get("chunks_skipped", 0),
            "truncated": syn_meta.get("truncated", False),
            "supervisor_directive": (sup_dir + f" [Level-1 Notice: Prioritize testing {threat_cat}]").strip(),
            "agent_messages": updated_msgs,
            "status": "in_progress",
        }

    return {
        "contracts": contracts,
        "level1_report": l1_report,
        "chunks_total": syn_meta.get("chunks_total", 1),
        "chunks_processed": syn_meta.get("chunks_processed", 1),
        "chunks_skipped": syn_meta.get("chunks_skipped", 0),
        "truncated": syn_meta.get("truncated", False),
        "agent_messages": updated_msgs,
        "status": "in_progress",
    }


def test_gen_node(state: PipelineState) -> Dict[str, Any]:
    """
    Node 2: A_gen (Test & Fixture Generator Agent)
    Autonomous LLM agent generating realistic mock files, CLI flags, env vars, and deterministic checks.
    Guided by supervisor directives and targeted contract lists during refinement.
    """
    skill_path = state["skill_path"]
    contracts = state.get("contracts") or []
    prediction = state.get("prediction") or {}
    attempts = state.get("refinement_attempts", 0)

    uncovered_ids = prediction.get("uncovered_contracts", []) if attempts > 0 else None
    supervisor_directive = state.get("supervisor_directive")

    res_gen = generate_test_cases(
        contracts=contracts,
        skill_dir=skill_path,
        uncovered_contract_ids=uncovered_ids,
        supervisor_directive=supervisor_directive,
        declaration_text=state.get("declaration_text", ""),
        return_meta=True,
    )
    if isinstance(res_gen, tuple):
        test_cases, gen_meta = res_gen
    else:
        test_cases, gen_meta = res_gen, {"mode": "deterministic", "model": None, "fallback_reason": "No metadata returned"}

    from src.agent_skill_loader import get_agent_skill_version_hash
    agen_hash = get_agent_skill_version_hash("a_gen")
    prior_messages = list(state.get("agent_messages") or [])
    gen_msg = {
        "round": attempts,
        "agent": "a_gen",
        "action": "generate_tests",
        "total_tests": len(test_cases),
        "target_contracts": uncovered_ids or [],
        "mode": gen_meta.get("mode", "deterministic"),
        "model": gen_meta.get("model"),
        "skill_version_hash": agen_hash,
        "input_tokens": gen_meta.get("input_tokens"),
        "output_tokens": gen_meta.get("output_tokens"),
        "latency_ms": gen_meta.get("latency_ms", 0),
        "fallback_reason": gen_meta.get("fallback_reason"),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    return {
        "test_cases": test_cases,
        "agent_messages": prior_messages + [gen_msg],
        "status": "in_progress",
    }


def apply_trial_result_to_state(
    state: PipelineState,
    task_dir: str,
    trial_res: Dict[str, Any],
) -> Dict[str, Any]:
    """Convert a Harbor trial result dict into the state update produced by `sandbox_exec_node`."""
    skill_path = state["skill_path"]
    test_cases = state.get("test_cases") or []
    prior_traces = state.get("traces") or []

    current_test_results = []
    if test_cases:
        for idx, tc in enumerate(test_cases):
            c_id = tc.get("contract_id", f"C_{idx+1:02d}")
            t_id = tc.get("test_id", f"TC_{idx+1:02d}")
            current_test_results.append(
                {
                    "test_id": t_id,
                    "contract_id": c_id,
                    "execution_mode": f"harbor_{trial_res['agent_mode']}",
                    "status": "completed" if trial_res["run_status"] == "INVOKED_SUCCEEDED" else "failed",
                    "return_code": trial_res["exit_code"] if trial_res["exit_code"] is not None else 0,
                    "events": trial_res.get("events", []),
                    "run_status": trial_res["run_status"],
                    "entry_point_reached": trial_res["entry_point_reached"],
                }
            )
    else:
        current_test_results.append(
            {
                "test_id": "TC_01",
                "contract_id": "C_01",
                "execution_mode": f"harbor_{trial_res['agent_mode']}",
                "status": "completed" if trial_res["run_status"] == "INVOKED_SUCCEEDED" else "failed",
                "return_code": trial_res["exit_code"] if trial_res["exit_code"] is not None else 0,
                "events": trial_res.get("events", []),
                "run_status": trial_res["run_status"],
                "entry_point_reached": trial_res["entry_point_reached"],
            }
        )

    updated_traces = prior_traces + current_test_results

    trial_root_dir = trial_res.get("trial_dir")
    if trial_root_dir:
        cand_traj_paths = [
            os.path.join(trial_root_dir, "agent", "trajectory.json"),
            os.path.join(trial_root_dir, "artifacts", "trajectory.json"),
        ]
        for ctp in cand_traj_paths:
            if os.path.exists(ctp):
                try:
                    shutil.copy2(ctp, os.path.join(skill_path, "trajectory.json"))
                    break
                except Exception:
                    pass

    return {
        "traces": updated_traces,
        "run_status": trial_res["run_status"],
        "entry_point_reached": trial_res["entry_point_reached"],
        "activation": trial_res.get("activation"),
        "script_execution": trial_res.get("script_execution"),
        "failure_type": trial_res.get("failure_type"),
        "execution_error_sublabel": trial_res.get("execution_error_sublabel"),
        "auto_installed_packages": trial_res.get("auto_installed_packages", []),
        "fs_diff": trial_res.get("fs_diff"),
        "harbor_task_dir": task_dir,
        "harbor_trial_dir": trial_res.get("trial_dir"),
        "backend": trial_res.get("backend", "harbor_docker"),
        "valid_for_paper": trial_res.get("valid_for_paper", True),
        "goal_drift_audit": trial_res.get("goal_drift_audit"),
        "status": "in_progress",
    }


def sandbox_exec_node(state: PipelineState) -> Dict[str, Any]:
    """
    Node 3: A_exec (Execution Engine)
    Executes skill inside real Harbor Docker sandbox (`EXEC_BACKEND=harbor`).
    """
    skill_path = state["skill_path"]
    skill_id = state["skill_id"]
    test_cases = state.get("test_cases") or []
    prior_traces = state.get("traces") or []
    contracts = state.get("contracts") or []
    exec_backend = os.environ.get("EXEC_BACKEND", "harbor").lower()

    if exec_backend == "legacy":
        current_test_results = []
        for tc in test_cases:
            res = execute_skill_test(skill_path, tc)
            current_test_results.append(res)

        updated_traces = prior_traces + current_test_results
        any_crashed = any(r.get("status") == "crashed" for r in current_test_results)
        legacy_status = "INVOKED_FAILED" if any_crashed else "INVOKED_SUCCEEDED"

        return {
            "traces": updated_traces,
            "run_status": legacy_status,
            "entry_point_reached": True,
            "status": "in_progress",
        }

    adapter = SkillHarborAdapter(base_output_dir="harbor_tasks")
    task_dir = adapter.scaffold_task(
        skill_id=skill_id,
        skill_dir=skill_path,
        declaration_text=state.get("declaration_text", ""),
        contracts=contracts,
    )

    trial_res = execute_harbor_trial(
        task_dir=task_dir,
        skill_dir=skill_path,
        test_cases=test_cases,
        contracts=contracts,
        refinement_attempt=state.get("refinement_attempts", 0),
    )
    return apply_trial_result_to_state(state, task_dir, trial_res)


def _build_fallback_evidence_from_state(
    state: PipelineState,
    contracts_raw: List[Dict[str, Any]],
) -> tuple[Evidence, tuple[Contract, ...]]:
    """Build Evidence from in-memory state when `adjudicate_node` is called directly without a Harbor trial directory."""
    parsed_contracts = tuple(
        parse_contract_from_dict(c, index=idx)
        for idx, c in enumerate(contracts_raw or [{"contract_id": "C_01"}])
    )
    traces = state.get("traces") or []
    units: List[BehaviorUnit] = []
    exit_code = 0
    for r in traces:
        if r.get("return_code") is not None:
            exit_code = int(r["return_code"])
        for ev in r.get("events", []):
            ev_type = ev.get("event_type")
            details = ev.get("details") or {}
            if ev_type == "filesystem":
                op = details.get("operation", "read")
                p = details.get("path", "")
                units.append(
                    BehaviorUnit(
                        id=f"bu_{len(units)+1:03d}",
                        kind="file_write" if op == "write" else "file_read",
                        target=str(p),
                        ts=0.0,
                        evidence_ref="trace.jsonl:1",
                    )
                )
            elif ev_type == "network":
                dest = details.get("destination") or details.get("host") or ""
                units.append(
                    BehaviorUnit(
                        id=f"bu_{len(units)+1:03d}",
                        kind="net_connect",
                        target=str(dest),
                        ts=0.0,
                        evidence_ref="trace.jsonl:1",
                    )
                )
            elif ev_type == "os_command":
                cmd = details.get("command") or details.get("argv") or ""
                units.append(
                    BehaviorUnit(
                        id=f"bu_{len(units)+1:03d}",
                        kind="exec",
                        target=str(cmd),
                        ts=0.0,
                        evidence_ref="trace.jsonl:1",
                    )
                )
    raw_rs = str(state.get("run_status") or "INVOKED_SUCCEEDED")
    sig = None
    if raw_rs == "INFRA_FAILURE":
        sig = "INFRA"
    elif state.get("failure_type") == "HARNESS_ERROR":
        sig = "HARNESS"
    ev = Evidence(
        run_status=RunStatusInfo(
            entry_reached=bool(state.get("entry_point_reached", True)),
            exit_code=exit_code,
            failure_signature=sig,
        ),
        behavior_units=tuple(units),
        fs_diff=tuple([state["fs_diff"]]) if state.get("fs_diff") else (),
    )
    return ev, parsed_contracts


def adjudicate_node(state: PipelineState) -> Dict[str, Any]:
    """
    Node 4: A_adj (Adjudication Agent)
    Pure functional judge (`src/judge.py:judge(contracts, evidence, config) -> JudgeResult`)
    evaluating contracts against OS-level BehaviorUnits and deterministic checks.
    """
    contracts_raw = [dict(c) for c in (state.get("contracts") or [])]
    test_cases_state = state.get("test_cases") or []
    if test_cases_state and contracts_raw:
        from src.system_baseline import is_forbidden_path, normalize_posix_path

        tc_checks_by_cid: Dict[str, List[Dict[str, Any]]] = {}
        mock_read_paths: List[str] = []
        for tc in test_cases_state:
            if not isinstance(tc, dict):
                continue
            cid = str(tc.get("contract_id") or tc.get("test_id") or "C_01")
            for chk in tc.get("checks") or []:
                if isinstance(chk, dict):
                    tc_checks_by_cid.setdefault(cid, []).append(chk)
            for mp in (tc.get("mock_files") or {}).keys():
                raw_mp = str(mp)
                if raw_mp.startswith("~/"):
                    for h_pre in ("/home/agent/", "/root/"):
                        cand_mp = normalize_posix_path(h_pre + raw_mp[2:])
                        if is_forbidden_path(cand_mp, "file_read", skill_dir="/app/skill") is None:
                            mock_read_paths.append(cand_mp)
                else:
                    cand_mp = normalize_posix_path(raw_mp if raw_mp.startswith("/") else f"/app/skill/{raw_mp}")
                    if is_forbidden_path(cand_mp, "file_read", skill_dir="/app/skill") is None:
                        mock_read_paths.append(cand_mp)
        for idx, c_item in enumerate(contracts_raw):
            cid = str(c_item.get("contract_id") or c_item.get("id") or f"C_{idx+1:02d}")
            if cid in tc_checks_by_cid and not c_item.get("checks"):
                c_item["checks"] = tc_checks_by_cid[cid]
            if mock_read_paths:
                fa = c_item.get("frame_axiom")
                if isinstance(fa, list):
                    c_item["frame_axiom"] = list(fa) + [f"read: {p}" for p in mock_read_paths]
                elif isinstance(fa, dict):
                    fa_copy = dict(fa)
                    fa_copy["read"] = list(fa_copy.get("read") or []) + mock_read_paths
                    c_item["frame_axiom"] = fa_copy
                else:
                    c_item["frame_axiom"] = [f"read: {p}" for p in mock_read_paths]

    trial_dir = state.get("harbor_trial_dir")

    if trial_dir and os.path.isdir(os.path.join(trial_dir, "artifacts")):
        artifacts_dir = os.path.join(trial_dir, "artifacts")
        trial_result_path = os.path.join(trial_dir, "result.json")
        evidence, parsed_contracts = build_evidence_from_artifacts(
            artifacts_dir=artifacts_dir,
            skill_dir="/app/skill",
            trial_result_path=trial_result_path,
            contracts_override=contracts_raw,
        )
    else:
        evidence, parsed_contracts = _build_fallback_evidence_from_state(state, contracts_raw)

    min_cov = float(os.environ.get("ALIGNED_MIN_COVERAGE", "0.5"))
    postcondition_fn = None
    try:
        from src.a_adj_adjudicator import judge_postcondition as _llm_judge_postcondition

        if os.environ.get("USE_LLM_POSTCONDITION", "1") != "0" and (
            os.environ.get("OPENAI_API_KEY", "").strip() or os.environ.get("GEMINI_API_KEY", "").strip()
        ):
            postcondition_fn = _llm_judge_postcondition
    except Exception:
        postcondition_fn = None

    config = JudgeConfig(
        aligned_min_coverage=min_cov,
        skill_dir=state.get("skill_path") or state.get("skill_dir") or "/app/skill",
        postcondition_judge_fn=postcondition_fn,
    )
    judge_res = judge(parsed_contracts, evidence, config)
    pred = judge_res.to_prediction_dict()
    pred["chunks_total"] = state.get("chunks_total", 1)
    pred["chunks_processed"] = state.get("chunks_processed", 1)
    pred["chunks_skipped"] = state.get("chunks_skipped", 0)
    pred["truncated"] = state.get("truncated", False)

    # Check for trajectory goal drift in instruction-only executions
    trial_dir = state.get("harbor_trial_dir")
    traj_file = None
    if trial_dir:
        for cand in [
            os.path.join(trial_dir, "agent", "trajectory.json"),
            os.path.join(trial_dir, "artifacts", "trajectory.json"),
        ]:
            if os.path.isfile(cand):
                traj_file = cand
                break
    if not traj_file:
        cand_skill_traj = os.path.join(state.get("skill_path", ""), "trajectory.json")
        if os.path.isfile(cand_skill_traj):
            traj_file = cand_skill_traj

    gd_res = state.get("goal_drift_audit")
    if not gd_res and traj_file:
        try:
            from src.security.goal_drift_auditor import audit_trajectory_goal_drift
            with open(traj_file, "r", encoding="utf-8") as tf:
                traj_data = json.load(tf)
            gd_res = audit_trajectory_goal_drift(traj_data, skill_id=state.get("skill_id", ""))
        except Exception:
            gd_res = None

    if gd_res:
        pred["goal_drift_audit"] = gd_res
        if gd_res.get("drift_detected") and judge_res.verdict == "Aligned":
            judge_res.verdict = "Undeclared_Behavior"
            pred["verdict"] = "Undeclared_Behavior"
            pred["predicted_label"] = "Undeclared_Behavior"
            for ev_item in gd_res.get("evidence", []):
                pred.setdefault("violations", []).append({
                    "rule_id": "GOAL_DRIFT_" + str(gd_res.get("drift_type", "HIJACK")),
                    "behavior_unit_id": "trajectory_goal_drift",
                    "evidence_ref": "trajectory.json",
                    "kind": "forbidden",
                    "detail": ev_item,
                })

    verdict_before = judge_res.verdict
    try:
        from src.a_adj_adjudicator import generate_grounded_explanation
        explanation = generate_grounded_explanation(
            skill_id=state.get("skill_id", ""),
            verdict=judge_res.verdict,
            contract_status=pred.get("contract_status", []),
            violations=pred.get("violations", []),
            behavior_units=pred.get("behavior_units", []),
            dtc=judge_res.dtc,
            csr_c=judge_res.csr_c,
            attributions=pred.get("attribution", []),
        )
        assert judge_res.verdict == verdict_before, "Attribution/explanation must not alter deterministic verdict"
        pred["explanation"] = explanation
    except Exception:
        pass

    # Supervisor loop eligibility: HARNESS | SKILL_CRASH | LOW_COVERAGE, or NO_TESTABLE_CONTRACTS (refinable once)
    current_refinement_attempts = int(state.get("refinement_attempts", 0))
    needs_rerun = bool(
        judge_res.verdict == "Inconclusive"
        and (
            judge_res.no_verdict_reason in ("HARNESS", "SKILL_CRASH", "LOW_COVERAGE")
            or (judge_res.no_verdict_reason == "NO_TESTABLE_CONTRACTS" and current_refinement_attempts < 1)
        )
    )
    pred["needs_rerun"] = needs_rerun
    pred["stderr_feedback"] = (evidence.stderr or "")[-1500:]

    from src.agent_skill_loader import get_agent_skill_version_hash
    aadj_hash = get_agent_skill_version_hash("a_adj")
    explanation_obj = pred.get("explanation") or {}
    exp_meta = explanation_obj.get("_meta") or {}
    adj_mode = exp_meta.get("mode") or "deterministic"
    adj_fallback = exp_meta.get("fallback_reason")

    downgrade_reasons = [
        cs.get("downgrade_reason")
        for cs in pred.get("contract_status", [])
        if cs.get("downgrade_reason")
    ]
    if downgrade_reasons and adj_mode == "deterministic":
        adj_mode = "llm"

    prior_messages = list(state.get("agent_messages") or [])
    adj_msg = {
        "round": state.get("refinement_attempts", 0),
        "agent": "a_adj",
        "action": "adjudicate",
        "verdict": judge_res.verdict,
        "dtc": judge_res.dtc,
        "csr_c": judge_res.csr_c,
        "violations_count": len(pred.get("violations") or []),
        "mode": adj_mode,
        "model": exp_meta.get("model") if adj_mode != "deterministic" else None,
        "skill_version_hash": aadj_hash,
        "input_tokens": exp_meta.get("input_tokens"),
        "output_tokens": exp_meta.get("output_tokens"),
        "latency_ms": exp_meta.get("latency_ms", 0),
        "fallback_reason": adj_fallback,
        "downgrade_reason": downgrade_reasons[0] if downgrade_reasons else None,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    return {
        "prediction": pred,
        "level2_verdict": judge_res.verdict,
        "gating_status": pred.get("gating_status"),
        "coverage_score": judge_res.coverage,
        "dtc": judge_res.dtc,
        "csr_c": judge_res.csr_c,
        "needs_rerun": needs_rerun,
        "execution_error_sublabel": pred.get("execution_error_sublabel") or state.get("execution_error_sublabel"),
        "agent_messages": prior_messages + [adj_msg],
        "status": "in_progress",
    }


def supervisor_eval_node(state: PipelineState) -> Dict[str, Any]:
    """
    Node 5: A_orch (Supervisor Evaluation & Routing Controller)
    Evaluates adjudication results and decides next move: REFINE vs CONCLUDE.
    """
    attempts = int(state.get("refinement_attempts", 0))
    step_res = supervisor_step(state)

    new_decision = step_res["decision"]
    new_directive = step_res["directive"] or step_res["reason"]

    prior_messages = list(state.get("agent_messages") or [])
    updated_messages = prior_messages + [step_res["agent_message"]]

    return {
        "supervisor_decision": new_decision,
        "supervisor_directive": new_directive,
        "refinement_attempts": attempts + 1 if new_decision == "REFINE" else attempts,
        "agent_messages": updated_messages,
    }


def finalize_node(state: PipelineState) -> Dict[str, Any]:
    """Finalizes verification state."""
    return {
        "status": "done",
    }
