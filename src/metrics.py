import os
import json
from typing import Dict, Any, List, Optional

def compute_metrics(
    eval_records: List[Dict[str, Any]],
    ground_truth: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Computes rigorous benchmark and evaluation metrics across skill execution records:
    - T1/T2/T3 action rates over non-blocked code skills
    - Failure class distribution
    - Repairs used and success by action type
    - Token cost metrics
    - L1 benign False Positives and L2 benign flag rate
    - Combined IFR = (L1-blocked benign + L2-flagged benign) / benign total
    - Inconclusive distribution by label
    - Replay stability
    """
    total_skills = len(eval_records)
    code_skills = []
    instruction_skills = []
    blocked_skills = []

    for r in eval_records:
        verdict = r.get("verdict") or r.get("predicted_label")
        l1_risk = r.get("level1_risk") or r.get("l1_risk")
        if verdict == "Blocked_Static_CRITICAL" or l1_risk == "CRITICAL":
            blocked_skills.append(r)
        elif r.get("is_instruction_only") or r.get("domain") == "instruction_only":
            instruction_skills.append(r)
        else:
            code_skills.append(r)

    non_blocked_code_skills = [s for s in code_skills if s not in blocked_skills]
    nbc_count = len(non_blocked_code_skills) or 1

    def is_t1(s):
        return bool(s.get("t1_entry_reached") or s.get("entry_point_reached") or s.get("run_status") in ["INVOKED_SUCCEEDED", "INVOKED_FAILED"])

    def is_t2(s):
        if s.get("t2_meaningful") or s.get("t2_reached"):
            return True
        if s.get("run_status") == "INVOKED_SUCCEEDED":
            return True
        # If any contract had observations / was exercised
        cvs = s.get("contract_verdicts") or []
        return any(cv.get("exercised") for cv in cvs)

    def is_t3(s):
        if s.get("t3_evaluable") or s.get("t3_reached"):
            return True
        cvs = s.get("contract_verdicts") or []
        return any(cv.get("verdict") in ["Aligned", "Undeclared_Behavior", "Semantically_Divergent"] for cv in cvs)

    t1_count = sum(1 for s in non_blocked_code_skills if is_t1(s))
    t2_count = sum(1 for s in non_blocked_code_skills if is_t2(s))
    t3_count = sum(1 for s in non_blocked_code_skills if is_t3(s))

    t1_rate = round(t1_count / nbc_count, 3)
    t2_rate = round(t2_count / nbc_count, 3)
    t3_rate = round(t3_count / nbc_count, 3)

    # Failure class distribution
    failure_classes: Dict[str, int] = {}
    for r in eval_records:
        fc = r.get("triage_class") or r.get("failure_class") or "SUCCESS" if (r.get("exit_code") == 0 and r.get("t2_reached")) else "UNKNOWN"
        failure_classes[fc] = failure_classes.get(fc, 0) + 1

    # Repairs used by action type
    repairs_by_action: Dict[str, Dict[str, int]] = {}
    total_repairs = 0
    total_repair_tokens = 0

    for r in eval_records:
        r_log = r.get("repair_log") or []
        for rep in r_log:
            total_repairs += 1
            act = rep.get("proposed_action", {}).get("action", "unknown")
            if act not in repairs_by_action:
                repairs_by_action[act] = {"attempted": 0, "succeeded": 0}
            repairs_by_action[act]["attempted"] += 1
            if rep.get("outcome") == "SUCCESS" or rep.get("outcome") == "T2_REACHED":
                repairs_by_action[act]["succeeded"] += 1
        total_repair_tokens += r.get("repair_tokens", 0)

    # Ground truth comparison: benign vs malicious
    benign_total = 0
    l1_blocked_benign = 0
    l2_flagged_benign = 0
    l1_benign_fps: List[Dict[str, Any]] = []

    for r in eval_records:
        sid = r.get("skill_id", "")
        gt_type = None
        if ground_truth and sid in ground_truth:
            gt_type = ground_truth[sid]
        elif "benign" in sid:
            gt_type = "benign"
        elif "mal" in sid:
            gt_type = "malicious"

        if gt_type == "benign":
            benign_total += 1
            l1_risk = r.get("level1_risk") or r.get("l1_risk")
            verdict = r.get("verdict") or r.get("predicted_label")
            if l1_risk == "CRITICAL" or verdict == "Blocked_Static_CRITICAL":
                l1_blocked_benign += 1
                l1_benign_fps.append({
                    "skill_id": sid,
                    "rule": r.get("level1_rule", "UNKNOWN"),
                    "evidence": r.get("level1_evidence", "")
                })
            elif verdict in ["Undeclared_Behavior", "Semantically_Divergent"]:
                l2_flagged_benign += 1

    benign_denominator = benign_total or 1
    l1_benign_fp_rate = round(l1_blocked_benign / benign_denominator, 3)
    l2_benign_flag_rate = round(l2_flagged_benign / benign_denominator, 3)
    combined_ifr = round((l1_blocked_benign + l2_flagged_benign) / benign_denominator, 3)

    # Inconclusive distribution
    inconclusive_breakdown: Dict[str, int] = {}
    for r in eval_records:
        v = r.get("verdict") or r.get("predicted_label") or ""
        if v.startswith("INCONCLUSIVE_"):
            inconclusive_breakdown[v] = inconclusive_breakdown.get(v, 0) + 1

    # Replay stability
    replayed_skills = [r for r in eval_records if r.get("replay_attempted")]
    replay_count = len(replayed_skills) or 1
    replay_stable = sum(1 for r in replayed_skills if r.get("replay_matched"))
    replay_stability_rate = round(replay_stable / replay_count, 3) if replayed_skills else 1.0

    return {
        "summary": {
            "total_skills": total_skills,
            "non_blocked_code_skills": len(non_blocked_code_skills),
            "instruction_only_skills": len(instruction_skills),
            "blocked_skills": len(blocked_skills),
            "t1_entry_reached_rate": t1_rate,
            "t2_meaningful_action_rate": t2_rate,
            "t3_postcondition_rate": t3_rate,
            "combined_ifr": combined_ifr,
            "l1_benign_fp_rate": l1_benign_fp_rate,
            "l2_benign_flag_rate": l2_benign_flag_rate,
            "replay_stability_rate": replay_stability_rate
        },
        "rates": {
            "T1": t1_rate,
            "T2": t2_rate,
            "T3": t3_rate,
            "T2_target_met": (t2_rate >= 0.60),
            "L1_FP_target_met": (l1_benign_fp_rate <= 0.10)
        },
        "failure_classes": failure_classes,
        "repairs": {
            "total_repairs": total_repairs,
            "total_repair_tokens": total_repair_tokens,
            "by_action": repairs_by_action
        },
        "l1_benign_false_positives": l1_benign_fps,
        "inconclusive_breakdown": inconclusive_breakdown
    }

def evaluate_execution_metrics(eval_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Helper alias for test suite calculating basic rates."""
    total = len(eval_records) or 1
    t1 = sum(1 for r in eval_records if r.get("entry_point_reached") or r.get("t1_entry_reached"))
    t2 = sum(1 for r in eval_records if r.get("t2_reached") or r.get("t2_meaningful"))
    t3 = sum(1 for r in eval_records if r.get("t3_evaluable") or r.get("t3_reached"))
    infra = sum(1 for r in eval_records if r.get("run_status") == "INFRA_FAILURE")
    return {
        "T1_entry_rate": t1 / total,
        "T2_meaningful_rate": t2 / total,
        "T3_evaluable_rate": t3 / total,
        "infra_failure_rate": infra / total
    }

