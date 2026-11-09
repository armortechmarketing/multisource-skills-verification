"""W2 Shadow Mode Evaluation over Saved Harbor Trials in `jobs/`.

Runs the new pure `judge(contracts, evidence)` alongside the historical verdicts/old adjudicator
on saved trials in `jobs/`, prints the full disagreement table, and verifies:
1. All 8 benign skills in `sample_20261007_202014_4a8104` that were falsely labeled
   `Undeclared_Behavior` (due to `detect_canary_content_exfiltration` scanning `artifacts/canaries.json`)
   are no longer `Undeclared_Behavior`.
2. True positives `mal_airflow-dag-patterns_CI_B8` (`s3.filebase.com` / `51.79.228.160:443`)
   and `mal_Git_Commit_Helper_CI_B4` (`cdn.gitops.dev`) remain `Undeclared_Behavior` with
   concrete `strace.log:<line>` evidence references.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from src.a_adj_adjudicator import adjudicate_skill_behavior
from src.judge import JudgeConfig, judge
from src.telemetry_parser import build_evidence_from_artifacts, parse_strace_telemetry


def _run_legacy_adjudicator_on_trial(art_dir: Path, task_name: str) -> str:
    """Run the legacy 9-gate `adjudicate_skill_behavior` on a saved trial's artifacts."""
    rs_path = art_dir / "run_status.json"
    rs_data = {}
    if rs_path.exists():
        try:
            rs_data = json.loads(rs_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            rs_data = {}

    strace_path = art_dir / "strace.log"
    canaries_path = art_dir / "canaries.json"
    canary_paths: List[str] = []
    if canaries_path.exists():
        try:
            canary_paths = json.loads(canaries_path.read_text(encoding="utf-8", errors="ignore")).get("paths", [])
        except Exception:
            canary_paths = []

    parsed_strace = parse_strace_telemetry(
        str(strace_path) if strace_path.exists() else "",
        canary_paths=canary_paths,
    )
    events = parsed_strace.get("events", [])

    fix_path = art_dir / "fixtures.json"
    contracts = [{"contract_id": "C_01"}]
    if fix_path.exists():
        try:
            fix_data = json.loads(fix_path.read_text(encoding="utf-8", errors="ignore"))
            tcs = fix_data.get("test_cases") or []
            if tcs:
                contracts = [
                    {
                        "contract_id": tc.get("contract_id") or f"C_{i+1}",
                        "precondition": tc.get("precondition") or "",
                        "postcondition": tc.get("expected_postcondition") or "",
                    }
                    for i, tc in enumerate(tcs)
                ]
        except Exception:
            pass

    stdout_txt = (art_dir / "stdout.log").read_text(encoding="utf-8", errors="ignore") if (art_dir / "stdout.log").exists() else ""
    stderr_txt = (art_dir / "stderr.log").read_text(encoding="utf-8", errors="ignore") if (art_dir / "stderr.log").exists() else ""
    fs_diff_txt = (art_dir / "fs_diff.patch").read_text(encoding="utf-8", errors="ignore") if (art_dir / "fs_diff.patch").exists() else ""

    legacy_res = adjudicate_skill_behavior(
        contracts=contracts,
        traces=[{"events": events}],
        skill_dir=task_name,
        run_status=rs_data.get("run_status", "INVOKED_SUCCEEDED"),
        entry_point_reached=bool(rs_data.get("entry_point_reached", True)),
        failure_type=rs_data.get("failure_type"),
        execution_error_sublabel=rs_data.get("execution_error_sublabel"),
        fs_diff=fs_diff_txt,
        stdout=stdout_txt,
        stderr=stderr_txt,
    )
    return str(legacy_res.get("verdict") or legacy_res.get("predicted_label") or "UNKNOWN")


def test_w2_shadow_mode_across_saved_trials() -> None:
    """Run shadow mode across saved trials in `jobs/` and verify false positives vs true positives."""
    jobs_root = Path("jobs")
    if not jobs_root.exists():
        pytest.skip("jobs/ directory not present")

    # Collect all recent saved trials (20261007 and 20261008) that have a trial_*/artifacts directory
    job_dirs = sorted(jobs_root.glob("job_20261007*")) + sorted(jobs_root.glob("job_20261008*"))
    assert len(job_dirs) > 0, "Expected saved job_20261007* / job_20261008* directories in jobs/"

    # Also load historical report verdicts from the 3 sample report.json files for direct comparison
    sample_old_verdicts: Dict[str, str] = {}
    for s_dir in [
        Path("dynamic_samples/sample_20261007_202014_4a8104"),
        Path("dynamic_samples/sample_20261008_181535_639e49"),
        Path("dynamic_samples/sample_20261008_204736_fd8a31"),
    ]:
        s_path = s_dir / "report.before_rebuild.json"
        if not s_path.exists():
            s_path = s_dir / "report.json"
        if s_path.exists():
            rep = json.loads(s_path.read_text(encoding="utf-8"))
            for r in rep.get("results", []):
                sid = r.get("skill_id")
                if sid and sid not in sample_old_verdicts:
                    sample_old_verdicts[sid] = str(r.get("level2_verdict") or r.get("verdict") or "UNKNOWN")

    rows: List[Tuple[str, str, str, str, str, str]] = []
    disagreements: List[Tuple[str, str, str, str, str, str]] = []
    by_skill_latest: Dict[str, Dict[str, Any]] = {}

    for jd in job_dirs:
        trial_dirs = sorted(jd.glob("trial_*"))
        if not trial_dirs:
            continue
        td = trial_dirs[-1]
        art_dir = td / "artifacts"
        res_file = td / "result.json"
        if not art_dir.exists() or not res_file.exists():
            continue

        try:
            res_json = json.loads(res_file.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        task_name = str(res_json.get("task_name") or jd.name)

        # Build pure Evidence + Contracts and run new judge()
        evidence, contracts = build_evidence_from_artifacts(
            str(art_dir),
            skill_dir="/app/skill_package",
            trial_result_path=str(res_file),
        )
        new_res = judge(contracts, evidence, JudgeConfig(skill_dir="/app/skill_package"))
        new_label = (
            f"Inconclusive({new_res.no_verdict_reason})"
            if new_res.verdict == "Inconclusive" and new_res.no_verdict_reason
            else new_res.verdict
        )

        legacy_adj_label = _run_legacy_adjudicator_on_trial(art_dir, task_name)
        hist_report_label = sample_old_verdicts.get(task_name, legacy_adj_label)

        row = (
            jd.name,
            task_name,
            hist_report_label,
            legacy_adj_label,
            new_label,
            new_res.evidence_scope[:110],
        )
        rows.append(row)
        if hist_report_label != new_label or legacy_adj_label != new_label:
            disagreements.append(row)

        by_skill_latest[task_name] = {
            "job": jd.name,
            "hist_report_label": hist_report_label,
            "legacy_adj_label": legacy_adj_label,
            "new_label": new_label,
            "result": new_res,
        }

    print(f"\n=== W2 SHADOW MODE SUMMARY: Evaluated {len(rows)} saved trials ({len(disagreements)} disagreements) ===")
    print(f"{'Job':<22} | {'Skill ID':<38} | {'Report(Old)':<22} | {'OldAdj':<22} | {'NewJudge':<24} | {'Reason'}")
    print("-" * 165)
    for r in disagreements:
        print(f"{r[0]:<22} | {r[1][:38]:<38} | {r[2][:22]:<22} | {r[3][:22]:<22} | {r[4][:24]:<24} | {r[5]}")

    # 1. Verify the 8 benign skills from sample_20261007_202014_4a8104 that were falsely Undeclared_Behavior
    false_undeclared_benign_skills = [
        "benign_x",
        "benign_senior-architect",
        "benign_game-voice-content-inspiration",
        "benign_trace",
        "benign_strategic-planning-manager",
        "benign_alpha-insights",
        "benign_session-handoff",
        "benign_next-bundle-analyzer",
    ]
    for b_sid in false_undeclared_benign_skills:
        assert b_sid in by_skill_latest, f"Expected {b_sid} in evaluated trials"
        info = by_skill_latest[b_sid]
        assert info["hist_report_label"] == "Undeclared_Behavior"
        assert info["result"].verdict != "Undeclared_Behavior", (
            f"Benign skill {b_sid} is still Undeclared_Behavior: {info['result'].violations}"
        )

    # 2. Verify true positives mal_airflow-dag-patterns_CI_B8 and mal_Git_Commit_Helper_CI_B4 remain Undeclared_Behavior
    for tp_sid, expected_host_substr in [
        ("mal_airflow-dag-patterns_CI_B8", "filebase.com"),
        ("mal_Git_Commit_Helper_CI_B4", "cdn.gitops.dev"),
    ]:
        assert tp_sid in by_skill_latest, f"Expected true positive {tp_sid} in evaluated trials"
        tp_res = by_skill_latest[tp_sid]["result"]
        assert tp_res.verdict == "Undeclared_Behavior", f"{tp_sid} verdict was {tp_res.verdict}"
        assert any(expected_host_substr in v.detail or "51.79.228.160" in v.detail for v in tp_res.violations), (
            f"Expected {expected_host_substr} in {tp_sid} violations, got: {tp_res.violations}"
        )
        assert all(v.evidence_ref.startswith("strace.log:") for v in tp_res.violations)
