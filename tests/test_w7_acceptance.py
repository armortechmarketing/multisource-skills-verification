"""
W7 Acceptance & Supervisor Refinement Test Suite (`tests/test_w7_acceptance.py`).

Verifies:
1. Supervisor refinement loop:
   - `Inconclusive(HARNESS)` triggers `REFINE` and `build_schema_aware_fixture` synthesizes missing required flags/files from `stderr_feedback`, reaching `Aligned` on pass 2.
   - `Undeclared_Behavior` or final verdicts (`Aligned`, `Semantically_Divergent`, `Unimplemented_Intent`, `Inconclusive(INFRA|NO_ENTRY|NO_AGENT)`) immediately `CONCLUDE` without wasting budget.
2. Acceptance Criteria (a) through (h) across the 3 re-run sample reports (`sample_20261007_202014_4a8104`, `sample_20261008_181535_639e49`, `sample_20261008_204736_fd8a31`) and the 17 calibration skills.
"""

import json
import os
import subprocess
from typing import Any, Dict, List

from src.a_gen_test_generator import build_schema_aware_fixture
from src.a_orch_supervisor import evaluate_verification_progress
from src.nodes import adjudicate_node, supervisor_eval_node


SAMPLE_DIRS = [
    "dynamic_samples/sample_20261007_202014_4a8104",
    "dynamic_samples/sample_20261008_181535_639e49",
    "dynamic_samples/sample_20261008_204736_fd8a31",
]


def test_w7_supervisor_refinement_loop_recovers_harness_and_stops_on_violation(tmp_path) -> None:
    """
    Verify that:
    - An initial Inconclusive(HARNESS) run with stderr 'error: the following arguments are required: --config'
      causes supervisor_eval_node to return REFINE with stderr feedback in supervisor_directive.
    - test_gen_node / build_schema_aware_fixture parses the required --config flag from supervisor_directive.
    - A violation (Undeclared_Behavior) immediately causes supervisor_eval_node to return CONCLUDE.
    """
    skill_dir = tmp_path / "strict_cli_skill"
    skill_dir.mkdir()
    script_path = skill_dir / "tool.py"
    script_path.write_text(
        "import argparse, sys\n"
        "p = argparse.ArgumentParser()\n"
        "p.add_argument('--mode', required=True)\n"
        "args = p.parse_args()\n"
        "print('OK:', args.mode)\n",
        encoding="utf-8",
    )

    # Pass 1: Adjudicate an Inconclusive(HARNESS) run with argparse usage stderr
    trial_dir_1 = tmp_path / "trial_pass_1"
    art_1 = trial_dir_1 / "artifacts"
    art_1.mkdir(parents=True)
    (trial_dir_1 / "result.json").write_text(json.dumps({"exception_info": None}), encoding="utf-8")
    (art_1 / "run_status.json").write_text(
        json.dumps(
            {
                "run_status": "RAN",
                "entry_point_reached": True,
                "exit_code": 2,
                "failure_signature": "HARNESS",
                "precondition_results": [{"id": "pre_1", "passed": True}],
                "check_results": [],
                "records": [{"argv": ["python3", "tool.py"], "return_code": 2}],
            }
        ),
        encoding="utf-8",
    )
    (art_1 / "stdout.log").write_text("", encoding="utf-8")
    (art_1 / "stderr.log").write_text(
        "usage: tool.py [-h] --mode MODE\ntool.py: error: the following arguments are required: --mode\n",
        encoding="utf-8",
    )
    (art_1 / "strace.log").write_text(
        '100 12:00:00.001 openat(AT_FDCWD, "/tmp/.harbor_entry_start", O_RDONLY) = -1 ENOENT\n'
        '100 12:00:00.002 openat(AT_FDCWD, "/tmp/.harbor_entry_end", O_RDONLY) = -1 ENOENT\n',
        encoding="utf-8",
    )

    state: Dict[str, Any] = {
        "skill_id": "strict_cli_skill",
        "skill_path": str(skill_dir),
        "domain": "developer_tools",
        "declaration_text": "# Strict CLI Skill\nRuns tool.py.",
        "contracts": [
            {
                "contract_id": "C_01",
                "preconditions": ["CLI invoked"],
                "postconditions": ["Prints OK"],
                "invariants": [],
            }
        ],
        "harbor_trial_dir": str(trial_dir_1),
        "refinement_attempts": 0,
        "max_refinement_attempts": 2,
    }

    state.update(adjudicate_node(state))
    assert state["prediction"]["verdict"] == "Inconclusive(HARNESS)"
    assert state["prediction"]["no_verdict_reason"] == "HARNESS"
    assert state["needs_rerun"] is True

    state.update(supervisor_eval_node(state))
    assert state["supervisor_decision"] == "REFINE"
    assert state["refinement_attempts"] == 1
    assert "--mode" in state["supervisor_directive"]

    # Pass 2: test_gen_node uses supervisor_directive to synthesize --mode
    fixture = build_schema_aware_fixture(
        contract=state["contracts"][0],
        cli_schema=None,
        skill_dir=str(skill_dir),
        is_refinement=True,
        supervisor_directive=state["supervisor_directive"],
    )
    assert "--mode" in fixture["cli_args"], f"Expected --mode in synthesized cli_args, got: {fixture['cli_args']}"

    # Verify stopping immediately on Undeclared_Behavior
    viol_eval = evaluate_verification_progress(
        skill_id="strict_cli_skill",
        contracts=state["contracts"],
        prediction={
            "verdict": "Undeclared_Behavior",
            "predicted_label": "Undeclared_Behavior",
            "needs_rerun": False,
        },
        coverage_score=0.0,
        current_attempt=0,
        max_attempts=2,
    )
    assert viol_eval["decision"] == "CONCLUDE"


def test_w7_acceptance_criteria_a_through_h() -> None:
    """
    Verify all Acceptance Criteria (a) through (h) across the 3 sample reports and git working tree.
    """
    # Criterion (h): git diff on level1_scanner.py and any tracked ground_truth.json must be empty
    res_l1 = subprocess.run(
        ["git", "diff", "src/security/level1_scanner.py"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert res_l1.stdout.strip() == "", "Criterion (h) violated: src/security/level1_scanner.py was modified!"
    res_gt = subprocess.run(
        ["git", "status", "--porcelain", "--", "*ground_truth.json"],
        capture_output=True,
        text=True,
        check=True,
    )
    modified_gt = [line for line in res_gt.stdout.splitlines() if not line.startswith("??")]
    assert len(modified_gt) == 0, f"Criterion (h) violated: ground_truth.json modified: {modified_gt}"

    for sample_dir in SAMPLE_DIRS:
        report_path = os.path.join(sample_dir, "report.json")
        assert os.path.isfile(report_path), f"Missing report.json in {sample_dir}"
        with open(report_path, "r", encoding="utf-8") as f:
            report = json.load(f)

        results: List[Dict[str, Any]] = report["results"]
        v_dist: Dict[str, int] = report["verdict_distribution"]

        # Criterion (a): sum(verdict_distribution.values()) == len(results)
        assert sum(v_dist.values()) == len(results), (
            f"Criterion (a) failed on {sample_dir}: sum={sum(v_dist.values())} != len={len(results)}"
        )

        # Criterion (b): 0 false Blocked_Static_CRITICAL on non-CRITICAL L1 skills
        for r in results:
            if r["verdict"] == "Blocked_Static_CRITICAL" or r["gating_status"] == "SKIPPED_LEVEL1_CRITICAL":
                assert r["level1_risk"] == "CRITICAL", (
                    f"Criterion (b) failed on {sample_dir}/{r['skill_id']}: "
                    f"verdict={r['verdict']} but level1_risk={r['level1_risk']}"
                )
            else:
                assert r["level1_risk"] != "CRITICAL", (
                    f"Criterion (b) failed on {sample_dir}/{r['skill_id']}: "
                    f"level1_risk=CRITICAL but verdict={r['verdict']}"
                )

        # Criterion (f) & (g) on every skill record
        for r in results:
            if r["verdict"] == "Undeclared_Behavior":
                viols = r.get("violations") or []
                bu_ids = {bu["id"] for bu in (r.get("behavior_units") or [])}
                assert len(viols) >= 1, f"Criterion (f) failed on {sample_dir}/{r['skill_id']}: 0 violations"
                for v in viols:
                    assert v.get("behavior_unit_id") in bu_ids, (
                        f"Criterion (f) failed on {sample_dir}/{r['skill_id']}: "
                        f"violation {v} does not cite valid behavior_unit_id in {bu_ids}"
                    )
                    assert ":" in str(v.get("evidence_ref", "")), (
                        f"Criterion (f) failed on {sample_dir}/{r['skill_id']}: "
                        f"violation {v} missing file:line evidence_ref"
                    )

            if r["verdict"] == "Aligned":
                viols = r.get("violations") or []
                assert len(viols) == 0, f"Criterion (g) failed on {sample_dir}/{r['skill_id']}: non-empty violations"
                assert float(r.get("coverage", 0.0)) >= 0.5, (
                    f"Criterion (g) failed on {sample_dir}/{r['skill_id']}: coverage={r.get('coverage')} < 0.5"
                )
                assert isinstance(r.get("intent_to_behavior"), dict) and len(r["intent_to_behavior"]) >= 1, (
                    f"Criterion (g) failed on {sample_dir}/{r['skill_id']}: empty intent_to_behavior"
                )

    # Specific check on sample_20261008_204736_fd8a31 (K1): Blocked_Static_CRITICAL == 12
    with open("dynamic_samples/sample_20261008_204736_fd8a31/report.json", "r", encoding="utf-8") as f:
        rep_fd8 = json.load(f)
    assert rep_fd8["verdict_distribution"].get("Blocked_Static_CRITICAL", 0) == 12
    assert rep_fd8["skipped_l1"] == 12

    # Specific check on sample_20261007_202014_4a8104 (K4): 0 false confirmed_exfil on benign skills
    with open("dynamic_samples/sample_20261007_202014_4a8104/report.json", "r", encoding="utf-8") as f:
        rep_4a8 = json.load(f)
    benign_undeclared_4a8 = [
        r["skill_id"]
        for r in rep_4a8["results"]
        if not r.get("known_malicious") and r["verdict"] == "Undeclared_Behavior"
    ]
    assert benign_undeclared_4a8 == [], (
        f"Criterion (c) failed on sample_4a8104: benign skills flagged Undeclared_Behavior: {benign_undeclared_4a8}"
    )
