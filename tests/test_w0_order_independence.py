"""W0 Order-Independence & Stale-Verdict Regression Tests.

Verifies:
1. `execute_manifest_pipeline` produces identical per-skill verdicts and top-level
   summary counters across 3 shuffled orders of a mixed manifest (CRITICAL, SAFE,
   ERROR, and Inconclusive skills).
2. No stale `Blocked_Static_CRITICAL` leaks from an earlier CRITICAL skill to
   subsequent SAFE skills.
3. Recomputes the true Level-1 risk distribution across all 50 skills in
   `dynamic_samples/sample_20261008_204736_fd8a31/skills` and proves how the old
   loop-carried `verdict` bug inflated `Blocked_Static_CRITICAL` from 12 to 36.
"""
from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any, Dict, List

import pytest

from src.pipeline_runner import (
    build_error_skill_record,
    build_skill_record,
    derive_gating_status,
    execute_manifest_pipeline,
    summarize_report_records,
)
from src.security.level1_scanner import scan_skill_for_level1_security


def _fake_run_skill(skill_id: str, manifest_file: str = "", force_refresh: bool = True) -> Dict[str, Any]:
    """Deterministic stub of graph.run_skill for order-independence testing."""
    if skill_id == "skill_raise_exception":
        raise RuntimeError("Synthetic pipeline error for testing")
    if skill_id == "skill_critical_static":
        return {
            "skill_id": skill_id,
            "level1_report": {
                "risk_level": "CRITICAL",
                "static_verdict": "SUSPICIOUS_STATIC",
                "reason": "Flagged CRITICAL — REVERSE_SHELL",
            },
            "gating_status": "SKIPPED_LEVEL1_CRITICAL",
            "run_status": "NOT_INVOKED",
            "prediction": {},
        }
    if skill_id == "skill_safe_aligned":
        return {
            "skill_id": skill_id,
            "level1_report": {
                "risk_level": "LOW",
                "static_verdict": "CLEAN_STATIC",
                "reason": "No static security patterns triggered.",
            },
            "gating_status": "INVOKED",
            "run_status": "INVOKED_SUCCEEDED",
            "prediction": {
                "verdict": "Aligned",
                "predicted_label": "Aligned",
                "no_verdict_reason": None,
                "coverage": 1.0,
                "contract_status": [{"contract_id": "C1", "status": "PASS", "reason": "All checks passed"}],
                "violations": [],
                "behavior_units": [{"id": "BU1", "kind": "file_write", "target": "/tmp/out.txt"}],
                "intent_to_behavior": {"C1": ["BU1"]},
                "execution_error_note": None,
            },
        }
    if skill_id == "skill_low_undeclared":
        return {
            "skill_id": skill_id,
            "level1_report": {
                "risk_level": "MEDIUM",
                "static_verdict": "SUSPICIOUS_STATIC",
                "reason": "Flagged MEDIUM — network capability",
            },
            "gating_status": "INVOKED",
            "run_status": "INVOKED_SUCCEEDED",
            "prediction": {
                "verdict": "Undeclared_Behavior",
                "predicted_label": "Undeclared_Behavior",
                "no_verdict_reason": None,
                "coverage": 0.5,
                "contract_status": [{"contract_id": "C1", "status": "PASS", "reason": "ok"}],
                "violations": [{"rule_id": "NET_UNDECLARED", "behavior_unit_id": "BU2", "kind": "frame"}],
                "behavior_units": [{"id": "BU2", "kind": "net_connect", "target": "evil.example.com:443"}],
                "intent_to_behavior": {},
                "execution_error_note": None,
            },
        }
    if skill_id == "skill_safe_inconclusive_harness":
        return {
            "skill_id": skill_id,
            "level1_report": {
                "risk_level": "LOW",
                "static_verdict": "CLEAN_STATIC",
                "reason": "No static security patterns triggered.",
            },
            "gating_status": "INCONCLUSIVE_HARNESS",
            "run_status": "INVOKED_FAILED",
            "prediction": {
                "verdict": "Inconclusive(HARNESS)",
                "predicted_label": "INCONCLUSIVE_HARNESS",
                "no_verdict_reason": "HARNESS",
                "coverage": 0.0,
                "contract_status": [{"contract_id": "C1", "status": "NOT_EXERCISED", "reason": "argparse usage error"}],
                "violations": [],
                "behavior_units": [],
                "intent_to_behavior": {},
                "execution_error_note": "argparse usage error exit=2",
            },
        }
    raise ValueError(f"Unexpected skill_id: {skill_id}")


def test_w0_order_independence_across_three_shuffles(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Running the same manifest in 3 shuffled orders produces identical per-skill verdicts."""
    monkeypatch.setattr("src.pipeline_runner.run_skill", _fake_run_skill)
    monkeypatch.setattr("tests.controls.test_calibration_controls.run_calibration_controls", lambda: None)

    base_skills: List[Dict[str, Any]] = [
        {"skill_id": "skill_raise_exception", "domain": "ops", "known_malicious": False},
        {"skill_id": "skill_critical_static", "domain": "ops", "known_malicious": True},
        {"skill_id": "skill_safe_aligned", "domain": "dev", "known_malicious": False},
        {"skill_id": "skill_low_undeclared", "domain": "dev", "known_malicious": True},
        {"skill_id": "skill_safe_inconclusive_harness", "domain": "dev", "known_malicious": False},
    ]

    rng = random.Random(42)
    orders = [list(base_skills) for _ in range(3)]
    for order in orders[1:]:
        rng.shuffle(order)

    reports = []
    for idx, skill_list in enumerate(orders):
        manifest_dir = tmp_path / f"run_{idx}"
        manifest_dir.mkdir(parents=True, exist_ok=True)
        manifest_path = manifest_dir / "manifest.json"
        manifest_path.write_text(
            json.dumps({"run_id": f"test_sample_{idx}", "skills": skill_list}),
            encoding="utf-8",
        )
        rep = execute_manifest_pipeline(str(manifest_path), resume=False)
        reports.append(rep)

    for rep in reports:
        by_id = {r["skill_id"]: r for r in rep["results"]}
        assert by_id["skill_critical_static"]["verdict"] == "Blocked_Static_CRITICAL"
        assert by_id["skill_critical_static"]["gating_status"] == "SKIPPED_LEVEL1_CRITICAL"
        assert by_id["skill_safe_aligned"]["verdict"] == "Aligned"
        assert by_id["skill_safe_aligned"]["gating_status"] == "INVOKED"
        assert by_id["skill_low_undeclared"]["verdict"] == "Undeclared_Behavior"
        assert by_id["skill_safe_inconclusive_harness"]["verdict"] == "Inconclusive(HARNESS)"
        assert by_id["skill_safe_inconclusive_harness"]["no_verdict_reason"] == "HARNESS"
        assert by_id["skill_raise_exception"]["verdict"] == "ERROR"
        assert by_id["skill_raise_exception"]["no_verdict_reason"] == "INFRA"
        assert by_id["skill_raise_exception"]["gating_status"] == "INCONCLUSIVE_INFRA"

        assert sum(rep["verdict_distribution"].values()) == len(rep["results"]) == 5
        assert rep["skipped_l1"] == 1
        assert rep["no_verdict_by_reason"] == {"HARNESS": 1, "INFRA": 1}

    baseline_by_id = {r["skill_id"]: r for r in reports[0]["results"]}
    for rep in reports[1:]:
        cand_by_id = {r["skill_id"]: r for r in rep["results"]}
        assert cand_by_id == baseline_by_id
        assert rep["verdict_distribution"] == reports[0]["verdict_distribution"]
        assert rep["no_verdict_by_reason"] == reports[0]["no_verdict_by_reason"]
        assert rep["skipped_l1"] == reports[0]["skipped_l1"]


def test_w0_sample_fd8a31_true_l1_distribution() -> None:
    """Recompute true L1 risk classes on sample_20261008_204736_fd8a31 and verify fix."""
    sample_dir = Path("dynamic_samples/sample_20261008_204736_fd8a31")
    manifest_path = sample_dir / "manifest.json"
    old_report_path = sample_dir / "report.before_rebuild.json"
    if not old_report_path.exists():
        old_report_path = sample_dir / "report.json"
    if not manifest_path.exists():
        pytest.skip("sample_20261008_204736_fd8a31 not present on disk")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    old_report = json.loads(old_report_path.read_text(encoding="utf-8"))
    old_by_id = {r["skill_id"]: r for r in old_report["results"]}

    l1_counts: Dict[str, int] = {}
    recomputed_records: List[Dict[str, Any]] = []
    leaked_skills: List[str] = []

    for entry in manifest["skills"]:
        sid = entry["skill_id"]
        skill_path = sample_dir / "skills" / sid
        l1_rep = scan_skill_for_level1_security(str(skill_path))
        r_level = l1_rep.get("risk_level", "UNKNOWN")
        l1_counts[r_level] = l1_counts.get(r_level, 0) + 1

        old_rec = old_by_id.get(sid, {})
        old_l2 = old_rec.get("level2_verdict")
        old_gating = old_rec.get("gating_status")
        old_run = old_rec.get("run_status", "NOT_INVOKED")

        new_rec = build_skill_record(
            skill_entry=entry,
            state={
                "level1_report": l1_rep,
                "gating_status": "SKIPPED_LEVEL1_CRITICAL" if r_level == "CRITICAL" else old_gating,
                "run_status": "NOT_INVOKED" if r_level == "CRITICAL" else old_run,
                "prediction": {
                    "verdict": old_l2 if r_level != "CRITICAL" else None,
                    "predicted_label": old_l2 if r_level != "CRITICAL" else None,
                    "coverage": old_rec.get("coverage_score", 0.0),
                    "contract_verdicts": old_rec.get("contract_verdicts", []),
                    "execution_error_sublabel": old_rec.get("execution_error_sublabel"),
                },
            },
        )
        recomputed_records.append(new_rec)
        if old_rec.get("verdict") == "Blocked_Static_CRITICAL" and r_level != "CRITICAL":
            leaked_skills.append(sid)

    summary = summarize_report_records(
        manifest_path=str(manifest_path),
        manifest_data=manifest,
        results=recomputed_records,
        total_skills=len(manifest["skills"]),
        elapsed_sec=0.0,
    )
    print("\n=== W0 CHECK: sample_20261008_204736_fd8a31 True Level-1 Risk Distribution ===")
    print(f"Total skills in manifest: {len(manifest['skills'])}")
    print(f"True Level-1 risk_level counts: {json.dumps(l1_counts, sort_keys=True)}")
    print(f"Old report.json Blocked_Static_CRITICAL count: {old_report['verdict_distribution'].get('Blocked_Static_CRITICAL')}")
    print(f"True Blocked_Static_CRITICAL count (skipped_l1): {summary['skipped_l1']}")
    print(f"Skills falsely labeled Blocked_Static_CRITICAL due to K1 leak ({len(leaked_skills)}): {leaked_skills}")
    print(f"Recomputed verdict_distribution (without K1 leak): {json.dumps(summary['verdict_distribution'], sort_keys=True)}")
    print(f"Recomputed no_verdict_by_reason: {json.dumps(summary['no_verdict_by_reason'], sort_keys=True)}")

    assert l1_counts.get("CRITICAL", 0) == 12
    assert summary["skipped_l1"] == 12
    assert summary["verdict_distribution"].get("Blocked_Static_CRITICAL", 0) == 12
    assert len(leaked_skills) == 34
    assert sum(summary["verdict_distribution"].values()) == 50
