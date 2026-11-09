"""
Phase 4 — Calibration Controls Runner & Batch Preflight
Executes calibration controls C1-C11 through the adjudication pipeline before every batch run.
Aborts the batch if any control fails its expected verdict.
"""

import os
import sys
import tempfile
import pytest
from typing import Dict, Any, List

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.a_adj_adjudicator import adjudicate_skill_behavior
from tests.controls.control_specs import CONTROLS_SPEC, materialize_control_skill


def run_calibration_controls() -> List[Dict[str, Any]]:
    """
    Executes all calibration controls C1-C11 through the adjudicator logic.
    Returns results list. Raises RuntimeError if any control fails.
    """
    results = []
    with tempfile.TemporaryDirectory() as td:
        for spec in CONTROLS_SPEC:
            ctrl_id = spec["id"]
            ctrl_dir = materialize_control_skill(spec, td)
            
            # Run adjudication
            res = adjudicate_skill_behavior(
                contracts=spec["contracts"],
                traces=spec.get("traces", []),
                skill_dir=ctrl_dir,
                run_status=spec.get("run_status", "INVOKED_SUCCEEDED"),
                entry_point_reached=True,
                failure_type=spec.get("failure_type"),
                execution_error_sublabel=spec.get("execution_error_sublabel"),
                domain="general",
                assertion_results=spec.get("assertion_results"),
                stdout=spec.get("stdout"),
                stderr=spec.get("stderr")
            )
            
            actual_verdict = res.get("verdict")
            expected_verdicts = spec["expected_verdicts"]
            passed = actual_verdict in expected_verdicts
            
            ctrl_result = {
                "control_id": ctrl_id,
                "description": spec["description"],
                "expected": expected_verdicts,
                "actual": actual_verdict,
                "passed": passed,
                "headline": (res.get("explanation") or {}).get("headline")
            }
            results.append(ctrl_result)
            
            if not passed:
                err_msg = (
                    f"BATCH PREFLIGHT ABORTED: Calibration control '{ctrl_id}' failed!\n"
                    f"Description: {spec['description']}\n"
                    f"Expected verdict in: {expected_verdicts}\n"
                    f"Actual verdict: {actual_verdict}\n"
                    f"Headline: {ctrl_result['headline']}"
                )
                raise RuntimeError(err_msg)

    return results


def test_calibration_controls_all_pass():
    """Pytest wrapper executing all calibration controls C1-C11."""
    results = run_calibration_controls()
    assert len(results) == len(CONTROLS_SPEC)
    for r in results:
        assert r["passed"] is True, f"Control {r['control_id']} failed: {r}"


if __name__ == "__main__":
    print("Executing Phase 4 Calibration Controls Preflight (C1 - C11)...")
    try:
        res = run_calibration_controls()
        print(f"All {len(res)} calibration controls PASSED cleanly:")
        for r in res:
            print(f"  [PASS] {r['control_id']}: {r['actual']} (Expected: {r['expected']})")
        sys.exit(0)
    except Exception as e:
        print(f"\n[FAIL] {e}", file=sys.stderr)
        sys.exit(1)
