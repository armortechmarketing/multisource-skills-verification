"""A7 regression: benign_engrenagem-style same-trial consistency.

Human review noted exit-code-2 trials mixed with exit_code=0 PASS oracles.
"""
from __future__ import annotations

import pytest

from src.judge import (
    Check,
    CheckResult,
    Contract,
    Evidence,
    JudgeConfig,
    RunStatusInfo,
    assert_same_trial_consistency,
    classify_run_health,
    judge,
)


def test_engrenagem_mismatch_detected_and_not_aligned_on_exit2():
    """Checks claiming exit_code=0 PASS must not coexist with trial exit 2."""
    ev = Evidence(
        run_status=RunStatusInfo(entry_reached=True, exit_code=2),
        stderr="usage: engrenagem.py [-h]\nerror: unrecognized arguments: --bogus",
        check_results=(
            CheckResult("c_exit", "C_01", True, "exit_code=0 (expected 0)"),
            CheckResult("c_file", "C_01", True, "file_exists(.engrenagem/config.md) -> True"),
        ),
        run_kind="script",
    )
    rh = classify_run_health(ev)
    msg = assert_same_trial_consistency(ev, rh)
    assert msg is not None
    assert "same-trial inconsistency" in msg

    contracts = [
        Contract(
            id="C_01",
            postcondition="config exists and exit 0",
            checks=(
                Check("c_exit", "C_01", "exit_code", 0),
                Check("c_file", "C_01", "file_exists", ".engrenagem/config.md"),
            ),
            expects_effect=False,
        )
    ]
    res = judge(contracts, ev, JudgeConfig(aligned_min_dtc=0.0))
    # Must not emit Aligned when the trial itself failed with usage/exit 2
    assert res.verdict != "Aligned"
    assert res.failure_class in ("USAGE_ERROR", "UNKNOWN_FAILURE", "NONE") or res.no_verdict_reason in (
        "HARNESS",
        "INFRA",
        "SKILL_CRASH",
        "LOW_COVERAGE",
    )


def test_engrenagem_consistent_exit0_aligned_path():
    ev = Evidence(
        run_status=RunStatusInfo(entry_reached=True, exit_code=0),
        stdout="ok",
        check_results=(
            CheckResult("c_exit", "C_01", True, "exit_code=0 (expected 0)"),
            CheckResult("c_file", "C_01", True, "file_exists(.engrenagem/config.md) -> True"),
        ),
        run_kind="script",
    )
    rh = classify_run_health(ev)
    assert assert_same_trial_consistency(ev, rh) is None
    contracts = [
        Contract(
            id="C_01",
            postcondition="config exists and exit 0",
            checks=(
                Check("c_exit", "C_01", "exit_code", 0),
                Check("c_file", "C_01", "file_exists", ".engrenagem/config.md"),
            ),
            expects_effect=False,
        )
    ]
    res = judge(contracts, ev, JudgeConfig(aligned_min_dtc=0.5))
    assert res.verdict in ("Aligned", "Inconclusive")
    assert res.failure_class in (None, "NONE")
