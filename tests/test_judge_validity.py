"""Synthetic Evidence cases 1–19 for Agent A judge validity gates."""
from __future__ import annotations

import os

import pytest

from src.failure_classifier import classify_failure
from src.judge import (
    BehaviorUnit,
    Check,
    CheckResult,
    Contract,
    Evidence,
    FrameAxiom,
    JudgeConfig,
    RunStatusInfo,
    assert_same_trial_consistency,
    classify_check_strength,
    classify_run_health,
    judge,
)


def _contract(cid: str = "C_01", *, expects_effect: bool = True, checks=None) -> Contract:
    return Contract(
        id=cid,
        precondition="input present",
        postcondition="write output file",
        frame_axiom=FrameAxiom(write=("/tmp/out.txt",)),
        expects_effect=expects_effect,
        checks=tuple(checks or ()),
    )


def _ev(**kwargs) -> Evidence:
    defaults = dict(
        run_status=RunStatusInfo(entry_reached=True, exit_code=0),
        skill_dir="/app/skill",
        input_valid=True,
    )
    defaults.update(kwargs)
    return Evidence(**defaults)


def test_01_usage_error_not_divergent():
    ev = _ev(
        stderr="usage: tool.py [-h]\nerror: the following arguments are required: --in",
        run_status=RunStatusInfo(entry_reached=True, exit_code=2),
        entry_kind="script_cli",
        targets_contracts=("C_01",),
        preconditions_satisfied=True,
        placeholder_inputs_used=False,
        secret_args_used=False,
        run_kind="script",
        check_results=(CheckResult("c1", "C_01", False, "exit_code=2"),),
    )
    c = _contract(checks=(Check("c1", "C_01", "exit_code", 0),))
    res = judge([c], ev)
    assert res.verdict == "Inconclusive"
    assert res.no_verdict_reason == "HARNESS"
    assert res.failure_class == "USAGE_ERROR"
    assert all(cs.status != "CONTRADICTED" for cs in res.contract_status)


def test_02_missing_module_infra():
    ev = _ev(
        stderr="ModuleNotFoundError: No module named 'foo'",
        run_status=RunStatusInfo(entry_reached=True, exit_code=1),
    )
    res = judge([_contract()], ev)
    assert res.verdict == "Inconclusive"
    assert res.no_verdict_reason == "INFRA"
    assert res.failure_class == "MISSING_MODULE"


def test_03_missing_binary_infra():
    ev = _ev(
        stderr="bash: jq: command not found",
        run_status=RunStatusInfo(entry_reached=True, exit_code=127),
    )
    res = judge([_contract()], ev)
    assert res.no_verdict_reason == "INFRA"
    assert res.failure_class == "MISSING_BINARY"


def test_04_file_not_found_input_harness():
    ev = _ev(
        stderr="FileNotFoundError: [Errno 2] No such file or directory: '/tmp/test_workspace/x.csv'",
        run_status=RunStatusInfo(entry_reached=True, exit_code=1, argv=("/tmp/test_workspace/x.csv",)),
        test_args=("/tmp/test_workspace/x.csv",),
    )
    res = judge([_contract()], ev)
    assert res.no_verdict_reason == "HARNESS"
    assert res.failure_class == "FILE_NOT_FOUND_INPUT"


def test_05_agent_telemetry_gap():
    ev = _ev(
        run_kind="agent",
        trajectory_present=True,
        trajectory_units=0,
        run_status=RunStatusInfo(entry_reached=True, exit_code=0, instruction_only=True),
    )
    res = judge([_contract()], ev)
    assert res.verdict == "Inconclusive"
    assert res.no_verdict_reason == "TELEMETRY_GAP"
    assert res.failure_class == "AGENT_NO_TELEMETRY"


def test_06_agent_no_effect_absent():
    ev = _ev(
        run_kind="agent",
        trajectory_present=True,
        trajectory_units=3,
        run_status=RunStatusInfo(entry_reached=True, exit_code=0, instruction_only=True),
        behavior_units=(),
        stdout="",
    )
    # Force failure_cls NONE path by not triggering telemetry gap
    res = judge([_contract(expects_effect=True)], ev)
    assert all(cs.status != "EFFECT_ABSENT" for cs in res.contract_status)


def test_07_placeholder_inputs_demote_contradicted():
    ev = _ev(
        entry_kind="script_cli",
        targets_contracts=("C_01",),
        preconditions_satisfied=True,
        placeholder_inputs_used=True,
        secret_args_used=False,
        run_kind="script",
        stdout="wrong",
        check_results=(CheckResult("c1", "C_01", False, "stdout mismatch", effect_observed=True),),
        behavior_units=(BehaviorUnit("u1", "file_write", "/tmp/out.txt"),),
    )
    c = _contract(checks=(Check("c1", "C_01", "stdout_contains", "ok"),))
    res = judge([c], ev)
    assert all(cs.status != "CONTRADICTED" for cs in res.contract_status)


def test_08_passive_flags_demote():
    ev = _ev(
        entry_kind="script_cli",
        targets_contracts=("C_01",),
        preconditions_satisfied=True,
        placeholder_inputs_used=False,
        secret_args_used=False,
        passive_flags_used=("--dry-run",),
        run_kind="script",
        check_results=(CheckResult("c1", "C_01", False, "no write", effect_observed=False),),
    )
    c = _contract(checks=(Check("c1", "C_01", "file_exists", "/tmp/out.txt"),))
    res = judge([c], ev)
    assert all(cs.status == "NOT_EXERCISED" for cs in res.contract_status)


def test_09_contract_not_targeted():
    ev = _ev(
        entry_kind="script_cli",
        targets_contracts=("C_OTHER",),
        preconditions_satisfied=True,
        placeholder_inputs_used=False,
        secret_args_used=False,
        run_kind="script",
        check_results=(CheckResult("c1", "C_01", False, "fail"),),
    )
    res = judge([_contract(checks=(Check("c1", "C_01", "exit_code", 0),))], ev)
    assert res.contract_status[0].status == "NOT_EXERCISED"
    assert "not_targeted" in res.contract_status[0].exercise_reason or "demoted" in res.contract_status[0].reason


def test_10_valid_exercise_allows_effect_absent():
    ev = _ev(
        entry_kind="script_cli",
        targets_contracts=("C_01",),
        preconditions_satisfied=True,
        placeholder_inputs_used=False,
        secret_args_used=False,
        run_kind="script",
        stdout="",
        behavior_units=(),
        check_results=(CheckResult("c1", "C_01", True, "exit_code=0"),),
    )
    c = _contract(
        expects_effect=True,
        checks=(Check("c1", "C_01", "exit_code", 0),),
    )
    res = judge([c], ev)
    assert any(cs.status == "EFFECT_ABSENT" for cs in res.contract_status)


def test_11_j1_violation_wins_over_failed_invocation():
    ev = _ev(
        stderr="usage: x",
        run_status=RunStatusInfo(entry_reached=True, exit_code=2),
        behavior_units=(BehaviorUnit("u1", "file_write", "/etc/passwd"),),
    )
    c = _contract()
    res = judge([c], ev)
    # Usage makes failed invocation, but forbidden write still Undeclared if J1 fires
    assert res.verdict in ("Undeclared_Behavior", "Inconclusive")


def test_12_skill_traceback_crash():
    ev = _ev(
        stderr='Traceback (most recent call last):\n  File "/app/skill/scripts/main.py", line 1, in <module>\n    raise ValueError("x")\nValueError: x',
        run_status=RunStatusInfo(entry_reached=True, exit_code=1),
        skill_dir="/app/skill",
    )
    res = judge([_contract()], ev)
    assert res.verdict == "Inconclusive"
    assert res.no_verdict_reason == "SKILL_CRASH"
    assert res.failure_class == "SKILL_TRACEBACK"


def test_13_timeout_infra():
    ev = _ev(run_status=RunStatusInfo(entry_reached=True, exit_code=124), stderr="TimeoutExpired")
    res = judge([_contract()], ev)
    assert res.no_verdict_reason == "INFRA"
    assert res.failure_class == "TIMEOUT"


def test_14_speculative_could_not_allowed():
    from src.judge import _J2_SPECULATIVE_PATTERN

    assert _J2_SPECULATIVE_PATTERN.search("the skill could not write the file") is None
    assert _J2_SPECULATIVE_PATTERN.search("the skill could write secrets") is not None
    assert _J2_SPECULATIVE_PATTERN.search("output may be wrong") is not None


def test_15_oracle_strength_weak_exit_only():
    assert classify_check_strength(Check("c", "C", "exit_code", 0)) == "weak"
    assert classify_check_strength(Check("c", "C", "file_exists", "/tmp/x")) == "weak"
    assert classify_check_strength(Check("c", "C", "stdout_contains", "ok")) == "strong"


def test_16_aligned_require_strong(monkeypatch):
    monkeypatch.setenv("ALIGNED_REQUIRE_STRONG", "1")
    chk = Check("c1", "C_01", "exit_code", 0)
    ev = _ev(
        check_results=(CheckResult("c1", "C_01", True, "exit_code=0"),),
        behavior_units=(BehaviorUnit("u1", "stdout", "ok"),),
        stdout="ok",
    )
    c = _contract(checks=(chk,), expects_effect=False)
    # Also mark frame empty so exit-only can PASS without EFFECT_ABSENT
    c = Contract(
        id="C_01",
        postcondition="exit zero",
        checks=(chk,),
        expects_effect=False,
        testable=True,
    )
    res = judge([c], ev, JudgeConfig(aligned_min_dtc=0.0, require_strong_oracle=True))
    if res.verdict == "Aligned":
        pytest.fail("Aligned must not pass with weak-only oracles when ALIGNED_REQUIRE_STRONG=1")
    assert res.verdict == "Inconclusive"
    assert res.no_verdict_reason == "LOW_COVERAGE"
    assert "weak_oracles_only" in (res.evidence_scope or "")


def test_17_same_trial_consistency_detects_mismatch():
    ev = _ev(
        run_status=RunStatusInfo(entry_reached=True, exit_code=2),
        check_results=(CheckResult("c1", "C_01", True, "exit_code=0"),),
    )
    rh = classify_run_health(ev)
    msg = assert_same_trial_consistency(ev, rh)
    assert msg and "same-trial inconsistency" in msg


def test_18_dtc_exercise_valid_legacy_pass():
    ev = _ev(
        check_results=(CheckResult("c1", "C_01", True, "ok"),),
        behavior_units=(BehaviorUnit("u1", "file_write", "/tmp/out.txt"),),
        stdout="wrote",
    )
    c = _contract(checks=(Check("c1", "C_01", "file_contains", "x"),))
    res = judge([c], ev, JudgeConfig(aligned_min_dtc=0.5))
    assert res.dtc >= 0.5 or res.verdict in ("Aligned", "Inconclusive", "Unimplemented_Intent")


def test_19_unknown_failure_low_confidence():
    info = classify_failure(stderr="weird boom", exit_code=9)
    assert info.cls == "UNKNOWN_FAILURE"
    assert info.low_confidence is True
    ev = _ev(stderr="weird boom", run_status=RunStatusInfo(entry_reached=True, exit_code=9))
    res = judge([_contract()], ev)
    assert res.failure_class == "UNKNOWN_FAILURE"
    assert res.low_confidence is True
