"""Unit tests for Step 1: Judge Correctness (1.A, 1.B, 1.C, 1.D)."""

import os
import pytest
from src.judge import (
    BehaviorUnit,
    Check,
    Contract,
    Evidence,
    FrameAxiom,
    JudgeConfig,
    RunStatusInfo,
    judge,
    parse_contract_from_dict,
)
from src.security.level1_scanner import MITRE_MAPPINGS


def test_1a_dtc_split_and_aligned_threshold(monkeypatch):
    """1.A: DTC = exercised / testable. Aligned requires dtc >= ALIGNED_MIN_DTC."""
    monkeypatch.setenv("ALIGNED_MIN_DTC", "0.8")
    
    # Contract 1: testable, passes
    # Contract 2: non-testable (observability claim) -> excluded from testable denominator
    # Contract 3: testable, not exercised
    c1 = Contract(
        id="C_01",
        precondition="Init",
        postcondition="Create file",
        frame_axiom=FrameAxiom(write=("/app/output.txt",)),
        checks=(Check(id="chk_1", contract_id="C_01", kind="exit_code", expect=0),),
        testable=True,
        expects_effect=True,
    )
    c2 = Contract(
        id="C_02",
        precondition="Init",
        postcondition="Executed with proper authorization",
        testable=False,
        expects_effect=False,
    )
    c3 = Contract(
        id="C_03",
        precondition="Init",
        postcondition="Send alert",
        testable=True,
        expects_effect=True,
    )

    # Only C1 is exercised out of 2 testable contracts -> DTC = 1/2 = 0.5 < 0.8 -> LOW_COVERAGE
    ev = Evidence(
        run_status=RunStatusInfo(entry_reached=True, exit_code=0),
        behavior_units=(
            BehaviorUnit(id="b1", kind="file_write", target="/app/output.txt"),
        ),
        stdout="Job complete",
    )

    res = judge((c1, c2, c3), ev, JudgeConfig(aligned_min_dtc=0.8))
    assert res.verdict == "Inconclusive"
    assert res.no_verdict_reason == "LOW_COVERAGE"
    assert res.dtc == 0.5
    assert res.csr_c == 0.5

    # Now if C3 is also exercised and passes -> DTC = 2/2 = 1.0 >= 0.8 -> Aligned
    c3_with_check = Contract(
        id="C_03",
        precondition="Init",
        postcondition="Send alert",
        checks=(Check(id="chk_3", contract_id="C_03", kind="exit_code", expect=0),),
        testable=True,
        expects_effect=False,
    )
    res_aligned = judge((c1, c2, c3_with_check), ev, JudgeConfig(aligned_min_dtc=0.8))
    assert res_aligned.verdict == "Aligned"
    assert res_aligned.dtc == 1.0
    assert res_aligned.csr_c == 1.0


def test_1b_effect_absent_guard():
    """1.B: EFFECT_ABSENT is emitted ONLY IF entry reached, exit 0, input_valid True, and expects_effect True."""
    c_expects = Contract(
        id="C_01",
        precondition="Init",
        postcondition="Create report",
        frame_axiom=FrameAxiom(write=("/app/report.csv",)),
        testable=True,
        expects_effect=True,
    )
    c_no_effect = Contract(
        id="C_02",
        precondition="Init",
        postcondition="Informational query",
        testable=True,
        expects_effect=False,
    )

    # Case 1: Clean exit 0 with valid input on contract with expects_effect=True -> EFFECT_ABSENT -> Unimplemented_Intent
    ev_clean = Evidence(
        run_status=RunStatusInfo(entry_reached=True, exit_code=0),
        behavior_units=(),
        stdout="",
        stderr="",
        input_valid=True,
    )
    res1 = judge((c_expects,), ev_clean, JudgeConfig())
    assert res1.verdict == "Unimplemented_Intent"
    assert res1.contract_status[0].status == "EFFECT_ABSENT"

    # Case 2: Clean exit 0 on contract with expects_effect=False -> NOT_EXERCISED (not EFFECT_ABSENT)
    res2 = judge((c_no_effect,), ev_clean, JudgeConfig())
    assert res2.contract_status[0].status == "NOT_EXERCISED"
    assert res2.verdict == "Inconclusive"
    assert res2.no_verdict_reason == "LOW_COVERAGE"

    # Case 3: Argparse/usage error in stdout/stderr -> input_valid=False -> NOT_EXERCISED (refinement loop runs)
    ev_usage = Evidence(
        run_status=RunStatusInfo(entry_reached=True, exit_code=0),
        behavior_units=(),
        stdout="usage: my_script.py [-h] --data DATA",
        stderr="unrecognized arguments: --foo",
        input_valid=False,
    )
    res3 = judge((c_expects,), ev_usage, JudgeConfig())
    assert res3.contract_status[0].status == "NOT_EXERCISED"
    assert res3.verdict == "Inconclusive"


def test_1c_static_level1_signals_forbidden_invariants_no_false_undeclared():
    """1.C: Level-1 static rule IDs in forbidden_invariant must NOT by themselves trigger Undeclared_Behavior

    Only observed runtime BehaviorUnits or exfil may yield Undeclared_Behavior.
    """
    # Use real Level-1 rule IDs from level1_scanner.py (A5): EXFIL_DOWNLOAD, scope_creep, read_only_but_writes
    real_l1_rules = ["EXFIL_DOWNLOAD", "SETUP_CMD_INJECTION", "C2_RAW_IP", "SHELL_PERSISTENCE"]
    for r_id in real_l1_rules:
        assert r_id in MITRE_MAPPINGS

    c = Contract(
        id="C_01",
        precondition="Init",
        postcondition="Run benign task",
        frame_axiom=FrameAxiom(write=("/app/output.txt",)),
        forbidden_invariant=(
            "MUST NOT violate EXFIL_DOWNLOAD: detected curl in AST",
            "MUST NOT violate SETUP_CMD_INJECTION: detected shell command",
            "MUST NOT violate C2_RAW_IP: raw IP detected",
        ),
        checks=(Check(id="chk_1", contract_id="C_01", kind="exit_code", expect=0),),
        testable=True,
        expects_effect=True,
    )

    # Runtime executed cleanly without executing forbidden actions
    ev = Evidence(
        run_status=RunStatusInfo(entry_reached=True, exit_code=0),
        behavior_units=(
            BehaviorUnit(id="b1", kind="file_write", target="/app/output.txt"),
        ),
        stdout="success",
    )

    res = judge((c,), ev, JudgeConfig(aligned_min_dtc=0.5))
    assert res.verdict != "Undeclared_Behavior"
    assert len(res.violations) == 0
    assert res.verdict == "Aligned"


def test_1d_stub_detection_executed_path():
    """1.D: ast_is_stub counts only if stub function is the entry or in executed call path."""
    c = Contract(
        id="C_01",
        precondition="Init",
        postcondition="Execute calculation",
        checks=(Check(id="chk_1", contract_id="C_01", kind="exit_code", expect=0),),
    )

    # When ast_is_stub is True, entry is reached, but traceback shows NotImplementedError in skill
    ev_stub = Evidence(
        run_status=RunStatusInfo(entry_reached=True, exit_code=1, ast_is_stub=True),
        stderr='File "/app/skill/main.py", line 12, in run\n    raise NotImplementedError("TODO")',
    )
    res_stub = judge((c,), ev_stub, JudgeConfig(skill_dir="/app/skill"))
    assert res_stub.verdict == "Unimplemented_Intent"
    assert res_stub.contract_status[0].status == "STUB"

    # When NotImplementedError occurs in a 3rd party library outside skill (e.g. pandas/_core),
    # it must NOT be labeled as skill Unimplemented_Intent; it should be SKILL_CRASH
    ev_external_err = Evidence(
        run_status=RunStatusInfo(entry_reached=True, exit_code=1, ast_is_stub=False),
        stderr='File "/usr/local/lib/python3.11/site-packages/pandas/core.py", line 99, in compute\n    raise NotImplementedError()',
    )
    res_crash = judge((c,), ev_external_err, JudgeConfig(skill_dir="/app/skill"))
    assert res_crash.verdict == "Inconclusive"
    assert res_crash.no_verdict_reason == "SKILL_CRASH"
