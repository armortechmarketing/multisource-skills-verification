"""Parametrized unit tests for src.failure_classifier.classify_failure."""
from __future__ import annotations

import pytest

from src.failure_classifier import (
    FAILED_INVOCATION_CLASSES,
    FailureInfo,
    classify_failure,
    failure_cls_to_no_verdict_reason,
)


@pytest.mark.parametrize(
    "kwargs,expected_cls,expected_reason",
    [
        (
            {"stdout": "ok", "stderr": "", "exit_code": 0},
            "NONE",
            None,
        ),
        (
            {
                "stdout": "",
                "stderr": "usage: tool.py [-h]\nerror: the following arguments are required: --input",
                "exit_code": 2,
            },
            "USAGE_ERROR",
            "HARNESS",
        ),
        (
            {
                "stdout": "",
                "stderr": "error: unrecognized arguments: --bogus",
                "exit_code": 2,
            },
            "USAGE_ERROR",
            "HARNESS",
        ),
        (
            {
                "stdout": "",
                "stderr": "FileNotFoundError: [Errno 2] No such file or directory: '/tmp/test_workspace/fixture.csv'",
                "exit_code": 1,
                "test_args": ["/tmp/test_workspace/fixture.csv"],
            },
            "FILE_NOT_FOUND_INPUT",
            "HARNESS",
        ),
        (
            {
                "stdout": "",
                "stderr": "ModuleNotFoundError: No module named 'requests'",
                "exit_code": 1,
            },
            "MISSING_MODULE",
            "INFRA",
        ),
        (
            {
                "stdout": "",
                "stderr": "bash: jq: command not found",
                "exit_code": 127,
            },
            "MISSING_BINARY",
            "INFRA",
        ),
        (
            {
                "stdout": "",
                "stderr": "KeyError: 'OPENAI_API_KEY'",
                "exit_code": 1,
            },
            "MISSING_CONFIG",
            "INFRA",
        ),
        (
            {
                "stdout": "",
                "stderr": "PermissionError: [Errno 13] Permission denied: '/etc/shadow'",
                "exit_code": 1,
            },
            "PERMISSION",
            "INFRA",
        ),
        (
            {
                "stdout": "",
                "stderr": "Connection refused while connecting to api.example.com",
                "exit_code": 1,
            },
            "NETWORK_ERROR",
            "INFRA",
        ),
        (
            {
                "stdout": "",
                "stderr": "TimeoutExpired: Command timed out after 300s",
                "exit_code": 124,
            },
            "TIMEOUT",
            "INFRA",
        ),
        (
            {
                "stdout": "",
                "stderr": 'Traceback (most recent call last):\n  File "/usr/local/lib/python3.11/site-packages/harbor/agent/factory.py", line 10, in create\n    raise RuntimeError("boom")\nRuntimeError: boom',
                "exit_code": 1,
                "harbor_exception": "harbor agent factory failed",
            },
            "HARNESS_EXCEPTION",
            "INFRA",
        ),
        (
            {
                "stdout": "",
                "stderr": "",
                "exit_code": 0,
                "run_status": {
                    "run_kind": "agent",
                    "trajectory_present": True,
                    "trajectory_units": 0,
                },
            },
            "AGENT_NO_TELEMETRY",
            "TELEMETRY_GAP",
        ),
        (
            {
                "stdout": "",
                "stderr": 'Traceback (most recent call last):\n  File "/app/skill/scripts/main.py", line 42, in <module>\n    raise ValueError("bad")\nValueError: bad',
                "exit_code": 1,
                "skill_dir": "/app/skill",
                "run_status": {"entry_point_reached": True},
            },
            "SKILL_TRACEBACK",
            "SKILL_CRASH",
        ),
        (
            {
                "stdout": "",
                "stderr": "something weird happened",
                "exit_code": 7,
            },
            "UNKNOWN_FAILURE",
            "SKILL_CRASH",
        ),
        (
            # Exit 0 but usage text still classifies
            {
                "stdout": "usage: prog.py [-h]",
                "stderr": "",
                "exit_code": 0,
            },
            "USAGE_ERROR",
            "HARNESS",
        ),
        (
            {
                "stdout": "",
                "stderr": "FileNotFoundError: [Errno 2] No such file or directory: 'ffmpeg'",
                "exit_code": 1,
            },
            "MISSING_BINARY",
            "INFRA",
        ),
    ],
)
def test_classify_failure_table(kwargs, expected_cls, expected_reason):
    info = classify_failure(**kwargs)
    assert isinstance(info, FailureInfo)
    assert info.cls == expected_cls, f"got {info.cls} symptom={info.symptom}"
    assert failure_cls_to_no_verdict_reason(info.cls) == expected_reason
    assert info.no_verdict_reason == expected_reason
    if expected_cls in ("USAGE_ERROR", "FILE_NOT_FOUND_INPUT"):
        assert info.refinable is True
    elif expected_cls != "NONE":
        assert info.refinable is False
    if expected_cls == "UNKNOWN_FAILURE":
        assert info.low_confidence is True


def test_failed_invocation_set_covers_non_skill():
    assert "USAGE_ERROR" in FAILED_INVOCATION_CLASSES
    assert "AGENT_NO_TELEMETRY" in FAILED_INVOCATION_CLASSES
    assert "SKILL_TRACEBACK" not in FAILED_INVOCATION_CLASSES
    assert "NONE" not in FAILED_INVOCATION_CLASSES


def test_missing_module_captures_name():
    info = classify_failure(
        stderr="ModuleNotFoundError: No module named 'numpy'",
        exit_code=1,
    )
    assert info.cls == "MISSING_MODULE"
    assert "numpy" in info.missing
