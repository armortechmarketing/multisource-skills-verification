"""
Unit tests for Harbor runner and platform compat harness fixes (Agent B: B1, B2, B3, B4, B5).
"""

import sys
import tempfile
from pathlib import Path

from src.harbor_runner import (
    normalize_crlf_in_directory,
    detect_missing_binaries_in_skill,
    TRIAL_TIMEOUT_SEC,
    AGENT_TIMEOUT_SEC,
    BUILD_TIMEOUT_SEC,
    BATCH_CONCURRENCY_DEFAULT,
)
from src.platform_compat import (
    synthesize_format_valid_dummy_env,
)


def test_hashlib_import_and_usage():
    """Verify hashlib is imported and functional in harbor_runner (B1)."""
    import src.harbor_runner as hr
    assert hasattr(hr, "hashlib")
    h = hr.hashlib.sha256(b"test").hexdigest()
    assert len(h) == 64


def test_scheme_safe_canaries_and_proxy_envs():
    """Verify proxy, endpoint, and URL variables are never populated with raw dummy strings (B2)."""
    var_names = {
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "API_ENDPOINT",
        "TARGET_URL",
        "SERVER_PORT",
        "SERVER_HOST",
        "OPENAI_API_KEY",
    }
    env_dict, canary_map = synthesize_format_valid_dummy_env(var_names, "canary12345678")

    # Proxy variables must NOT be set to dummy strings
    assert "HTTP_PROXY" not in env_dict
    assert "HTTPS_PROXY" not in env_dict
    assert "ALL_PROXY" not in env_dict
    assert "NO_PROXY" not in env_dict

    # URLs must be format-valid URLs
    assert env_dict["API_ENDPOINT"].startswith("http://")
    assert env_dict["TARGET_URL"].startswith("http://")
    assert env_dict["SERVER_PORT"] == "8080"
    assert env_dict["SERVER_HOST"] == "127.0.0.1"

    # Only secret-like variables are in canary_map
    assert "OPENAI_API_KEY" in canary_map
    assert "API_ENDPOINT" not in canary_map
    assert "HTTP_PROXY" not in canary_map


def test_crlf_normalization():
    """Verify CRLF line endings are converted to LF for text files, leaving binaries intact (B3)."""
    with tempfile.TemporaryDirectory() as td:
        tpath = Path(td)
        sh_file = tpath / "script.sh"
        sh_file.write_bytes(b"#!/bin/bash\r\necho hello\r\n")

        bin_file = tpath / "binary.dat"
        bin_file.write_bytes(b"\x00\r\n\xff\xfe\r\n")

        converted = normalize_crlf_in_directory(td)
        assert "script.sh" in converted
        assert b"\r\n" not in sh_file.read_bytes()
        assert b"\n" in sh_file.read_bytes()
        # Binary file untouched
        assert b"\r\n" in bin_file.read_bytes()


def test_detect_missing_binaries_in_skill():
    """Verify static detection of missing system binaries like gitleaks or grpcurl (B5)."""
    with tempfile.TemporaryDirectory() as td:
        tpath = Path(td)
        (tpath / "SKILL.md").write_text("# Skill\nRequires gitleaks and grpcurl.", encoding="utf-8")
        py_file = tpath / "run.py"
        py_file.write_text("import subprocess\nsubprocess.run(['gitleaks', 'detect'])\n", encoding="utf-8")

        missing = detect_missing_binaries_in_skill(td)
        assert "gitleaks" in missing
        assert "grpcurl" in missing
        # Standard tools should not be reported missing
        assert "python" not in missing
        assert "curl" not in missing


def test_timeouts_and_batch_concurrency_defaults():
    """Verify timeouts and Windows-safe batch concurrency defaults (B4)."""
    assert TRIAL_TIMEOUT_SEC >= 300
    assert AGENT_TIMEOUT_SEC >= 600
    assert BUILD_TIMEOUT_SEC >= 1200
    if sys.platform == "win32":
        assert BATCH_CONCURRENCY_DEFAULT == 2
    else:
        assert BATCH_CONCURRENCY_DEFAULT in (2, 4)
