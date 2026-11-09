"""Canonical failure classifier for Judge J0 (Agent A shared interface).

Maps stdout/stderr/exit/harbor exceptions into FailureInfo classes used by
valid-exercise gating and no_verdict_reason plumbing.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

FAILURE_CLASSES = (
    "NONE",
    "USAGE_ERROR",
    "FILE_NOT_FOUND_INPUT",
    "MISSING_MODULE",
    "MISSING_BINARY",
    "MISSING_CONFIG",
    "PERMISSION",
    "NETWORK_ERROR",
    "TIMEOUT",
    "HARNESS_EXCEPTION",
    "AGENT_NO_TELEMETRY",
    "SKILL_TRACEBACK",
    "UNKNOWN_FAILURE",
)

# Classes that mean the skill was never validly exercised for negative verdicts
FAILED_INVOCATION_CLASSES = frozenset({
    "USAGE_ERROR",
    "FILE_NOT_FOUND_INPUT",
    "MISSING_MODULE",
    "MISSING_BINARY",
    "MISSING_CONFIG",
    "PERMISSION",
    "NETWORK_ERROR",
    "TIMEOUT",
    "HARNESS_EXCEPTION",
    "AGENT_NO_TELEMETRY",
})

_USAGE_PATTERNS = (
    r"\busage:",
    r"unrecognized arguments",
    r"the following arguments are required",
    r"invalid choice",
    r"error: argument",
    r"optional arguments:",
    r"positional arguments:",
)

_MODULE_PATTERNS = (
    r"No module named ['\"]([^'\"]+)['\"]",
    r"ModuleNotFoundError:\s*(.+)",
    r"The ['\"]([^'\"]+)['\"] package is required",
    r"ImportError:\s*(.+)",
    r"package is required",
)

_BINARY_PATTERNS = (
    r"command not found[:\s]+([^\s\n]+)",
    r"/bin/sh: ([^\s:]+): not found",
    r"FileNotFoundError: \[Errno 2\] No such file or directory: ['\"]([^'\"]+)['\"]",
)

_CONFIG_PATTERNS = (
    r"KeyError: ['\"]([A-Z0-9_]+)['\"]",
    r"environment variable ['\"]?([A-Z0-9_]+)['\"]? (?:is )?(?:required|missing|not set)",
    r"Missing (?:required )?(?:env(?:ironment)? )?var(?:iable)?[:\s]+([A-Z0-9_]+)",
    r"API[_ ]?key",
    r"\b401\b|\b403\b",
)

_PERM_PATTERNS = (
    r"Permission denied",
    r"EACCES",
    r"Operation not permitted",
)

_NET_PATTERNS = (
    r"Connection refused",
    r"ConnectionResetError",
    r"Name or service not known",
    r"Temporary failure in name resolution",
    r"Failed to establish a new connection",
    r"Max retries exceeded",
    r"tls handshake",
    r"waiting for network",
)

_TIMEOUT_PATTERNS = (
    r"TimeoutExpired",
    r"timed out",
    r"TimeoutError",
    r"AgentTimeoutError",
)

_HARBOR_FRAME_RE = re.compile(
    r'File "[^"]*(?:[/\\]harbor[/\\]|[/\\]harbor_runner\.py|/site-packages/harbor/)',
    re.IGNORECASE,
)
_TRACEBACK_RE = re.compile(r"Traceback \(most recent call last\):", re.IGNORECASE)
_FILE_FRAME_RE = re.compile(r'File "([^"]+)", line (\d+)', re.IGNORECASE)


@dataclass
class FailureInfo:
    cls: str
    symptom: str = ""
    evidence_line: str = ""
    refinable: bool = False
    missing: List[str] = field(default_factory=list)
    low_confidence: bool = False
    no_verdict_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "failure_class": self.cls,
            "failure_symptom": self.symptom,
            "evidence_line": self.evidence_line,
            "refinable": self.refinable,
            "missing": list(self.missing),
            "low_confidence": self.low_confidence,
            "no_verdict_reason": self.no_verdict_reason,
        }


def failure_cls_to_no_verdict_reason(cls: str) -> Optional[str]:
    if cls in ("USAGE_ERROR", "FILE_NOT_FOUND_INPUT"):
        return "HARNESS"
    if cls in (
        "MISSING_MODULE", "MISSING_BINARY", "MISSING_CONFIG",
        "PERMISSION", "NETWORK_ERROR", "TIMEOUT", "HARNESS_EXCEPTION",
    ):
        return "INFRA"
    if cls == "AGENT_NO_TELEMETRY":
        return "TELEMETRY_GAP"
    if cls in ("SKILL_TRACEBACK", "UNKNOWN_FAILURE"):
        return "SKILL_CRASH"
    return None


def _is_refinable(cls: str) -> bool:
    return cls in ("USAGE_ERROR", "FILE_NOT_FOUND_INPUT")


def _first_match(patterns: Sequence[str], text: str) -> Optional[re.Match]:
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
        if m:
            return m
    return None


def _traceback_frames(text: str) -> List[str]:
    return [m.group(1) for m in _FILE_FRAME_RE.finditer(text or "")]


def _frames_in_harbor(frames: List[str]) -> bool:
    for fr in frames:
        norm = fr.replace("\\", "/").lower()
        if "/harbor/" in norm or norm.endswith("harbor_runner.py") or "/site-packages/harbor/" in norm:
            return True
    return False


def _frames_in_skill(frames: List[str], skill_dir: str) -> bool:
    if not skill_dir:
        # Without skill_dir, treat non-harbor frames with .py under scripts/ as skill
        return any(
            ("/scripts/" in fr.replace("\\", "/") or fr.replace("\\", "/").endswith(".py"))
            and not _frames_in_harbor([fr])
            for fr in frames
        )
    skill_abs = os.path.abspath(skill_dir).replace("\\", "/").lower()
    skill_base = os.path.basename(skill_abs.rstrip("/"))
    for fr in frames:
        norm = os.path.abspath(fr).replace("\\", "/").lower() if os.path.isabs(fr) else fr.replace("\\", "/").lower()
        if skill_abs and skill_abs in norm:
            return True
        if skill_base and f"/{skill_base}/" in f"/{norm}/":
            return True
        if "/skill_package/" in norm or "/scripts/" in norm:
            if not _frames_in_harbor([fr]):
                return True
    return False


def _looks_like_input_path(path: str) -> bool:
    p = (path or "").lower()
    if not p:
        return False
    if any(tok in p for tok in ("path/to/", "/tmp/test_workspace/", "fixture", "mock", ".json", ".csv", ".yaml", ".yml", ".xml")):
        # Exclude obvious python modules / binaries
        if p.endswith(".py") or "/site-packages/" in p:
            return False
        return True
    return False


def classify_failure(
    stdout: str = "",
    stderr: str = "",
    exit_code: Optional[int] = None,
    run_status: Optional[Dict[str, Any]] = None,
    harbor_exception: Optional[str] = None,
    skill_dir: str = "",
    test_args: Optional[List[Any]] = None,
) -> FailureInfo:
    """Classify a trial outcome into a FailureInfo (shared Agent A/B interface)."""
    run_status = run_status or {}
    test_args = list(test_args or [])
    stdout = stdout or ""
    stderr = stderr or ""
    combined = f"{stdout}\n{stderr}\n{harbor_exception or ''}"
    combined_l = combined.lower()

    entry_reached = bool(run_status.get("entry_point_reached", run_status.get("entry_reached", True)))
    traj_present = bool(run_status.get("trajectory_present", False))
    traj_units = int(run_status.get("trajectory_units") or 0)
    run_kind = str(run_status.get("run_kind") or "")

    def _make(cls: str, symptom: str = "", evidence: str = "", missing: Optional[List[str]] = None, low: bool = False) -> FailureInfo:
        return FailureInfo(
            cls=cls,
            symptom=symptom,
            evidence_line=(evidence or symptom)[:500],
            refinable=_is_refinable(cls),
            missing=list(missing or []),
            low_confidence=low,
            no_verdict_reason=failure_cls_to_no_verdict_reason(cls),
        )

    # Agent telemetry gap
    if run_kind == "agent" or run_status.get("instruction_only"):
        if traj_present and traj_units == 0 and (exit_code in (0, None) or exit_code == 0):
            if not _TRACEBACK_RE.search(combined):
                return _make("AGENT_NO_TELEMETRY", "trajectory_present_zero_units", "trajectory_units=0")

    # Harbor / infra exception text
    hexc = (harbor_exception or "") + "\n" + str(run_status.get("exception_info") or "")
    if hexc.strip():
        if _first_match(_TIMEOUT_PATTERNS, hexc) or exit_code in (124,):
            return _make("TIMEOUT", "harbor_timeout", hexc.strip()[:300])
        if any(k in hexc.lower() for k in ("docker", "image", "build", "pull access", "harbor-base", "oom")):
            return _make("HARNESS_EXCEPTION", "harbor_infra_exception", hexc.strip()[:300])
        if _first_match(_NET_PATTERNS, hexc):
            return _make("NETWORK_ERROR", "harbor_network", hexc.strip()[:300])

    # Timeout
    if exit_code in (124,) or _first_match(_TIMEOUT_PATTERNS, combined):
        m = _first_match(_TIMEOUT_PATTERNS, combined)
        return _make("TIMEOUT", "timeout", (m.group(0) if m else "timeout")[:300])

    # Usage / argparse
    if _first_match(_USAGE_PATTERNS, combined) or (exit_code == 2 and ("usage:" in combined_l or "invalid choice" in combined_l or "unrecognized arguments" in combined_l)):
        m = _first_match(_USAGE_PATTERNS, combined)
        return _make("USAGE_ERROR", "usage_or_argparse", (m.group(0) if m else combined.strip()[:200]))

    # Missing module
    m = _first_match(_MODULE_PATTERNS, combined)
    if m:
        missing = [g for g in m.groups() if g] if m.lastindex else []
        if not missing and "package is required" in combined_l:
            pkg_m = re.search(r"['\"]([^'\"]+)['\"] package is required", combined, re.IGNORECASE)
            if pkg_m:
                missing = [pkg_m.group(1)]
        return _make("MISSING_MODULE", "missing_python_module", m.group(0)[:300], missing=missing)

    # Permission
    m = _first_match(_PERM_PATTERNS, combined)
    if m:
        return _make("PERMISSION", "permission_denied", m.group(0)[:300])

    # Network
    m = _first_match(_NET_PATTERNS, combined)
    if m:
        return _make("NETWORK_ERROR", "network_error", m.group(0)[:300])

    # Missing binary / command not found
    if exit_code == 127 or "command not found" in combined_l or "strace: cannot find executable" in combined_l:
        m = _first_match(_BINARY_PATTERNS, combined)
        missing = [m.group(1)] if m and m.lastindex else []
        return _make("MISSING_BINARY", "missing_binary", (m.group(0) if m else "command not found")[:300], missing=missing)

    # FileNotFoundError on inputs
    fnf = re.search(
        r"FileNotFoundError:.*?['\"]([^'\"]+)['\"]|No such file or directory: ['\"]([^'\"]+)['\"]",
        combined,
        re.IGNORECASE,
    )
    if fnf:
        path = fnf.group(1) or fnf.group(2) or ""
        # Binary-looking vs input fixture
        base = os.path.basename(path)
        if _looks_like_input_path(path) or any(str(a) in path for a in test_args if a):
            return _make("FILE_NOT_FOUND_INPUT", "missing_input_file", fnf.group(0)[:300], missing=[path])
        if "/" not in path.replace("\\", "/") and not path.endswith((".py", ".json", ".csv", ".yaml", ".yml", ".xml", ".txt", ".md")):
            return _make("MISSING_BINARY", "missing_binary_path", fnf.group(0)[:300], missing=[base or path])
        if path.endswith((".json", ".csv", ".yaml", ".yml", ".xml", ".txt")) or "fixture" in path.lower() or "test_workspace" in path.lower():
            return _make("FILE_NOT_FOUND_INPUT", "missing_input_file", fnf.group(0)[:300], missing=[path])

    # Placeholder inputs in args
    for a in test_args:
        s = str(a)
        if "path/to/" in s.lower() or s.lower() in ("/path/to/project", "path/to/x.json"):
            return _make("FILE_NOT_FOUND_INPUT", "placeholder_input", s, missing=[s])

    # Missing config / API key / env
    m = _first_match(_CONFIG_PATTERNS, combined)
    if m and ("api" in combined_l or "keyerror" in combined_l or "env" in combined_l or "401" in combined_l or "403" in combined_l):
        missing = [g for g in m.groups() if g] if m.lastindex else []
        # Filter out non-env captures from 401/403 only matches
        missing = [x for x in missing if re.match(r"^[A-Z0-9_]+$", x or "")]
        return _make("MISSING_CONFIG", "missing_config_or_auth", m.group(0)[:300], missing=missing)

    # Explicit stub signal without full traceback still maps to skill-side failure (not INFRA)
    if "NotImplementedError" in combined and exit_code not in (0, None):
        return _make("SKILL_TRACEBACK", "not_implemented_error", "NotImplementedError")

    # Tracebacks
    if _TRACEBACK_RE.search(combined) or _HARBOR_FRAME_RE.search(combined):
        frames = _traceback_frames(combined)
        if _frames_in_harbor(frames) or _HARBOR_FRAME_RE.search(combined):
            # Prefer harbor if any harbor frame appears
            if _frames_in_harbor(frames) and not _frames_in_skill(frames, skill_dir):
                return _make("HARNESS_EXCEPTION", "traceback_in_harbor", combined[combined.lower().find("traceback"):][:400])
            if _frames_in_harbor(frames) and _frames_in_skill(frames, skill_dir):
                # Mixed: if innermost skill frame after harbor bootstrap, still skill if entry reached
                if entry_reached and _frames_in_skill(frames, skill_dir):
                    # Check last frames
                    if frames and _frames_in_skill(frames[-3:], skill_dir):
                        return _make("SKILL_TRACEBACK", "traceback_in_skill", combined[combined.lower().find("traceback"):][:400])
                return _make("HARNESS_EXCEPTION", "traceback_harbor_dominant", combined[combined.lower().find("traceback"):][:400])
        if entry_reached and _frames_in_skill(frames, skill_dir):
            return _make("SKILL_TRACEBACK", "traceback_in_skill", combined[combined.lower().find("traceback"):][:400])
        if entry_reached and frames:
            return _make("SKILL_TRACEBACK", "traceback_after_invoke", combined[combined.lower().find("traceback"):][:400])
        if frames:
            return _make("HARNESS_EXCEPTION", "traceback_before_skill", combined[combined.lower().find("traceback"):][:400])

    # Non-zero exit without classification
    if exit_code not in (0, None):
        return _make(
            "UNKNOWN_FAILURE",
            f"exit_{exit_code}",
            f"Unclassified non-zero exit_code={exit_code}",
            low=True,
        )

    # Exit 0 with soft error text already handled above; clean success
    return _make("NONE", "ok", "No failure class detected")
