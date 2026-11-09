import os
import re
import ast
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

TRIAGE_CLASSES = [
    "SUCCESS",
    "BAD_ARGS",
    "MISSING_FIXTURE",
    "MISSING_ENV",
    "MISSING_BINARY",
    "DEP_IMPORT",
    "EOL",
    "NEEDS_SERVICE",
    "TIMEOUT",
    "STUB",
    "SKILL_BUG",
    "NO_RUNNABLE_ENTRY"
]

def is_usage_only_output(output: str) -> bool:
    """Detects if stdout/stderr output contains only a usage/help string."""
    lines = [line.strip().lower() for line in output.splitlines() if line.strip()]
    if not lines:
        return False
    if any(line.startswith("usage:") for line in lines):
        # Check if output is mostly just options/help
        help_keywords = ["options:", "optional arguments:", "positional arguments:", "-h, --help", "show this help message"]
        if any(hk in output.lower() for hk in help_keywords) and len(lines) <= 40:
            return True
    return False

def classify_failure(
    exit_code: Optional[int],
    stdout: str,
    stderr: str,
    traceback_str: str = "",
    events: Optional[List[Dict[str, Any]]] = None,
    strace_info: Optional[Dict[str, Any]] = None,
    entry_point_reached: bool = False
) -> Tuple[str, Optional[str], Dict[str, Any]]:
    """
    Deterministic triage classifier over exit code, output, traceback, and strace.
    Returns (triage_class, sublabel, details).
    """
    combined = f"{stdout}\n{stderr}\n{traceback_str}"
    combined_lower = combined.lower()
    details: Dict[str, Any] = {}

    # Check for T2 events: >=1 contract-relevant observation
    has_t2_events = False
    if events:
        for ev in events:
            ev_type = ev.get("event_type")
            if ev_type in ["network", "filesystem", "os_command", "persistence_write"]:
                has_t2_events = True
                break

    if strace_info:
        if strace_info.get("attempted_connections") or strace_info.get("persistence_writes") or len(strace_info.get("executed_commands", [])) > 1:
            has_t2_events = True

    # 1. SUCCESS: T2 reached and clean exit, and not just usage text
    if exit_code == 0 and has_t2_events and not is_usage_only_output(combined):
        return "SUCCESS", None, {"reason": "T2 reached with clean exit"}

    # 2. EOL failure: carriage return issues
    if any(m in combined for m in ["$'\r'", "pipefail\r", "/bin/bash^M", "command not found: \r", ": not found\r"]):
        return "EOL", "crlf_interpreter", {"matched": "CRLF formatting in script"}

    # 3. Missing Binary (shell 127 or executable not found)
    if strace_info and strace_info.get("has_missing_binary"):
        bin_name = strace_info.get("missing_binary_name") or "unknown_binary"
        return "MISSING_BINARY", f"binary_missing:{bin_name}", {"binary": bin_name}
    if "strace: cannot find executable" in combined_lower or "strace: can't find executable" in combined_lower:
        return "MISSING_BINARY", "strace_no_exec", {"reason": "Executable not found"}
    if exit_code == 127 or "command not found" in combined_lower:
        bin_match = re.search(r"command not found: ([^\s\n]+)", combined)
        target = bin_match.group(1) if bin_match else "unknown"
        return "MISSING_BINARY", f"binary_missing:{target}", {"target": target}

    # 4. Dependency Import failure
    if "modulenotfounderror" in combined_lower or "importerror" in combined_lower:
        mod_m = re.search(r"No module named ['\"]([^'\"]+)['\"]", combined)
        pkg_name = mod_m.group(1) if mod_m else "unknown"
        return "DEP_IMPORT", f"dep_unavailable:{pkg_name}", {"missing_module": pkg_name}

    # 5. Missing Environment Variable
    if "keyerror:" in combined_lower and any(kw in combined_lower for kw in ["env", "environ", "token", "key", "secret"]):
        key_m = re.search(r"KeyError: ['\"]([^'\"]+)['\"]", combined)
        var_name = key_m.group(1) if key_m else "unknown_env"
        return "MISSING_ENV", f"missing_env:{var_name}", {"env_var": var_name}
    if "nonetype" in combined_lower and any(kw in combined_lower for kw in ["getenv", "environ"]):
        return "MISSING_ENV", "none_type_getenv", {"reason": "os.getenv returned None"}

    # 6. Missing Fixture / File
    if "filenotfounderror" in combined_lower or "no such file or directory" in combined_lower:
        path_m = re.search(r"FileNotFoundError:.*?'([^']+)'|No such file or directory: '([^']+)'", combined)
        fpath = path_m.group(1) or path_m.group(2) if path_m else "unknown_path"
        return "MISSING_FIXTURE", f"missing_fixture:{fpath}", {"path": fpath}
    if any(phrase in combined_lower for phrase in ["configuration not found", "config not found", "no files matched"]):
        return "MISSING_FIXTURE", "missing_config_fixture", {"reason": "Config or fixture file missing"}

    # 7. Bad Arguments: exit 2, usage printed, missing required arguments, or exit 0 with usage-only
    if exit_code == 0 and is_usage_only_output(combined) and not has_t2_events:
        return "BAD_ARGS", "usage_only_exit_zero", {"reason": "Exited 0 with usage-only output and no T2 events"}
    if exit_code == 2 or any(phrase in combined_lower for phrase in [
        "usage:", "the following arguments are required", "unrecognized argument",
        "error: argument", "invalid choice:", "expected one argument"
    ]):
        return "BAD_ARGS", "bad_args", {"reason": "CLI argument syntax/usage error"}

    # 8. Needs Service / Network connection refused
    if "connectionrefusederror" in combined_lower or "connection refused" in combined_lower:
        return "NEEDS_SERVICE", "conn_refused", {"reason": "Local server/daemon port unreachable"}

    # 9. Timeout
    if "timed out" in combined_lower or "timeoutexpired" in combined_lower:
        return "TIMEOUT", "execution_timeout", {"reason": "Process exceeded execution time limit"}

    # 10. Stub
    if "notimplementederror" in combined_lower:
        return "STUB", "NotImplementedError", {"reason": "Hit NotImplementedError stub"}

    # 11. No runnable entry point
    if not entry_point_reached or "no_runnable_entry" in combined_lower:
        return "NO_RUNNABLE_ENTRY", "no_entry", {"reason": "No entry script found"}

    # 12. General Skill Bug
    if "traceback (most recent call last)" in combined_lower:
        err_m = re.search(r"([A-Za-z0-9_]+Error):", combined)
        sublabel = err_m.group(1) if err_m else "skill_exception"
        return "SKILL_BUG", sublabel, {"traceback": traceback_str[-300:]}

    if exit_code != 0:
        return "SKILL_BUG", f"exit_{exit_code}", {"exit_code": exit_code}

    return "SUCCESS", None, {"reason": "Default clean execution"}

def apply_deterministic_repair(
    triage_class: str,
    sublabel: Optional[str],
    details: Dict[str, Any],
    skill_dir: str
) -> Optional[Dict[str, Any]]:
    """
    Applies deterministic repair without calling an LLM:
    - EOL: normalize CRLF to LF
    - MISSING_ENV: add sensible default
    - DEP_IMPORT: alias-mapped package install
    - BAD_ARGS: derive minimal args from --help
    - MISSING_FIXTURE: create inert fixture
    """
    from src.platform_compat import normalize_skill_sources
    from src.dep_resolver import PIP_ALIAS_MAP

    if triage_class == "EOL":
        normalized = normalize_skill_sources(skill_dir)
        return {"action": "normalize_eol", "count": len(normalized)}

    elif triage_class == "MISSING_ENV":
        env_var = details.get("env_var")
        if env_var:
            default_val = "1" if "PORT" in env_var or "COUNT" in env_var else "/tmp/fixture.txt"
            return {"action": "set_env", "name": env_var, "value": default_val}

    elif triage_class == "DEP_IMPORT":
        missing_mod = details.get("missing_module")
        if missing_mod:
            pip_pkg = PIP_ALIAS_MAP.get(missing_mod, missing_mod)
            return {"action": "install_pkg", "name": pip_pkg}

    elif triage_class == "MISSING_FIXTURE":
        fpath = details.get("path")
        if fpath and not fpath.startswith("/"):
            target = os.path.join(skill_dir, fpath)
            try:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "w", encoding="utf-8") as f:
                    if target.endswith(".json"):
                        f.write("{}")
                    elif target.endswith((".yaml", ".yml")):
                        f.write("---\n")
                    else:
                        f.write("test fixture content\n")
                return {"action": "create_fixture", "path": fpath, "kind": "text"}
            except Exception:
                pass

    return None
