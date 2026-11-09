"""Runtime Call-Site Hook and Profile Capture for Level-2 Verification.

Installed by sitecustomize.py.
Captures:
1. sys.addaudithook events (file I/O, sockets, processes, urllib/http, ctypes).
   Filters frames to /app/skill (or candidate skill directories).
   Writes structured JSONL entries to /logs/agent/callsites.jsonl.
2. Executed skill functions set via sys.setprofile (file, qualname, firstlineno).
   Writes summary to /logs/agent/executed_functions.json at process exit.
3. Safe execution: try/except wrapped everywhere, zero behavior modification.
"""
from __future__ import annotations

import atexit
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, Set

_in_hook = False
_callsites_log_path = os.environ.get("CALLSITES_LOG_PATH", "/logs/agent/callsites.jsonl")
_executed_funcs_path = os.environ.get("EXECUTED_FUNCS_PATH", "/logs/agent/executed_functions.json")
_skill_root = os.path.abspath(os.environ.get("SKILL_DIR", "/app/skill")).replace("\\", "/")

_executed_functions: Set[tuple] = set()
_max_executed_funcs = 2000

AUDIT_EVENTS_OF_INTEREST = {
    "open",
    "os.rename",
    "shutil.copyfile",
    "os.remove",
    "os.unlink",
    "os.mkdir",
    "os.rmdir",
    "os.system",
    "subprocess.Popen",
    "socket.connect",
    "socket.getaddrinfo",
    "socket.__new__",
    "http.client.connect",
    "urllib.Request",
    "ctypes.dlsym",
    "ctypes.cdata",
}


def _normalize_arg(val: Any) -> Any:
    try:
        if isinstance(val, (str, int, float, bool)) or val is None:
            return val
        if isinstance(val, (list, tuple)):
            return [_normalize_arg(x) for x in val[:6]]
        if isinstance(val, dict):
            return {str(k): _normalize_arg(v) for k, v in list(val.items())[:6]}
        return str(val)[:120]
    except Exception:
        return "<unrepresentable>"


def _is_skill_frame(fn: str) -> bool:
    if not fn or fn.startswith("<"):
        return False
    base = os.path.basename(fn)
    if base in ("sitecustomize.py", "callsite_hook.py", "runner.py"):
        return False
    norm_prefix = sys.prefix.replace("\\", "/")
    if fn.startswith(("/tmp/.harbor_host_harness", "/harness", "/usr", "/lib", "/opt", norm_prefix)):
        return False
    return (
        _skill_root in fn
        or "/app/skill" in fn
        or not fn.startswith(("/usr", "/lib", "/opt", norm_prefix))
    )


def callsite_audit_hook(event: str, args: tuple) -> None:
    global _in_hook
    if _in_hook:
        return
    if event not in AUDIT_EVENTS_OF_INTEREST:
        return

    _in_hook = True
    try:
        frame = sys._getframe().f_back
        chain: List[Dict[str, Any]] = []
        depth = 0
        has_skill_frame = False

        while frame and depth < 16:
            co = frame.f_code
            fn = co.co_filename.replace("\\", "/")
            if _is_skill_frame(fn):
                has_skill_frame = True
                rel_fn = os.path.relpath(fn, _skill_root).replace("\\", "/") if fn.startswith(_skill_root) else fn
                chain.append({
                    "file": rel_fn,
                    "abs_file": fn,
                    "function": co.co_name,
                    "qualname": getattr(co, "co_qualname", co.co_name),
                    "line": frame.f_lineno,
                })
            frame = frame.f_back
            depth += 1

        # Only record if at least one skill frame was in the execution call chain
        if has_skill_frame and chain:
            # Order outermost caller -> innermost actor so chain[-1] is the actor function
            ordered_chain = list(reversed(chain))
            norm_args = [_normalize_arg(a) for a in args]
            record = {
                "ts": time.time(),
                "pid": os.getpid(),
                "event": event,
                "args": norm_args,
                "chain": ordered_chain,
            }
            try:
                os.makedirs(os.path.dirname(_callsites_log_path), exist_ok=True)
                with open(_callsites_log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
            except Exception:
                pass
    except Exception:
        pass
    finally:
        _in_hook = False


def _profile_tracer(frame, event: str, arg: Any):
    if event == "call":
        try:
            co = frame.f_code
            fn = co.co_filename.replace("\\", "/")
            if _is_skill_frame(fn) and len(_executed_functions) < _max_executed_funcs:
                rel_fn = os.path.relpath(fn, _skill_root).replace("\\", "/") if fn.startswith(_skill_root) else fn
                qname = getattr(co, "co_qualname", co.co_name)
                _executed_functions.add((rel_fn, qname, co.co_firstlineno))
        except Exception:
            pass
    return _profile_tracer


def _save_executed_functions():
    try:
        os.makedirs(os.path.dirname(_executed_funcs_path), exist_ok=True)
        dump_data = [
            {"file": f, "qualname": q, "firstlineno": l}
            for f, q, l in sorted(_executed_functions)
        ]
        with open(_executed_funcs_path, "w", encoding="utf-8") as f:
            json.dump(dump_data, f, indent=2)
    except Exception:
        pass


def install_callsite_hook(enable_profile: bool = True) -> None:
    """Installs the sys.addaudithook and optional profiler."""
    try:
        sys.addaudithook(callsite_audit_hook)
    except Exception:
        pass

    if enable_profile:
        try:
            sys.setprofile(_profile_tracer)
            atexit.register(_save_executed_functions)
        except Exception:
            pass


# Auto-install when imported by sitecustomize
install_callsite_hook()
