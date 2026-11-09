import os
import re
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Tuple, Set

def normalize_skill_sources(skill_dir: str) -> List[Dict[str, Any]]:
    """
    CRLF -> LF and UTF-8 BOM strip for .sh, .bash, .py, .js, .json, .yaml, .yml, .toml, .md.
    chmod +x on shebang files.
    Returns normalized_files list with path, original sha256, and whether modified.
    """
    target_exts = {".sh", ".bash", ".py", ".js", ".mjs", ".json", ".yaml", ".yml", ".toml", ".md"}
    normalized = []

    for root, _, files in os.walk(skill_dir):
        for fn in sorted(files):
            ext = os.path.splitext(fn)[1].lower()
            if ext in target_exts:
                fp = os.path.join(root, fn)
                rel = os.path.relpath(fp, skill_dir).replace("\\", "/")
                try:
                    raw_bytes = Path(fp).read_bytes()
                    orig_sha = hashlib.sha256(raw_bytes).hexdigest()

                    # Strip UTF-8 BOM if present
                    content_bytes = raw_bytes
                    bom_stripped = False
                    if content_bytes.startswith(b"\xef\xbb\xbf"):
                        content_bytes = content_bytes[3:]
                        bom_stripped = True

                    # Convert CRLF to LF
                    crlf_converted = b"\r\n" in content_bytes
                    new_bytes = content_bytes.replace(b"\r\n", b"\n")

                    modified = bom_stripped or crlf_converted
                    if modified:
                        Path(fp).write_bytes(new_bytes)

                    # Check shebang for chmod +x
                    if new_bytes.startswith(b"#!"):
                        try:
                            os.chmod(fp, 0o755)
                        except Exception:
                            pass

                    normalized.append({
                        "file": rel,
                        "original_sha256": orig_sha,
                        "modified": modified
                    })
                except Exception:
                    pass

    return normalized

def generate_sitecustomize_py() -> str:
    """
    Generates container sitecustomize.py ensuring Windows-only attributes exist.
    NEVER replaces a class with a function — uses subclass or setattr only if missing.
    """
    return '''import sys
import subprocess
import os

# 0. Level-2 Runtime Call-Site and Profile Hook
try:
    import callsite_hook
except Exception:
    pass

# 1. Windows subprocess attributes (safe setattr if missing)
if not hasattr(subprocess, "CREATE_NO_WINDOW"):
    setattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

if not hasattr(subprocess, "STARTF_USESHOWWINDOW"):
    setattr(subprocess, "STARTF_USESHOWWINDOW", 0x00000001)

if not hasattr(subprocess, "SW_HIDE"):
    setattr(subprocess, "SW_HIDE", 0)

if not hasattr(subprocess, "STARTUPINFO"):
    class STARTUPINFO:
        """Compatibility shim for Windows STARTUPINFO on POSIX runtimes."""
        def __init__(self):
            self.dwFlags = 0
            self.wShowWindow = 0
    setattr(subprocess, "STARTUPINFO", STARTUPINFO)

# 2. Windows registry stubs if winreg requested
if sys.platform != "win32" and "winreg" not in sys.modules:
    import types
    winreg_stub = types.ModuleType("winreg")
    winreg_stub.HKEY_CURRENT_USER = 0x80000001
    winreg_stub.HKEY_LOCAL_MACHINE = 0x80000002
    def _stub_open_key(*args, **kwargs):
        raise FileNotFoundError("Windows registry not present in Linux sandbox")
    winreg_stub.OpenKey = _stub_open_key
    winreg_stub.QueryValueEx = _stub_open_key
    winreg_stub.CloseKey = lambda *args, **kwargs: None
    sys.modules["winreg"] = winreg_stub

# 3. Headless container os.getlogin fallback (avoids OSError Errno 25 ENOTTY)
_orig_getlogin = getattr(os, "getlogin", None)
if _orig_getlogin is not None:
    def _safe_getlogin():
        try:
            return _orig_getlogin()
        except OSError:
            return os.environ.get("USER") or os.environ.get("LOGNAME") or "agent"
    os.getlogin = _safe_getlogin

# 4. Egress hostname telemetry capture via socket.getaddrinfo (captures HTTPS/DNS attempts even when SSL or no-network fails)
try:
    import socket
    import json
    _orig_getaddrinfo = socket.getaddrinfo
    _seen_dns_hosts = set()
    def _traced_getaddrinfo(host, port, *args, **kwargs):
        try:
            h_str = host.decode("utf-8", errors="ignore") if isinstance(host, bytes) else str(host or "")
            h_low = h_str.strip().lower()
            if (
                h_low
                and h_low not in ("localhost", "127.0.0.1", "::1", "0.0.0.0")
                and not h_low.startswith("127.")
                and (os.environ.get("HARBOR_IN_ENTRY") == "1" or os.path.exists("/tmp/.harbor_entry_start"))
                and h_low not in _seen_dns_hosts
            ):
                _seen_dns_hosts.add(h_low)
                os.makedirs("/logs/artifacts", exist_ok=True)
                with open("/logs/artifacts/mock_egress.jsonl", "a", encoding="utf-8") as _ef:
                    _ef.write(json.dumps({"host": h_low, "port": port, "source": "getaddrinfo"}) + "\\n")
        except Exception:
            pass
        return _orig_getaddrinfo(host, port, *args, **kwargs)
    socket.getaddrinfo = _traced_getaddrinfo
except Exception:
    pass

# 5. Pure-Python fallback for optional data/utility libraries (pandas, chardet, faker) ONLY if not installed in container
try:
    import importlib.util
    import types
    import csv as _csv_mod

    if importlib.util.find_spec("chardet") is None and "chardet" not in sys.modules:
        _chardet = types.ModuleType("chardet")
        _chardet.detect = lambda raw: {"encoding": "utf-8", "confidence": 0.99, "language": ""}
        sys.modules["chardet"] = _chardet

    if importlib.util.find_spec("faker") is None and "faker" not in sys.modules:
        _faker_mod = types.ModuleType("faker")
        class _FakerStub:
            def __init__(self, *args, **kwargs):
                pass
            def phone_number(self): return "13800138000"
            def ssn(self): return "110101199001011234"
            def name(self): return "Sample User"
            def email(self): return "user@example.com"
            def credit_card_number(self): return "6222021234567890"
            def address(self): return "123 Sample Street"
            def __getattr__(self, name):
                return lambda *a, **kw: "sample_value"
        _faker_mod.Faker = _FakerStub
        sys.modules["faker"] = _faker_mod

    if importlib.util.find_spec("pandas") is None and "pandas" not in sys.modules:
        _pd = types.ModuleType("pandas")
        def _isna(val):
            return val is None or val == "" or (isinstance(val, float) and val != val)
        _pd.isna = _isna
        _pd.isnull = _isna
        _pd.notna = lambda val: not _isna(val)
        _pd.notnull = _pd.notna

        class _MaskSumList(list):
            def sum(self):
                return sum(1 for x in self if x)

        class _Series:
            def __init__(self, values):
                self._values = list(values)
            def notna(self):
                return _MaskSumList([not _isna(v) for v in self._values])
            def isna(self):
                return _MaskSumList([_isna(v) for v in self._values])
            def apply(self, func, *args, **kwargs):
                return _Series([func(v) for v in self._values])
            def tolist(self):
                return list(self._values)
            def __len__(self):
                return len(self._values)
            def __iter__(self):
                return iter(self._values)

        class DataFrame:
            def __init__(self, data=None, columns=None):
                self._rows = []
                self.columns = list(columns) if columns else []
                if isinstance(data, list):
                    for r in data:
                        if isinstance(r, dict):
                            for k in r.keys():
                                if k not in self.columns:
                                    self.columns.append(k)
                            self._rows.append(dict(r))
                elif isinstance(data, dict):
                    self.columns = list(data.keys())
                    n = len(next(iter(data.values()), []))
                    for i in range(n):
                        self._rows.append({k: list(v)[i] for k, v in data.items()})
            def __len__(self):
                return len(self._rows)
            @property
            def empty(self):
                return len(self._rows) == 0
            @property
            def shape(self):
                return (len(self._rows), len(self.columns))
            def __getitem__(self, col):
                return _Series([r.get(col) for r in self._rows])
            def __setitem__(self, col, val):
                if col not in self.columns:
                    self.columns.append(col)
                vals = list(val) if hasattr(val, "__iter__") and not isinstance(val, (str, bytes)) else [val] * len(self._rows)
                for idx_r, r in enumerate(self._rows):
                    r[col] = vals[idx_r] if idx_r < len(vals) else None
            def to_csv(self, path_or_buf=None, sep=",", index=False, encoding="utf-8", **kwargs):
                import io
                buf = io.StringIO()
                writer = _csv_mod.DictWriter(buf, fieldnames=self.columns, delimiter=sep, lineterminator="\\n")
                writer.writeheader()
                for r in self._rows:
                    writer.writerow({c: r.get(c, "") for c in self.columns})
                out_str = buf.getvalue()
                if path_or_buf is None:
                    return out_str
                with open(path_or_buf, "w", encoding=encoding or "utf-8", newline="") as f:
                    f.write(out_str)
            def to_dict(self, orient="records"):
                return [dict(r) for r in self._rows]

        def read_csv(filepath, sep=",", encoding="utf-8", **kwargs):
            with open(filepath, "r", encoding=encoding or "utf-8", errors="replace") as f:
                reader = _csv_mod.DictReader(f, delimiter=sep)
                cols = list(reader.fieldnames or [])
                rows = [dict(r) for r in reader]
            return DataFrame(rows, columns=cols)

        _pd.DataFrame = DataFrame
        _pd.Series = _Series
        _pd.read_csv = read_csv
        sys.modules["pandas"] = _pd
except Exception:
    pass

# 6. Join short-lived background threads at process exit so daemon/worker threads complete within the trace window
try:
    import atexit
    import threading
    def _join_background_threads():
        main_t = threading.main_thread()
        for t in list(threading.enumerate()):
            if t is not main_t and t.is_alive():
                try:
                    t.join(timeout=2.0)
                except Exception:
                    pass
    atexit.register(_join_background_threads)
except Exception:
    pass
'''

LOG_ONLY_SHIMMED_BINARIES = [
    "cmd", "cmd.exe", "powershell", "pwsh", "schtasks", "reg",
    "taskkill", "shutdown", "reboot", "halt", "poweroff",
    "systemctl", "launchctl", "osascript", "crontab",
    "cargo", "gh", "ffmpeg", "ffprobe",
    "mongodump", "mongorestore", "pg_dump", "pg_restore", "mysqldump",
]

def generate_log_only_shim_script(binary_name: str) -> str:
    """Generates POSIX log-only shim script logging invocation to /logs/artifacts/shims.jsonl."""
    return f'''#!/bin/sh
# Log-only shim for {binary_name}
mkdir -p /logs/artifacts /logs/shims
python3 -c "
import json, sys, os, time
record = {{
    'binary': '{binary_name}',
    'argv': sys.argv[1:],
    'cwd': os.getcwd(),
    'timestamp': time.time()
}}
line = json.dumps(record) + '\\n'
for p in ['/logs/shims.jsonl', '/logs/artifacts/shims.jsonl']:
    try:
        with open(p, 'a', encoding='utf-8') as f:
            f.write(line)
    except Exception:
        pass
" "$@"
exit 0
'''

def extract_env_var_names_from_skill(skill_dir: str) -> Set[str]:
    """Finds referenced env var names via regex from code and docs."""
    env_vars = set()
    patterns = [
        re.compile(r"os\.(?:getenv|environ(?:\[|\.get\())\s*['\"]([A-Z0-9_]{3,})['\"]"),
        re.compile(r"process\.env\.([A-Z0-9_]{3,})"),
        re.compile(r"\$([A-Z0-9_]{3,})")
    ]
    for root, _, files in os.walk(skill_dir):
        for fn in files:
            if fn.endswith((".py", ".sh", ".js", ".md", ".json", ".yaml", ".yml")):
                try:
                    text = Path(os.path.join(root, fn)).read_text(encoding="utf-8", errors="ignore")
                    for p in patterns:
                        for m in p.findall(text):
                            if m and not m.startswith("PYTHON") and m not in ["PATH", "HOME", "USER", "PWD", "SHELL"]:
                                env_vars.add(m)
                except Exception:
                    pass
    return env_vars

def synthesize_format_valid_dummy_env(
    var_names: Set[str],
    canary_id: str
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Synthesizes format-valid dummy credentials with per-run canary markers.
    Returns (env_dict, canary_map).
    """
    canary_seed = canary_id[:8]
    env_dict: Dict[str, str] = {}
    canary_map: Dict[str, str] = {}

    for name in var_names:
        upper = name.upper()

        # B2: Never write canary or dummy strings into proxy, URL, endpoint, host or port variables
        if any(p in upper for p in ("PROXY", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")):
            # Leave unset or set to empty so httpx/requests url parsers do not throw ValueError
            continue
        elif any(upper.endswith(s) or s in upper for s in ("_URL", "ENDPOINT", "_HOST", "_PORT", "_BASE")) and not any(
            k in upper for k in ("KEY", "SECRET", "TOKEN", "PASS")
        ):
            if "PORT" in upper and "URL" not in upper:
                env_dict[name] = "8080"
            elif "HOST" in upper and "URL" not in upper:
                env_dict[name] = "127.0.0.1"
            else:
                env_dict[name] = f"http://canary-endpoint-{canary_seed}.internal:8080"
            continue
        elif upper.endswith("SKILLS_DIR") or upper == "HERMES_SKILLS_EXTERNAL_DIRS":
            env_dict[name] = "/app/skill/skills"
        elif any(upper.endswith(s) for s in ("_WORKSPACE", "_WORKDIR", "_ROOT", "_DIR")) and not any(
            k in upper for k in ("KEY", "SECRET", "TOKEN", "PASS")
        ):
            env_dict[name] = "/app/skill"
        elif "GITHUB" in upper or "GH_" in upper:
            val = f"ghp_CANARY_{canary_seed}_{'A'*20}"
            env_dict[name] = val
            canary_map[name] = val
        elif "AWS" in upper and "SECRET" in upper:
            val = f"wJalrXUtnFEMI/K7MDENG/bPxRfiCYCANARY_{canary_seed}"
            env_dict[name] = val
            canary_map[name] = val
        elif "AWS" in upper and ("KEY" in upper or "ID" in upper):
            val = f"AKIA{canary_seed.upper()}{'X'*8}"
            env_dict[name] = val
            canary_map[name] = val
        elif any(k in upper for k in ("OPENAI", "API_KEY", "KEY", "SECRET", "TOKEN", "PASS", "PASSWORD", "CREDENTIAL")):
            val = f"sk-canary-{canary_seed}-{'a'*24}"
            env_dict[name] = val
            canary_map[name] = val
        else:
            # Generic non-secret variable: plain valid identifier, no canary token
            val = f"safe_env_val_{canary_seed}"
            env_dict[name] = val

    # Standard platform compat env vars
    platform_env = {
        "APPDATA": "/root/AppData/Roaming",
        "LOCALAPPDATA": "/root/AppData/Local",
        "USERPROFILE": "/root",
        "TEMP": "/tmp",
        "TMP": "/tmp",
        "PROGRAMDATA": "/root/ProgramData",
        "USERNAME": "root",
        "COMPUTERNAME": "SANDBOX-HARBOR"
    }
    env_dict.update(platform_env)
    return env_dict, canary_map
