import os
import sys
import json
import time
import builtins
import subprocess
import socket

TRACE_FILE = os.environ.get("TRACE_OUTPUT_FILE", "trace.jsonl")

def log_trace_event(event_type: str, details: dict):
    event = {
        "timestamp": time.time(),
        "event_type": event_type,
        "details": details
    }
    try:
        with open(TRACE_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")
    except Exception:
        pass

# --- 1. Filesystem Hooking ---
_orig_open = builtins.open

def traced_open(file, *args, **kwargs):
    mode = kwargs.get("mode", args[0] if len(args) > 0 else "r")
    path_str = str(file)
    # Avoid infinite recursion when writing the trace file itself
    if not path_str.endswith(os.path.basename(TRACE_FILE)):
        op = "write" if any(m in mode for m in ("w", "a", "x", "+")) else "read"
        try:
            abs_p = os.path.abspath(path_str)
        except Exception:
            abs_p = path_str
        log_trace_event("filesystem", {
            "operation": op,
            "path": abs_p,
            "mode": mode
        })
    return _orig_open(file, *args, **kwargs)

builtins.open = traced_open

# --- 2. Process / OS Command Hooking ---
_orig_subprocess_run = subprocess.run
_orig_subprocess_popen = subprocess.Popen
_orig_os_system = os.system

def traced_subprocess_run(*args, **kwargs):
    cmd = args[0] if args else kwargs.get("args")
    cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
    log_trace_event("os_command", {
        "command": cmd_str,
        "shell": kwargs.get("shell", False)
    })
    return _orig_subprocess_run(*args, **kwargs)

class TracedPopen(_orig_subprocess_popen):
    """Subclass preserving class type hierarchy and asyncio compatibility."""
    def __init__(self, *args, **kwargs):
        cmd = args[0] if args else kwargs.get("args")
        cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
        log_trace_event("os_command", {
            "command": cmd_str,
            "shell": kwargs.get("shell", False)
        })
        super().__init__(*args, **kwargs)

def traced_os_system(command):
    log_trace_event("os_command", {
        "command": str(command),
        "shell": True
    })
    return _orig_os_system(command)

subprocess.run = traced_subprocess_run
subprocess.Popen = TracedPopen
os.system = traced_os_system

# Also hook os.popen if used
if hasattr(os, "popen"):
    _orig_os_popen = os.popen
    def traced_os_popen(cmd, *args, **kwargs):
        log_trace_event("os_command", {
            "command": str(cmd),
            "shell": True
        })
        return _orig_os_popen(cmd, *args, **kwargs)
    os.popen = traced_os_popen

# --- 3. Network Interception: urllib.request ---
import urllib.request
_orig_urlopen = urllib.request.urlopen

def traced_urlopen(url, *args, **kwargs):
    req_url = url.full_url if hasattr(url, "full_url") else str(url)
    log_trace_event("network", {
        "destination": req_url,
        "method": getattr(url, "get_method", lambda: "GET")() if hasattr(url, "get_method") else "GET",
        "action": "intercepted_outbound_call",
        "library": "urllib"
    })
    # Transparent interception: mock 200 response
    import io
    from http.client import HTTPMessage
    msg = HTTPMessage()
    msg.add_header("Content-Type", "application/json")
    resp = urllib.request.addinfourl(io.BytesIO(b'{"status": "intercepted", "mock": true}'), msg, req_url, 200)
    return resp

urllib.request.urlopen = traced_urlopen

# --- 4. Network Interception: requests library ---
try:
    import requests
    _orig_requests_session_send = requests.sessions.Session.send
    
    def traced_requests_send(self, request, **kwargs):
        log_trace_event("network", {
            "destination": request.url,
            "method": request.method,
            "action": "intercepted_outbound_call",
            "library": "requests"
        })
        # Build mock response
        resp = requests.Response()
        resp.status_code = 200
        resp.url = request.url
        resp._content = b'{"status": "intercepted", "mock": true}'
        resp.encoding = "utf-8"
        return resp

    requests.sessions.Session.send = traced_requests_send
except ImportError:
    pass

# --- 5. Network Interception: Low-level DNS resolution & socket.connect ---
_orig_getaddrinfo = socket.getaddrinfo

def traced_getaddrinfo(host, port, *args, **kwargs):
    if host and host not in ("localhost", "127.0.0.1", "::1"):
        log_trace_event("network", {
            "destination": f"{host}:{port}",
            "action": "attempted_dns_resolution",
            "library": "socket"
        })
    return _orig_getaddrinfo(host, port, *args, **kwargs)

socket.getaddrinfo = traced_getaddrinfo

_orig_socket_connect = socket.socket.connect

def traced_socket_connect(self, address):
    dest_str = f"{address[0]}:{address[1]}" if isinstance(address, tuple) and len(address) >= 2 else str(address)
    log_trace_event("network", {
        "destination": dest_str,
        "action": "attempted_socket_connect",
        "library": "socket"
    })
    # Do not raise error to allow script to proceed without crashing
    return None

socket.socket.connect = traced_socket_connect

# --- 6. Filesystem Probe Hooking (os.path.exists) ---
_orig_path_exists = os.path.exists

def traced_path_exists(path):
    p_str = str(path)
    if any(s in p_str.lower() for s in ("secrets", ".env", "environment", "shadow", "credentials", ".ssh", ".aws", "id_rsa")):
        log_trace_event("filesystem", {
            "operation": "probe_exists",
            "path": p_str,
            "mode": "stat"
        })
    return _orig_path_exists(path)

os.path.exists = traced_path_exists

# Log instrumentation ready
log_trace_event("system", {"status": "instrumentation_active"})

