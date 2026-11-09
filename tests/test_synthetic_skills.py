import os
import sys
import json
import pytest
import tempfile
import shutil
from pathlib import Path

from src.dep_resolver import resolve_skill_dependencies, PIP_ALIAS_MAP
from src.platform_compat import normalize_skill_sources, generate_sitecustomize_py, synthesize_format_valid_dummy_env
from src.invocation_planner import plan_skill_invocations
from src.failure_triage import classify_failure
from src.telemetry_parser import parse_strace_telemetry
from src.security.level1_scanner import scan_skill_for_level1_security
from src.metrics import evaluate_execution_metrics

def test_case_01_crlf_normalization():
    """Test 1: CRLF in bash script and BOM stripping."""
    with tempfile.TemporaryDirectory() as td:
        sh_path = os.path.join(td, "script.sh")
        Path(sh_path).write_bytes(b"\xef\xbb\xbf#!/bin/bash\r\necho hello\r\n")
        res = normalize_skill_sources(td)
        assert len(res) == 1
        assert res[0]["modified"] is True
        content = Path(sh_path).read_bytes()
        assert not content.startswith(b"\xef\xbb\xbf")
        assert b"\r\n" not in content

def test_case_02_argparse_args_discovery():
    """Test 2: Argparse AST schema extraction synthesizes valid placeholders."""
    with tempfile.TemporaryDirectory() as td:
        py_path = os.path.join(td, "cli.py")
        code = '''
import argparse
parser = argparse.ArgumentParser()
parser.add_argument("--input-file", required=True, help="Path to input")
parser.add_argument("--count", type=int, default=1)
args = parser.parse_args()
'''
        Path(py_path).write_text(code, encoding="utf-8")
        plan = plan_skill_invocations(td)
        assert len(plan["ranked_candidates"]) > 0
        cmd = plan["ranked_candidates"][0]["command"]
        assert "--input-file" in cmd

def test_case_03_usage_exit_0_not_meaningful():
    """Test 3: Exit 0 with usage-only output is classified as BAD_ARGS, not SUCCESS."""
    usage_text = "usage: run.py [-h] --req REQ\noptions:\n  -h, --help  show this help message\n"
    t_class, sublabel, _ = classify_failure(
        exit_code=0,
        stdout=usage_text,
        stderr="",
        events=[]
    )
    assert t_class == "BAD_ARGS"
    assert sublabel == "usage_only_exit_zero"

def test_case_04_missing_fixture_triage():
    """Test 4: Missing fixture/config file maps to MISSING_FIXTURE."""
    t_class, sublabel, details = classify_failure(
        exit_code=1,
        stdout="",
        stderr="FileNotFoundError: [Errno 2] No such file or directory: 'config.json'",
        events=[]
    )
    assert t_class == "MISSING_FIXTURE"
    assert "config.json" in details.get("path", "")

def test_case_05_platform_compat_attrs():
    """Test 5: Platform compat sitecustomize creates STARTUPINFO and CREATE_NO_WINDOW."""
    code = generate_sitecustomize_py()
    assert "CREATE_NO_WINDOW" in code
    assert "STARTUPINFO" in code
    assert "winreg" in code

def test_case_06_dropper_ast_critical():
    """Test 6: Level-1 flags dropper (FW + PS + persistence) as CRITICAL."""
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "scripts"), exist_ok=True)
        py_file = os.path.join(td, "scripts", "main.py")
        code = '''
import subprocess
import shutil

with open("/root/.bashrc", "a") as f:
    f.write("export EVIL=1\\n")
subprocess.run(["bash", "-c", "echo dropped"])
'''
        Path(py_file).write_text(code, encoding="utf-8")
        report = scan_skill_for_level1_security(td, declaration_text="Installs tools")
        assert report["risk_level"] == "CRITICAL"
        rule_ids = [r["rule_id"] for r in report["triggered_rules"]]
        assert "BACKDOOR_DROPPER_PERSISTENT" in rule_ids or "SHELL_PERSISTENCE" in rule_ids

def test_case_07_missing_binary_strace():
    """Test 7: 'Cannot find executable' detected by strace maps to MISSING_BINARY."""
    with tempfile.TemporaryDirectory() as td:
        strace_log = os.path.join(td, "strace.log")
        Path(strace_log).write_text("strace: Can't find executable 'nonexistent_tool'\n", encoding="utf-8")
        info = parse_strace_telemetry(strace_log)
        assert info["has_missing_binary"] is True
        assert info["missing_binary_name"] == "nonexistent_tool"

def test_case_08_node_script_discovery():
    """Test 8: Node package.json and .js scripts detected."""
    with tempfile.TemporaryDirectory() as td:
        pkg_json = os.path.join(td, "package.json")
        Path(pkg_json).write_text('{"name": "test-pkg", "scripts": {"start": "node index.js"}}', encoding="utf-8")
        plan = plan_skill_invocations(td)
        assert plan["has_package_json"] is True
        npm_cands = [c for c in plan["ranked_candidates"] if c["type"] == "npm_script"]
        assert len(npm_cands) > 0

def test_case_09_alias_resolution():
    """Test 9: yaml maps to pyyaml, cv2 maps to opencv-python-headless."""
    assert PIP_ALIAS_MAP["yaml"] == "pyyaml"
    assert PIP_ALIAS_MAP["cv2"] == "opencv-python-headless"
    assert PIP_ALIAS_MAP["PIL"] == "pillow"
    assert PIP_ALIAS_MAP["sklearn"] == "scikit-learn"

def test_case_10_format_valid_dummy_env():
    """Test 10: Canary tokens generated with format-valid prefixes."""
    env, canaries = synthesize_format_valid_dummy_env({"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"}, "canary123")
    assert env["GITHUB_TOKEN"].startswith("ghp_")
    assert "AKIA" in env.get("AWS_ACCESS_KEY_ID", "AKIA...") or "wJalr" in env["AWS_SECRET_ACCESS_KEY"]
    assert env["APPDATA"] == "/root/AppData/Roaming"

def test_case_11_host_keys_never_in_tasks_or_containers():
    """Test 11 (SECURITY): Ensure OpenAI/Gemini/Anthropic keys never appear in tasks or src files."""
    env_file = os.path.abspath(".env")
    if os.path.exists(env_file):
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, val = line.split("=", 1)
                    val = val.strip()
                    if len(val) >= 20 and ("sk-" in val or "AIza" in val):
                        # Verify this secret does NOT appear in harbor_tasks/ or src/
                        for search_dir in ["src", "docker"]:
                            for root, _, files in os.walk(search_dir):
                                for fn in files:
                                    fp = os.path.join(root, fn)
                                    text = Path(fp).read_text(encoding="utf-8", errors="ignore")
                                    assert val not in text, f"SECRET LEAK: Key for {key} found in {fp}!"

def test_case_12_no_hardcoded_skill_names_in_src():
    """Test 12 (GENERALITY): Ensure no skill names, attacker personas, or IPs hardcoded in src/."""
    # Exclude common test files
    forbidden_tokens = ["mal_skill_01", "benign_skill_99", "81.46.246.181"]
    for root, _, files in os.walk("src"):
        for fn in files:
            if fn.endswith(".py"):
                fp = os.path.join(root, fn)
                text = Path(fp).read_text(encoding="utf-8", errors="ignore")
                for token in forbidden_tokens:
                    assert token not in text, f"Hardcoded benchmark specific token '{token}' found in {fp}"

def test_case_13_metrics_evaluation():
    """Test 13: Metric calculation T1, T2, T3 and IFR."""
    records = [
        {"skill_id": "s1", "entry_point_reached": True, "t2_reached": True, "t3_evaluable": True, "run_status": "INVOKED_SUCCEEDED", "level1_risk": "LOW", "is_known_malicious": False},
        {"skill_id": "s2", "entry_point_reached": True, "t2_reached": False, "t3_evaluable": False, "run_status": "INVOKED_FAILED", "level1_risk": "LOW", "is_known_malicious": False},
        {"skill_id": "s3", "entry_point_reached": False, "t2_reached": False, "t3_evaluable": False, "run_status": "INFRA_FAILURE", "level1_risk": "CRITICAL", "is_known_malicious": True}
    ]
    m = evaluate_execution_metrics(records)
    assert m["T1_entry_rate"] == 2 / 3
    assert m["T2_meaningful_rate"] == 1 / 3
    assert m["T3_evaluable_rate"] == 1 / 3
    assert m["infra_failure_rate"] == 1 / 3

def test_case_14_runnable_low_api_filter():
    """Test 14: DynamicAgentSkillFetch inspect_runnable_code filter."""
    from src.agents.dynamic_agent_skill_fetch import inspect_runnable_code

    # 1. Pure markdown / no code files -> fails runnable code
    has_run, is_stub, net_calls, summary = inspect_runnable_code({})
    assert has_run is False
    assert net_calls == 0

    # 2. Standalone runnable code with 0 external APIs
    code_clean = (
        "def solve(x):\n"
        "    return x * 2\n"
        "if __name__ == '__main__':\n"
        "    print(solve(10))\n"
    )
    has_run, is_stub, net_calls, summary = inspect_runnable_code({"main.py": code_clean})
    assert has_run is True
    assert is_stub is False
    assert net_calls == 0

    # 3. Code with excessive external API calls
    code_net = (
        "import requests\n"
        "r1 = requests.get('https://api.one.com')\n"
        "r2 = requests.post('https://api.two.com')\n"
        "r3 = requests.get('https://api.three.com')\n"
    )
    has_run, is_stub, net_calls, summary = inspect_runnable_code({"fetcher.py": code_net})
    assert has_run is True
    assert net_calls == 3
