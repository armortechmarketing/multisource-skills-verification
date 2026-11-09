import os
import json
import tempfile
import pytest
from unittest.mock import patch

from src.harbor_runner import (
    PROVIDER_KEY_MAP,
    PROVIDER_HOST_MAP,
    get_instruction_agent_config,
    get_keys_to_scrub,
    scrub_api_keys,
    scrub_api_keys_in_object,
    scrub_api_keys_in_dir,
    _extract_declared_hosts,
    _write_no_agent_artifacts,
)
from src.telemetry_parser import detect_canary_content_exfiltration


def test_instruction_agent_config_resolution():
    """Verify dynamic agent resolution across providers and model overrides."""
    with patch.dict(os.environ, {"INSTR_AGENT": "claude-code", "INSTR_AGENT_MODEL": ""}):
        agent, model, key_env, _ = get_instruction_agent_config()
        assert agent == "claude-code"
        assert model == "anthropic/claude-3-5-sonnet-20241022"
        assert key_env == "ANTHROPIC_API_KEY"

    with patch.dict(os.environ, {"INSTR_AGENT": "codex", "INSTR_AGENT_MODEL": "", "OPENAI_API_KEY": "sk-test-openai"}):
        agent, model, key_env, key_val = get_instruction_agent_config()
        assert agent == "codex"
        assert model == "openai/gpt-4o"
        assert key_env == "OPENAI_API_KEY"
        assert key_val == "sk-test-openai"

    with patch.dict(os.environ, {"INSTR_AGENT": "gemini-cli", "INSTR_AGENT_MODEL": "google/gemini-2.0-flash"}):
        agent, model, key_env, _ = get_instruction_agent_config()
        assert agent == "gemini-cli"
        assert model == "google/gemini-2.0-flash"
        assert key_env == "GEMINI_API_KEY"

    with patch.dict(os.environ, {"INSTR_AGENT": "qwen-coder", "INSTR_AGENT_MODEL": ""}):
        agent, model, key_env, _ = get_instruction_agent_config()
        assert agent == "qwen-coder"
        assert model == "qwen/qwen-2.5-coder-32b-instruct"
        assert key_env == "DASHSCOPE_API_KEY"


def test_no_agent_artifacts_generation():
    """Verify _write_no_agent_artifacts writes proper error message for the selected provider."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_no_agent_artifacts(tmpdir, key_env_var="OPENAI_API_KEY", agent_name="codex")
        
        status_file = os.path.join(tmpdir, "run_status.json")
        stderr_file = os.path.join(tmpdir, "stderr.log")
        assert os.path.isfile(status_file)
        assert os.path.isfile(stderr_file)
        
        with open(status_file, "r", encoding="utf-8") as f:
            status = json.load(f)
        assert status["run_status"] == "NOT_INVOKED"
        assert status["failure_type"] == "NO_AGENT"
        assert status["exit_code"] is None
        
        with open(stderr_file, "r", encoding="utf-8") as f:
            stderr_text = f.read()
        assert "OPENAI_API_KEY" in stderr_text
        assert "codex" in stderr_text


def test_extract_declared_hosts_and_provider_hosts():
    """Verify extraction of declared network hosts from contracts and provider hosts."""
    contracts = [
        {
            "contract_id": "C_NET_1",
            "frame_axiom": ["network: https://api.weather.gov/v1/forecast", "read: /app/data"],
        },
        {
            "contract_id": "C_NET_2",
            "frame_axiom": ["network: metrics.example.com", "network: none"],
        },
    ]
    hosts = _extract_declared_hosts(contracts)
    assert "api.weather.gov" in hosts
    assert "metrics.example.com" in hosts
    assert "none" not in hosts

    # Verify provider hosts mapping
    assert "api.anthropic.com" in PROVIDER_HOST_MAP["claude-code"]
    assert "api.openai.com" in PROVIDER_HOST_MAP["codex"]
    assert "generativelanguage.googleapis.com" in PROVIDER_HOST_MAP["gemini-cli"]
    assert "dashscope.aliyuncs.com" in PROVIDER_HOST_MAP["qwen-coder"]


def test_api_key_scrubbing():
    """Verify sensitive provider API keys are scrubbed from text, nested objects, and files."""
    secret_key = "sk-ant-api03-verysecretstring987654321"
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": secret_key}):
        scrub_keys = get_keys_to_scrub()
        assert secret_key in scrub_keys

        # Text scrubbing
        raw_text = f"Connecting to Anthropic using Authorization: Bearer {secret_key} with header."
        scrubbed = scrub_api_keys(raw_text)
        assert secret_key not in scrubbed
        assert "[REDACTED_API_KEY]" in scrubbed

        # Object scrubbing
        raw_obj = {
            "stdout": f"Error: Key {secret_key} was rejected.",
            "meta": ["nested", {"key": secret_key}],
        }
        scrubbed_obj = scrub_api_keys_in_object(raw_obj)
        assert secret_key not in scrubbed_obj["stdout"]
        assert scrubbed_obj["meta"][1]["key"] == "[REDACTED_API_KEY]"

        # Directory scrubbing
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "agent.log")
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(f"DEBUG: api_key={secret_key}")
            
            scrub_api_keys_in_dir(tmpdir)
            
            with open(log_path, "r", encoding="utf-8") as f:
                scrubbed_log = f.read()
            assert secret_key not in scrubbed_log
            assert "[REDACTED_API_KEY]" in scrubbed_log


def test_canary_exfiltration_in_written_files():
    """Verify detect_canary_content_exfiltration detects canary tokens in written files."""
    token = "CANARY_TOKEN_999888777"
    with tempfile.TemporaryDirectory() as tmpdir:
        # File inside written files dir containing canary token
        exfil_file = os.path.join(tmpdir, "leaked_credentials.txt")
        with open(exfil_file, "w", encoding="utf-8") as f:
            f.write(f"The extracted secret is: {token}")

        # Harness-owned file should be ignored even if containing token
        harness_file = os.path.join(tmpdir, "canaries.json")
        with open(harness_file, "w", encoding="utf-8") as f:
            f.write(json.dumps({"tokens": [token]}))

        events = detect_canary_content_exfiltration(
            canary_tokens=[token],
            written_files_dir=tmpdir,
        )
        assert len(events) >= 1
        assert events[0]["event_type"] == "confirmed_exfil"
        assert events[0]["channel"] == "written_file"
        assert events[0]["details"]["token"] == token
        assert "leaked_credentials.txt" in events[0]["details"]["file"]
