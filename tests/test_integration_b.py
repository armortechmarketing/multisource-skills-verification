"""
Integration tests for Agent B components (tests/test_integration_b.py).
Tests non-Docker task staging, test synthesis, fixture generation, and evidence extraction
for the audited skills.
"""

import json
import tempfile
from pathlib import Path

from src.adapters.skills_adapter import (
    extract_entry_point_and_cwd,
)
from src.a_gen_test_generator import (
    generate_test_cases,
)
from src.harbor_runner import (
    normalize_crlf_in_directory,
    detect_missing_binaries_in_skill,
    _write_task_fixtures,
)
from src.telemetry_parser import (
    build_evidence_from_artifacts,
)
from tests.fixtures.make_skills import create_mini_skill


def test_yuenkong_library_staging_and_generation():
    """Verify YuenKong-style library skill is treated as instruction-only, not CLI (B6)."""
    with tempfile.TemporaryDirectory() as td:
        sdir = create_mini_skill(td, "benign_YuenKong_liuyao", "library_only")
        ep, cwd, is_instr = extract_entry_point_and_cwd(sdir)
        assert is_instr is True
        assert ep == "SKILL.md"

        contracts = [{
            "contract_id": "C_01",
            "precondition": "Module loaded",
            "postcondition": "Service executes calculation",
            "frame_axiom": ["read: workspace"],
            "forbidden_invariant": ["read: ~/.ssh"],
            "testable": True,
            "expects_effect": True,
        }]

        tcs = generate_test_cases(contracts, sdir, declaration_text="# YuenKong\nPure library.")
        assert len(tcs) > 0
        tc0 = tcs[0]
        assert tc0["entry_kind"] == "agent"
        # Must not invent a runnable CLI script
        assert tc0["entry_point"] == "SKILL.md"
        assert tc0["cli_args"] == []


def test_fetch_open_meteo_passive_flag_handling():
    """Verify fetch-open-meteo-style skill does not use passive flags like --dry-run (B7b)."""
    with tempfile.TemporaryDirectory() as td:
        sdir = create_mini_skill(td, "benign_fetch-open-meteo-flood", "passive_flags")
        ep, cwd, is_instr = extract_entry_point_and_cwd(sdir)
        assert is_instr is False
        assert "deploy.py" in ep

        contracts = [{
            "contract_id": "C_01",
            "precondition": "Target path specified",
            "postcondition": "Files deployed to target",
            "frame_axiom": ["write: output.txt"],
            "forbidden_invariant": ["read: ~/.ssh"],
            "testable": True,
            "expects_effect": True,
        }]

        tcs = generate_test_cases(contracts, sdir)
        assert len(tcs) > 0
        tc0 = tcs[0]
        assert "--dry-run" not in tc0["cli_args"]
        assert tc0["entry_kind"] == "cli"


def test_nano_banana_secret_flag_handling():
    """Verify nano-banana-style skill does not override real API keys with dummy flags (B7a)."""
    with tempfile.TemporaryDirectory() as td:
        sdir = create_mini_skill(td, "benign_nano-banana-pro", "secret_flags")
        contracts = [{
            "contract_id": "C_01",
            "precondition": "Environment configured",
            "postcondition": "API access granted",
            "frame_axiom": ["network: api.openai.com"],
            "forbidden_invariant": ["read: ~/.ssh"],
            "testable": True,
            "expects_effect": True,
        }]

        tcs = generate_test_cases(contracts, sdir)
        assert len(tcs) > 0
        tc0 = tcs[0]
        assert "--api-key" not in tc0["cli_args"]
        assert tc0["secret_args_used"] is False
        for arg in tc0["cli_args"]:
            assert "dummy" not in arg.lower()
            assert "canary" not in arg.lower()


def test_missing_binary_detection_staging():
    """Verify implementing-secrets-scanning skill detects missing gitleaks binary (B5)."""
    with tempfile.TemporaryDirectory() as td:
        sdir = create_mini_skill(td, "benign_implementing-secrets-scanning-in-ci-cd", "missing_binary")
        missing = detect_missing_binaries_in_skill(sdir)
        assert "gitleaks" in missing


def test_crlf_normalization_staging():
    """Verify staging normalizes CRLF shell scripts before execution (B3)."""
    with tempfile.TemporaryDirectory() as td:
        sdir = create_mini_skill(td, "crlf_skill", "crlf_sh")
        sh_file = Path(sdir) / "scripts" / "run.sh"
        assert b"\r\n" in sh_file.read_bytes()

        converted = normalize_crlf_in_directory(sdir)
        assert any("run.sh" in f for f in converted)
        assert b"\r\n" not in sh_file.read_bytes()
        assert b"\n" in sh_file.read_bytes()


def test_task_fixtures_materialization():
    """Verify _write_task_fixtures writes fixtures.json and populates mock files (B7e)."""
    with tempfile.TemporaryDirectory() as td:
        task_dir = Path(td) / "task"
        env_dir = task_dir / "environment"
        env_skill = env_dir / "skill"
        env_skill.mkdir(parents=True, exist_ok=True)
        art_dir = Path(td) / "artifacts"

        test_cases = [
            {
                "test_id": "TC_01",
                "contract_id": "C_01",
                "cli_args": ["--input", "input_1.txt"],
                "mock_files": {"input_1.txt": "sample mock data"},
                "env_vars": {"TEST_VAR": "1"},
                "checks": [{"id": "chk_1", "kind": "exit_code", "expect": 0}],
                "entry_kind": "cli",
                "targets_contracts": ["C_01"],
                "preconditions_satisfied": True,
                "flags_used": ["--input"],
                "passive_flags_used": [],
                "placeholder_inputs_used": False,
                "secret_args_used": False,
            }
        ]

        _write_task_fixtures(str(task_dir), str(art_dir), test_cases)
        assert (task_dir / "fixtures.json").is_file()
        assert (art_dir / "fixtures.json").is_file()
        # Mock file materialized
        assert (env_skill / "input_1.txt").is_file()
        assert (env_skill / "input_1.txt").read_text(encoding="utf-8") == "sample mock data"


def test_evidence_building_end_to_end():
    """Verify evidence builder extracts all B8 interface fields into Evidence structure."""
    with tempfile.TemporaryDirectory() as td:
        art_dir = Path(td)
        status_file = art_dir / "run_status.json"
        status_file.write_text(json.dumps({
            "run_status": "COMPLETED",
            "entry_point_reached": True,
            "exit_code": 0,
        }), encoding="utf-8")

        fixtures_file = art_dir / "fixtures.json"
        fixtures_file.write_text(json.dumps({
            "test_cases": [{
                "entry_kind": "cli",
                "targets_contracts": ["C_01"],
                "preconditions_satisfied": True,
                "flags_used": ["--verbose"],
                "passive_flags_used": [],
                "placeholder_inputs_used": False,
                "secret_args_used": False,
                "cli_args": ["--verbose"],
            }]
        }), encoding="utf-8")

        contracts = [{
            "contract_id": "C_01",
            "precondition": "CLI invoked",
            "postcondition": "Task finished",
            "frame_axiom": ["read: workspace"],
            "forbidden_invariant": ["read: ~/.ssh"],
        }]

        evidence, _ = build_evidence_from_artifacts(
            artifacts_dir=str(art_dir),
            skill_dir="/app/skill",
            contracts_override=contracts,
        )

        assert evidence.run_status.entry_reached is True
        assert evidence.entry_kind == "cli"
        assert evidence.targets_contracts == ("C_01",)
        assert evidence.preconditions_satisfied is True
        assert evidence.flags_used == ("--verbose",)
        assert evidence.passive_flags_used == ()
        assert evidence.placeholder_inputs_used is False
        assert evidence.secret_args_used is False
