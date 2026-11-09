"""
Unit tests for A_gen test generator validity fixes (Agent B: B6, B7, B8).
"""

import tempfile

from src.adapters.skills_adapter import extract_entry_point_and_cwd
from src.a_gen_test_generator import (
    compute_deterministic_test_case_fields,
    fallback_deterministic_test_cases,
)
from tests.fixtures.make_skills import create_mini_skill


def test_entry_point_selection_cli_vs_library():
    """Verify CLI scripts are identified but pure library modules are classified as instruction-only (B6)."""
    with tempfile.TemporaryDirectory() as td:
        cli_dir = create_mini_skill(td, "my_cli", "cli_basic")
        ep_cli, cwd_cli, is_instr_cli = extract_entry_point_and_cwd(cli_dir)
        assert not is_instr_cli
        assert "main.py" in ep_cli

        lib_dir = create_mini_skill(td, "my_lib", "library_only")
        ep_lib, cwd_lib, is_instr_lib = extract_entry_point_and_cwd(lib_dir)
        # Library module has no CLI parser and no __main__, must be instruction-only!
        assert is_instr_lib
        assert ep_lib == "SKILL.md"


def test_secret_flags_stripped_from_cli_args():
    """Verify secret flags like --api-key and tokens are stripped from cli_args (B7a)."""
    with tempfile.TemporaryDirectory() as td:
        sdir = create_mini_skill(td, "secret_skill", "secret_flags")
        contracts = [{
            "contract_id": "C_01",
            "precondition": "API key set",
            "postcondition": "Data fetched",
            "frame_axiom": ["network: api.openai.com"],
            "forbidden_invariant": ["read: ~/.ssh"],
        }]
        tcs = fallback_deterministic_test_cases(contracts, sdir)
        assert len(tcs) > 0
        for tc in tcs:
            args = tc.get("cli_args", [])
            assert "--api-key" not in args
            assert "-k" not in args
            # No dummy canary secret passed in args
            for a in args:
                assert "canary" not in a.lower()
                assert "dummy" not in a.lower()


def test_passive_flags_excluded_from_effect_tests():
    """Verify passive flags like --dry-run are excluded from effect tests (B7b)."""
    raw_tc = {
        "contract_id": "C_01",
        "cli_args": ["--target", "output.txt", "--dry-run"],
        "mock_files": {},
    }
    stc = compute_deterministic_test_case_fields(raw_tc, None, "/tmp")
    assert "--dry-run" not in stc["cli_args"]
    assert "--dry-run" in stc["passive_flags_used"]


def test_schema_choices_enforcement():
    """Verify cli_args strictly obey schema choices (B7c)."""
    schema = {
        "script_path": "/app/skill/scripts/format.py",
        "options": [
            {
                "flags": ["--format"],
                "choices": ["json", "yaml"],
                "required": True,
            }
        ]
    }
    # Pass an invalid choice 'csv'
    raw_tc = {
        "contract_id": "C_01",
        "cli_args": ["--format", "csv"],
        "mock_files": {},
    }
    stc = compute_deterministic_test_case_fields(raw_tc, schema, "/tmp")
    idx = stc["cli_args"].index("--format")
    assert stc["cli_args"][idx + 1] in ["json", "yaml"]


def test_placeholder_paths_and_mock_files_materialized():
    """Verify placeholder paths are replaced and files are present in mock_files (B7d, B7e)."""
    raw_tc = {
        "contract_id": "C_01",
        "cli_args": ["--input", "path/to/spec.json", "--config", "<config_file>"],
        "mock_files": {},
    }
    stc = compute_deterministic_test_case_fields(raw_tc, None, "/tmp")
    for a in stc["cli_args"]:
        assert "path/to/" not in a
        assert "<" not in a and ">" not in a
    assert stc["placeholder_inputs_used"] is True
    # Non-flag file args must be declared in mock_files
    for a in stc["cli_args"]:
        if "." in a and not a.startswith("-"):
            assert a in stc["mock_files"]


def test_interface_fields_deterministic_computation():
    """Verify all required Agent B interface fields are present and typed correctly (B8)."""
    schema = {"script_path": "/app/skill/scripts/main.py"}
    raw_tc = {
        "contract_id": "C_01",
        "cli_args": ["--input", "data.json", "--verbose"],
        "mock_files": {},
    }
    stc = compute_deterministic_test_case_fields(
        raw_tc, schema, "/tmp", contracts=[{"contract_id": "C_01"}]
    )
    assert stc["entry_kind"] == "cli"
    assert stc["targets_contracts"] == ["C_01"]
    assert stc["preconditions_satisfied"] is True
    assert "--input" in stc["flags_used"]
    assert "--verbose" in stc["flags_used"]
    assert isinstance(stc["passive_flags_used"], list)
    assert isinstance(stc["placeholder_inputs_used"], bool)
    assert isinstance(stc["secret_args_used"], bool)
