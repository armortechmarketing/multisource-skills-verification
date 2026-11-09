"""
Unit tests for ATIF trajectory and Codex agent telemetry parsing (Agent B: B1, B9).
"""

import json
import tempfile
from pathlib import Path

from src.telemetry_parser import (
    build_behavior_units_from_trajectory,
    build_evidence_from_artifacts,
)


def test_codex_js_exec_command_parsing():
    """Verify Codex js-style await tools.exec_command(...) produces exec behavior units (B9)."""
    traj_steps = [
        {
            "step_id": 1,
            "source": "model",
            "message": "I will inspect the skill files now.",
            "tool_calls": [
                {
                    "name": "exec",
                    "arguments": {
                        "input": 'text(await tools.exec_command({cmd:"cat /etc/os-release"}))'
                    }
                }
            ]
        },
        {
            "step_id": 2,
            "source": "model",
            "message": "Writing output file.",
            "tool_calls": [
                {
                    "name": "exec",
                    "arguments": {
                        "input": 'text(await tools.write_file({path:"output.txt", content:"done"}))'
                    }
                }
            ]
        },
        {
            "step_id": 3,
            "source": "model",
            "message": "Calling remote webhook.",
            "tool_calls": [
                {
                    "name": "exec",
                    "arguments": {
                        "input": 'text(await tools.exec_command({cmd:"curl -s https://api.github.com/repos"}))'
                    }
                }
            ]
        }
    ]

    units, steps, _, _ = build_behavior_units_from_trajectory(traj_steps)
    assert len(units) >= 3

    kinds = [u.kind for u in units]
    targets = [u.target for u in units]

    assert "exec" in kinds
    assert any("cat /etc/os-release" in t for t in targets)

    assert "file_write" in kinds
    assert any("output.txt" in t for t in targets)

    assert "net_connect" in kinds
    assert any("api.github.com" in t for t in targets)


def test_standard_tool_calls_parsing():
    """Verify standard tool calls like write_file and read_file produce behavior units (B9)."""
    traj_steps = [
        {
            "step_id": 1,
            "source": "agent",
            "message": "Reading config",
            "tool_calls": [
                {
                    "name": "read_file",
                    "arguments": {"path": "config.yaml"}
                }
            ]
        },
        {
            "step_id": 2,
            "source": "agent",
            "message": "Running tool",
            "tool_calls": [
                {
                    "name": "bash",
                    "arguments": {"command": "ls -la"}
                }
            ]
        }
    ]
    units, steps, _, _ = build_behavior_units_from_trajectory(traj_steps)
    assert len(units) == 2
    assert units[0].kind == "file_read"
    assert "config.yaml" in units[0].target
    assert units[1].kind == "exec"
    assert "ls -la" in units[1].target


def test_build_evidence_from_artifacts_with_trajectory():
    """Verify build_evidence_from_artifacts populates agent evidence fields (B1, B9)."""
    with tempfile.TemporaryDirectory() as td:
        art_dir = Path(td)
        traj_data = [
            {
                "step_id": 1,
                "source": "assistant",
                "message": "Starting evaluation.",
                "tool_calls": [
                    {
                        "name": "exec",
                        "arguments": {"input": 'text(await tools.exec_command({cmd:"python test.py"}))'}
                    }
                ]
            }
        ]
        (art_dir / "trajectory.json").write_text(json.dumps(traj_data), encoding="utf-8")
        status_data = {
            "run_status": "COMPLETED",
            "entry_point_reached": True,
            "exit_code": 0,
            "instruction_only": True,
        }
        (art_dir / "run_status.json").write_text(json.dumps(status_data), encoding="utf-8")
        fixtures_data = {
            "test_cases": [
                {
                    "entry_kind": "agent",
                    "targets_contracts": ["C_01"],
                    "preconditions_satisfied": True,
                    "flags_used": [],
                    "passive_flags_used": [],
                    "placeholder_inputs_used": False,
                    "secret_args_used": False,
                }
            ]
        }
        (art_dir / "fixtures.json").write_text(json.dumps(fixtures_data), encoding="utf-8")

        contracts = [{
            "contract_id": "C_01",
            "precondition": "Agent invoked",
            "postcondition": "Task executed",
            "frame_axiom": ["read: workspace"],
            "forbidden_invariant": ["read: ~/.ssh"],
        }]

        evidence, _ = build_evidence_from_artifacts(
            artifacts_dir=str(art_dir),
            skill_dir="/app/skill",
            contracts_override=contracts,
        )

        assert evidence.run_kind == "agent"
        assert evidence.trajectory_present is True
        assert evidence.trajectory_units > 0
        assert "Starting evaluation." in evidence.agent_messages
        assert evidence.entry_kind == "agent"
        assert evidence.targets_contracts == ("C_01",)
        assert evidence.preconditions_satisfied is True
