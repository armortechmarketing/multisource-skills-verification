import os
import json
import re
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional

# UNVERIFIED — confirm against live Harbor: Trajectory Output Path Normalization for Real Agents

READ_TOOL_NAMES = {"read_file", "view", "cat", "open_file", "fileread", "read"}
EXEC_TOOL_NAMES = {"bash", "execute_command", "run_script", "terminal", "exec", "exec_command", "shell"}

def parse_aces_trajectory(
    trajectory_path: str,
    skill_package_dir: Optional[str] = None
) -> Tuple[bool, bool]:
    """
    Parses an ATIF RFC 0001 trajectory (from /logs/agent/trajectory.json)
    and computes the two deterministic ACES checks:
      1. activation: agent read the expected SKILL.md
      2. script_execution: agent invoked the expected script in a later step

    Returns:
        (activation: bool, script_execution: bool)
    """
    if not os.path.exists(trajectory_path):
        return False, False

    try:
        with open(trajectory_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return False, False

    steps = data.get("steps", [])
    if not isinstance(steps, list):
        return False, False

    # Find known bundled scripts in skill package
    bundled_scripts = []
    if skill_package_dir and os.path.exists(skill_package_dir):
        for root, _, files in os.walk(skill_package_dir):
            for file in files:
                if file.endswith((".py", ".sh", ".bash")):
                    rel_p = os.path.relpath(os.path.join(root, file), skill_package_dir).replace("\\", "/")
                    bundled_scripts.append(rel_p)
                    bundled_scripts.append(file)

    activation = False
    script_execution = False
    activation_step_idx = -1

    for idx, step in enumerate(steps):
        # Step source must be agent
        source = step.get("source", "").lower()
        if source not in ["agent", "assistant", "model"]:
            continue

        tool_calls = step.get("tool_calls", [])
        for tc in tool_calls:
            fname = tc.get("function_name", tc.get("name", "")).lower()
            args = tc.get("arguments", tc.get("args", {}))
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {"command": args, "path": args}

            target_path = str(args.get("path") or args.get("file_path") or "").replace("\\", "/")
            cmd_str = str(args.get("command") or args.get("cmd") or "")

            # Check 1: Activation
            if not activation:
                if fname in READ_TOOL_NAMES and (target_path.endswith("SKILL.md") or "skill.md" in target_path.lower()):
                    activation = True
                    activation_step_idx = idx
                elif fname in EXEC_TOOL_NAMES and "skill.md" in cmd_str.lower():
                    activation = True
                    activation_step_idx = idx

            # Check 2: Script execution (must occur at or after activation step)
            if activation and idx >= activation_step_idx and fname in EXEC_TOOL_NAMES:
                if bundled_scripts:
                    for bs in bundled_scripts:
                        if bs in cmd_str:
                            script_execution = True
                            break
                elif "scripts/" in cmd_str or ".py" in cmd_str or ".sh" in cmd_str:
                    script_execution = True

    return activation, script_execution
