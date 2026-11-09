import os
import re
import ast
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

def synthesize_placeholder_value(name: str, hint: str = "") -> str:
    """Synthesizes generic dummy values for CLI parameter placeholders."""
    name_lower = name.lower().strip("<>[]_-$")
    hint_lower = hint.lower().strip()

    if any(k in name_lower or k in hint_lower for k in ["path", "file", "dir", "folder", "dest", "src", "input", "output"]):
        return "/tmp/fixture.txt"
    if any(k in name_lower or k in hint_lower for k in ["int", "count", "num", "port", "limit", "max", "min", "size"]):
        return "1"
    if any(k in name_lower or k in hint_lower for k in ["repo", "repository", "owner"]):
        return "octocat/hello-world"
    if any(k in name_lower or k in hint_lower for k in ["url", "uri", "endpoint", "link"]):
        return "http://example.test/x"
    if any(k in name_lower or k in hint_lower for k in ["id", "uuid"]):
        return "test-id-001"
    if any(k in name_lower or k in hint_lower for k in ["email"]):
        return "user@example.test"
    if any(k in name_lower or k in hint_lower for k in ["date", "time"]):
        return "2026-01-01"
    if any(k in name_lower or k in hint_lower for k in ["subcommand", "command", "cmd", "action"]):
        return "run"
    return "lorem"

def extract_fenced_commands_from_skill_md(skill_md_path: str, skill_dest: str = "/workspace/skill_package") -> List[Dict[str, Any]]:
    """Extracts shell commands from SKILL.md fenced code blocks and synthesizes generic placeholders."""
    candidates = []
    if not os.path.exists(skill_md_path):
        return candidates

    try:
        content = Path(skill_md_path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return candidates

    # Match bash, sh, shell code blocks
    blocks = re.findall(r"```(?:bash|sh|shell|console|zsh)?\n([\s\S]*?)```", content, re.IGNORECASE)
    for block in blocks:
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if any(tool in line for tool in ["npm install", "pip install", "cd ", "docker build", "mkdir "]):
                continue

            # Path rewriting
            rewritten = line
            rewritten = re.sub(r"(?:python3?|bash|node)?\s*(?:\./)?scripts/", f"{skill_dest}/scripts/", rewritten)
            rewritten = re.sub(r"(?:\./)?bin/", f"{skill_dest}/bin/", rewritten)
            rewritten = rewritten.replace("/path/to/project", skill_dest).replace("/path/to/skill", skill_dest)

            # Placeholder replacement: e.g. <owner/repo>, [file], $VAR, {url}
            def _replace_placeholder(m):
                raw = m.group(0)
                name = m.group(1)
                return synthesize_placeholder_value(name)

            rewritten = re.sub(r"<([a-zA-Z0-9_\-/: ]+)>", _replace_placeholder, rewritten)
            rewritten = re.sub(r"\[([a-zA-Z0-9_\-/: ]+)\]", _replace_placeholder, rewritten)
            rewritten = re.sub(r"\{([a-zA-Z0-9_\-/: ]+)\}", _replace_placeholder, rewritten)

            candidates.append({
                "source": "fenced_skill_md",
                "raw_command": line,
                "synthesized_command": rewritten,
                "confidence": 0.95
            })
    return candidates

def extract_ast_argparse_schema(py_file_path: str) -> Optional[Dict[str, Any]]:
    """Analyzes Python AST to detect argparse, click, or typer schemas."""
    if not os.path.exists(py_file_path):
        return None

    try:
        code = Path(py_file_path).read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(code)
    except Exception:
        return None

    required_args = []
    options = []
    subcommands = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id

            # argparse add_argument
            if func_name == "add_argument":
                arg_names = []
                is_required = False
                nargs = None
                for a in node.args:
                    if isinstance(a, ast.Constant) and isinstance(a.value, str):
                        arg_names.append(a.value)
                for kw in node.keywords:
                    if kw.arg == "required" and isinstance(kw.value, ast.Constant):
                        is_required = bool(kw.value.value)
                    elif kw.arg == "nargs" and isinstance(kw.value, ast.Constant):
                        nargs = kw.value.value

                pos_args = [n for n in arg_names if not n.startswith("-")]
                flag_args = [n for n in arg_names if n.startswith("-")]

                if pos_args:
                    required_args.append({
                        "name": pos_args[0],
                        "type": "positional",
                        "synthesized": synthesize_placeholder_value(pos_args[0])
                    })
                elif is_required and flag_args:
                    longest_flag = max(flag_args, key=len)
                    required_args.append({
                        "name": longest_flag,
                        "type": "flag_required",
                        "synthesized": synthesize_placeholder_value(longest_flag)
                    })
                elif flag_args:
                    options.append(flag_args[-1])

            # click or typer
            elif func_name in ["command", "Typer", "option", "argument"]:
                if func_name == "argument":
                    for a in node.args:
                        if isinstance(a, ast.Constant) and isinstance(a.value, str):
                            required_args.append({
                                "name": a.value,
                                "type": "click_argument",
                                "synthesized": synthesize_placeholder_value(a.value)
                            })

    if required_args or options:
        synthesized_argv = []
        for r in required_args:
            if r["type"] == "flag_required":
                synthesized_argv.extend([r["name"], r["synthesized"]])
            else:
                synthesized_argv.append(r["synthesized"])
        return {
            "required_args": required_args,
            "options": options,
            "synthesized_argv": synthesized_argv
        }
    return None

def plan_skill_invocations(
    skill_dir: str,
    target_container_dir: str = "/workspace/skill_package"
) -> Dict[str, Any]:
    """
    Comprehensive entry and invocation discovery producing invocation_plan.json.
    Discovers:
    - SKILL.md fenced commands
    - .py, .sh, .js in root, scripts/, bin/
    - package.json scripts / bin
    - MCP server entries
    - AST-based parameter synthesis
    """
    plan: Dict[str, Any] = {
        "ranked_candidates": [],
        "runnable_entries": [],
        "has_package_json": False,
        "is_instruction_only": False,
        "has_mcp_entry": False
    }

    # 1. Inspect package.json
    pkg_json_p = os.path.join(skill_dir, "package.json")
    if os.path.isfile(pkg_json_p):
        plan["has_package_json"] = True
        try:
            with open(pkg_json_p, "r", encoding="utf-8") as f:
                pkg_data = json.load(f)
            bin_entry = pkg_data.get("bin")
            if isinstance(bin_entry, str):
                plan["runnable_entries"].append({"path": bin_entry, "type": "node_bin"})
            elif isinstance(bin_entry, dict):
                for b_k, b_v in bin_entry.items():
                    plan["runnable_entries"].append({"path": b_v, "type": "node_bin", "name": b_k})
            scripts_entry = pkg_data.get("scripts", {})
            for s_name in ["start", "run", "main"]:
                if s_name in scripts_entry:
                    plan["ranked_candidates"].append({
                        "order": 2,
                        "type": "npm_script",
                        "command": f"npm run {s_name}",
                        "provenance": "package.json scripts",
                        "confidence": 0.90
                    })
        except Exception:
            pass

    # 2. Discover files
    valid_exts = (".py", ".sh", ".js")
    for root, _, files in os.walk(skill_dir):
        for fn in sorted(files):
            if any(fn.endswith(ext) for ext in valid_exts):
                rel = os.path.relpath(os.path.join(root, fn), skill_dir).replace("\\", "/")
                is_mcp = "mcp" in fn.lower() or "server" in fn.lower()
                if is_mcp:
                    plan["has_mcp_entry"] = True
                plan["runnable_entries"].append({
                    "path": rel,
                    "filename": fn,
                    "is_mcp": is_mcp
                })

    # 3. Fenced shell commands in SKILL.md
    skill_md = os.path.join(skill_dir, "SKILL.md")
    fenced_cmds = extract_fenced_commands_from_skill_md(skill_md, target_container_dir)
    for c in fenced_cmds:
        plan["ranked_candidates"].append({
            "order": 1,
            "type": "fenced_skill_md",
            "command": c["synthesized_command"],
            "raw_command": c["raw_command"],
            "provenance": "SKILL.md fenced code block",
            "confidence": c["confidence"]
        })

    # 4. AST schema extraction for top python files
    for entry in plan["runnable_entries"]:
        if entry["path"].endswith(".py"):
            full_path = os.path.join(skill_dir, entry["path"])
            schema = extract_ast_argparse_schema(full_path)
            if schema:
                cmd_parts = ["python3", f"{target_container_dir}/{entry['path']}"] + schema["synthesized_argv"]
                plan["ranked_candidates"].append({
                    "order": 3,
                    "type": "ast_argparse_schema",
                    "entry_path": entry["path"],
                    "argv": schema["synthesized_argv"],
                    "command": " ".join(cmd_parts),
                    "provenance": "AST ArgumentParser/Click/Typer inspection",
                    "confidence": 0.85
                })

    # 5. Default direct entry execution candidates
    for entry in plan["runnable_entries"]:
        rel = entry["path"]
        base_fn = os.path.basename(rel)
        if base_fn in ["main.py", "run.py", "agent.py", "server.py", "index.js", "main.sh", "run.sh"]:
            interp = "python3" if rel.endswith(".py") else ("bash" if rel.endswith(".sh") else "node")
            cmd = f"{interp} {target_container_dir}/{rel}"
            plan["ranked_candidates"].append({
                "order": 4,
                "type": "standard_named_entry",
                "entry_path": rel,
                "command": cmd,
                "provenance": "standard entrypoint name",
                "confidence": 0.80
            })

    # 6. Fallback candidates
    if not plan["ranked_candidates"] and plan["runnable_entries"]:
        first = plan["runnable_entries"][0]["path"]
        interp = "python3" if first.endswith(".py") else ("bash" if first.endswith(".sh") else "node")
        plan["ranked_candidates"].append({
            "order": 5,
            "type": "fallback_first_runnable",
            "entry_path": first,
            "command": f"{interp} {target_container_dir}/{first}",
            "provenance": "first runnable file discovered",
            "confidence": 0.60
        })

    if not plan["runnable_entries"]:
        plan["is_instruction_only"] = True

    # Sort candidates by order
    plan["ranked_candidates"].sort(key=lambda x: (x.get("order", 99), -x.get("confidence", 0)))
    return plan
