import ast
import base64
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


def load_env() -> None:
    for env_path in [".env", os.path.join(os.path.dirname(__file__), "..", ".env")]:
        if os.path.exists(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            os.environ[k.strip()] = v.strip()
                break
            except Exception:
                pass


load_env()

_PROTECTED_HOME_DOTFILES = {
    "~/.ssh",
    "~/.ssh/id_rsa",
    "~/.aws",
    "~/.aws/credentials",
    "~/.env",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.zshrc",
}


def _normalize_example_token(tok: str) -> str:
    """Resolve `<placeholder>`, `{placeholder}`, and `choiceA|choiceB` tokens in CLI examples into concrete test values."""
    clean = tok.strip("'\"")
    if ("$(pwd)" in clean or "${PWD}" in clean or "$PWD" in clean or "{ws}" in clean or "{workspace}" in clean or "{project_slug}" in clean or "{user_cwd}" in clean):
        return "/tmp/test_workspace"
    if clean.startswith("<") and clean.endswith(">"):
        inner = clean[1:-1].lower()
        if "xhtml" in inner or "html" in inner:
            return "input_1.xhtml"
        if any(k in inner for k in ("dir", "path", "folder", "workspace", "root", "task-dir")):
            return "/tmp/test_workspace"
        if "json" in inner:
            return "input_1.json"
        if "csv" in inner:
            return "input_1.csv"
        if "yaml" in inner or "yml" in inner:
            return "input_1.yaml"
        if any(k in inner for k in ("commit", "hash", "ref")):
            return "HEAD"
        if inner in ("n", "num", "count", "stage", "tier"):
            return "1"
        return "sample_skill"
    if clean.startswith("{") and clean.endswith("}"):
        inner = clean[1:-1].lower()
        if inner in ("n", "num", "count", "stage", "stage_num", "tier"):
            return "1"
        if any(k in inner for k in ("ws", "workspace", "dir", "path", "folder", "slug")):
            return "/tmp/test_workspace"
        if "json" in inner or "result" in inner:
            return '{"status":"PASS"}'
        return "sample_val"
    if re.search(r"\{[a-zA-Z0-9_\-]+\}", clean):
        clean = re.sub(r"\{(?:N|stage|stage_num|tier)\}", "1", clean)
        clean = re.sub(r"\{[a-zA-Z0-9_\-]+\}", "sample_val", clean)
    if "|" in clean and not clean.startswith("-"):
        return clean.split("|")[0]
    if clean.startswith("/") and not clean.startswith(("/tmp", "/app", "/var/tmp", "/dev")):
        return "/tmp/test_workspace" + clean
    return clean


def extract_markdown_code_examples(
    declaration_text: str,
    entry_script_name: str = "",
    help_text: str = "",
) -> List[List[str]]:
    """Extract CLI invocation argv examples from script docstrings and SKILL.md fenced bash/sh code blocks."""
    import shlex

    examples: List[List[str]] = []
    candidate_blocks: List[str] = []
    if help_text:
        candidate_blocks.append(help_text)
    if declaration_text:
        candidate_blocks.extend(
            re.findall(r"```(?:bash|sh|shell|console|zsh)?\r?\n([\s\S]*?)```", declaration_text, re.IGNORECASE)
        )

    for block in candidate_blocks:
        joined_block = re.sub(r"\\\s*\r?\n\s*", " ", block)
        for raw_line in joined_block.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            # Strip leading `Usage:` prefix if present in docstring
            if line.lower().startswith("usage:"):
                line = line[6:].strip()
            # Strip leading `cd <dir> &&`
            m_cd = re.match(r"^cd\s+\S+\s*(?:&&|;)\s*(.+)$", line)
            if m_cd:
                line = m_cd.group(1).strip()
            try:
                parts = shlex.split(line)
            except Exception:
                parts = line.split()
            if not parts:
                continue
            if parts[0] in ("python", "python3", "bash", "sh", "node"):
                parts = parts[1:]
            if not parts:
                continue
            first = parts[0].replace("\\", "/")
            if first.endswith((".py", ".sh", ".js", ".mjs")):
                if entry_script_name and os.path.basename(first) != entry_script_name:
                    continue
                parts = parts[1:]
                # Clean out shell redirections (`> out.txt`) and bracketed optional placeholders `[-h]`
                clean_args: List[str] = []
                skip_next = False
                for p in parts:
                    if skip_next:
                        skip_next = False
                        continue
                    if p in (">", ">>", "<", "|", "2>&1"):
                        skip_next = True
                        continue
                    if p.startswith((">", "<")) and not p.endswith(">"):
                        continue
                    if p.startswith("[") and p.endswith("]"):
                        continue
                    norm_tok = _normalize_example_token(p)
                    if norm_tok in ("-h", "--help"):
                        continue
                    clean_args.append(norm_tok)
                if clean_args and clean_args[0] != "record_validation":
                    if clean_args not in examples:
                        examples.append(clean_args)
    examples.sort(key=lambda ex: 0 if (ex and ex[0] == "init") else 1)
    return examples


def probe_script_help(script_path: str) -> str:
    """Statically extract docstring / usage banner from script source without executing untrusted code on the host (R2)."""
    if not script_path or not os.path.exists(script_path):
        return ""
    try:
        text = Path(script_path).read_text(encoding="utf-8", errors="ignore")
        if script_path.endswith(".py"):
            tree = ast.parse(text, filename=script_path)
            doc = ast.get_docstring(tree) or ""
            return doc
        lines = [line.lstrip("# ").strip() for line in text.splitlines()[:40] if line.strip().startswith("#")]
        return "\n".join(lines)
    except Exception:
        return ""


def parse_help_output(help_text: str) -> Dict[str, Any]:
    """Extract subcommands and required flags from `--help` usage output."""
    info: Dict[str, Any] = {"subcommands": [], "required_flags": [], "optional_flags": []}
    if not help_text:
        return info
    # Subcommands inside `{sub1,sub2,...}`
    for m in re.finditer(r"\{([a-zA-Z0-9_,\-]+)\}", help_text):
        subs = [s.strip() for s in m.group(1).split(",") if s.strip()]
        if len(subs) >= 2:
            for s in subs:
                if s not in info["subcommands"]:
                    info["subcommands"].append(s)
    # Required flags in usage line: `usage: script.py [-h] --input INPUT [--opt OPT]`
    usage_m = re.search(r"usage:\s+[^\n]+(?:\n\s+[^\n]+)*", help_text, re.IGNORECASE)
    if usage_m:
        usage_block = usage_m.group(0)
        # Remove bracketed optional groups `[...]`
        stripped = re.sub(r"\[[^\]]*\]", "", usage_block)
        for fm in re.finditer(r"(--[a-zA-Z0-9\-_]+)(?:\s+([A-Z0-9_]+))?", stripped):
            flag = fm.group(1)
            takes_val = bool(fm.group(2))
            info["required_flags"].append({"flag": flag, "takes_value": takes_val})
    return info


def identify_entry_point_script(skill_dir: str, contracts: Optional[List[Dict[str, Any]]] = None) -> Optional[str]:
    """Identify the primary runnable script in `skill_dir`."""
    from src.adapters.skills_adapter import extract_entry_point_and_cwd

    ep, _, is_instr = extract_entry_point_and_cwd(skill_dir, contracts)
    if is_instr or not ep:
        return None
    cand = os.path.join(skill_dir, ep)
    if os.path.isfile(cand):
        return cand
    cand2 = os.path.join(skill_dir, "scripts", ep)
    if os.path.isfile(cand2):
        return cand2
    return None


def extract_cli_schema_from_ast(script_path: str) -> Dict[str, Any]:
    """Statically analyze a script using AST + `--help` to extract its CLI interface and file requirements (`H5`)."""
    schema: Dict[str, Any] = {
        "script_name": os.path.basename(script_path) if script_path else "",
        "script_path": script_path,
        "parser_type": None,
        "subcommands": [],
        "positionals": [],
        "options": [],
        "required_relative_files": [],
        "home_config_reads": [],
        "uses_base64_decode": False,
        "expects_xhtml": False,
        "required_md_headings": [],
        "ast_is_stub": False,
        "script_code": "",
        "help_text": "",
    }
    if not script_path or not os.path.isfile(script_path):
        return schema

    help_text = probe_script_help(script_path)
    schema["help_text"] = help_text[:2000]
    help_info = parse_help_output(help_text)
    for sub in help_info.get("subcommands", []):
        if sub not in schema["subcommands"]:
            schema["subcommands"].append(sub)

    try:
        raw_code = Path(script_path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        raw_code = ""
    schema["script_code"] = raw_code[:20000]

    if "Cargo.toml" in raw_code and "Cargo.toml" not in schema["required_relative_files"]:
        schema["required_relative_files"].append("Cargo.toml")

    if script_path.endswith(".sh"):
        schema["parser_type"] = "shell"
        # Detect `Either (--flagA) or (--flagB) ... is required`
        either_req_flags: Set[str] = set()
        for m_either in re.finditer(r"Either\s*\(?(--[a-zA-Z0-9\-_]+)\)?\s*or\s*\(?(--[a-zA-Z0-9\-_]+)\)?[^\n]*?\bis\s*required", raw_code, re.IGNORECASE):
            either_req_flags.add(m_either.group(1))
        # Parse case branches for flags (both single-line and multi-line)
        for m_case in re.finditer(r"^\s*(--[a-zA-Z0-9\-_|]+)\)\s*([\s\S]*?);;", raw_code, re.MULTILINE):
            raw_flags = [f.strip() for f in m_case.group(1).split("|") if f.strip().startswith("-")]
            branch_body = m_case.group(2)
            takes_val = ("$2" in branch_body) or ("shift 2" in branch_body)
            is_req = any(f in either_req_flags for f in raw_flags)
            if raw_flags and raw_flags[0] not in ("-h", "--help"):
                schema["options"].append({
                    "flags": raw_flags,
                    "required": is_req,
                    "action": None if takes_val else "store_true",
                    "subcommand": None,
                })
        for ef in sorted(either_req_flags):
            if not any(ef in o.get("flags", []) for o in schema["options"]):
                schema["options"].append({
                    "flags": [ef],
                    "required": True,
                    "action": None,
                    "subcommand": None,
                })
        # Detect positional requirement in shell scripts when no required flags exist
        if not any(o.get("required") for o in schema["options"]):
            if re.search(r"\[\[?\s*\$#\s*-(?:lt|eq)\s*[01]\b|\[\s*-z\s*\"\$1\"\s*\]|Usage:.*(?:<[A-Za-z0-9_\-]+>|OWNER/REPO)", raw_code):
                if "OWNER/REPO" in raw_code:
                    pos_name = "owner_repo"
                elif "COMMIT" in raw_code.upper():
                    pos_name = "commit_hash"
                else:
                    pos_name = "arg_1"
                schema["positionals"].append({
                    "name": pos_name,
                    "required": True,
                    "subcommand": None,
                })
        return schema

    if script_path.endswith((".js", ".mjs")):
        schema["parser_type"] = "node"
        if "process.argv" in raw_code:
            pos_name = "html_path" if ("index.html" in raw_code or ".html" in raw_code) else ("dir" if "isDirectory" in raw_code else "arg_1")
            schema["positionals"].append({
                "name": pos_name,
                "required": True,
                "subcommand": None,
            })
        return schema

    if not script_path.endswith(".py"):
        return schema

    from src.adapters.skills_adapter import detect_ast_is_stub
    schema["ast_is_stub"] = detect_ast_is_stub(script_path)

    try:
        code = raw_code
        tree = ast.parse(code, filename=script_path)
    except Exception as e:
        schema["error"] = f"Failed to parse AST: {e}"
        return schema

    if "b64decode" in code:
        schema["uses_base64_decode"] = True
    if ".xhtml" in code or "HTMLParser" in code:
        schema["expects_xhtml"] = True
    for m_hd in re.finditer(r"['\"](##+\s+[^'\n\"]+)['\"]", code):
        hd = m_hd.group(1).strip()
        if hd not in schema["required_md_headings"]:
            schema["required_md_headings"].append(hd)

    def eval_node(node: Optional[ast.AST]) -> Any:
        if node is None:
            return None
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.List):
            return [eval_node(el) for el in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(eval_node(el) for el in node.elts)
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{eval_node(node.value)}.{node.attr}"
        return None

    has_parser = False
    subparser_vars: Dict[str, str] = {}

    # Pre-pass: map subparser variable assignments `sub_p = subparsers.add_parser("name")`
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            f_name = node.value.func.attr if isinstance(node.value.func, ast.Attribute) else (
                node.value.func.id if isinstance(node.value.func, ast.Name) else ""
            )
            if f_name == "add_parser" and node.value.args:
                s_name = eval_node(node.value.args[0])
                if isinstance(s_name, str):
                    for t in node.targets:
                        if isinstance(t, ast.Name):
                            subparser_vars[t.id] = s_name

    # Inspect module-level constants like REQUIRED_FILES = [...]
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and "REQUIRED" in target.id.upper() and "FILE" in target.id.upper():
                    val = eval_node(node.value)
                    if isinstance(val, (list, tuple)):
                        for item in val:
                            if isinstance(item, str) and not item.startswith("/") and ".." not in item:
                                schema["required_relative_files"].append(item)

        if isinstance(node, ast.Call):
            func_name = ""
            caller_var = ""
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
                if isinstance(node.func.value, ast.Name):
                    caller_var = node.func.value.id
            elif isinstance(node.func, ast.Name):
                func_name = node.func.id

            # Detect expanduser("~/.config_name") reads (excluding protected honeypots/shell rc)
            if func_name == "expanduser" and node.args:
                arg0 = eval_node(node.args[0])
                if isinstance(arg0, str) and arg0.startswith("~/"):
                    if arg0 not in _PROTECTED_HOME_DOTFILES and not any(
                        arg0.startswith(p + "/") for p in _PROTECTED_HOME_DOTFILES
                    ):
                        if arg0 not in schema["home_config_reads"]:
                            schema["home_config_reads"].append(arg0)

            if func_name in ("ArgumentParser", "add_subparsers"):
                has_parser = True
                schema["parser_type"] = "argparse"

            elif func_name == "add_parser":
                has_parser = True
                schema["parser_type"] = "argparse"
                if node.args:
                    sub_name = eval_node(node.args[0])
                    if isinstance(sub_name, str) and sub_name not in schema["subcommands"]:
                        schema["subcommands"].append(sub_name)

            elif func_name == "add_argument":
                has_parser = True
                schema["parser_type"] = schema["parser_type"] or "argparse"
                subcmd_scope = subparser_vars.get(caller_var)
                arg_names: List[str] = []
                for a in node.args:
                    val = eval_node(a)
                    if isinstance(val, str):
                        arg_names.append(val)

                kwargs: Dict[str, Any] = {}
                for kw in node.keywords:
                    if kw.arg:
                        kwargs[kw.arg] = eval_node(kw.value)

                flags = [a for a in arg_names if a.startswith("-")]
                positionals = [a for a in arg_names if not a.startswith("-")]

                for pos in positionals:
                    nargs = kwargs.get("nargs")
                    req = kwargs.get("required", nargs not in ("?", "*"))
                    schema["positionals"].append({
                        "name": pos,
                        "required": bool(req),
                        "nargs": nargs,
                        "type": str(kwargs.get("type")) if kwargs.get("type") else None,
                        "choices": kwargs.get("choices"),
                        "default": kwargs.get("default"),
                        "help": kwargs.get("help"),
                        "subcommand": subcmd_scope,
                    })
                if flags:
                    schema["options"].append({
                        "flags": flags,
                        "required": bool(kwargs.get("required", False)),
                        "type": str(kwargs.get("type")) if kwargs.get("type") else None,
                        "choices": kwargs.get("choices"),
                        "default": kwargs.get("default"),
                        "action": kwargs.get("action"),
                        "help": kwargs.get("help"),
                        "subcommand": subcmd_scope,
                    })

            # Click / Typer support
            elif func_name == "option":
                has_parser = True
                schema["parser_type"] = schema["parser_type"] or "click"
                flags = [eval_node(a) for a in node.args if isinstance(eval_node(a), str) and str(eval_node(a)).startswith("-")]
                kwargs = {kw.arg: eval_node(kw.value) for kw in node.keywords if kw.arg}
                if flags:
                    schema["options"].append({
                        "flags": flags,
                        "required": bool(kwargs.get("required", False)),
                        "type": str(kwargs.get("type")) if kwargs.get("type") else None,
                        "default": kwargs.get("default"),
                        "action": "store_true" if kwargs.get("is_flag") else None,
                        "help": kwargs.get("help"),
                        "subcommand": None,
                    })
            elif func_name == "argument":
                has_parser = True
                schema["parser_type"] = schema["parser_type"] or "click"
                pos_names = [eval_node(a) for a in node.args if isinstance(eval_node(a), str) and not str(eval_node(a)).startswith("-")]
                kwargs = {kw.arg: eval_node(kw.value) for kw in node.keywords if kw.arg}
                for p in pos_names:
                    schema["positionals"].append({
                        "name": p,
                        "required": bool(kwargs.get("required", True)),
                        "type": str(kwargs.get("type")) if kwargs.get("type") else None,
                        "default": kwargs.get("default"),
                        "subcommand": None,
                    })

    # Merge any required flags discovered from --help that weren't marked required in AST
    existing_opt_flags = {f for o in schema["options"] for f in o.get("flags", [])}
    for rf in help_info.get("required_flags", []):
        flag = rf["flag"]
        if flag not in existing_opt_flags:
            schema["options"].append({
                "flags": [flag],
                "required": True,
                "action": None if rf.get("takes_value", True) else "store_true",
                "subcommand": None,
            })

    if not has_parser:
        argv_indices: List[int] = []
        argv_names: Dict[int, str] = {}
        argv_literals: Dict[int, str] = {}
        types_map: Dict[int, str] = {}

        def _get_argv_idx(n: ast.AST) -> Optional[int]:
            if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Attribute) and n.value.attr == "argv":
                val = eval_node(n.slice)
                if isinstance(val, int) and val >= 1:
                    return val
            return None

        for node in ast.walk(tree):
            idx = _get_argv_idx(node)
            if idx is not None:
                argv_indices.append(idx)

            # Check `len(sys.argv) < N`
            if isinstance(node, ast.Compare) and isinstance(node.left, ast.Call):
                if isinstance(node.left.func, ast.Name) and node.left.func.id == "len" and node.left.args:
                    arg0 = node.left.args[0]
                    if isinstance(arg0, ast.Attribute) and arg0.attr == "argv" and node.comparators:
                        comp_val = eval_node(node.comparators[0])
                        if isinstance(comp_val, int) and comp_val >= 2:
                            if any(isinstance(op, (ast.Lt, ast.NotEq)) for op in node.ops):
                                argv_indices.append(comp_val - 1)

            # Check `var = sys.argv[i]`
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                s_idx = _get_argv_idx(node.value)
                if s_idx is not None:
                    argv_names[s_idx] = node.targets[0].id

            # Check `sys.argv[i] != '--path'` or `sys.argv[i] == '--path'`
            if isinstance(node, ast.Compare) and node.comparators:
                s_idx = _get_argv_idx(node.left)
                c_val = eval_node(node.comparators[0])
                if s_idx is not None and isinstance(c_val, str) and c_val:
                    argv_literals[s_idx] = c_val

        name_to_idx = {v: k for k, v in argv_names.items()}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                f_id = node.func.id if isinstance(node.func, ast.Name) else (
                    node.func.attr if isinstance(node.func, ast.Attribute) else ""
                )
                if f_id in ("int", "float", "str") and node.args:
                    s_idx = _get_argv_idx(node.args[0])
                    if s_idx is None and isinstance(node.args[0], ast.Name):
                        s_idx = name_to_idx.get(node.args[0].id)
                    if s_idx is not None:
                        types_map[s_idx] = f_id
                elif f_id == "loads" and node.args:
                    s_idx = _get_argv_idx(node.args[0])
                    if s_idx is None and isinstance(node.args[0], ast.Name):
                        s_idx = name_to_idx.get(node.args[0].id)
                    if s_idx is not None:
                        types_map[s_idx] = "json_str"

        if argv_indices:
            schema["parser_type"] = "sys.argv"
            max_idx = max(argv_indices)
            for i in range(1, max_idx + 1):
                schema["positionals"].append({
                    "name": argv_names.get(i, f"arg_{i}"),
                    "index": i,
                    "type": types_map.get(i, "str"),
                    "literal": argv_literals.get(i),
                    "required": True,
                    "subcommand": None,
                })

    return schema


def synthesize_mock_file_content(filename: str) -> str:
    """Synthesize well-formed content based on file extension or name."""
    lower = filename.lower()
    if lower.endswith("cargo.toml"):
        return '[package]\nname = "sample_pkg"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n'
    if lower.endswith((".xhtml", ".html", ".htm")):
        return (
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<!DOCTYPE html>\n'
            '<html xmlns="http://www.w3.org/1999/xhtml"><head><title>Sample</title></head>'
            '<body><h1>Chapter 1</h1><p>Sample paragraph content for verification.</p></body></html>\n'
        )
    if lower.endswith(".json"):
        return json.dumps({"id": 1, "name": "sample", "status": "active", "items": [{"id": 1, "value": "test"}]}, indent=2) + "\n"
    if lower.endswith(".jsonl"):
        return '{"id": 1, "type": "user", "message": {"content": "hello world"}}\n'
    if lower.endswith(".csv"):
        return "id,name,value\n1,Alice,10\n2,Bob,20\n"
    if lower.endswith(".tsv"):
        return "id\tname\tvalue\n1\tAlice\t10\n2\tBob\t20\n"
    if lower.endswith((".yaml", ".yml")):
        return "version: '3.8'\nname: sample\nservices:\n  app:\n    image: alpine\n"
    if lower.endswith((".xml", ".ghx")):
        return '<?xml version="1.0" encoding="utf-8"?>\n<Archive><chunk name="DefinitionObjects"><chunks></chunks></chunk></Archive>\n'
    if lower.endswith(".md"):
        return "# Document\n\nStatus: completed\n"
    if lower.endswith(".gitignore"):
        return "__pycache__/\n*.pyc\n.env\n"
    return "Sample input content for verification.\n"


def _is_valid_concrete_write_target(
    clean_w: str,
    cli_args: List[str],
    script_code: str = "",
    ast_is_stub: bool = True,
) -> bool:
    """Return True only if `clean_w` is a concrete file path (no templates/placeholders) relevant to the entry script."""
    if not clean_w or clean_w.lower() in ("none", "false", "stdout", "stderr", "null", "n/a"):
        return False
    if any(ch in clean_w for ch in ("*", "?", "<", ">", "{", "}", "$", ",", "\\", ":", ";", "|")):
        return False
    if any(tok in clean_w for tok in ("YYYY", "MM-DD", "HH-MM", "timestamp")):
        return False
    if clean_w.endswith("/"):
        return False
    base = os.path.basename(clean_w)
    if "." not in base or base.startswith("."):
        return False
    if not ast_is_stub and script_code:
        if base not in script_code and clean_w not in cli_args:
            return False
    return True


def synthesize_checks_for_contract(
    contract: Dict[str, Any],
    cli_args: List[str],
    script_code: str = "",
    ast_is_stub: bool = True,
) -> List[Dict[str, Any]]:
    """Synthesize deterministic `Check` objects (`exit_code`, `file_exists`, etc.) for a contract (`H5`)."""
    cid = str(contract.get("contract_id") or contract.get("id") or "C_01")
    checks: List[Dict[str, Any]] = []
    seen_ids: Set[str] = set()

    # 1. Preserve any explicit checks already present on the contract
    for idx, chk in enumerate(contract.get("checks") or [], 1):
        if isinstance(chk, dict) and chk.get("kind"):
            c_copy = dict(chk)
            c_copy.setdefault("id", f"{cid}_chk_{idx}")
            c_copy.setdefault("contract_id", cid)
            seen_ids.add(c_copy["id"])
            checks.append(c_copy)

    # 2. If CLI args specify `--output <file>` or `-o <file>`, add file_exists check if not already covered
    for i, arg in enumerate(cli_args):
        if arg in ("-o", "--output", "--out", "--out-file") and i + 1 < len(cli_args):
            out_p = cli_args[i + 1]
            if out_p and not out_p.startswith("-") and "*" not in out_p:
                chk_id = f"{cid}_file_exists_cli"
                if chk_id not in seen_ids and not any(c.get("kind") == "file_exists" for c in checks):
                    seen_ids.add(chk_id)
                    checks.append({
                        "id": chk_id,
                        "contract_id": cid,
                        "kind": "file_exists",
                        "expect": {"path": out_p},
                    })

    # 3. Inspect contract frame_axiom.write for concrete (non-glob, non-template) output filenames
    raw_fa = contract.get("frame_axiom", {})
    write_items: List[str] = []
    if isinstance(raw_fa, dict):
        write_items.extend(str(x) for x in (raw_fa.get("write") or []))
    elif isinstance(raw_fa, list):
        for item in raw_fa:
            s = str(item).strip()
            if s.lower().startswith("write:"):
                write_items.append(s.split(":", 1)[1].strip())
    for w_item in write_items:
        clean_w = w_item.strip().strip("'\"")
        if _is_valid_concrete_write_target(clean_w, cli_args, script_code=script_code, ast_is_stub=ast_is_stub):
            chk_id = f"{cid}_file_exists_{os.path.basename(clean_w)}"
            if chk_id not in seen_ids and not any(c.get("kind") == "file_exists" for c in checks):
                seen_ids.add(chk_id)
                checks.append({
                    "id": chk_id,
                    "contract_id": cid,
                    "kind": "file_exists",
                    "expect": {"path": clean_w},
                })

    # 3b. Inspect postcondition for explicit quoted strings or stdout/output claims
    post_text = str(contract.get("postcondition") or contract.get("expected_postcondition") or "")
    has_substantive = any(c.get("kind") != "exit_code" for c in checks)
    if not has_substantive and post_text:
        for q_match in re.findall(r"['\"`]([^'\"`\r\n]{3,60})['\"`]", post_text):
            cand_lit = q_match.strip()
            if (
                cand_lit
                and not cand_lit.startswith(("/", "~", ".", "-"))
                and (not script_code or cand_lit in script_code)
            ):
                chk_id = f"{cid}_text_contains"
                if chk_id not in seen_ids:
                    seen_ids.add(chk_id)
                    checks.append({
                        "id": chk_id,
                        "contract_id": cid,
                        "kind": "text_contains",
                        "expect": {"text": cand_lit},
                    })
                    has_substantive = True
                    break
        if not has_substantive and any(
            kw in post_text.lower()
            for kw in ("stdout", "output", "print", "display", "log", "report", "message", "status")
        ):
            if not script_code or any(tok in script_code for tok in ("print(", "echo ", "printf ", "sys.stdout", "console.log")):
                chk_id = f"{cid}_stdout_nonempty"
                if chk_id not in seen_ids:
                    seen_ids.add(chk_id)
                    checks.append({
                        "id": chk_id,
                        "contract_id": cid,
                        "kind": "stdout_regex",
                        "expect": {"pattern": r"\S+"},
                    })

    # 4. Always ensure exit_code == 0 check is present unless another exit_code check is defined
    if not any(c.get("kind") == "exit_code" for c in checks):
        checks.append({
            "id": f"{cid}_exit_0",
            "contract_id": cid,
            "kind": "exit_code",
            "expect": 0,
        })

    return checks


SECRET_FLAG_PATTERNS = re.compile(
    r"^--(api[-_]?key|token|auth[-_]?token|secret|access[-_]?key|password|api[-_]?secret)$",
    re.IGNORECASE,
)
PASSIVE_FLAG_PATTERNS = re.compile(
    r"^--(dry[-_]?run|simulate|check[-_]?only|dryrun|no[-_]?op|noop|validate[-_]?only|test[-_]?only)$",
    re.IGNORECASE,
)
PLACEHOLDER_PATTERNS = re.compile(
    r"(\bpath/to/|\<[a-zA-Z0-9_\-]+\>|\{[a-zA-Z0-9_\-]+\}|\byour[-_][a-zA-Z0-9_\-]+)",
    re.IGNORECASE,
)


def compute_deterministic_test_case_fields(
    tc: Dict[str, Any],
    cli_schema: Optional[Dict[str, Any]],
    skill_dir: str,
    contracts: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Sanitize CLI arguments and compute deterministic test case metadata interface fields (B6, B7, B8)."""
    raw_args = list(tc.get("cli_args") or [])
    mock_files = dict(tc.get("mock_files") or {})

    sanitized_args: List[str] = []
    flags_used: List[str] = []
    passive_flags_used: List[str] = []
    placeholder_detected = False

    skip_next = False
    for i, tok in enumerate(raw_args):
        if skip_next:
            skip_next = False
            continue

        tok_str = str(tok)

        # Check for secret flags (B7a)
        if SECRET_FLAG_PATTERNS.match(tok_str) or tok_str in ("-k",):
            if i + 1 < len(raw_args) and not str(raw_args[i + 1]).startswith("-"):
                skip_next = True
            continue

        # Check for passive flags (B7b)
        if PASSIVE_FLAG_PATTERNS.match(tok_str):
            passive_flags_used.append(tok_str)
            continue

        # Check for placeholder tokens (B7d)
        if PLACEHOLDER_PATTERNS.search(tok_str):
            placeholder_detected = True
            tok_str = re.sub(r"path/to/([a-zA-Z0-9_.\-]+)", r"input_1.\1", tok_str)
            tok_str = re.sub(r"\<[a-zA-Z0-9_\-]+\>", "input_1.txt", tok_str)
            tok_str = re.sub(r"\{[a-zA-Z0-9_\-]+\}", "input_1.txt", tok_str)
            tok_str = re.sub(r"your[-_][a-zA-Z0-9_\-]+", "sample_val", tok_str)

        if tok_str.startswith("-"):
            flags_used.append(tok_str.split("=")[0])

        sanitized_args.append(tok_str)

    # Validate against cli_schema choices (B7c)
    if cli_schema and cli_schema.get("options"):
        opt_map = {}
        for opt in cli_schema["options"]:
            for f in opt.get("flags", []):
                opt_map[f] = opt

        for i, a in enumerate(sanitized_args):
            if a in opt_map and i + 1 < len(sanitized_args):
                opt_info = opt_map[a]
                choices = opt_info.get("choices")
                val = sanitized_args[i + 1]
                if choices and isinstance(choices, (list, tuple)) and str(val) not in [str(c) for c in choices]:
                    sanitized_args[i + 1] = str(choices[0])

    # Ensure mock files exist for file arguments (B7e)
    for idx_a, a in enumerate(sanitized_args):
        prev = sanitized_args[idx_a - 1] if idx_a > 0 else ""
        if prev in ("-o", "--output", "--out", "--out-file"):
            continue
        if not a.startswith("-") and "." in os.path.basename(a) and not a.startswith(("http://", "https://", "/tmp", "/dev")):
            if a not in mock_files:
                mock_files[a] = synthesize_mock_file_content(a)

    tc["cli_args"] = sanitized_args
    tc["mock_files"] = mock_files

    has_script = bool(cli_schema and cli_schema.get("script_path"))
    entry_kind = "cli" if has_script else "agent"
    tc["entry_kind"] = entry_kind
    if not has_script:
        tc["cli_args"] = []
        tc["entry_point"] = "SKILL.md"
    elif not tc.get("entry_point"):
        tc["entry_point"] = os.path.relpath(cli_schema["script_path"], skill_dir).replace("\\", "/")

    c_ids: List[str] = []
    if tc.get("contract_id"):
        c_ids.append(str(tc["contract_id"]))
    if tc.get("contract_ids"):
        c_ids.extend(str(x) for x in tc["contract_ids"])
    if not c_ids and contracts:
        c_ids = [str(c.get("contract_id") or c.get("id") or "C_01") for c in contracts]
    tc["targets_contracts"] = sorted(list(dict.fromkeys(c_ids))) if c_ids else ["C_01"]

    tc["preconditions_satisfied"] = True
    tc["flags_used"] = flags_used
    tc["passive_flags_used"] = passive_flags_used
    tc["placeholder_inputs_used"] = placeholder_detected
    tc["secret_args_used"] = any(SECRET_FLAG_PATTERNS.match(a) or a == "-k" for a in tc["cli_args"])

    return tc


def build_schema_aware_fixture(
    contract: Dict[str, Any],
    cli_schema: Optional[Dict[str, Any]],
    skill_dir: str,
    declaration_text: str = "",
    test_idx: int = 1,
    is_refinement: bool = False,
    supervisor_directive: Optional[str] = None,
) -> Dict[str, Any]:
    """Construct a generalized, schema-compliant test fixture from AST + `--help` + `SKILL.md` (`H5`, `R2`)."""
    contract_id = str(contract.get("contract_id") or contract.get("id") or f"C_{test_idx:02d}")
    subcommands = cli_schema.get("subcommands", []) if cli_schema else []
    positionals = cli_schema.get("positionals", []) if cli_schema else []
    options = cli_schema.get("options", []) if cli_schema else []
    parser_type = cli_schema.get("parser_type") if cli_schema else None
    script_name = cli_schema.get("script_name", "") if cli_schema else ""
    script_code = str(cli_schema.get("script_code") or "") if cli_schema else ""
    ast_is_stub = bool(cli_schema.get("ast_is_stub", False)) if cli_schema else False
    expects_xhtml = bool(cli_schema.get("expects_xhtml", False)) if cli_schema else False
    help_text = str(cli_schema.get("help_text") or "") if cli_schema else ""

    cli_args: List[str] = []
    mock_files: Dict[str, str] = {}
    env_vars: Dict[str, str] = {"TEST_MODE": "1", "CI": "true"}

    # 0. Populate any required relative files discovered from script AST (e.g. REQUIRED_FILES = [".gitignore", ...], Cargo.toml)
    for req_rel in (cli_schema.get("required_relative_files", []) if cli_schema else []):
        full_req = os.path.join(skill_dir, req_rel)
        if not os.path.exists(full_req):
            if req_rel == ".gitignore" and os.path.isfile(os.path.join(skill_dir, "templates", "scaffold", "GITIGNORE_TEMPLATE")):
                mock_files[req_rel] = Path(os.path.join(skill_dir, "templates", "scaffold", "GITIGNORE_TEMPLATE")).read_text(encoding="utf-8", errors="ignore")
            else:
                mock_files[req_rel] = synthesize_mock_file_content(req_rel)

    # Pre-populate /tmp/test_workspace with any markdown templates in assets/ or required headings discovered in AST
    req_headings = (cli_schema.get("required_md_headings") or []) if cli_schema else []
    default_md_doc = "# Documentation\n\n" + "\n\n".join(f"{h}\n\nVerified content section." for h in req_headings) + "\n"
    mock_files["/tmp/test_workspace/README.md"] = default_md_doc
    mock_files["/tmp/test_workspace/index.html"] = synthesize_mock_file_content("index.html")
    assets_dir = os.path.join(skill_dir, "assets")
    if os.path.isdir(assets_dir):
        for fn in sorted(os.listdir(assets_dir)):
            full_asset = os.path.join(assets_dir, fn)
            if os.path.isfile(full_asset) and fn.endswith(".md"):
                try:
                    asset_txt = Path(full_asset).read_text(encoding="utf-8", errors="ignore")
                    if "slo-sla" in fn.lower():
                        mock_files["/tmp/test_workspace/operation/slo-sla.md"] = asset_txt
                    elif "operation" in fn.lower() and "readme" in fn.lower():
                        mock_files["/tmp/test_workspace/operation/README.md"] = asset_txt
                    else:
                        mock_files[f"/tmp/test_workspace/{fn}"] = asset_txt
                except Exception:
                    pass
    if req_headings:
        mock_files.setdefault("/tmp/test_workspace/operation/slo-sla.md", default_md_doc)
        mock_files.setdefault("/tmp/test_workspace/operation/README.md", default_md_doc)

    # Populate any non-protected home config dotfiles read by the script
    uses_b64 = bool(cli_schema.get("uses_base64_decode")) if cli_schema else False
    for home_cfg in (cli_schema.get("home_config_reads", []) if cli_schema else []):
        raw_payload = b"export TEST_CONFIG_VALUE=1\n"
        mock_files[home_cfg] = base64.b64encode(raw_payload).decode("utf-8") if uses_b64 else raw_payload.decode("utf-8")

    # 1. Check SKILL.md fenced examples and docstring Usage examples
    md_examples = extract_markdown_code_examples(declaration_text, entry_script_name=script_name, help_text=help_text)
    if md_examples and (parser_type in (None, "sys.argv") or (not subcommands and not positionals and not options)):
        cli_args = list(md_examples[(test_idx - 1) % len(md_examples)])
        for idx_a, arg in enumerate(cli_args):
            prev_arg = cli_args[idx_a - 1] if idx_a > 0 else ""
            if prev_arg in ("-o", "--output", "--out", "--out-file"):
                continue
            if not arg.startswith("-") and "." in os.path.basename(arg) and not arg.startswith(("http", "/")):
                if not os.path.exists(os.path.join(skill_dir, arg)):
                    mock_files[arg] = synthesize_mock_file_content(arg)

    # 2. Subcommands & Subparser Scoping
    selected_sub: Optional[str] = None
    if not cli_args and subcommands:
        preferred_subs = [
            s for s in subcommands
            if s.lower() in ("list", "status", "check", "info", "version", "init", "cleanup", "validate", "help")
        ]
        if preferred_subs:
            selected_sub = preferred_subs[(test_idx - 1) % len(preferred_subs)]
        else:
            selected_sub = subcommands[(test_idx - 1) % len(subcommands)]

    scoped_positionals = [
        p for p in positionals
        if p.get("subcommand") in (None, selected_sub)
    ] if selected_sub else positionals

    root_options = [o for o in options if o.get("subcommand") is None] if selected_sub else options
    sub_options = [o for o in options if o.get("subcommand") == selected_sub] if selected_sub else []

    extra_required_flags: Set[str] = set()
    if supervisor_directive:
        for m in re.finditer(r"the following arguments are required:\s*([^\n]+)", supervisor_directive, re.IGNORECASE):
            for tok in re.split(r"[, ]+", m.group(1).strip()):
                if tok.startswith("-"):
                    extra_required_flags.add(tok.strip())

    def _append_option_args(opt_list: List[Dict[str, Any]], target_argv: List[str]) -> None:
        for o in opt_list:
            flags = o.get("flags", [])
            if not flags:
                continue
            long_flags = [f for f in flags if f.startswith("--")]
            flag = long_flags[0] if long_flags else flags[0]
            is_req = bool(o.get("required")) or any(f in extra_required_flags for f in flags)
            if not is_req:
                continue
            if any(f in target_argv for f in flags):
                continue

            action = o.get("action")
            choices = o.get("choices")
            f_lower = flag.lower()
            h_lower = str(o.get("help") or "").lower()

            if action in ("store_true", "store_false"):
                target_argv.append(flag)
            elif choices and isinstance(choices, (list, tuple)):
                target_argv.extend([flag, str(choices[0])])
            elif any(k in f_lower or k in h_lower for k in ("timestamp", "iso", "datetime")):
                target_argv.extend([flag, "2026-01-15T00:00:00"])
            elif any(k in f_lower or k in h_lower for k in ("date", "cloture", "since", "until", "deadline", "period")):
                target_argv.extend([flag, "2026-12-31"])
            elif any(k in f_lower or k in h_lower for k in ("rule", "masking", "mapping", "pair")) or "field:type" in h_lower:
                target_argv.extend([flag, "name:name"])
            elif any(k in f_lower or k in h_lower for k in ("out", "output", "dest", "report")):
                ext = "csv" if ("csv" in f_lower or "csv" in h_lower or "pandas" in script_code or ".csv" in script_code) else ("json" if "json" in f_lower or "json" in h_lower else "txt")
                target_argv.extend([flag, f"output_{test_idx}.{ext}"])
            elif any(k in f_lower or k in h_lower for k in ("compose", "yaml", "yml")):
                fname = "docker-compose.yml"
                mock_files[fname] = synthesize_mock_file_content(fname)
                target_argv.extend([flag, fname])
            elif any(k in f_lower or k in h_lower for k in ("csv",)) or (
                ("pandas" in script_code or "csv" in script_code) and any(k in f_lower for k in ("in", "input", "file", "data", "src"))
            ):
                fname = f"input_{test_idx}.csv"
                mock_files[fname] = synthesize_mock_file_content(fname)
                target_argv.extend([flag, fname])
            elif any(k in f_lower or k in h_lower for k in ("in", "input", "file", "config", "src", "fec")):
                ext = "json" if "json" in f_lower or "json" in h_lower else "txt"
                fname = f"input_{test_idx}.{ext}"
                mock_files[fname] = synthesize_mock_file_content(fname)
                target_argv.extend([flag, fname])
            elif any(k in f_lower or k in h_lower for k in ("dir", "repo", "folder", "project", "workspace", "path")):
                target_argv.extend([flag, "/tmp/test_workspace"])
            elif o.get("type") in ("int", "<class 'int'>", "float", "<class 'float'>") or any(
                k in f_lower for k in ("count", "num", "limit", "port", "pr", "id", "payes", "ca-")
            ):
                target_argv.extend([flag, "1"])
            else:
                target_argv.extend([flag, "sample_value"])

    if not cli_args:
        # Root required options go before subcommand in argparse
        if selected_sub:
            _append_option_args(root_options, cli_args)
            cli_args.append(selected_sub)

        # 3. Positional arguments
        if scoped_positionals:
            if parser_type == "sys.argv":
                for pos in scoped_positionals:
                    p_lit = pos.get("literal")
                    p_type = pos.get("type", "str")
                    p_name = str(pos.get("name", "")).lower()
                    if p_lit:
                        cli_args.append(str(p_lit))
                    elif p_type == "json_str":
                        cli_args.append(json.dumps({"title": "Sample", "summary": "Test", "status": "ok", "items": ["a"], "body": {"name": "Sample"}, "shopId": "12345"}))
                    elif p_type in ("int", "float"):
                        cli_args.append(str(5 * test_idx))
                    elif any(k in p_name for k in ("dir", "folder", "workspace", "path", "root", "feature")):
                        cli_args.append("/tmp/test_workspace")
                    elif expects_xhtml or "xhtml" in p_name:
                        fname = f"input_{test_idx}.xhtml"
                        mock_files[fname] = synthesize_mock_file_content(fname)
                        cli_args.append(fname)
                    elif any(k in p_name for k in ("skill_name", "name", "command", "cmd", "action")):
                        cli_args.append("sample-skill")
                    else:
                        fname = f"input_{test_idx}.txt"
                        mock_files[fname] = synthesize_mock_file_content(fname)
                        cli_args.append(fname)
            else:
                for pos in scoped_positionals:
                    if not pos.get("required", True) and pos.get("default") is not None:
                        continue
                    p_name = str(pos.get("name", "input")).lower()
                    p_help = str(pos.get("help", "")).lower()
                    choices = pos.get("choices")
                    if choices and isinstance(choices, (list, tuple)):
                        cli_args.append(str(choices[(test_idx - 1) % len(choices)]))
                    elif p_name == "owner_repo":
                        cli_args.append("owner/repo")
                    elif p_name == "html_path":
                        cli_args.append("/tmp/test_workspace/index.html")
                    elif any(term in p_help or term in p_name for term in ("commit", "hash", "revision")):
                        cli_args.append("HEAD")
                    elif any(term in p_help or term in p_name for term in ("directory", "dir", "folder", "repo", "project", "workspace")):
                        cli_args.append("/tmp/test_workspace" if "feature" in p_name or "workspace" in p_name else ".")
                    elif expects_xhtml or "xhtml" in p_name or "xhtml" in p_help:
                        fname = f"input_{test_idx}.xhtml"
                        mock_files[fname] = synthesize_mock_file_content(fname)
                        cli_args.append(fname)
                    elif any(term in p_help or term in p_name for term in ("json",)):
                        fname = f"input_{test_idx}.json"
                        mock_files[fname] = synthesize_mock_file_content(fname)
                        cli_args.append(fname)
                    elif any(term in p_help or term in p_name for term in ("csv", "data", "table")):
                        fname = f"input_{test_idx}.csv"
                        mock_files[fname] = synthesize_mock_file_content(fname)
                        cli_args.append(fname)
                    elif any(term in p_help or term in p_name for term in ("xml", "ghx")):
                        ext = "ghx" if "ghx" in p_name or "ghx" in script_name.lower() else "xml"
                        fname = f"input_{test_idx}.{ext}"
                        mock_files[fname] = synthesize_mock_file_content(fname)
                        cli_args.append(fname)
                    elif any(term in p_help or term in p_name for term in ("yaml", "yml", "config")):
                        fname = f"input_{test_idx}.yaml"
                        mock_files[fname] = synthesize_mock_file_content(fname)
                        cli_args.append(fname)
                    elif any(term in p_help or term in p_name for term in ("file", "path", "input", "src", "source", "session")):
                        fname = f"input_{test_idx}.txt"
                        mock_files[fname] = synthesize_mock_file_content(fname)
                        cli_args.append(fname)
                    elif pos.get("type") in ("int", "<class 'int'>"):
                        cli_args.append(str(test_idx))
                    else:
                        cli_args.append(f"sample_{test_idx}")

        # 4. Required options
        if selected_sub:
            _append_option_args(sub_options, cli_args)
        else:
            _append_option_args(root_options, cli_args)

    # If supervisor_directive reported required flags that weren't in AST options, synthesize them too
    for req_flag in sorted(extra_required_flags):
        if req_flag not in cli_args:
            rf_lower = req_flag.lower()
            if any(k in rf_lower for k in ("date", "cloture", "since", "until")):
                cli_args.extend([req_flag, "2026-12-31"])
            elif any(k in rf_lower for k in ("out", "output", "dest", "report")):
                cli_args.extend([req_flag, f"output_{test_idx}.txt"])
            elif any(k in rf_lower for k in ("in", "input", "file", "config", "spec", "src")):
                ext = "json" if "json" in rf_lower else ("yaml" if "yaml" in rf_lower or "yml" in rf_lower else "txt")
                fname = f"input_{test_idx}.{ext}"
                mock_files[fname] = synthesize_mock_file_content(fname)
                cli_args.extend([req_flag, fname])
            else:
                cli_args.extend([req_flag, "sample_value"])

    # If supervisor_directive reported a missing file (e.g. FileNotFoundError or Missing spec file), synthesize it in mock_files
    if supervisor_directive:
        for pat in (
            r"No such file or directory:\s*['\"]([^'\"]+)['\"]",
            r"Missing [^:\n]+:\s*([^\s'\"\n]+)",
            r"File not found:\s*['\"]?([^'\"\s\n]+)['\"]?",
        ):
            for m_file in re.finditer(pat, supervisor_directive, re.IGNORECASE):
                missing_p = m_file.group(1).strip()
                if missing_p.startswith("/app/skill/"):
                    missing_p = missing_p[len("/app/skill/"):]
                if missing_p and not missing_p.startswith("/") and ".." not in missing_p:
                    mock_files.setdefault(missing_p, synthesize_mock_file_content(missing_p))

    entry_path = "SKILL.md"
    if cli_schema and cli_schema.get("script_path"):
        entry_path = os.path.relpath(cli_schema["script_path"], skill_dir).replace("\\", "/")
    else:
        ep_cand = identify_entry_point_script(skill_dir, [contract] if contract else None)
        if ep_cand:
            entry_path = os.path.relpath(ep_cand, skill_dir).replace("\\", "/")

    checks = synthesize_checks_for_contract(
        contract,
        cli_args,
        script_code=script_code,
        ast_is_stub=ast_is_stub,
    )

    raw_tc = {
        "test_id": f"TC_{contract_id}_{'refine' if is_refinement else 'init'}",
        "contract_id": contract_id,
        "entry_point": entry_path,
        "precondition": contract.get("precondition") or f"Exercising contract {contract_id} against {script_name}",
        "expected_postcondition": contract.get("postcondition") or f"Contract {contract_id} satisfied with exit code 0",
        "frame_axiom": contract.get("frame_axiom") or {},
        "forbidden_invariant": contract.get("forbidden_invariant") or contract.get("forbidden_invariants") or [],
        "mock_files": mock_files,
        "cli_args": cli_args,
        "env_vars": env_vars,
        "checks": checks,
        "rationale": f"Schema-compliant test fixture targeting {script_name}",
    }

    return compute_deterministic_test_case_fields(
        tc=raw_tc,
        cli_schema=cli_schema,
        skill_dir=skill_dir,
        contracts=[contract] if contract else None,
    )


AGEN_SYSTEM_PROMPT = """You are A_gen (Test & Fixture Generator Agent) in a formal skill intent-behavior verification pipeline.
Read the behavioral contracts, skill declaration, and actual CLI schema, and synthesize realistic test fixtures, CLI arguments, mock files, environment variables, and deterministic postcondition checks.

For each targeted contract, output a JSON object inside a "test_cases" array:
{
  "test_id": "TC_<contract_id>_<init|refine>",
  "contract_id": "<contract_id>",
  "precondition": "<stated precondition>",
  "expected_postcondition": "<stated postcondition>",
  "entry_point": "<relative path to entry script>",
  "mock_files": {
    "<relative_path>": "<realistic mock content>"
  },
  "cli_args": ["<subcommand_or_flag>", "<value>"],
  "env_vars": {
    "<ENV_KEY>": "<value>"
  },
  "checks": [
    {"id": "<check_id>", "contract_id": "<contract_id>", "kind": "exit_code", "expect": 0}
  ],
  "rationale": "<brief explanation>"
}

RULES:
1. Return ONLY valid JSON with a top-level "test_cases" array.
2. Strictly obey the ACTUAL SCRIPT CLI INTERFACE. Use ONLY declared subcommands, positional arguments, and flags. Never invent flags.
3. If an input file is passed in 'cli_args', define it with valid content in 'mock_files'.
4. Do NOT include 'python', 'python3', or the script path in 'cli_args'.
5. Allowed check kinds in 'checks': exit_code, file_exists, json_schema, text_contains, order_check, stdout_regex, custom_py.
6. For skills with subcommands, you MUST generate at least one test case per declared subcommand/contract-relevant entry point so that all functional capabilities and contracts are exercised.
7. NEVER pass secret flags (e.g. '--api-key', '--token', '--secret', '--api_key') in 'cli_args'. Any credentials must come from environment variables.
8. NEVER pass passive or no-op flags (e.g. '--dry-run', '--simulate', '--dryrun', '--no-op', '--validate-only', '--check') when verifying effect-producing contracts. Use flags that perform real execution.
9. NEVER use placeholder paths like 'path/to/...' or '<filename>'. Use concrete filenames (e.g. 'input_1.txt'), and define them in 'mock_files'.
10. Obey argument choices strictly. If a flag has choices, select one of the allowed choices.
"""


def call_openai_test_generator(
    contracts: List[Dict[str, Any]],
    declaration_text: str,
    cli_schema: Optional[Dict[str, Any]] = None,
    uncovered_ids: Optional[List[str]] = None,
    supervisor_directive: Optional[str] = None,
    api_key: Optional[str] = None,
    model: str = "gpt-4o-mini",
) -> Tuple[Optional[List[Dict[str, Any]]], Dict[str, Any]]:
    """Invoke LLM (OpenAI or Gemini) to synthesize test cases when API key is configured."""
    from src.llm_client import call_llm_json_with_meta

    effective_key = api_key or os.environ.get("OPENAI_API_KEY", "").strip() or os.environ.get("GEMINI_API_KEY", "").strip()
    target_model = os.environ.get("AGEN_MODEL", model).strip() or "gpt-4o-mini"

    if not effective_key:
        return None, {
            "mode": "deterministic",
            "model": None,
            "latency_ms": 0,
            "input_tokens": None,
            "output_tokens": None,
            "fallback_reason": "No API key configured",
        }

    is_refinement = bool(uncovered_ids or supervisor_directive)
    target_contracts = contracts
    if uncovered_ids:
        target_contracts = [c for c in contracts if c.get("contract_id") in uncovered_ids] or contracts

    prompt_lines = [
        f"Mode: {'REFINEMENT PASS' if is_refinement else 'INITIAL GENERATION'}",
        f"Declaration Excerpt:\n{declaration_text[:4000]}\n",
        f"Target Contracts ({len(target_contracts)}):\n{json.dumps(target_contracts, indent=2)}\n",
    ]

    if cli_schema and not cli_schema.get("error"):
        prompt_lines.append("ACTUAL SCRIPT CLI INTERFACE (STRICT COMPLIANCE REQUIRED):")
        prompt_lines.append(f"Entry Script: {cli_schema.get('script_name')}")
        prompt_lines.append(f"Parser Type: {cli_schema.get('parser_type')}")
        if cli_schema.get("help_text"):
            prompt_lines.append(f"--help Output:\n{cli_schema.get('help_text')}\n")
        if cli_schema.get("subcommands"):
            prompt_lines.append(f"Valid Subcommands: {cli_schema.get('subcommands')}")
        if cli_schema.get("positionals"):
            prompt_lines.append(f"Positional Arguments: {json.dumps(cli_schema.get('positionals'))}")
        if cli_schema.get("options"):
            prompt_lines.append(f"Options/Flags: {json.dumps(cli_schema.get('options'))}")

    if supervisor_directive:
        prompt_lines.append(f"Supervisor / Refinement Directive (including prior stderr):\n{supervisor_directive}\n")

    from src.agent_skill_loader import get_agent_system_prompt
    sys_prompt = get_agent_system_prompt("a_gen", fallback_prompt=AGEN_SYSTEM_PROMPT)

    parsed_dict, meta = call_llm_json_with_meta(
        prompt="\n".join(prompt_lines),
        system_prompt=sys_prompt,
        model=target_model,
        api_key=effective_key,
        temperature=0.0,
    )

    if isinstance(parsed_dict, dict):
        if isinstance(parsed_dict.get("test_cases"), list):
            return parsed_dict["test_cases"], meta
        if isinstance(parsed_dict.get("tests"), list):
            return parsed_dict["tests"], meta
        if "test_id" in parsed_dict or "contract_id" in parsed_dict or "contract_ids" in parsed_dict:
            return [parsed_dict], meta
    elif isinstance(parsed_dict, list):
        return parsed_dict, meta

    return None, meta


def fallback_deterministic_test_cases(
    contracts: List[Dict[str, Any]],
    skill_dir: str,
    cli_schema: Optional[Dict[str, Any]] = None,
    uncovered_ids: Optional[List[str]] = None,
    declaration_text: str = "",
    supervisor_directive: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Deterministic schema-aware test generator (`H5`)."""
    test_cases: List[Dict[str, Any]] = []
    is_refinement = bool(uncovered_ids or supervisor_directive)
    targets = [c for c in contracts if c.get("contract_id") in uncovered_ids] if uncovered_ids else contracts
    if not targets:
        targets = contracts or [{"contract_id": "C_01"}]

    for idx, c in enumerate(targets, 1):
        tc = build_schema_aware_fixture(
            contract=c,
            cli_schema=cli_schema,
            skill_dir=skill_dir,
            declaration_text=declaration_text,
            test_idx=idx,
            is_refinement=is_refinement,
            supervisor_directive=supervisor_directive,
        )
        test_cases.append(tc)

    # For skills with subcommands, ensure every declared subcommand has at least one test case
    if cli_schema and cli_schema.get("subcommands"):
        all_subs = [str(s) for s in cli_schema["subcommands"]]
        covered_subs = set()
        for tc in test_cases:
            args = [str(a) for a in (tc.get("cli_args") or [])]
            for a in args:
                if a in all_subs:
                    covered_subs.add(a)
                    break
        missing_subs = [s for s in all_subs if s not in covered_subs]
        for m_idx, m_sub in enumerate(missing_subs, start=len(test_cases) + 1):
            # Select contract that mentions the subcommand or cycle
            c_match = next(
                (c for c in targets if m_sub.lower() in str(c.get("postcondition", "")).lower() or m_sub.lower() in str(c.get("precondition", "")).lower()),
                targets[(m_idx - 1) % len(targets)]
            )
            sub_tc = build_schema_aware_fixture(
                contract=c_match,
                cli_schema=cli_schema,
                skill_dir=skill_dir,
                declaration_text=declaration_text,
                test_idx=m_idx,
                is_refinement=is_refinement,
                supervisor_directive=supervisor_directive,
            )
            # Force selected subcommand
            cur_args = [str(a) for a in (sub_tc.get("cli_args") or [])]
            sub_idx_in_args = next((i for i, a in enumerate(cur_args) if a in all_subs), None)
            if sub_idx_in_args is not None:
                cur_args[sub_idx_in_args] = m_sub
            else:
                cur_args.insert(0, m_sub)
            sub_tc["cli_args"] = cur_args
            sub_tc["test_id"] = f"TC_{c_match.get('contract_id', 'C_01')}_{m_sub}_{m_idx}"
            test_cases.append(sub_tc)

    return test_cases


def generate_test_cases(
    contracts: List[Dict[str, Any]],
    skill_dir: str,
    uncovered_contract_ids: Optional[List[str]] = None,
    supervisor_directive: Optional[str] = None,
    declaration_text: str = "",
    return_meta: bool = False,
) -> Any:
    """A_gen: Synthesize schema-compliant test cases, mock fixtures, and executable `checks[]` (`H5`)."""
    if not declaration_text:
        skill_md = os.path.join(skill_dir, "SKILL.md")
        if os.path.exists(skill_md):
            try:
                declaration_text = Path(skill_md).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass

    entry_script = identify_entry_point_script(skill_dir, contracts)
    cli_schema: Optional[Dict[str, Any]] = None
    if entry_script and os.path.exists(entry_script):
        cli_schema = extract_cli_schema_from_ast(entry_script)
        cli_schema["script_path"] = entry_script

    api_key = os.environ.get("OPENAI_API_KEY", "").strip() or os.environ.get("GEMINI_API_KEY", "").strip()
    use_llm = os.environ.get("USE_LLM_AGEN", "1") != "0" and bool(api_key)
    test_cases: Optional[List[Dict[str, Any]]] = None
    gen_meta: Dict[str, Any] = {
        "mode": "deterministic",
        "model": None,
        "latency_ms": 0,
        "input_tokens": None,
        "output_tokens": None,
        "fallback_reason": "USE_LLM_AGEN set to 0" if os.environ.get("USE_LLM_AGEN") == "0" else "No API key configured",
    }

    if use_llm and contracts:
        raw_tcs, llm_meta = call_openai_test_generator(
            contracts=contracts,
            declaration_text=declaration_text,
            cli_schema=cli_schema,
            uncovered_ids=uncovered_contract_ids,
            supervisor_directive=supervisor_directive,
            api_key=api_key,
        )
        gen_meta = dict(llm_meta)
        test_cases = raw_tcs

    # Validate LLM test cases against CLI schema
    if test_cases and cli_schema and not cli_schema.get("error"):
        valid_subs = set(cli_schema.get("subcommands", []))
        valid_opts = {flag for o in cli_schema.get("options", []) for flag in o.get("flags", [])}
        validated: List[Dict[str, Any]] = []
        contract_map = {str(c.get("contract_id") or c.get("id") or f"C_{i+1:02d}"): c for i, c in enumerate(contracts)}

        for tc in test_cases:
            args = [str(a) for a in (tc.get("cli_args") or [])]
            is_valid = True
            if valid_subs and args:
                if args[0] not in valid_subs and not args[0].startswith("-"):
                    is_valid = False
            if valid_opts:
                for a in args:
                    if a.startswith("-") and a not in valid_opts and not any(a.startswith(f"{vo}=") for vo in valid_opts):
                        is_valid = False
                        break
            if is_valid:
                cid = str(tc.get("contract_id") or "C_01")
                c_obj = contract_map.get(cid, {"contract_id": cid})
                tc["checks"] = synthesize_checks_for_contract(c_obj, args)
                if entry_script and not tc.get("entry_point"):
                    tc["entry_point"] = os.path.relpath(entry_script, skill_dir).replace("\\", "/")
                validated.append(tc)
        if validated:
            test_cases = validated
            gen_meta["mode"] = "llm"
            gen_meta["fallback_reason"] = None
        else:
            test_cases = None
            gen_meta["mode"] = "llm_failed_fallback"
            gen_meta["fallback_reason"] = "LLM generated test cases failed CLI schema validation"
    elif test_cases:
        gen_meta["mode"] = "llm"
        gen_meta["fallback_reason"] = None

    if not test_cases:
        if use_llm and gen_meta.get("mode") != "llm_failed_fallback":
            gen_meta["mode"] = "llm_failed_fallback"
            if not gen_meta.get("fallback_reason"):
                gen_meta["fallback_reason"] = "LLM returned no test cases"

        test_cases = fallback_deterministic_test_cases(
            contracts=contracts,
            skill_dir=skill_dir,
            cli_schema=cli_schema,
            uncovered_ids=uncovered_contract_ids,
            declaration_text=declaration_text,
            supervisor_directive=supervisor_directive,
        )

    # Sanitize and ensure deterministic test-case fields across all test cases
    sanitized_tcs: List[Dict[str, Any]] = []
    for tc in (test_cases or []):
        stc = compute_deterministic_test_case_fields(
            tc=tc,
            cli_schema=cli_schema,
            skill_dir=skill_dir,
            contracts=contracts,
        )
        sanitized_tcs.append(stc)
    test_cases = sanitized_tcs

    tc_path = os.path.join(skill_dir, "test_cases.json")
    try:
        with open(tc_path, "w", encoding="utf-8") as f:
            json.dump(test_cases, f, indent=2)
    except Exception:
        pass

    if return_meta:
        return test_cases, gen_meta
    return test_cases
