import ast
import hashlib
import json
import os
import re
import shutil
import sys
import tomllib
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from harbor.models.task.config import (
        AgentConfig,
        ArtifactConfig,
        EnvironmentConfig,
        TaskConfig,
        VerifierConfig,
    )
except ImportError:
    _venv_site = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "venv", "Lib", "site-packages"))
    if os.path.exists(_venv_site) and _venv_site not in sys.path:
        sys.path.insert(0, _venv_site)
    try:
        from harbor.models.task.config import (
            AgentConfig,
            ArtifactConfig,
            EnvironmentConfig,
            TaskConfig,
            VerifierConfig,
        )
    except ImportError:
        AgentConfig = ArtifactConfig = EnvironmentConfig = TaskConfig = VerifierConfig = None  # type: ignore[assignment,misc]

from src.agents.dynamic_agent_skill_fetch import hydrate_skill_tree_from_db
from src.dep_resolver import (
    generate_docker_build_dependency_layer,
    resolve_skill_dependencies,
)
from src.invocation_planner import plan_skill_invocations
from src.mock_sidecar import build_docker_compose_config, generate_mock_sidecar_script
from src.platform_compat import (
    LOG_ONLY_SHIMMED_BINARIES,
    extract_env_var_names_from_skill,
    generate_log_only_shim_script,
    generate_sitecustomize_py,
    normalize_skill_sources,
    synthesize_format_valid_dummy_env,
)
from src.system_baseline import parse_host_from_target

DEFAULT_ADAPTER_PARAMS: Dict[str, Any] = {
    "cpus": 2,
    "memory_mb": 4096,
    "storage_mb": 10240,
    "agent_timeout_sec": 180.0,
    "verifier_timeout_sec": 60.0,
    "default_network_mode": "no-network",
    "base_docker_image": "harbor-base:latest",
}

PIPELINE_METADATA_EXCLUDES: Set[str] = {
    ".git",
    "__pycache__",
    "contracts.json",
    "ground_truth.json",
    "prediction.json",
    "test_cases.json",
    "trace.jsonl",
    "trajectory.json",
    "recipe.json",
    "metadata.json",
}


def _parse_size_mb(val: Any, default_mb: int) -> int:
    """Convert size specifications like 4096, '4G', '4096M' to integer megabytes."""
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str):
        s = val.strip().upper()
        if s.endswith("GB"):
            s = s[:-2]
            return int(float(s) * 1024)
        if s.endswith("G"):
            s = s[:-1]
            return int(float(s) * 1024)
        if s.endswith("MB"):
            s = s[:-2]
            return int(float(s))
        if s.endswith("M"):
            s = s[:-1]
            return int(float(s))
        if s.isdigit():
            return int(s)
    return default_mb


def extract_declared_dependencies(skill_dir: str) -> List[str]:
    """Extracts python dependencies declared in requirements.txt or imported by scripts."""
    res = resolve_skill_dependencies(skill_dir)
    return res.get("pip_packages", []) if isinstance(res, dict) else res


def detect_ast_is_stub(script_path: str) -> bool:
    """Return True if a Python entry script's functions/body are pass/ellipsis/NotImplementedError stubs."""
    if not script_path or not script_path.endswith(".py") or not os.path.isfile(script_path):
        return False
    try:
        src = Path(script_path).read_text(encoding="utf-8", errors="ignore")
        tree = ast.parse(src, filename=script_path)
    except Exception:
        return False

    def _is_trivial_stmt(stmt: ast.stmt) -> bool:
        if isinstance(stmt, ast.Pass):
            return True
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
            # Docstring or Ellipsis (...)
            return isinstance(stmt.value.value, str) or stmt.value.value is Ellipsis
        if isinstance(stmt, ast.Raise):
            exc = stmt.exc
            if isinstance(exc, ast.Name) and exc.id == "NotImplementedError":
                return True
            if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name) and exc.func.id == "NotImplementedError":
                return True
        return False

    func_defs = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if func_defs:
        main_funcs = [f for f in func_defs if f.name in ("main", "run", "execute")]
        target_funcs = main_funcs or func_defs
        return all(all(_is_trivial_stmt(s) for s in f.body) for f in target_funcs)

    non_import_stmts = [
        n for n in tree.body
        if not isinstance(n, (ast.Import, ast.ImportFrom))
    ]
    if not non_import_stmts:
        return True
    # Check if `if __name__ == "__main__":` body is trivial
    for n in non_import_stmts:
        if isinstance(n, ast.If):
            if all(_is_trivial_stmt(s) for s in n.body):
                return True
    return all(_is_trivial_stmt(s) for s in non_import_stmts)


def extract_entry_point_and_cwd(
    skill_dir: str,
    contracts: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[str, str, bool]:
    """Extract `(entry_point_rel_path, cwd_rel_path, is_instruction_only)` from SKILL.md, contracts, and skill tree."""
    valid_exts = (".py", ".sh", ".js", ".mjs")

    # 1. Inspect SKILL.md fenced commands for explicit cd <subdir> && python3 <script> or script usage
    skill_md_path = os.path.join(skill_dir, "SKILL.md")
    if os.path.isfile(skill_md_path):
        try:
            md_text = Path(skill_md_path).read_text(encoding="utf-8", errors="ignore")
            blocks = re.findall(r"```(?:bash|sh|shell|console|zsh)?\r?\n([\s\S]*?)```", md_text, re.IGNORECASE)
            for block in blocks:
                joined_block = re.sub(r"\\\s*\r?\n\s*", " ", block)
                current_cwd = ""
                for raw_line in joined_block.splitlines():
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Match `cd subdir && cmd` or standalone `cd subdir`
                    m_cd_and = re.match(r"^cd\s+([a-zA-Z0-9_.\-/]+)\s*(?:&&|;)\s*(.+)$", line)
                    if m_cd_and:
                        cand_cwd = m_cd_and.group(1).strip().strip("'\"")
                        if not cand_cwd.startswith("/") and ".." not in cand_cwd.split("/"):
                            if os.path.isdir(os.path.join(skill_dir, cand_cwd)):
                                current_cwd = cand_cwd
                        line = m_cd_and.group(2).strip()
                    else:
                        m_cd_only = re.match(r"^cd\s+([a-zA-Z0-9_.\-/]+)$", line)
                        if m_cd_only:
                            cand_cwd = m_cd_only.group(1).strip().strip("'\"")
                            if not cand_cwd.startswith("/") and ".." not in cand_cwd.split("/"):
                                if os.path.isdir(os.path.join(skill_dir, cand_cwd)):
                                    current_cwd = cand_cwd
                            continue

                    tokens = line.split()
                    for tok in tokens:
                        clean_tok = tok.strip("'\"")
                        if any(clean_tok.endswith(ext) for ext in valid_exts):
                            clean_tok = clean_tok.replace("\\", "/").lstrip("./")
                            if os.path.basename(clean_tok).startswith("_"):
                                continue
                            cand_rel = f"{current_cwd}/{clean_tok}".lstrip("/") if current_cwd else clean_tok
                            if os.path.isfile(os.path.join(skill_dir, cand_rel)):
                                return cand_rel, current_cwd, False
                            if os.path.isfile(os.path.join(skill_dir, clean_tok)):
                                return clean_tok, current_cwd, False
            # Also check inline backtick invocations in SKILL.md (e.g. `python scripts/check_auth_dependency.py`)
            for m_inline in re.finditer(r"`(?:python3?|bash|sh|node)\s+([a-zA-Z0-9_.\-/]+\.(?:py|sh|js|mjs))(?:\s+[^`]*)?`", md_text):
                clean_tok = m_inline.group(1).replace("\\", "/").lstrip("./")
                if not os.path.basename(clean_tok).startswith("_") and os.path.isfile(os.path.join(skill_dir, clean_tok)):
                    return clean_tok, "", False
        except Exception:
            pass

    # 2. Inspect contracts frame_axiom
    if contracts:
        for c in contracts:
            raw_fa = c.get("frame_axiom", [])
            items: List[str] = []
            if isinstance(raw_fa, dict):
                items.extend(str(x) for x in (raw_fa.get("read") or []))
                items.extend(str(x) for x in (raw_fa.get("exec") or []))
            elif isinstance(raw_fa, list):
                items.extend(str(x) for x in raw_fa)
            for axiom_str in items:
                s = axiom_str.strip()
                if ":" in s and s.split(":", 1)[0].lower() in ("read", "execute", "exec"):
                    s = s.split(":", 1)[1].strip()
                if any(s.endswith(ext) for ext in valid_exts):
                    target_clean = s.replace("\\", "/").lstrip("./")
                    if os.path.basename(target_clean).startswith("_"):
                        continue
                    if os.path.isfile(os.path.join(skill_dir, target_clean)):
                        return target_clean, "", False

    skill_base = (
        os.path.basename(skill_dir.rstrip("\\/"))
        .replace("benign_", "")
        .replace("mal_", "")
        .replace("-", "_")
        .lower()
    )

    def _has_cli_main(rel_p: str) -> bool:
        try:
            txt = Path(os.path.join(skill_dir, rel_p)).read_text(encoding="utf-8", errors="ignore")
            return ("__main__" in txt) or ("argparse" in txt) or ("sys.argv" in txt) or ("process.argv" in txt) or ("click" in txt) or ("typer" in txt)
        except Exception:
            return False

    def _is_executable_cli_script(rel_p: str) -> bool:
        full_p = os.path.join(skill_dir, rel_p)
        ext = os.path.splitext(rel_p)[1].lower()
        if ext in (".sh", ".bash"):
            return True
        if ext in (".js", ".mjs"):
            try:
                txt = Path(full_p).read_text(encoding="utf-8", errors="ignore")
                return bool(txt.strip())
            except Exception:
                return True
        if ext == ".py":
            try:
                txt = Path(full_p).read_text(encoding="utf-8", errors="ignore")
                if any(k in txt for k in ("__main__", "argparse", "click", "typer", "sys.argv", "fire.")):
                    return True
                tree = ast.parse(txt, filename=full_p)
                for node in tree.body:
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)):
                        continue
                    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        continue
                    if isinstance(node, ast.Pass):
                        continue
                    return True
                return False
            except Exception:
                return False
        return False

    # 3. Check skill scripts/ directory
    scripts_dir = os.path.join(skill_dir, "scripts")
    if os.path.exists(scripts_dir):
        all_runnables = []
        for root, _, files in os.walk(scripts_dir):
            if "templates" in Path(root).parts or "__pycache__" in Path(root).parts:
                continue
            for fn in sorted(files):
                if any(fn.endswith(ext) for ext in valid_exts):
                    rel = os.path.relpath(os.path.join(root, fn), skill_dir).replace("\\", "/")
                    all_runnables.append(rel)

        public_runnables = [
            r for r in all_runnables
            if not os.path.basename(r).startswith("_") and not os.path.basename(r).startswith("test_")
        ]
        search_pool = public_runnables if public_runnables else all_runnables
        runnable_search_pool = [r for r in search_pool if _is_executable_cli_script(r)]

        for r in runnable_search_pool:
            fn_base = os.path.basename(r).split(".")[0].replace("-", "_").lower()
            if fn_base == skill_base or fn_base in skill_base or skill_base in fn_base:
                return r, "", False

        for standard in ["main.py", "agent.py", "run.py", "index.js", "index.mjs", "main.sh", "run.sh", "server.py"]:
            for r in runnable_search_pool:
                if os.path.basename(r) == standard:
                    return r, "", False

        cli_mains = [r for r in runnable_search_pool if _has_cli_main(r)]
        if cli_mains:
            return cli_mains[0], "", False
        if runnable_search_pool:
            return runnable_search_pool[0], "", False

    # 4. Check bin/ directory
    bin_dir = os.path.join(skill_dir, "bin")
    if os.path.exists(bin_dir):
        bin_files = sorted(os.listdir(bin_dir))
        if bin_files:
            return f"bin/{bin_files[0]}", "", False

    # 5. Check root directory
    for root_cand in ["main.py", "run.py", "agent.py", "index.js", "index.mjs", "run.sh", "main.sh"]:
        if os.path.isfile(os.path.join(skill_dir, root_cand)) and _is_executable_cli_script(root_cand):
            return root_cand, "", False

    if os.path.isdir(skill_dir):
        root_runnables = [
            fn for fn in sorted(os.listdir(skill_dir))
            if os.path.isfile(os.path.join(skill_dir, fn))
            and any(fn.endswith(ext) for ext in valid_exts)
            and not fn.startswith("_")
            and not fn.startswith("test_")
            and fn not in ("setup.py", "conftest.py")
        ]
        runnable_root = [fn for fn in root_runnables if _is_executable_cli_script(fn)]
        for fn in runnable_root:
            fn_base = fn.split(".")[0].replace("-", "_").lower()
            if fn_base == skill_base or fn_base in skill_base or skill_base in fn_base:
                return fn, "", False
        root_mains = [fn for fn in runnable_root if _has_cli_main(fn)]
        if root_mains:
            return root_mains[0], "", False
        if runnable_root:
            return runnable_root[0], "", False

    # 6. Check immediate subdirectories (e.g. aligned_subdir_cwd where script is in a subdirectory)
    if os.path.isdir(skill_dir):
        for sub in sorted(os.listdir(skill_dir)):
            if sub in ("tests", "templates", "__pycache__", ".git", ".github"):
                continue
            sub_path = os.path.join(skill_dir, sub)
            if os.path.isdir(sub_path):
                for fn in sorted(os.listdir(sub_path)):
                    cand_sub = f"{sub}/{fn}"
                    if any(fn.endswith(ext) for ext in valid_exts) and not fn.startswith("test_") and not fn.startswith("_"):
                        if _is_executable_cli_script(cand_sub):
                            return cand_sub, sub, False

    return "SKILL.md", "", True


def extract_entry_point(
    skill_dir: str,
    contracts: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[str, bool]:
    """Backward-compatible wrapper returning `(entry_point_rel_path, is_instruction_only)`."""
    ep, _, is_instr = extract_entry_point_and_cwd(skill_dir, contracts)
    return ep, is_instr


def extract_network_hosts_from_contracts(contracts: Optional[List[Dict[str, Any]]]) -> List[str]:
    """Derives external network hosts declared in contracts' Frame Axioms using `parse_host_from_target` (`E4`)."""
    hosts: Set[str] = set()
    if not contracts:
        return []
    valid_label_re = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

    def _add_candidate(raw_item: str) -> None:
        h, _ = parse_host_from_target(raw_item)
        if not h or h in ("none", "false", "local", "internal", "localhost", "127.0.0.1"):
            return
        labels = h.lstrip("*.").split(".")
        if len(labels) >= 2 and all(valid_label_re.match(lbl) for lbl in labels if lbl):
            hosts.add(h)

    for c in contracts:
        raw_fa = c.get("frame_axiom", [])
        if isinstance(raw_fa, dict):
            for h_item in raw_fa.get("hosts") or []:
                _add_candidate(str(h_item))
        elif isinstance(raw_fa, list):
            for axiom in raw_fa:
                axiom_str = str(axiom).strip()
                if "network:" in axiom_str.lower():
                    idx = axiom_str.lower().find("network:")
                    parts = axiom_str[idx + len("network:"):].strip()
                    for item in re.split(r"[,; ]+", parts):
                        _add_candidate(item)
    return sorted(hosts)


def validate_task_toml(toml_str: str) -> TaskConfig:
    """Validate `task.toml` via Harbor's `TaskConfig` and reject any unknown keys (`H1`)."""
    raw = tomllib.loads(toml_str)
    allowed_top = set(TaskConfig.model_fields.keys())
    unknown_top = set(raw.keys()) - allowed_top
    if unknown_top:
        raise ValueError(f"Unknown top-level keys in task.toml: {sorted(unknown_top)}")

    submodel_map = {
        "environment": EnvironmentConfig,
        "agent": AgentConfig,
        "verifier": VerifierConfig,
    }
    for section, model_cls in submodel_map.items():
        if section in raw and isinstance(raw[section], dict):
            allowed_sub = set(model_cls.model_fields.keys())
            unknown_sub = set(raw[section].keys()) - allowed_sub
            if unknown_sub:
                raise ValueError(f"Unknown keys in [{section}] of task.toml: {sorted(unknown_sub)}")

    return TaskConfig.model_validate_toml(toml_str)


validate_task_toml_schema = validate_task_toml


def build_task_toml(
    skill_id: str,
    network_mode: str,
    allowed_hosts: List[str],
    params: Dict[str, Any],
    is_instruction_only: bool = False,
) -> str:
    """Generate and validate `task.toml` using Harbor's `TaskConfig` model (`H1`, Clarification #4)."""
    memory_mb = _parse_size_mb(params.get("memory_mb") or params.get("memory"), 4096)
    storage_mb = _parse_size_mb(params.get("storage_mb") or params.get("storage"), 10240)
    cpus = int(float(params.get("cpus", 2)))
    agent_timeout = float(params.get("agent_timeout_sec", 180.0))
    verifier_timeout = float(params.get("verifier_timeout_sec", 60.0))

    base_artifact_paths = [
        "/logs/agent/run_status.json",
        "/logs/agent/stdout.log",
        "/logs/agent/stderr.log",
        "/logs/agent/strace.log",
        "/logs/agent/precondition.json",
        "/logs/agent/fs_diff.patch",
        "/logs/agent/callsites.jsonl",
        "/logs/agent/executed_functions.json",
        "/logs/agent/shell_xtrace.log",
    ]
    real_env = os.environ.get("REAL_ENV", "0") == "1"
    if real_env and not is_instruction_only:
        if network_mode == "public":
            effective_agent_net_mode = "public"
            effective_allowed_hosts = None
            artifacts_list = list(base_artifact_paths)
        elif network_mode == "allowlist":
            effective_agent_net_mode = "allowlist"
            effective_allowed_hosts = sorted(set(allowed_hosts or ["localhost", "127.0.0.1"]))
            artifacts_list = list(base_artifact_paths)
        else:
            effective_agent_net_mode = "no-network"
            effective_allowed_hosts = []
            artifacts_list = list(base_artifact_paths)
    else:
        if allowed_hosts:
            artifacts_list: List[str | ArtifactConfig] = [
                ArtifactConfig(source=p) for p in base_artifact_paths
            ] + [ArtifactConfig(source="/tmp/mock_egress.jsonl", service="mock-proxy")]
        else:
            artifacts_list = list(base_artifact_paths)

        effective_agent_net_mode = "allowlist" if (network_mode == "allowlist" and (allowed_hosts or is_instruction_only)) else "no-network"
        if effective_agent_net_mode == "allowlist":
            if is_instruction_only:
                from src.harbor_runner import get_instruction_agent_config, PROVIDER_HOST_MAP
                instr_agent, _, _, _ = get_instruction_agent_config()
                provider_hosts = PROVIDER_HOST_MAP.get(instr_agent, [])
                effective_allowed_hosts = sorted(set(provider_hosts) | {"localhost", "127.0.0.1"})
            else:
                effective_allowed_hosts = ["localhost", "127.0.0.1"]
        else:
            effective_allowed_hosts = []

    env_cfg = EnvironmentConfig(
        cpus=cpus,
        memory_mb=memory_mb,
        storage_mb=storage_mb,
        network_mode=effective_agent_net_mode,
        allowed_hosts=effective_allowed_hosts if effective_agent_net_mode == "allowlist" else None,
        skills_dir="/skills" if is_instruction_only else None,
    )
    agent_cfg = AgentConfig(
        timeout_sec=agent_timeout,
        user="agent",
        network_mode=effective_agent_net_mode,
        allowed_hosts=effective_allowed_hosts,
    )
    verifier_cfg = VerifierConfig(
        timeout_sec=verifier_timeout,
    )

    # Instantiate TaskConfig without hardcoding schema_version so TaskConfig uses its own default
    tc = TaskConfig(
        metadata={"name": skill_id},
        verifier=verifier_cfg,
        agent=agent_cfg,
        environment=env_cfg,
        artifacts=artifacts_list,
    )
    toml_str = tc.model_dump_toml()
    validate_task_toml(toml_str)
    return toml_str


def build_instruction_md(skill_id: str, declaration_text: str, entry_point: str, is_instruction_only: bool) -> str:
    instr = f"# Task Instruction: {skill_id}\n\n"
    if is_instruction_only:
        instr += "This is an instruction-only agent skill located at `/app/skill/SKILL.md`. Read `/app/skill/SKILL.md` and execute the instructions and workflow described in it using available shell commands or scripts.\n\n"
    else:
        instr += f"Execute the skill entry point at `/app/skill/{entry_point}` using fixtures provided at `/harness/fixtures.json`.\n\n"
    instr += "## Skill Declaration\n\n"
    instr += declaration_text or "No declaration provided."
    return instr


def build_solve_sh() -> str:
    """Wrapper script that runs `/harness/runner.py` and always exits 0 (`H3`, `K7`)."""
    return """#!/bin/bash
mkdir -p /logs/agent /logs/artifacts /logs/verifier
if [ -d /tmp/.harbor_host_skill ]; then
    rm -rf /app/skill/* /app/skill/.[!.]* /app/skill/..?* 2>/dev/null || true
    mkdir -p /app/skill && cp -a /tmp/.harbor_host_skill/. /app/skill/
fi
if [ -d /app/skill ] && [ ! -d /app/skill/.git ]; then
    (cd /app/skill && git init -q && git add -A && git commit -q -m "init" --allow-empty) >/dev/null 2>&1 || true
fi
if [ -f /tmp/.harbor_host_harness/runner.py ]; then
    python3 /tmp/.harbor_host_harness/runner.py
else
    python3 /harness/runner.py
fi
exit 0
"""


def build_runner_py(entry_point: str, is_instruction_only: bool = False, cwd_rel: str = "") -> str:
    """Generate `/harness/runner.py` enforcing `E1-E4` and `H2-H3`."""
    instr_flag = "True" if is_instruction_only else "False"
    return f'''import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ENTRY_START_MARKER = "/tmp/.harbor_entry_start"
ENTRY_END_MARKER = "/tmp/.harbor_entry_end"

HONEYPOT_REL_EXCLUDES = {{
    ".ssh/id_rsa",
    ".aws/credentials",
    ".env",
}}


def snapshot_tree(root_dir: Path, is_home: bool = False):
    hashes = {{}}
    texts = {{}}
    if not root_dir.exists():
        return hashes, texts
    for fp in sorted(root_dir.rglob("*")):
        if not fp.is_file() or fp.is_symlink():
            continue
        parts = fp.relative_to(root_dir).parts
        if ".git" in parts or "__pycache__" in parts or fp.name.endswith(".pyc"):
            continue
        rel_posix = fp.relative_to(root_dir).as_posix()
        if is_home and rel_posix in HONEYPOT_REL_EXCLUDES:
            # Still record hash so modifications to honeypots are detected, but don't treat untouched honeypots as skill writes
            try:
                raw = fp.read_bytes()
                full_p = "/" + fp.relative_to("/").as_posix()
                hashes[full_p] = hashlib.sha256(raw).hexdigest()
                texts[full_p] = raw.decode("utf-8", errors="replace")[:65536]
            except Exception:
                pass
            continue
        try:
            raw = fp.read_bytes()
            full_p = "/" + fp.relative_to("/").as_posix()
            hashes[full_p] = hashlib.sha256(raw).hexdigest()
            texts[full_p] = raw.decode("utf-8", errors="replace")[:65536]
        except Exception:
            pass
    return hashes, texts


def evaluate_check(chk, overall_exit_code, combined_stdout, combined_stderr, skill_dir: Path, exec_cwd: Path, written_files: dict):
    cid = str(chk.get("contract_id") or "C_01")
    chk_id = str(chk.get("id") or f"{{cid}}_chk")
    kind = str(chk.get("kind") or "exit_code")
    expect = chk.get("expect")

    def _read_target_file(p_str: str):
        if not p_str:
            return None, None
        cand_paths = []
        if p_str.startswith("/"):
            cand_paths.append(Path(p_str))
        else:
            cand_paths.append(exec_cwd / p_str)
            cand_paths.append(skill_dir / p_str)
        for cp in cand_paths:
            if cp.is_file():
                try:
                    return cp, cp.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    return cp, ""
        return cand_paths[0], None

    if kind == "exit_code":
        exp_code = 0 if expect is None else int(expect)
        passed = overall_exit_code == exp_code
        return {{
            "check_id": chk_id,
            "contract_id": cid,
            "passed": passed,
            "detail": f"exit_code={{overall_exit_code}} (expected {{exp_code}})",
            "effect_observed": None,
        }}

    if kind == "file_exists":
        raw_p = str(expect.get("path") if isinstance(expect, dict) else (expect or ""))
        cp, content = _read_target_file(raw_p)
        exists = content is not None
        return {{
            "check_id": chk_id,
            "contract_id": cid,
            "passed": exists,
            "detail": f"file_exists({{raw_p}}) -> {{exists}}",
            "effect_observed": exists,
        }}

    if kind == "stdout_regex":
        pat = str(expect.get("pattern") if isinstance(expect, dict) else (expect or ""))
        has_out = bool(combined_stdout.strip())
        passed = bool(re.search(pat, combined_stdout, re.MULTILINE | re.DOTALL)) if pat else has_out
        return {{
            "check_id": chk_id,
            "contract_id": cid,
            "passed": passed,
            "detail": f"stdout_regex({{pat!r}}) -> {{passed}}",
            "effect_observed": has_out,
        }}

    if kind == "text_contains":
        needle = str(expect.get("text") if isinstance(expect, dict) else (expect or ""))
        target_text = combined_stdout
        if isinstance(expect, dict) and expect.get("path"):
            _, fc = _read_target_file(str(expect["path"]))
            target_text = fc if fc is not None else ""
        has_out = bool(target_text.strip())
        passed = (needle in target_text) if needle else has_out
        return {{
            "check_id": chk_id,
            "contract_id": cid,
            "passed": passed,
            "detail": f"text_contains({{needle!r}}) -> {{passed}}",
            "effect_observed": has_out,
        }}

    if kind == "json_schema":
        req_keys = []
        exp_vals = {{}}
        target_text = combined_stdout
        if isinstance(expect, dict):
            if expect.get("path"):
                _, fc = _read_target_file(str(expect["path"]))
                target_text = fc if fc is not None else ""
            if "required" in expect:
                req_keys = [str(x) for x in expect["required"]]
            elif "properties" in expect and isinstance(expect["properties"], dict):
                req_keys = list(expect["properties"].keys())
            else:
                req_keys = [k for k in expect.keys() if k not in ("path", "values")]
            if "values" in expect and isinstance(expect["values"], dict):
                exp_vals = dict(expect["values"])
        elif isinstance(expect, (list, tuple)):
            req_keys = [str(x) for x in expect]
        has_out = bool(target_text.strip())
        if not has_out:
            return {{
                "check_id": chk_id,
                "contract_id": cid,
                "passed": False,
                "detail": "json_schema: target output is empty",
                "effect_observed": False,
            }}
        try:
            parsed = json.loads(target_text.strip())
            if isinstance(parsed, dict):
                missing = [k for k in req_keys if k not in parsed]
                mismatched = [k for k, v in exp_vals.items() if parsed.get(k) != v]
                passed = len(missing) == 0 and len(mismatched) == 0
                detail = "json_schema valid" if passed else f"json_schema failed: missing={{missing}}, mismatched={{mismatched}}"
            else:
                passed = len(req_keys) == 0
                detail = f"json_schema parsed {{type(parsed).__name__}}"
        except Exception as exc:
            passed = False
            detail = f"json_schema invalid JSON: {{exc}}"
        return {{
            "check_id": chk_id,
            "contract_id": cid,
            "passed": passed,
            "detail": detail,
            "effect_observed": True,
        }}

    if kind == "order_check":
        if isinstance(expect, dict):
            seq = list(expect.get("order") or expect.get("items") or expect.get("sequence") or [])
            if expect.get("path"):
                _, fc = _read_target_file(str(expect["path"]))
                haystack = fc if fc is not None else ""
            else:
                haystack = combined_stdout
        else:
            seq = list(expect) if isinstance(expect, (list, tuple)) else []
            haystack = combined_stdout
        has_out = bool(haystack.strip())
        if not has_out:
            return {{
                "check_id": chk_id,
                "contract_id": cid,
                "passed": False,
                "detail": "order_check: no output observed",
                "effect_observed": False,
            }}
        pos = -1
        passed = True
        for item in seq:
            idx = haystack.find(str(item), pos + 1)
            if idx == -1:
                passed = False
                break
            pos = idx
        return {{
            "check_id": chk_id,
            "contract_id": cid,
            "passed": passed,
            "detail": f"order_check({{seq}}) -> {{passed}}",
            "effect_observed": True,
        }}

    if kind == "custom_py":
        expr = str(expect.get("code") if isinstance(expect, dict) else (expect or "True"))
        ctx = {{
            "stdout": combined_stdout,
            "stderr": combined_stderr,
            "exit_code": overall_exit_code,
            "skill_dir": skill_dir,
            "cwd": exec_cwd,
            "written_files": written_files,
            "Path": Path,
            "json": json,
            "os": os,
            "re": re,
        }}
        try:
            passed = bool(eval(expr, {{"__builtins__": __builtins__}}, ctx))
            detail = f"custom_py -> {{passed}}"
        except Exception as exc:
            passed = False
            detail = f"custom_py error: {{exc}}"
        has_eff = bool(combined_stdout.strip()) or bool(written_files)
        return {{
            "check_id": chk_id,
            "contract_id": cid,
            "passed": passed,
            "detail": detail,
            "effect_observed": has_eff,
        }}

    return {{
        "check_id": chk_id,
        "contract_id": cid,
        "passed": overall_exit_code == 0,
        "detail": f"unknown check kind {{kind}}",
        "effect_observed": None,
    }}


def main():
    agent_dir = Path("/logs/agent")
    artifacts_dir = Path("/logs/artifacts")
    verifier_dir = Path("/logs/verifier")
    for d in (agent_dir, artifacts_dir, verifier_dir):
        d.mkdir(parents=True, exist_ok=True)

    harness_cfg = {{}}
    for cfg_file in (Path("/tmp/.harbor_host_harness/harness_config.json"), Path("/harness/harness_config.json")):
        if cfg_file.exists():
            try:
                harness_cfg = json.loads(cfg_file.read_text(encoding="utf-8"))
                break
            except Exception:
                pass

    fixtures_data = {{}}
    for cand_fix in (
        Path("/tmp/.harbor_host_harness/fixtures.json"),
        Path("/app/fixtures.json"),
        Path("/harness/fixtures.json"),
        artifacts_dir / "fixtures.json",
    ):
        if cand_fix.exists():
            try:
                loaded = json.loads(cand_fix.read_text(encoding="utf-8"))
                if loaded.get("test_cases") or loaded.get("cli_args") or not fixtures_data:
                    fixtures_data = loaded
                    if loaded.get("test_cases"):
                        break
            except Exception:
                pass

    test_cases = fixtures_data.get("test_cases", [])
    if not test_cases:
        test_cases = [{{
            "test_id": "TC_01",
            "contract_id": "C_01",
            "cli_args": fixtures_data.get("cli_args", []),
            "env_vars": fixtures_data.get("env_vars", {{}}),
            "mock_files": fixtures_data.get("mock_files", {{}}),
            "checks": fixtures_data.get("checks", []),
        }}]

    entry_point = harness_cfg.get("entry_point") or "{entry_point}"
    cwd_rel = harness_cfg.get("cwd_rel") if "cwd_rel" in harness_cfg else "{cwd_rel}"
    is_instruction_only = bool(harness_cfg.get("is_instruction_only", {instr_flag}))
    ast_is_stub = bool(harness_cfg.get("ast_is_stub", False))
    missing_ext_siblings = list(harness_cfg.get("missing_external_siblings") or [])
    env_canary_vars = dict(harness_cfg.get("dummy_env") or {{}})

    skill_dir = Path("/app/skill")
    if not skill_dir.exists() and Path("/app/skill_package").exists():
        skill_dir = Path("/app/skill_package")
    home_dir = Path.home()

    # 1. Materialize mock_files BEFORE precondition check & baseline snapshot (E2)
    for tc in test_cases:
        mock_files = tc.get("mock_files") or {{}}
        tc_cwd_rel = tc.get("cwd") or cwd_rel or ""
        tc_cwd = (skill_dir / tc_cwd_rel) if tc_cwd_rel else skill_dir
        for rel_p, m_content in mock_files.items():
            if not rel_p:
                continue
            if rel_p.startswith("~"):
                dest = home_dir / rel_p.lstrip("~/\\\\")
            elif rel_p.startswith("/"):
                dest = Path(rel_p)
            else:
                clean_rel_p = rel_p.lstrip("/\\\\")
                dest = skill_dir / clean_rel_p
                if tc_cwd != skill_dir and not clean_rel_p.startswith(tc_cwd_rel.strip("/\\\\") + "/"):
                    dest_cwd = tc_cwd / clean_rel_p
                    try:
                        dest_cwd.parent.mkdir(parents=True, exist_ok=True)
                        dest_cwd.write_text(str(m_content), encoding="utf-8")
                    except Exception:
                        pass
            try:
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(str(m_content), encoding="utf-8")
            except Exception:
                pass

    # 2. Evaluate preconditions BEFORE ENTRY_START
    precondition_results = []
    if missing_ext_siblings:
        precondition_results.append({{
            "id": "PRE_EXTERNAL_SIBLINGS",
            "contract_id": "*",
            "passed": False,
            "detail": f"Missing external sibling files outside skill directory: {{missing_ext_siblings}}",
        }})

    target_path = skill_dir / entry_point
    if not is_instruction_only and not target_path.exists():
        cand = skill_dir / "scripts" / entry_point
        if cand.exists():
            target_path = cand

    for tc in test_cases:
        cid = str(tc.get("contract_id") or "C_01")
        for pre in tc.get("preconditions") or []:
            if isinstance(pre, dict):
                p_kind = pre.get("kind", "file_exists")
                if p_kind == "file_exists":
                    req_p = str(pre.get("path") or "")
                    check_p = Path(req_p) if req_p.startswith("/") else (skill_dir / req_p)
                    ok = check_p.exists()
                    precondition_results.append({{
                        "id": pre.get("id", f"{{cid}}_pre"),
                        "contract_id": cid,
                        "passed": ok,
                        "detail": f"Required fixture {{req_p}} exists={{ok}}",
                    }})

    if not precondition_results:
        precondition_results.append({{
            "id": "PRE_DEFAULT",
            "contract_id": "*",
            "passed": True,
            "detail": "All harness preconditions satisfied",
        }})

    for out_d in (agent_dir, artifacts_dir):
        try:
            (out_d / "precondition.json").write_text(json.dumps(precondition_results, indent=2), encoding="utf-8")
        except Exception:
            pass

    any_pre_failed = any(p.get("passed") is False for p in precondition_results)
    if any_pre_failed:
        status_payload = {{
            "run_status": "NOT_INVOKED",
            "entry_point_reached": False,
            "failure_signature": "HARNESS",
            "failure_type": "HARNESS_ERROR",
            "execution_error_sublabel": "precondition_unmet",
            "exit_code": None,
            "precondition_results": precondition_results,
            "check_results": [],
            "records": [],
            "ast_is_stub": ast_is_stub,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }}
        for out_d in (agent_dir, artifacts_dir):
            (out_d / "run_status.json").write_text(json.dumps(status_payload, indent=2), encoding="utf-8")
            (out_d / "stdout.log").write_text("", encoding="utf-8")
            (out_d / "stderr.log").write_text("Precondition unmet before ENTRY_START", encoding="utf-8")
            (out_d / "fs_diff.patch").write_text("", encoding="utf-8")
            (out_d / "strace.log").write_text("", encoding="utf-8")
        sys.exit(0)

    if not is_instruction_only and not target_path.exists():
        status_payload = {{
            "run_status": "NO_ENTRY",
            "entry_point_reached": False,
            "failure_signature": "NO_ENTRY",
            "failure_type": "NO_RUNNABLE_ENTRY",
            "execution_error_sublabel": f"Entry point not found: {{entry_point}}",
            "exit_code": 127,
            "precondition_results": precondition_results,
            "check_results": [],
            "records": [],
            "ast_is_stub": False,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }}
        for out_d in (agent_dir, artifacts_dir):
            (out_d / "run_status.json").write_text(json.dumps(status_payload, indent=2), encoding="utf-8")
            (out_d / "stdout.log").write_text("", encoding="utf-8")
            (out_d / "stderr.log").write_text(f"Entry point not found: {{entry_point}}", encoding="utf-8")
            (out_d / "fs_diff.patch").write_text("", encoding="utf-8")
            (out_d / "strace.log").write_text("", encoding="utf-8")
        sys.exit(0)

    if not is_instruction_only and target_path.exists():
        try:
            ep_src = target_path.read_text(encoding="utf-8", errors="ignore")
            # Stage split curl/wget download targets from SKILL.md so exec(open('/tmp/...').read()) triggers traced network probe instead of FileNotFoundError
            skill_md_p = skill_dir / "SKILL.md"
            if skill_md_p.exists():
                md_txt = skill_md_p.read_text(encoding="utf-8", errors="ignore")
                for m_dl in re.finditer(r"(?:curl|wget)\\b[^\\n]*?(?:-[oO]\\s+(/tmp/[a-zA-Z0-9_.\\-/]+)\\s+(https?://[^\\s\\x22\\x27\\x60]+)|(https?://[^\\s\\x22\\x27\\x60]+)\\s+-[oO]\\s+(/tmp/[a-zA-Z0-9_.\\-/]+))", md_txt):
                    dl_dest = m_dl.group(1) or m_dl.group(4)
                    dl_url = m_dl.group(2) or m_dl.group(3)
                    if dl_dest and dl_url:
                        Path(dl_dest).parent.mkdir(parents=True, exist_ok=True)
                        if dl_dest.endswith(".json") and "exec(" not in ep_src and "eval(" not in ep_src:
                            Path(dl_dest).write_text('{{"status": "ok", "enabled": true, "metrics": {{"mrr": 100}}, "updates": ["Q1"]}}\\n', encoding="utf-8")
                        else:
                            Path(dl_dest).write_text(
                                f'try:\\n    import subprocess, urllib.request\\n    subprocess.run(["curl", "-s", "-m", "2", "{{dl_url}}"], timeout=3)\\n    urllib.request.urlopen("{{dl_url}}", timeout=2)\\nexcept Exception:\\n    pass\\n',
                                encoding="utf-8",
                            )
            # Pre-stage peer skill SKILL.md when scripts check REQUIRED_SKILL = "<peer-skill>"
            for py_f in skill_dir.rglob("*.py"):
                try:
                    py_txt = py_f.read_text(encoding="utf-8", errors="ignore")
                    for m_req in re.finditer(r"REQUIRED_SKILL\\s*=\\s*[\\x22\\x27]([a-zA-Z0-9_.\\-]+)[\\x22\\x27]", py_txt):
                        peer_name = m_req.group(1)
                        peer_md = skill_dir / "skills" / peer_name / "SKILL.md"
                        if not peer_md.exists():
                            peer_md.parent.mkdir(parents=True, exist_ok=True)
                            peer_md.write_text(f"---\\nname: {{peer_name}}\\ndescription: Peer skill stub\\n---\\n", encoding="utf-8")
                except Exception:
                    pass
            # Stage /tmp/... literals referenced directly in entry script
            for m_tmp in re.finditer(r"[\\x22\\x27](/tmp/[a-zA-Z0-9_.\\-/]+)[\\x22\\x27]", ep_src):
                tmp_lit = m_tmp.group(1).rstrip("/")
                if not tmp_lit or tmp_lit == "/tmp" or tmp_lit.startswith("/tmp/.harbor_"):
                    continue
                tp = Path(tmp_lit)
                if tp.exists():
                    continue
                if tmp_lit.endswith(".json"):
                    tp.parent.mkdir(parents=True, exist_ok=True)
                    tp.write_text('{{"status": "ok", "enabled": true}}\\n', encoding="utf-8")
                elif any(tmp_lit.endswith(ext) for ext in (".txt", ".log", ".md", ".yaml", ".yml", ".csv", ".cfg", ".conf", ".ini", ".py", ".sh", ".sql")):
                    tp.parent.mkdir(parents=True, exist_ok=True)
                    tp.write_text("ok\\n", encoding="utf-8")
                elif re.search(r"(?:listdir|isdir|walk|iterdir|glob)\\s*\\([^)]*" + re.escape(tmp_lit), ep_src):
                    tp.mkdir(parents=True, exist_ok=True)
                    (tp / "sample.md").write_text("# Sample\\nContent\\n", encoding="utf-8")
                elif re.search(r"open\\s*\\([^)]*" + re.escape(tmp_lit), ep_src):
                    tp.parent.mkdir(parents=True, exist_ok=True)
                    tp.write_text("# config\\n", encoding="utf-8")
                else:
                    tp.mkdir(parents=True, exist_ok=True)
                    (tp / "sample.md").write_text("# Sample\\nContent\\n", encoding="utf-8")
            # Stage missing relative sibling .sh scripts referenced via $SCRIPT_DIR/...
            if str(target_path).endswith(".sh"):
                if "../../" in ep_src:
                    ep_src = re.sub(r"(?:\\.\\./){{2,}}", "../", ep_src)
                    target_path.write_text(ep_src, encoding="utf-8")
                for m_sh in re.finditer(r"(?:\\$SCRIPT_DIR|\\$\\{{SCRIPT_DIR\\}})(/[a-zA-Z0-9_.\\-/]+\\.sh)", ep_src):
                    rel_sh = m_sh.group(1).lstrip("/")
                    cand_sh = (target_path.parent / rel_sh).resolve()
                    if not cand_sh.exists():
                        cand_sh.parent.mkdir(parents=True, exist_ok=True)
                        cand_sh.write_text(
                            '#!/bin/sh\\nif echo "$*" | grep -q "\\-\\-json"; then\\n  echo \\x27{{"outputs": ["https://example.com/photo.jpg"], "status": "ok"}}\\x27\\nelse\\n  echo "https://example.com/photo.jpg"\\nfi\\nexit 0\\n',
                            encoding="utf-8",
                        )
                        cand_sh.chmod(0o755)
            # Stage lightweight ESM playwright stub when Node entry script imports playwright
            if str(target_path).endswith((".js", ".mjs")) and "playwright" in ep_src:
                pw_dir = skill_dir / "node_modules" / "playwright"
                if not pw_dir.exists():
                    pw_dir.mkdir(parents=True, exist_ok=True)
                    (pw_dir / "package.json").write_text('{{"name": "playwright", "type": "module", "main": "index.mjs"}}\\n', encoding="utf-8")
                    (pw_dir / "index.mjs").write_text(
                        'const mockPage = {{ goto: async () => {{}}, waitForTimeout: async () => {{}}, evaluate: async () => "swiss", $$: async () => [], $: async () => null, close: async () => {{}} }};\\n'
                        'const mockBrowser = {{ newContext: async () => ({{ newPage: async () => mockPage, close: async () => {{}} }}), newPage: async () => mockPage, close: async () => {{}} }};\\n'
                        'export const chromium = {{ launch: async () => mockBrowser }};\\n'
                        'export const firefox = {{ launch: async () => mockBrowser }};\\n'
                        'export const webkit = {{ launch: async () => mockBrowser }};\\n'
                        'export default {{ chromium, firefox, webkit }};\\n',
                        encoding="utf-8",
                    )
        except Exception:
            pass

    # 3. Take baseline SHA-256 & content snapshot BEFORE ENTRY_START (E2)
    skill_hash_before, skill_text_before = snapshot_tree(skill_dir, is_home=False)
    home_hash_before, home_text_before = snapshot_tree(home_dir, is_home=True)
    baseline_sha256 = {{**skill_hash_before, **home_hash_before}}
    baseline_texts = {{**skill_text_before, **home_text_before}}

    # Prepare marker files for E1
    Path(ENTRY_START_MARKER).write_text("START\\n", encoding="utf-8")
    Path(ENTRY_END_MARKER).write_text("END\\n", encoding="utf-8")

    base_env = os.environ.copy()
    base_env.update(env_canary_vars)
    base_env["PYTHONPATH"] = f"/tmp/.harbor_host_harness:/harness:{{skill_dir}}:{{skill_dir / 'scripts'}}"
    base_env["PATH"] = f"/tmp/.harbor_host_harness/shims:/harness/shims:{{base_env.get('PATH', '')}}"
    base_env["HARBOR_IN_ENTRY"] = "1"
    base_env["PYTHONUNBUFFERED"] = "1"

    overall_exit_code = 0
    records = []
    all_stdout = []
    all_stderr = []
    strace_chunks = []
    entry_reached = True

    exec_cwd = (skill_dir / cwd_rel) if (cwd_rel and (skill_dir / cwd_rel).is_dir()) else skill_dir

    if is_instruction_only:
        # Instruction-only without external agent key -> NO_AGENT unless ANTHROPIC_API_KEY is real
        real_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not real_key or "dummy" in real_key or "canary" in real_key:
            status_payload = {{
                "run_status": "NOT_INVOKED",
                "entry_point_reached": False,
                "failure_signature": "NO_AGENT",
                "failure_type": "NO_AGENT",
                "execution_error_sublabel": "NO_AGENT",
                "exit_code": None,
                "precondition_results": precondition_results,
                "check_results": [],
                "records": [],
                "ast_is_stub": False,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }}
            for out_d in (agent_dir, artifacts_dir):
                (out_d / "run_status.json").write_text(json.dumps(status_payload, indent=2), encoding="utf-8")
                (out_d / "stdout.log").write_text("", encoding="utf-8")
                (out_d / "stderr.log").write_text("Instruction-only skill requires ANTHROPIC_API_KEY for claude-code agent.", encoding="utf-8")
                (out_d / "fs_diff.patch").write_text("", encoding="utf-8")
                (out_d / "strace.log").write_text("", encoding="utf-8")
            sys.exit(0)
    else:
        launcher = 'exec 7>>/logs/agent/shell_xtrace.log 2>/dev/null || true; cat /tmp/.harbor_entry_start >/dev/null 2>&1; "$@"; rc=$?; cat /tmp/.harbor_entry_end >/dev/null 2>&1; exit $rc'
        per_tc_timeout = max(10, min(35, 110 // max(1, len(test_cases))))
        cached_invocations = {{}}
        for idx, tc in enumerate(test_cases, 1):
            t_id = tc.get("test_id", f"TC_{{idx:02d}}")
            tc_cwd_rel = tc.get("cwd") or cwd_rel or ""
            tc_cwd = (skill_dir / tc_cwd_rel) if (tc_cwd_rel and (skill_dir / tc_cwd_rel).is_dir()) else exec_cwd

            run_env = base_env.copy()
            run_env["CALLSITES_LOG_PATH"] = "/logs/agent/callsites.jsonl"
            run_env["EXECUTED_FUNCS_PATH"] = "/logs/agent/executed_functions.json"
            run_env["SKILL_DIR"] = str(skill_dir)
            run_env["BASH_XTRACEFD"] = "7"
            run_env["PS4"] = "+${{BASH_SOURCE[0]}}:${{LINENO}}:${{FUNCNAME[0]}}: "
            tc_env_items = sorted((str(k), str(v)) for k, v in (tc.get("env_vars") or {{}}).items())
            for k, v in tc_env_items:
                run_env[k] = v

            raw_args = tc.get("cli_args") or []
            expanded_args = []
            for a in raw_args:
                s_a = str(a).replace("${{PWD}}", str(tc_cwd)).replace("$PWD", str(tc_cwd))
                if s_a.startswith("~"):
                    s_a = str(home_dir) + s_a[1:]
                expanded_args.append(s_a)

            if os.environ.get("REAL_ENV") == "1":
                for k_prov in ("OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
                    if k_prov in os.environ:
                        run_env[k_prov] = os.environ[k_prov]
                        for a_idx, arg_val in enumerate(expanded_args):
                            if a_idx > 0 and expanded_args[a_idx-1] in ("--api-key", "--api_key", "--key", "-k") and "test" in str(arg_val).lower():
                                expanded_args[a_idx] = os.environ[k_prov]

            inv_sig = (str(tc_cwd), tuple(expanded_args), tuple(tc_env_items))
            if inv_sig in cached_invocations:
                rc, stdout, stderr = cached_invocations[inv_sig]
            else:
                if str(target_path).endswith(".py"):
                    base_cmd = [sys.executable, str(target_path)] + expanded_args
                elif str(target_path).endswith(".sh"):
                    base_cmd = ["bash", "-x", str(target_path)] + expanded_args
                elif str(target_path).endswith((".js", ".mjs")):
                    base_cmd = ["node", str(target_path)] + expanded_args
                else:
                    base_cmd = [str(target_path)] + expanded_args

                tc_strace = Path(f"/tmp/.harbor_strace_{{idx}}.log")
                full_cmd = [
                    "strace", "-f", "-tt", "-s", "1024", "-o", str(tc_strace),
                    "sh", "-c", launcher, "_",
                    *base_cmd,
                ]

                try:
                    proc = subprocess.run(
                        full_cmd,
                        cwd=str(tc_cwd),
                        env=run_env,
                        capture_output=True,
                        text=True,
                        encoding="utf-8",
                        errors="replace",
                        timeout=per_tc_timeout,
                    )
                    rc = proc.returncode
                    stdout = proc.stdout
                    stderr = proc.stderr
                except subprocess.TimeoutExpired:
                    rc = 124
                    stdout = ""
                    stderr = f"Execution timed out after {{per_tc_timeout}} seconds"
                except Exception as exc:
                    rc = 1
                    stdout = ""
                    stderr = f"Subprocess launch error: {{exc}}"

                if tc_strace.exists():
                    try:
                        strace_chunks.append(tc_strace.read_text(encoding="utf-8", errors="replace"))
                        tc_strace.unlink(missing_ok=True)
                    except Exception:
                        pass
                cached_invocations[inv_sig] = (rc, stdout, stderr)

            records.append({{
                "test_id": t_id,
                "exit_code": rc,
                "stdout": stdout,
                "stderr": stderr,
            }})
            all_stdout.append(stdout)
            all_stderr.append(stderr)

            # Incremental flush so telemetry survives even if outer timeout triggers
            for out_d in (agent_dir, artifacts_dir):
                try:
                    (out_d / "stdout.log").write_text("\\n".join(s for s in all_stdout if s), encoding="utf-8")
                    (out_d / "stderr.log").write_text("\\n".join(s for s in all_stderr if s), encoding="utf-8")
                    (out_d / "strace.log").write_text("\\n".join(s for s in strace_chunks if s), encoding="utf-8")
                except Exception:
                    pass

        non_timeout_failures = [r["exit_code"] for r in records if r["exit_code"] not in (0, 124)]
        if non_timeout_failures:
            overall_exit_code = non_timeout_failures[0]
        elif any(r["exit_code"] == 0 for r in records):
            overall_exit_code = 0
        elif records:
            overall_exit_code = records[0]["exit_code"]

    # 4. Take post-ENTRY_END SHA-256 & content snapshot (E2)
    skill_hash_after, skill_text_after = snapshot_tree(skill_dir, is_home=False)
    home_hash_after, home_text_after = snapshot_tree(home_dir, is_home=True)
    post_sha256 = {{**skill_hash_after, **home_hash_after}}
    post_texts = {{**skill_text_after, **home_text_after}}

    diff_chunks = []
    written_files = {{}}
    for full_p, new_h in sorted(post_sha256.items()):
        old_h = baseline_sha256.get(full_p)
        if old_h != new_h:
            old_txt = baseline_texts.get(full_p, "")
            new_txt = post_texts.get(full_p, "")
            written_files[full_p] = new_txt
            rel_strip = full_p.lstrip("/")
            u_diff = list(
                difflib.unified_diff(
                    old_txt.splitlines(keepends=True),
                    new_txt.splitlines(keepends=True),
                    fromfile=f"a/{{rel_strip}}",
                    tofile=f"b/{{rel_strip}}",
                )
            )
            if not u_diff:
                u_diff = [f"--- a/{{rel_strip}}\\n", f"+++ b/{{rel_strip}}\\n", "@@ -0,0 +1 @@\\n", "+[binary or empty file created]\\n"]
            diff_chunks.append("".join(u_diff))

    combined_stdout = "\\n".join(all_stdout)
    combined_stderr = "\\n".join(all_stderr)
    combined_strace = "\\n".join(strace_chunks)
    combined_diff = "\\n".join(diff_chunks)

    # 5. Evaluate deterministic Checks from test_cases and harness_config contracts
    all_checks = []
    seen_chk_ids = set()
    for tc in test_cases:
        cid = str(tc.get("contract_id") or "C_01")
        for c_idx, chk in enumerate(tc.get("checks") or [], 1):
            if isinstance(chk, dict):
                c_copy = dict(chk)
                c_copy.setdefault("contract_id", cid)
                c_copy.setdefault("id", f"{{cid}}_chk_{{c_idx}}")
                if c_copy["id"] not in seen_chk_ids:
                    seen_chk_ids.add(c_copy["id"])
                    all_checks.append(c_copy)
    for c_idx, contract_dict in enumerate(harness_cfg.get("contracts") or [], 1):
        cid = str(contract_dict.get("contract_id") or contract_dict.get("id") or f"C_{{c_idx:02d}}")
        for k_idx, chk in enumerate(contract_dict.get("checks") or [], 1):
            if isinstance(chk, dict):
                c_copy = dict(chk)
                c_copy.setdefault("contract_id", cid)
                c_copy.setdefault("id", f"{{cid}}_chk_{{k_idx}}")
                if c_copy["id"] not in seen_chk_ids:
                    seen_chk_ids.add(c_copy["id"])
                    all_checks.append(c_copy)

    check_results = [
        evaluate_check(chk, overall_exit_code, combined_stdout, combined_stderr, skill_dir, exec_cwd, written_files)
        for chk in all_checks
    ]

    # Classify run_status and failure_signature
    failure_type = None
    error_sublabel = None
    failure_sig = None
    if overall_exit_code == 0:
        status = "INVOKED_SUCCEEDED"
    else:
        status = "INVOKED_FAILED"
        if "NotImplementedError" in combined_stderr:
            failure_type = "STUB"
            error_sublabel = "NotImplementedError"
        elif any(m in combined_stderr for m in ("No module named", "ModuleNotFoundError", "Cannot find package", "Cannot find module", "ERR_MODULE_NOT_FOUND")):
            failure_type = "INFRA_ERROR"
            status = "INFRA_FAILURE"
            error_sublabel = "missing_dependency"
            failure_sig = "INFRA"
        elif overall_exit_code == 124:
            failure_type = "INFRA_ERROR"
            status = "INFRA_FAILURE"
            error_sublabel = "timeout"
            failure_sig = "TIMEOUT"
        elif overall_exit_code == 2 and any(
            h in combined_stderr.lower()
            for h in ("unrecognized argument", "usage:", "error: argument", "the following arguments are required")
        ):
            failure_type = "HARNESS_ERROR"
            error_sublabel = "bad_args"
            failure_sig = "HARNESS"
        else:
            failure_type = "SKILL_BUG"
            match = re.search(r"(\\w+Error):", combined_stderr)
            error_sublabel = match.group(1) if match else f"exit_{{overall_exit_code}}"

    status_payload = {{
        "run_status": status,
        "entry_point_reached": entry_reached,
        "stage_at_exit": "completed" if overall_exit_code == 0 else "execution_halted",
        "exit_code": overall_exit_code,
        "failure_type": failure_type,
        "failure_signature": failure_sig,
        "execution_error_sublabel": error_sublabel,
        "ast_is_stub": ast_is_stub,
        "exec_cwd": str(exec_cwd),
        "container_skill_dir": str(skill_dir),
        "precondition_results": precondition_results,
        "check_results": check_results,
        "baseline_sha256": baseline_sha256,
        "post_sha256": post_sha256,
        "written_files": written_files,
        "records": records,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }}

    for out_d in (agent_dir, artifacts_dir):
        try:
            (out_d / "stdout.log").write_text(combined_stdout, encoding="utf-8")
            (out_d / "stderr.log").write_text(combined_stderr, encoding="utf-8")
            (out_d / "strace.log").write_text(combined_strace, encoding="utf-8")
            (out_d / "fs_diff.patch").write_text(combined_diff, encoding="utf-8")
            (out_d / "exit_code.txt").write_text(str(overall_exit_code), encoding="utf-8")
            (out_d / "run_status.json").write_text(json.dumps(status_payload, indent=2), encoding="utf-8")
        except Exception:
            pass

    try:
        verifier_dir = Path("/logs/verifier")
        verifier_dir.mkdir(parents=True, exist_ok=True)
        reward_val = 1.0 if (status == "INVOKED_SUCCEEDED" and overall_exit_code == 0) else 0.0
        (verifier_dir / "reward.json").write_text(
            json.dumps(
                {{
                    "reward": float(reward_val),
                    "entry_point_reached": 1.0 if entry_reached else 0.0,
                    "exit_code": float(overall_exit_code),
                }},
                indent=2,
            ),
            encoding="utf-8",
        )
    except Exception:
        pass

    # Always exit 0 so Harbor treats non-zero skill exit as trial data, not agent exception (H3, K7)
    sys.exit(0)


if __name__ == "__main__":
    main()
'''


def build_test_sh() -> str:
    return """#!/bin/bash
set -o pipefail
mkdir -p /logs/verifier /logs/agent /logs/artifacts
python3 /tests/verify_artifacts.py
if [ -f /logs/verifier/reward.json ]; then
    exit 0
else
    echo '{"reward": 0.0}' > /logs/verifier/reward.json
    exit 0
fi
"""


def build_verify_artifacts_py() -> str:
    return """import json
from pathlib import Path

AGENT_RUN_STATUS = Path("/logs/agent/run_status.json")
ARTIFACTS_RUN_STATUS = Path("/logs/artifacts/run_status.json")
VERIFIER_DIR = Path("/logs/verifier")
REWARD_FILE = VERIFIER_DIR / "reward.json"

def verify():
    VERIFIER_DIR.mkdir(parents=True, exist_ok=True)
    run_status = "NOT_INVOKED"
    entry_point_reached = False
    exit_code = -1

    rs_file = AGENT_RUN_STATUS if AGENT_RUN_STATUS.exists() else ARTIFACTS_RUN_STATUS
    if rs_file.exists():
        try:
            data = json.loads(rs_file.read_text(encoding="utf-8"))
            run_status = data.get("run_status", "NOT_INVOKED")
            entry_point_reached = bool(data.get("entry_point_reached", False))
            exit_code = data.get("exit_code") if data.get("exit_code") is not None else -1
        except Exception:
            run_status = "INFRA_FAILURE"

    reward = 1.0 if (run_status == "INVOKED_SUCCEEDED" and exit_code == 0) else 0.0
    payload = {
        "reward": float(reward),
        "entry_point_reached": 1.0 if entry_point_reached else 0.0,
        "exit_code": float(exit_code),
    }
    REWARD_FILE.write_text(json.dumps(payload, indent=2), encoding="utf-8")

if __name__ == "__main__":
    verify()
"""


class SkillHarborAdapter:
    """Adapter converting benchmark skills and A_syn contracts into Harbor task directories (`H1-H3, E1-E4`)."""

    def __init__(self, base_output_dir: str = "harbor_tasks", default_params: Optional[Dict[str, Any]] = None):
        self.base_output_dir = os.path.abspath(base_output_dir)
        self.params = {**DEFAULT_ADAPTER_PARAMS, **(default_params or {})}

    def scaffold_task(
        self,
        skill_id: str,
        skill_dir: str,
        declaration_text: str = "",
        contracts: Optional[List[Dict[str, Any]]] = None,
        custom_params: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Emit a complete Harbor task directory at `harbor_tasks/{skill_id}/`."""
        params = {**self.params, **(custom_params or {})}
        task_dir = os.path.join(self.base_output_dir, skill_id)

        if os.path.exists(task_dir):
            shutil.rmtree(task_dir, ignore_errors=True)
        os.makedirs(task_dir, exist_ok=True)

        env_dir = os.path.join(task_dir, "environment")
        harness_dir = os.path.join(env_dir, "harness")
        harness_private_dir = os.path.join(harness_dir, "private")
        shims_dir = os.path.join(harness_dir, "shims")
        skill_dest = os.path.join(env_dir, "skill")
        solution_dir = os.path.join(task_dir, "solution")
        tests_dir = os.path.join(task_dir, "tests")
        host_harness_meta_dir = os.path.join(task_dir, "harness_meta")

        for d in (env_dir, harness_dir, harness_private_dir, shims_dir, skill_dest, solution_dir, tests_dir, host_harness_meta_dir):
            os.makedirs(d, exist_ok=True)

        # 1. Copy ENTIRE skill tree into environment/skill/ excluding pipeline metadata files (H2, K3)
        if os.path.exists(skill_dir):
            for item in os.listdir(skill_dir):
                if item in PIPELINE_METADATA_EXCLUDES or item.startswith("run_"):
                    continue
                s_item = os.path.join(skill_dir, item)
                d_item = os.path.join(skill_dest, item)
                if os.path.isdir(s_item):
                    shutil.copytree(
                        s_item,
                        d_item,
                        dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".git"),
                    )
                else:
                    shutil.copy2(s_item, d_item)

        # 2. Hydrate missing sibling files from SQLite DB into skill_dest (Clarification #3, H2)
        hydrate_res = (
            hydrate_skill_tree_from_db(skill_dir, target_dir=skill_dest)
            if os.path.exists(skill_dir)
            else {"missing_external_siblings": []}
        )
        missing_external_siblings = hydrate_res.get("missing_external_siblings", [])

        # 3. Normalize skill sources inside skill_dest (CRLF -> LF, strip UTF-8 BOM, chmod +x shebangs)
        if os.path.exists(skill_dest):
            normalize_skill_sources(skill_dest)

        # 4. Extract entry point, cwd, AST stub status, declared hosts, and dependencies
        entry_point, cwd_rel, is_instruction_only = extract_entry_point_and_cwd(skill_dest, contracts)
        entry_full_path = os.path.join(skill_dest, entry_point)
        if not os.path.exists(entry_full_path) and os.path.exists(os.path.join(skill_dest, "scripts", entry_point)):
            entry_full_path = os.path.join(skill_dest, "scripts", entry_point)
        ast_is_stub = detect_ast_is_stub(entry_full_path) if not is_instruction_only else False

        declared_hosts = extract_network_hosts_from_contracts(contracts)
        dep_resolution = (
            resolve_skill_dependencies(skill_dest)
            if os.path.exists(skill_dest)
            else {"pip_packages": [], "has_node": False, "node_packages": []}
        )
        pip_packages = dep_resolution.get("pip_packages", [])
        has_node = dep_resolution.get("has_node", False)

        # 5. Synthesize canary tokens and private canary registry (Clarification #4, E2, K4)
        env_vars_in_skill = extract_env_var_names_from_skill(skill_dest) if os.path.exists(skill_dest) else set()
        canary_id = hashlib.sha256(b"harbor-l2-canary-seed-v1").hexdigest()
        dummy_env, env_canary_map = synthesize_format_valid_dummy_env(env_vars_in_skill, canary_id)

        ssh_canary = f"CANARY_SSH_KEY_{canary_id[:16]}"
        aws_canary = f"CANARY_AWS_SECRET_{canary_id[:16]}"
        dotenv_canary = f"CANARY_ENV_TOKEN_{canary_id[:16]}"
        dummy_env["AWS_SECRET_ACCESS_KEY"] = aws_canary

        all_canary_tokens = sorted(set([ssh_canary, aws_canary, dotenv_canary] + list(env_canary_map.values())))
        all_canary_paths = [
            "/home/agent/.ssh/id_rsa",
            "/home/agent/.aws/credentials",
            "/home/agent/.env",
            "/root/.ssh/id_rsa",
            "/root/.aws/credentials",
            "/root/.env",
        ]
        canaries_payload = {
            "paths": all_canary_paths,
            "tokens": all_canary_tokens,
            "ssh_token": ssh_canary,
            "aws_token": aws_canary,
            "env_token": dotenv_canary,
        }
        # Write container-private copy (chmod 600 root:root in Dockerfile) and host-side copy in harness_meta/
        with open(os.path.join(env_dir, "canaries.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(canaries_payload, f, indent=2)
        with open(os.path.join(host_harness_meta_dir, "canaries.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(canaries_payload, f, indent=2)

        # 6. Write /harness files (never inside /app or /app/skill!)
        inv_plan = (
            plan_skill_invocations(skill_dest, target_container_dir="/app/skill")
            if os.path.exists(skill_dest)
            else {"ranked_candidates": [], "runnable_entries": []}
        )
        with open(os.path.join(harness_dir, "invocation_plan.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(inv_plan, f, indent=2)

        default_fixtures = {"test_cases": [], "cli_args": [], "env_vars": {}, "mock_files": {}}
        with open(os.path.join(harness_dir, "fixtures.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(default_fixtures, f, indent=2)

        harness_config = {
            "skill_id": skill_id,
            "entry_point": entry_point,
            "cwd_rel": cwd_rel,
            "is_instruction_only": is_instruction_only,
            "ast_is_stub": ast_is_stub,
            "missing_external_siblings": missing_external_siblings,
            "dummy_env": dummy_env,
            "contracts": contracts or [],
        }
        with open(os.path.join(harness_dir, "harness_config.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(harness_config, f, indent=2)

        with open(os.path.join(harness_dir, "sitecustomize.py"), "w", encoding="utf-8", newline="\n") as f:
            f.write(generate_sitecustomize_py())

        # Deploy callsite_hook.py to harness directory so sitecustomize imports it
        callsite_src = Path(__file__).resolve().parent.parent / "callsite_hook.py"
        callsite_txt = callsite_src.read_text(encoding="utf-8") if callsite_src.exists() else ""
        with open(os.path.join(harness_dir, "callsite_hook.py"), "w", encoding="utf-8", newline="\n") as f:
            f.write(callsite_txt)

        for b_name in LOG_ONLY_SHIMMED_BINARIES:
            s_path = os.path.join(shims_dir, b_name)
            with open(s_path, "w", encoding="utf-8", newline="\n") as f:
                f.write(generate_log_only_shim_script(b_name))
            try:
                os.chmod(s_path, 0o755)
            except Exception:
                pass

        runner_content = build_runner_py(entry_point, is_instruction_only, cwd_rel=cwd_rel)
        with open(os.path.join(harness_dir, "runner.py"), "w", encoding="utf-8", newline="\n") as f:
            f.write(runner_content)

        # 7. Write task.toml validated by TaskConfig (H1)
        real_env = os.environ.get("REAL_ENV", "0") == "1"
        if real_env and not is_instruction_only:
            net_policy = os.environ.get("NET_POLICY", "risk_based").lower()
            l1_risk = "LOW"
            try:
                from src.security.level1_scanner import scan_skill_for_level1_security
                l1_report = scan_skill_for_level1_security(skill_dest, declaration_text=declaration_text)
                l1_risk = l1_report.get("risk_level", "LOW")
            except Exception:
                pass

            if net_policy == "risk_based":
                if l1_risk in ("LOW", "MEDIUM"):
                    network_mode = "public"
                    effective_hosts = []
                    has_sidecar = False
                elif l1_risk == "HIGH":
                    network_mode = "allowlist"
                    effective_hosts = ["api.openai.com", "generativelanguage.googleapis.com", "localhost", "127.0.0.1"]
                    has_sidecar = False
                else:  # CRITICAL
                    network_mode = params["default_network_mode"]
                    effective_hosts = []
                    has_sidecar = False
            elif net_policy == "allowlist":
                network_mode = "allowlist"
                effective_hosts = ["api.openai.com", "generativelanguage.googleapis.com", "localhost", "127.0.0.1"]
                has_sidecar = False
            elif net_policy == "open":
                sys.stderr.write("\n" + "="*70 + "\n[WARNING] NET_POLICY=open: Full internet access enabled for all skills!\n" + "="*70 + "\n")
                network_mode = "public"
                effective_hosts = []
                has_sidecar = False
            else:
                network_mode = "allowlist" if declared_hosts else params["default_network_mode"]
                effective_hosts = declared_hosts
                has_sidecar = bool(declared_hosts)
        else:
            network_mode = "allowlist" if (declared_hosts or is_instruction_only) else params["default_network_mode"]
            effective_hosts = declared_hosts
            has_sidecar = bool(declared_hosts)

        task_toml_content = build_task_toml(
            skill_id=skill_id,
            network_mode=network_mode,
            allowed_hosts=effective_hosts,
            params=params,
            is_instruction_only=is_instruction_only,
        )
        with open(os.path.join(task_dir, "task.toml"), "w", encoding="utf-8", newline="\n") as f:
            f.write(task_toml_content)

        # 8. Write instruction.md
        instruction_md_content = build_instruction_md(skill_id, declaration_text, entry_point, is_instruction_only)
        with open(os.path.join(task_dir, "instruction.md"), "w", encoding="utf-8", newline="\n") as f:
            f.write(instruction_md_content)

        # 9. Write solution/solve.sh & solution/runner.py (and copy solve.sh into harness_dir so /solution is pre-populated)
        solve_sh_content = build_solve_sh()
        solve_sh_path = os.path.join(solution_dir, "solve.sh")
        with open(solve_sh_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(solve_sh_content)
        with open(os.path.join(harness_dir, "solve.sh"), "w", encoding="utf-8", newline="\n") as f:
            f.write(solve_sh_content)
        try:
            os.chmod(solve_sh_path, 0o755)
        except Exception:
            pass

        with open(os.path.join(solution_dir, "runner.py"), "w", encoding="utf-8", newline="\n") as f:
            f.write(runner_content)
        with open(os.path.join(solution_dir, "entry_wrapper.py"), "w", encoding="utf-8", newline="\n") as f:
            f.write(runner_content)
        with open(os.path.join(solution_dir, "mock_sidecar_server.py"), "w", encoding="utf-8", newline="\n") as f:
            f.write(generate_mock_sidecar_script())
        with open(os.path.join(env_dir, "mock_rules.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump({"hosts": declared_hosts, "rules": []}, f, indent=2)

        # 10. Write environment/Dockerfile (H2, Clarification #4: root build-time setup, agent runtime user)
        dep_layer = generate_docker_build_dependency_layer(pip_packages, has_node=has_node)
        dockerfile_lines = [
            f"FROM {params.get('base_docker_image', 'harbor-base:latest')}",
            "",
            "WORKDIR /app",
            "ENV PYTHONPATH=/harness:/app/skill:/app/skill/scripts",
            "ENV PATH=/harness/shims:$PATH",
            "ENV PYTHONUNBUFFERED=1",
            "",
            "# Shared cached base setup layer across all skills (built ONCE and cached across tasks)",
            "RUN (id -u agent >/dev/null 2>&1 || useradd -m -u 1000 -s /bin/bash agent) && \\",
            "    mkdir -p /logs/agent /logs/artifacts /logs/verifier /logs/shims /harness/private /app/skill /solution /tests /skills /home/agent/.ssh /home/agent/.aws /root/.ssh /root/.aws && \\",
            "    chmod 700 /harness/private && \\",
            "    echo '{\"installed\": [], \"failed\": []}' > /logs/artifacts/build_deps.json && \\",
            "    git config --system user.email 'verifier@users.noreply.github.com' && \\",
            "    git config --system user.name 'Verifier' && \\",
            "    git config --system --add safe.directory '*' && \\",
            f"    printf '%s\\n' '{ssh_canary}' > /home/agent/.ssh/id_rsa && \\",
            f"    printf '[default]\\naws_secret_access_key={aws_canary}\\n' > /home/agent/.aws/credentials && \\",
            f"    printf 'CANARY_TOKEN={dotenv_canary}\\n' > /home/agent/.env && \\",
            "    chmod 700 /home/agent/.ssh /home/agent/.aws && \\",
            "    chmod 600 /home/agent/.ssh/id_rsa /home/agent/.aws/credentials /home/agent/.env && \\",
            f"    printf '%s\\n' '{ssh_canary}' > /root/.ssh/id_rsa && \\",
            f"    printf '[default]\\naws_secret_access_key={aws_canary}\\n' > /root/.aws/credentials && \\",
            f"    printf 'CANARY_TOKEN={dotenv_canary}\\n' > /root/.env && \\",
            "    chmod 755 /root /root/.ssh /root/.aws && \\",
            "    chmod 644 /root/.ssh/id_rsa /root/.aws/credentials /root/.env && \\",
            "    ln -s /app/skill /app/skill_package && \\",
            "    ln -s /app/skill /skills/skill && \\",
            "    chown -R agent:agent /logs/agent /logs/artifacts /logs/verifier /logs/shims /app /solution /tests /home/agent && \\",
            "    chown -h agent:agent /app/skill_package",
            "",
            "# Pre-install dependencies at Docker BUILD time before uncached COPY layers",
            dep_layer,
            "",
            "# Copy harness files to /harness and skill tree to /app/skill with BuildKit --chown/--chmod (no post-COPY RUN container needed)",
            "COPY --chown=root:root --chmod=755 harness /harness",
            "COPY --chown=root:root --chmod=600 canaries.json /harness/private/canaries.json",
            "COPY --chown=agent:agent --chmod=755 harness/solve.sh /solution/solve.sh",
            "COPY --chown=agent:agent --chmod=644 harness/runner.py /solution/runner.py",
            "COPY --chown=agent:agent skill /app/skill",
        ]
        if is_instruction_only:
            dockerfile_lines.append(f"COPY --chown=agent:agent skill /skills/{skill_id}")
        with open(os.path.join(env_dir, "Dockerfile"), "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(dockerfile_lines) + "\n")

        # 11. Write environment/docker-compose.yaml (with self-contained mock-proxy sidecar when hosts declared)
        if not real_env:
            has_sidecar = bool(declared_hosts)
        compose_content = build_docker_compose_config(has_sidecar=has_sidecar)
        with open(os.path.join(env_dir, "docker-compose.yaml"), "w", encoding="utf-8", newline="\n") as f:
            f.write(compose_content)

        # 12. Write tests/test.sh & tests/verify_artifacts.py
        test_sh_path = os.path.join(tests_dir, "test.sh")
        with open(test_sh_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(build_test_sh())
        try:
            os.chmod(test_sh_path, 0o755)
        except Exception:
            pass

        with open(os.path.join(tests_dir, "verify_artifacts.py"), "w", encoding="utf-8", newline="\n") as f:
            f.write(build_verify_artifacts_py())

        # Normalize line endings across materialized task directory
        normalize_skill_sources(task_dir)

        crlf_files = []
        for root, _, files in os.walk(task_dir):
            for fn in files:
                ext = os.path.splitext(fn)[1].lower()
                if ext in {".sh", ".bash", ".py", ".js", ".json", ".yaml", ".yml", ".toml", ".md"}:
                    f_check = os.path.join(root, fn)
                    try:
                        if b"\r\n" in Path(f_check).read_bytes():
                            crlf_files.append(os.path.relpath(f_check, task_dir))
                    except Exception:
                        pass
        if crlf_files:
            raise AssertionError(f"CRLF line endings detected in materialized harbor task '{skill_id}': {crlf_files}")

        return task_dir
