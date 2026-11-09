import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from src.a_gen_test_generator import identify_entry_point_script
from src.aces_parser import parse_aces_trajectory
from src.failure_triage import classify_failure
from src.run_status_reader import read_and_cross_check_run_status
from src.telemetry_parser import (
    build_evidence_from_artifacts,
    detect_canary_content_exfiltration,
    parse_strace_telemetry,
)

def _load_project_env() -> None:
    for env_path in [".env", os.path.join(os.path.dirname(__file__), "..", ".env")]:
        if os.path.exists(env_path):
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            os.environ.setdefault(k.strip(), v.strip())
                break
            except Exception:
                pass

_load_project_env()

# Provider key mappings and defaults for instruction-only agent selection
PROVIDER_KEY_MAP = {
    "claude-code": ("ANTHROPIC_API_KEY", "anthropic/claude-3-5-sonnet-20241022"),
    "codex": ("OPENAI_API_KEY", "openai/gpt-4o"),
    "gemini-cli": ("GEMINI_API_KEY", "google/gemini-1.5-pro"),
    "qwen-coder": ("DASHSCOPE_API_KEY", "qwen/qwen-2.5-coder-32b-instruct"),
}

PROVIDER_HOST_MAP = {
    "claude-code": ["api.anthropic.com"],
    "codex": ["api.openai.com"],
    "gemini-cli": ["generativelanguage.googleapis.com"],
    "qwen-coder": ["dashscope.aliyuncs.com"],
}

INSTR_AGENT_DEFAULT = "codex"
INSTR_AGENT_MODEL_DEFAULT = "openai/gpt-4o"
REALENV_IMAGE_STATS: Dict[str, float] = {}

TRIAL_TIMEOUT_SEC = int(os.environ.get("HARBOR_TRIAL_TIMEOUT_SEC", 300))
AGENT_TIMEOUT_SEC = int(os.environ.get("HARBOR_AGENT_TIMEOUT_SEC", 600))
BUILD_TIMEOUT_SEC = int(os.environ.get("HARBOR_BUILD_TIMEOUT_SEC", 1200))
BATCH_CONCURRENCY_DEFAULT = int(os.environ.get("HARBOR_BATCH_CONCURRENCY", 2 if sys.platform == "win32" else 4))


def normalize_crlf_in_directory(target_dir: str) -> List[str]:
    """Normalize CRLF (\\r\\n) to LF (\\n) for text files, leaving binaries untouched. (B3)"""
    converted: List[str] = []
    text_exts = {".sh", ".py", ".js", ".mjs", ".json", ".md", ".txt", ".env", ".toml", ".yaml", ".yml", ".cfg"}
    target_path = Path(target_dir)
    if not target_path.exists():
        return converted
    for p in target_path.rglob("*"):
        if p.is_file():
            if p.suffix.lower() in text_exts or p.name in ("Dockerfile", "solve.sh", ".env"):
                try:
                    data = p.read_bytes()
                    if b"\r\n" in data:
                        p.write_bytes(data.replace(b"\r\n", b"\n"))
                        converted.append(str(p.relative_to(target_path)).replace("\\", "/"))
                except Exception:
                    pass
    return converted


def detect_missing_binaries_in_skill(skill_dir: str) -> List[str]:
    """Statically detect binary tools required by skill scripts that are absent from base image. (B5)"""
    import ast
    invoked: Set[str] = set()
    KNOWN_BINS = {
        "sh", "bash", "python", "python3", "cat", "ls", "echo", "mkdir", "rm", "cp", "mv",
        "grep", "sed", "awk", "head", "tail", "curl", "wget", "jq", "git", "tar", "gzip",
        "unzip", "zip", "find", "which", "chmod", "chown", "touch", "tee", "env", "sleep",
        "make", "sqlite3", "ripgrep", "rg", "diff", "patch", "sort", "uniq", "tr", "cut",
        "wc", "date", "whoami", "id", "uname", "ps", "kill", "xargs", "printf", "uv", "pip"
    }
    skill_path = Path(skill_dir)
    if not skill_path.exists():
        return []

    # 1. Python AST parsing for subprocess / os.system / shutil.which
    for py_file in skill_path.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8", errors="ignore"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    fname = ""
                    if isinstance(node.func, ast.Name):
                        fname = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        fname = node.func.attr
                    if fname in ("run", "Popen", "call", "check_call", "check_output", "system", "which"):
                        if node.args:
                            arg0 = node.args[0]
                            if isinstance(arg0, (ast.List, ast.Tuple)) and arg0.elts:
                                if isinstance(arg0.elts[0], ast.Constant) and isinstance(arg0.elts[0].value, str):
                                    cmd = arg0.elts[0].value.strip()
                                    if cmd and "/" not in cmd and not cmd.startswith("."):
                                        invoked.add(cmd)
                            elif isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                                parts = arg0.value.strip().split()
                                if parts:
                                    cmd = parts[0]
                                    if "/" not in cmd and not cmd.startswith("."):
                                        invoked.add(cmd)
        except Exception:
            pass

    # 2. Shell scripts
    for sh_file in skill_path.rglob("*.sh"):
        try:
            for line in sh_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    parts = line.split()
                    if parts and re.match(r"^[a-zA-Z0-9_\-]+$", parts[0]):
                        invoked.add(parts[0])
        except Exception:
            pass

    # 3. SKILL.md prerequisites
    md_file = skill_path / "SKILL.md"
    if md_file.is_file():
        try:
            text = md_file.read_text(encoding="utf-8", errors="ignore")
            for tool in ("gitleaks", "grpcurl", "ffmpeg", "tesseract", "graphviz"):
                if re.search(rf"\b{tool}\b", text, re.IGNORECASE):
                    invoked.add(tool)
        except Exception:
            pass

    return sorted(b for b in invoked if b.lower() not in KNOWN_BINS and not b.endswith((".py", ".sh", ".js")))


def get_instruction_agent_config() -> Tuple[str, str, str, str]:
    """Resolves (agent_name, model_name, key_env_var, key_value) for instruction-only agent execution.

    Reads INSTR_AGENT and INSTR_AGENT_MODEL from environment, falling back to PROVIDER_KEY_MAP.
    Defaults to 'codex' (OpenAI) when OPENAI_API_KEY is available.
    """
    explicit_agent = os.environ.get("INSTR_AGENT", "").strip()
    if explicit_agent:
        agent = explicit_agent
    else:
        # Auto-detect best agent based on available host keys
        if os.environ.get("OPENAI_API_KEY"):
            agent = "codex"
        elif os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"):
            agent = "gemini-cli"
        elif os.environ.get("ANTHROPIC_API_KEY"):
            agent = "claude-code"
        else:
            agent = INSTR_AGENT_DEFAULT

    key_env, default_model = PROVIDER_KEY_MAP.get(agent, ("OPENAI_API_KEY", INSTR_AGENT_MODEL_DEFAULT))
    model = (os.environ.get("INSTR_AGENT_MODEL") or "").strip() or default_model
    key_val = os.environ.get(key_env, "").strip()
    return agent, model, key_env, key_val


def get_keys_to_scrub() -> List[str]:
    """Returns active provider API keys that should be scrubbed from artifacts and logs."""
    keys: List[str] = []
    for env_var in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GEMINI_API_KEY",
        "GOOGLE_API_KEY",
        "DASHSCOPE_API_KEY",
    ):
        val = os.environ.get(env_var, "").strip()
        if val and len(val) >= 6 and val.lower() not in ("dummy", "canary"):
            keys.append(val)
    return keys


def scrub_api_keys(text: str, keys_to_redact: Optional[List[str]] = None) -> str:
    """Replaces provider API keys with [REDACTED_API_KEY]."""
    if not isinstance(text, str) or not text:
        return text
    if keys_to_redact is None:
        keys_to_redact = get_keys_to_scrub()
    res = text
    for k in keys_to_redact:
        if k and k in res:
            res = res.replace(k, "[REDACTED_API_KEY]")
    return res


def scrub_api_keys_in_object(obj: Any, keys_to_redact: Optional[List[str]] = None) -> Any:
    """Recursively redacts API keys from dicts, lists, tuples, and strings."""
    if keys_to_redact is None:
        keys_to_redact = get_keys_to_scrub()
    if not keys_to_redact:
        return obj
    if isinstance(obj, str):
        return scrub_api_keys(obj, keys_to_redact)
    if isinstance(obj, dict):
        return {k: scrub_api_keys_in_object(v, keys_to_redact) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub_api_keys_in_object(v, keys_to_redact) for v in obj]
    if isinstance(obj, tuple):
        return tuple(scrub_api_keys_in_object(v, keys_to_redact) for v in obj)
    return obj


def scrub_api_keys_in_dir(target_dir: str, keys_to_redact: Optional[List[str]] = None) -> None:
    """Scans all text/log/json files in target_dir and redacts sensitive API keys in place."""
    if not os.path.isdir(target_dir):
        return
    if keys_to_redact is None:
        keys_to_redact = get_keys_to_scrub()
    if not keys_to_redact:
        return
    for root, _, files in os.walk(target_dir):
        for f in files:
            ext = os.path.splitext(f)[1].lower()
            if ext in (".log", ".txt", ".json", ".jsonl", ".patch", ".md", ".diff", ".toml", ""):
                fpath = os.path.join(root, f)
                try:
                    content = Path(fpath).read_text(encoding="utf-8", errors="ignore")
                    scrubbed = scrub_api_keys(content, keys_to_redact)
                    if scrubbed != content:
                        Path(fpath).write_text(scrubbed, encoding="utf-8")
                except Exception:
                    pass


def _extract_declared_hosts(contracts: Optional[Any]) -> List[str]:
    """Extracts all declared network hosts from contracts for allowlisting."""
    hosts: List[str] = []
    if not contracts:
        return hosts
    from src.judge import parse_frame_axiom_from_dict
    for c in contracts:
        if isinstance(c, dict):
            try:
                fa = parse_frame_axiom_from_dict(c)
                hosts.extend(fa.hosts)
            except Exception:
                pass
        elif hasattr(c, "frame_axiom") and hasattr(c.frame_axiom, "hosts"):
            hosts.extend(c.frame_axiom.hosts)
    return list(dict.fromkeys(hosts))


def parse_strace_to_events(
    strace_file: str,
    canary_paths: Optional[List[str]] = None,
    mock_egress_path: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Parse OS-level syscalls from strace.log into standardized pipeline trace events."""
    if not os.path.exists(strace_file):
        return []
    parsed = parse_strace_telemetry(
        strace_log_path=strace_file,
        canary_paths=canary_paths,
        mock_egress_path=mock_egress_path,
    )
    return parsed.get("events", [])


def _run_harbor_cli_entrypoint() -> None:
    """Entry point for Harbor CLI subprocesses with Windows Docker Compose optimizations."""
    import contextlib
    import inspect
    import harbor.environments.docker.docker as hb_docker_mod
    import harbor.environments.docker.runtime as hb_runtime_mod
    from harbor.environments.docker.docker import DockerEnvironment
    from harbor.environments.docker.docker_unix import UnixOps
    from harbor.environments.docker.runtime import ContainerRuntime
    from harbor.models.trial.result import TimingInfo, VerifierResult
    from harbor.trial.single_step import SingleStepTrial
    from harbor.trial.trial import Trial

    # 1. Invoke docker-compose.exe directly on Windows to skip docker.exe CLI plugin enumeration
    direct_compose = r"C:\Program Files\Docker\cli-plugins\docker-compose.exe"
    if sys.platform == "win32" and os.path.isfile(direct_compose):
        fast_rt = ContainerRuntime(engine=("docker",), compose=(direct_compose,))
        hb_runtime_mod.DOCKER_RUNTIME = fast_rt
        hb_docker_mod.DOCKER_RUNTIME = fast_rt

    # 2. Fast daemon detection (docker version ~0.2s instead of docker info >10s timeout)
    @classmethod
    def _fast_detect_daemon_os(cls) -> Optional[str]:
        try:
            r = subprocess.run(
                cls._engine_cmd("version", "--format", "{{.Server.Os}}"),
                capture_output=True,
                text=True,
                timeout=60,
            )
            return r.stdout.strip().lower() or None
        except Exception:
            return None

    @classmethod
    def _fast_preflight(cls) -> None:
        if not shutil.which("docker") or not cls._detect_daemon_os():
            raise SystemExit("Docker daemon is not running.")

    DockerEnvironment._detect_daemon_os = _fast_detect_daemon_os
    DockerEnvironment.preflight = _fast_preflight
    DockerEnvironment._egress_control_kernel_support = classmethod(lambda cls: True)

    async def _async_noop(self, *args, **kwargs) -> None:
        return None

    DockerEnvironment._validate_image_os = _async_noop
    if sys.platform == "win32":
        DockerEnvironment.prepare_logs_for_host = _async_noop
        DockerEnvironment.ensure_dirs = _async_noop

    # 3. Boot directly in the agent's network policy; use COMPOSE_NO_NETWORK_PATH (network_mode: none)
    # for no-network tasks so we don't spawn a second gost sidecar container + bridge network + healthcheck poll
    from harbor.environments.docker import COMPOSE_NO_NETWORK_PATH
    from harbor.models.task.config import NetworkMode

    _orig_de_init = DockerEnvironment.__init__

    def _patched_de_init(self, *args, **kwargs) -> None:
        phase_policies = kwargs.get("phase_network_policies") or ()
        if phase_policies:
            kwargs["network_policy"] = phase_policies[0]
        _orig_de_init(self, *args, **kwargs)

    DockerEnvironment.__init__ = _patched_de_init

    @contextlib.asynccontextmanager
    async def _noop_phase_network_policy(self, environment, *, baseline_policy, phase_policy):
        yield

    Trial._phase_network_policy = _noop_phase_network_policy

    # 4. Build standard shared base image ONCE per batch and reuse via prebuilt compose + bind mounts
    _cached_sidecar_image: List[str] = []
    _sidecar_lock = hb_docker_mod.asyncio.Lock()
    _cached_shared_base: List[str] = []
    _shared_base_lock = hb_docker_mod.asyncio.Lock()

    async def _fast_start(self, force_build: bool) -> None:
        real_env = os.environ.get("REAL_ENV", "0") == "1"
        if real_env:
            # 1. Assert container security constraints
            for m in getattr(self, "_mounts", []):
                if isinstance(m, dict):
                    src = str(m.get("source", ""))
                    tgt = str(m.get("target", ""))
                    if "docker.sock" in src or "docker.sock" in tgt:
                        raise RuntimeError("Container security violation: docker.sock mounted!")
            if getattr(self, "_network_mode", "") == "host":
                raise RuntimeError("Container security violation: host networking requested!")

            # 2. Inspect skill for API keys and inject least-privilege
            skill_dir = self.environment_dir / "skill"
            reads_openai = False
            reads_gemini = False
            for py_f in skill_dir.rglob("*.py"):
                try:
                    txt = py_f.read_text(encoding="utf-8", errors="ignore")
                    if "OPENAI_API_KEY" in txt:
                        reads_openai = True
                    if "GEMINI_API_KEY" in txt or "GOOGLE_API_KEY" in txt:
                        reads_gemini = True
                except Exception:
                    pass

            if reads_openai:
                host_k = os.environ.get("OPENAI_API_KEY", "").strip()
                if not host_k:
                    raise RuntimeError("Skill requires OPENAI_API_KEY, but it is not set in host environment.")
                self._persistent_env["OPENAI_API_KEY"] = host_k
                self._persistent_env["REAL_ENV"] = "1"

            if reads_gemini:
                host_k = (os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or "").strip()
                if not host_k:
                    raise RuntimeError("Skill requires GEMINI_API_KEY / GOOGLE_API_KEY, but neither is set in host environment.")
                self._persistent_env["GEMINI_API_KEY"] = host_k
                self._persistent_env["GOOGLE_API_KEY"] = host_k
                self._persistent_env["REAL_ENV"] = "1"

        if self.network_policy.network_mode == NetworkMode.NO_NETWORK:
            self._enable_egress_control = False
            if COMPOSE_NO_NETWORK_PATH not in self.extra_docker_compose_paths:
                self.extra_docker_compose_paths = list(self.extra_docker_compose_paths) + [COMPOSE_NO_NETWORK_PATH]

        df_path = self.environment_dir / "Dockerfile"
        df_text = df_path.read_text(encoding="utf-8", errors="ignore") if df_path.is_file() else ""
        is_standard_base = (
            (self.environment_dir / "skill").is_dir()
            and (self.environment_dir / "harness").is_dir()
        )
        if is_standard_base:
            if not _cached_shared_base:
                async with _shared_base_lock:
                    if not _cached_shared_base:
                        try:
                            chk_v5 = subprocess.run(
                                ["docker", "image", "inspect", "hb__l2_shared_base_v5:latest"],
                                capture_output=True,
                                timeout=60,
                            )
                            has_v5 = chk_v5.returncode == 0
                        except Exception:
                            has_v5 = False
                        if has_v5:
                            _cached_shared_base.append("hb__l2_shared_base_v5:latest")
                        else:
                            # If harbor-base:latest is missing (fresh git clone), bootstrap it from docker/Dockerfile.base
                            try:
                                chk_hb = subprocess.run(
                                    ["docker", "image", "inspect", "harbor-base:latest"],
                                    capture_output=True,
                                    timeout=60,
                                )
                                has_hb = chk_hb.returncode == 0
                            except Exception:
                                has_hb = False
                            if not has_hb:
                                base_df = Path("docker/Dockerfile.base")
                                if base_df.exists():
                                    try:
                                        self.logger.info("harbor-base:latest missing on host. Bootstrapping from docker/Dockerfile.base...")
                                        subprocess.run(
                                            ["docker", "build", "-t", "harbor-base:latest", "-f", str(base_df), "."],
                                            capture_output=True,
                                            timeout=BUILD_TIMEOUT_SEC,
                                        )
                                    except Exception as exc:
                                        self.logger.warning(f"Failed to auto-build harbor-base:latest: {exc}")

                            try:
                                chk_v3 = subprocess.run(
                                    ["docker", "image", "inspect", "hb__l2_shared_base_v3:latest"],
                                    capture_output=True,
                                    timeout=60,
                                )
                                has_v3 = chk_v3.returncode == 0
                            except Exception:
                                has_v3 = False
                            shared_df = self.environment_dir / ".shared_base_v5.Dockerfile"
                            sys_tools_cmd = (
                                "RUN (apt-get update && apt-get install -y --no-install-recommends "
                                "curl jq git unzip zip ripgrep make sqlite3 && rm -rf /var/lib/apt/lists/*) || true\n"
                            )
                            pip_cmd = (
                                sys_tools_cmd
                                + "RUN uv pip install --system pandas chardet faker click typer rich jinja2 beautifulsoup4 "
                                "|| pip install --no-cache-dir --break-system-packages pandas chardet faker click typer rich jinja2 beautifulsoup4 "
                                "|| pip install --no-cache-dir pandas chardet faker click typer rich jinja2 beautifulsoup4 || true\n"
                            )
                            if has_v3:
                                shared_df.write_text(
                                    "FROM hb__l2_shared_base_v3:latest\n"
                                    "USER root\n"
                                    + pip_cmd
                                    + "COPY --chown=root:root --chmod=755 harness /harness\n"
                                    "COPY --chown=agent:agent --chmod=755 harness/solve.sh /solution/solve.sh\n",
                                    encoding="utf-8",
                                )
                            else:
                                shared_df.write_text(
                                    df_text + "\n" + pip_cmd,
                                    encoding="utf-8",
                                )
                            try:
                                built_base = await hb_docker_mod.ensure_docker_image_built(
                                    docker_name="hb__l2_shared_base_v5",
                                    docker_build_context=self.environment_dir,
                                    dockerfile_path=shared_df,
                                    build_args={},
                                    platform=await hb_docker_mod.default_docker_platform(),
                                    logger=self.logger,
                                )
                                subprocess.run(
                                    ["docker", "tag", built_base, "hb__l2_shared_base_v5:latest"],
                                    capture_output=True,
                                    timeout=30,
                                )
                                _cached_shared_base.append("hb__l2_shared_base_v5:latest")
                            finally:
                                shared_df.unlink(missing_ok=True)
            target_image = _cached_shared_base[0]
            if real_env:
                from src.dep_resolver import resolve_skill_dependencies
                resolved = resolve_skill_dependencies(str(self.environment_dir / "skill"))
                pkgs = [p.strip() for p in resolved.get("pip_packages", []) if p.strip()]
                base_known_pkgs = {
                    "pandas", "chardet", "faker", "click", "typer", "rich",
                    "jinja2", "beautifulsoup4", "pytest", "pyyaml", "requests", "uv"
                }
                missing_pkgs = [p for p in pkgs if p.lower().split(">=")[0].split("==")[0] not in base_known_pkgs]
                if missing_pkgs:
                    dep_hash = hashlib.sha256(",".join(sorted(missing_pkgs)).encode()).hexdigest()[:12]
                    target_image = f"hb__realenv_{dep_hash}:latest"
                    async with _shared_base_lock:
                        chk_img = subprocess.run(
                            ["docker", "image", "inspect", target_image],
                            capture_output=True,
                            timeout=30,
                        )
                        if chk_img.returncode != 0:
                            t0 = time.time()
                            self.logger.info(f"[REAL_ENV] Building cached dependency layer {target_image} for {missing_pkgs}...")
                            install_items = " ".join(f"'{p}'" for p in sorted(missing_pkgs))
                            df_real = (
                                f"FROM {_cached_shared_base[0]}\n"
                                f"USER root\n"
                                f"RUN uv pip install --system {install_items} || (for p in {install_items}; do uv pip install --system $p || true; done)\n"
                            )
                            df_tmp = self.environment_dir / f".df_realenv_{dep_hash}"
                            df_tmp.write_text(df_real, encoding="utf-8")
                            try:
                                b_res = subprocess.run(
                                    ["docker", "build", "-t", target_image, "-f", str(df_tmp), str(self.environment_dir)],
                                    capture_output=True,
                                    text=True,
                                    timeout=BUILD_TIMEOUT_SEC,
                                )
                                if b_res.returncode != 0:
                                    self.logger.warning(f"Failed to build {target_image}: {b_res.stderr[-300:]}")
                                    target_image = _cached_shared_base[0]
                                else:
                                    elapsed = round(time.time() - t0, 2)
                                    REALENV_IMAGE_STATS[target_image] = elapsed
                                    self.logger.info(f"[REAL_ENV] Successfully built {target_image} in {elapsed}s")
                            finally:
                                df_tmp.unlink(missing_ok=True)
            self._use_prebuilt = True
            self._env_vars.prebuilt_image_name = target_image
            existing_targets = {m.get("target") for m in self._mounts if isinstance(m, dict)}
            if "/tmp/.harbor_host_skill" not in existing_targets:
                task_skill_dir = str((self.environment_dir / "skill").resolve())
                skill_name = self.environment_dir.parent.name
                self._mounts = list(self._mounts) + [
                    {
                        "type": "bind",
                        "source": task_skill_dir,
                        "target": "/tmp/.harbor_host_skill",
                        "read_only": True,
                    },
                    {
                        "type": "bind",
                        "source": str((self.environment_dir / "harness").resolve()),
                        "target": "/tmp/.harbor_host_harness",
                        "read_only": True,
                    },
                    {
                        "type": "bind",
                        "source": task_skill_dir,
                        "target": f"/skills/{skill_name}",
                        "read_only": False,
                    },
                ]
        else:
            self._use_prebuilt = False

        mounts_res = self._write_mounts_compose_file()
        self._mounts_compose_path = await mounts_res if inspect.isawaitable(mounts_res) else mounts_res

        resources_res = self._write_resources_compose_file()
        self._resources_compose_path = await resources_res if inspect.isawaitable(resources_res) else resources_res

        env_res = self._write_env_compose_file()
        self._env_compose_path = await env_res if inspect.isawaitable(env_res) else env_res

        egress_res = self._write_egress_control_services_compose_file()
        if inspect.isawaitable(egress_res):
            await egress_res

        if self._enable_egress_control:
            if _cached_sidecar_image:
                self._env_vars.egress_control_sidecar_image_name = _cached_sidecar_image[0]
            else:
                async with _sidecar_lock:
                    if not _cached_sidecar_image:
                        await self._ensure_egress_control_sidecar_image_built()
                        _cached_sidecar_image.append(self._env_vars.egress_control_sidecar_image_name)
                    else:
                        self._env_vars.egress_control_sidecar_image_name = _cached_sidecar_image[0]
        runtime = type(self).runtime()
        for _up_attempt in range(3):
            try:
                await self._run_docker_compose_command(["up", *runtime.up_args])
                break
            except Exception:
                if _up_attempt == 2:
                    raise
                await hb_docker_mod.asyncio.sleep(1.5 * (_up_attempt + 1))
        await self._upload_environment_dir_after_start()

    async def _fast_stop(self, delete: bool) -> None:
        try:
            await self._run_docker_compose_command(["down", "--timeout", "0", "--volumes", "--remove-orphans"], check=False)
        except Exception:
            pass
        finally:
            for cleanup_fn in (
                self._cleanup_mounts_compose_file,
                self._cleanup_resources_compose_file,
                self._cleanup_env_compose_file,
                self._cleanup_egress_control_services_compose_file,
            ):
                try:
                    c_res = cleanup_fn()
                    if inspect.isawaitable(c_res):
                        await c_res
                except Exception:
                    pass

    DockerEnvironment.start = _fast_start
    DockerEnvironment.stop = _fast_stop

    # 5. Fast-path service_is_dir / is_dir and download_file for bind-mounted /logs/agent/* (avoids 12x compose exec/cp per trial)
    _orig_service_is_dir = DockerEnvironment.service_is_dir

    async def _fast_service_is_dir(self, path: str, *, service: str | None = None, user: str | int | None = None) -> bool:
        if (service is None or service == "main") and path.startswith("/logs/agent/"):
            rel = path[len("/logs/agent/"):]
            return (self.trial_paths.agent_dir / rel).is_dir()
        if Path(path).suffix in (".json", ".log", ".patch", ".jsonl", ".txt", ".md", ".py", ".sh"):
            return False
        return await _orig_service_is_dir(self, path, service=service, user=user)

    DockerEnvironment.service_is_dir = _fast_service_is_dir

    _orig_download_file = UnixOps.download_file

    async def _fast_download_file(self, source_path: str, target_path: Path | str, service: str | None = None) -> None:
        if (service is None or service == "main") and source_path.startswith("/logs/agent/"):
            rel = source_path[len("/logs/agent/"):]
            host_src = self._env.trial_paths.agent_dir / rel
            if host_src.is_file():
                Path(target_path).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(host_src, target_path)
                return
            raise FileNotFoundError(f"Bind-mounted artifact not found: {source_path}")
        await _orig_download_file(self, source_path, target_path, service=service)

    UnixOps.download_file = _fast_download_file

    # 6. Skip upload_dir and chmod +x for /solution when solve.sh is already baked into the image with 0755
    import harbor.agents.oracle as hb_oracle_mod
    hb_oracle_mod.needs_chmod = lambda p: False

    _orig_upload_dir = UnixOps.upload_dir
    _ = _orig_upload_dir

    async def _fast_upload_dir(self, source_dir: Path | str, target_dir: str) -> None:
        if target_dir == "/solution" and (Path(source_dir) / "solve.sh").is_file():
            return
        await self._env._run_docker_compose_command(
            ["cp", f"{source_dir}/.", f"main:{target_dir}"],
            check=True,
        )

    UnixOps.upload_dir = _fast_upload_dir

    # 7. Read reward.json directly from bind-mounted verifier_dir when written by runner.py
    _orig_run_verifier = SingleStepTrial._run_verifier

    async def _fast_run_verifier(self) -> None:
        reward_file = self.paths.verifier_dir / "reward.json"
        if reward_file.is_file():
            now = self._now()
            self.result.verifier = TimingInfo(started_at=now, finished_at=now)
            try:
                r_data = json.loads(reward_file.read_text(encoding="utf-8"))
                self.result.verifier_result = VerifierResult(rewards={k: float(v) for k, v in r_data.items() if isinstance(v, (int, float))})
            except Exception:
                self.result.verifier_result = VerifierResult(rewards={"reward": 0.0})
            return
        await _orig_run_verifier(self)

    SingleStepTrial._run_verifier = _fast_run_verifier

    from harbor.cli.main import app

    sys.argv = ["harbor"] + sys.argv[1:]
    app()


def _resolve_harbor_bin() -> str:
    """Resolve the harbor CLI executable path."""
    venv_scripts = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "venv", "Scripts"))
    if venv_scripts not in os.environ.get("PATH", "") and os.path.isdir(venv_scripts):
        os.environ["PATH"] = venv_scripts + os.pathsep + os.environ.get("PATH", "")
    harbor_bin = (
        shutil.which("harbor")
        or shutil.which("harbor.exe")
        or os.path.join(venv_scripts, "harbor.exe")
    )
    if os.path.isfile(harbor_bin):
        return harbor_bin
    return "harbor"


def _build_harbor_cli_cmd(cli_args: List[str]) -> List[str]:
    """Build Harbor CLI command using `_run_harbor_cli_entrypoint`."""
    py_bin = sys.executable
    venv_py = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "venv", "Scripts", "python.exe"))
    if os.path.isfile(venv_py):
        py_bin = venv_py
    return [
        py_bin,
        "-c",
        "from src.harbor_runner import _run_harbor_cli_entrypoint; _run_harbor_cli_entrypoint()",
        *cli_args,
    ]



def is_harbor_cli_available() -> bool:
    """Check if harbor CLI is installed and available."""
    harbor_bin = _resolve_harbor_bin()
    if os.path.isfile(harbor_bin) or shutil.which("harbor") or shutil.which("harbor.exe"):
        return True
    try:
        import importlib.util

        return importlib.util.find_spec("harbor") is not None
    except Exception:
        return False



def is_docker_daemon_running() -> bool:
    """Check if Docker daemon is responsive with Linux containers."""
    for cmd in (
        ["docker", "version", "--format", "{{.Server.Os}}"],
        ["docker", "info", "--format", "{{.OSType}}"],
    ):
        for _ in range(2):
            try:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                )
                if res.returncode == 0 and res.stdout.strip().lower() == "linux":
                    return True
            except Exception:
                time.sleep(1)
    return False



def _has_runnable_scripts(task_dir: str, skill_dir: str) -> bool:
    """Check whether the packaged skill or source skill directory contains any runnable script."""
    for base in (
        os.path.join(task_dir, "environment", "skill"),
        os.path.join(task_dir, "environment", "skill_package"),
        skill_dir,
    ):
        if not base or not os.path.isdir(base):
            continue
        ep = identify_entry_point_script(base)
        if ep and os.path.isfile(ep):
            return True
        for root, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "node_modules", ".venv", "venv")]
            for fn in files:
                if fn.endswith((".py", ".sh", ".js")) and fn not in ("sitecustomize.py", "__init__.py"):
                    return True
    return False


def _write_task_fixtures(task_dir: str, artifacts_dir: Optional[str], test_cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Write `fixtures.json` into the task harness and optional trial artifacts directory."""
    first_tc = test_cases[0] if test_cases else {}
    fixtures_payload = {
        "test_cases": test_cases or [],
        "contract_id": first_tc.get("contract_id", "C_01"),
        "mock_files": first_tc.get("mock_files", {}),
        "cli_args": first_tc.get("cli_args", []),
        "env_vars": first_tc.get("env_vars", {}),
        "checks": first_tc.get("checks", []),
    }
    targets = [os.path.join(task_dir, "fixtures.json")]
    env_dir = os.path.join(task_dir, "environment")
    if os.path.isdir(env_dir):
        targets.append(os.path.join(env_dir, "fixtures.json"))
        harness_dir = os.path.join(env_dir, "harness")
        os.makedirs(harness_dir, exist_ok=True)
        targets.append(os.path.join(harness_dir, "fixtures.json"))
    if artifacts_dir:
        os.makedirs(artifacts_dir, exist_ok=True)
        targets.append(os.path.join(artifacts_dir, "fixtures.json"))

    for t in targets:
        try:
            with open(t, "w", encoding="utf-8", newline="\n") as f:
                json.dump(fixtures_payload, f, indent=2)
        except Exception:
            pass

    # Materialize mock_files and update instruction.md for instruction-only runs
    mock_files = first_tc.get("mock_files") or {}
    if mock_files and os.path.isdir(env_dir):
        skill_in_env = os.path.join(env_dir, "skill")
        for m_path, m_content in mock_files.items():
            if not m_path:
                continue
            rel_m = m_path.lstrip("/\\")
            base_m = os.path.basename(m_path)
            for cand_dest in (
                os.path.join(skill_in_env, rel_m),
                os.path.join(skill_in_env, base_m),
                os.path.join(env_dir, rel_m),
            ):
                try:
                    os.makedirs(os.path.dirname(cand_dest), exist_ok=True)
                    with open(cand_dest, "w", encoding="utf-8") as mf:
                        mf.write(str(m_content))
                except Exception:
                    pass

    instr_path = os.path.join(task_dir, "instruction.md")
    if os.path.isfile(instr_path):
        try:
            cli_args = first_tc.get("cli_args")
            if cli_args or mock_files:
                curr_txt = Path(instr_path).read_text(encoding="utf-8")
                if "### Task Input & Instructions" not in curr_txt:
                    extra = "\n\n### Task Input & Instructions\n"
                    if cli_args:
                        extra += f"- Arguments: {' '.join(str(x) for x in cli_args)}\n"
                    if mock_files:
                        extra += f"- Target files: {', '.join(mock_files.keys())}\n"
                    extra += "Please process the target input file(s) according to the skill instructions.\n"
                    with open(instr_path, "a", encoding="utf-8") as f:
                        f.write(extra)
        except Exception:
            pass

    return fixtures_payload


def _copy_canaries_to_trial_meta(task_dir: str, trial_root: str) -> Optional[str]:
    """Copy `canaries.json` into `trial_root/harness_meta/canaries.json` (never into `artifacts/`)."""
    harness_meta_dir = os.path.join(trial_root, "harness_meta")
    os.makedirs(harness_meta_dir, exist_ok=True)
    for src_cand in (
        os.path.join(task_dir, "harness_meta", "canaries.json"),
        os.path.join(task_dir, "environment", "harness", "private", "canaries.json"),
        os.path.join(task_dir, "environment", "canaries.json"),
    ):
        if os.path.isfile(src_cand):
            dst = os.path.join(harness_meta_dir, "canaries.json")
            try:
                shutil.copy2(src_cand, dst)
                return dst
            except Exception:
                pass
    return None


def _collect_harbor_trial_artifacts(
    actual_trial_root: str,
    trial_root: str,
    task_dir: str,
    trial_result_data: Dict[str, Any],
) -> None:
    """Copy collected artifacts from a Harbor trial directory into standardized `trial_root/artifacts/`."""
    artifacts_dir = os.path.join(trial_root, "artifacts")
    verifier_dir = os.path.join(trial_root, "verifier")
    agent_dir = os.path.join(trial_root, "agent")
    os.makedirs(artifacts_dir, exist_ok=True)
    os.makedirs(verifier_dir, exist_ok=True)
    os.makedirs(agent_dir, exist_ok=True)

    _copy_canaries_to_trial_meta(task_dir, trial_root)

    cand_sources = [
        os.path.join(actual_trial_root, "artifacts"),
        os.path.join(actual_trial_root, "artifacts", "logs", "artifacts"),
        os.path.join(actual_trial_root, "artifacts", "logs", "agent"),
        os.path.join(actual_trial_root, "artifacts", "tmp"),
        os.path.join(actual_trial_root, "agent"),
    ]
    for src_dir in cand_sources:
        if not os.path.isdir(src_dir):
            continue
        for item in os.listdir(src_dir):
            # E2 / K4: Never copy canaries.json into artifacts_dir
            if item == "canaries.json":
                continue
            s_path = os.path.join(src_dir, item)
            d_path = os.path.join(artifacts_dir, item)
            if os.path.isfile(s_path):
                try:
                    if os.path.abspath(s_path) != os.path.abspath(d_path):
                        shutil.copy2(s_path, d_path)
                except Exception:
                    pass

    h_reward = os.path.join(actual_trial_root, "verifier", "reward.json")
    if os.path.isfile(h_reward):
        try:
            dss = os.path.join(verifier_dir, "reward.json")
            if os.path.abspath(h_reward) != os.path.abspath(dss):
                shutil.copy2(h_reward, dss)
        except Exception:
            pass

    h_traj = os.path.join(actual_trial_root, "agent", "trajectory.json")
    if os.path.isfile(h_traj):
        try:
            dst_traj = os.path.join(agent_dir, "trajectory.json")
            if os.path.abspath(h_traj) != os.path.abspath(dst_traj):
                shutil.copy2(h_traj, dst_traj)
        except Exception:
            pass

    h_res = os.path.join(actual_trial_root, "result.json")
    if os.path.isfile(h_res):
        try:
            with open(h_res, "r", encoding="utf-8") as rf:
                h_res_json = json.load(rf)
            trial_result_data["harbor_trial_result"] = h_res_json
            if h_res_json.get("exception_info"):
                trial_result_data["exception"] = h_res_json["exception_info"]
        except Exception:
            pass


def _finalize_trial_output(
    trial_root: str,
    task_dir: str,
    skill_dir: str,
    agent_mode: str,
    is_instruction_only: bool,
    trial_result_data: Dict[str, Any],
    contracts: Optional[List[Dict[str, Any]]],
    elapsed_sec: float,
) -> Dict[str, Any]:
    """Build structured Evidence and legacy return fields from a completed trial directory."""
    artifacts_dir = os.path.join(trial_root, "artifacts")
    agent_dir = os.path.join(trial_root, "agent")
    trial_result_path = os.path.join(trial_root, "result.json")

    with open(trial_result_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(trial_result_data, f, indent=2)

    run_status_file = os.path.join(artifacts_dir, "run_status.json")
    status, entry_reached, failure_type, error_sublabel, exit_code = read_and_cross_check_run_status(
        run_status_path=run_status_file,
        harbor_result_path=trial_result_path,
    )

    trajectory_file = os.path.join(agent_dir, "trajectory.json")
    skill_pkg_dir = os.path.join(task_dir, "environment", "skill")
    if not os.path.isdir(skill_pkg_dir):
        skill_pkg_dir = os.path.join(task_dir, "environment", "skill_package")
    activation = False
    script_execution = False
    goal_drift_audit = None
    if is_instruction_only and os.path.isfile(trajectory_file):
        activation, script_execution = parse_aces_trajectory(trajectory_file, skill_pkg_dir)
        if activation or script_execution:
            entry_reached = True
        try:
            from src.security.goal_drift_auditor import audit_trajectory_goal_drift
            with open(trajectory_file, "r", encoding="utf-8") as tf:
                traj_data = json.load(tf)
            goal_drift_audit = audit_trajectory_goal_drift(
                trajectory=traj_data,
                skill_id=task_dir.split(os.sep)[-1],
            )
        except Exception:
            pass

    strace_log_file = os.path.join(artifacts_dir, "strace.log")
    mock_egress_file = os.path.join(artifacts_dir, "mock_egress.jsonl")
    fs_diff_file = os.path.join(artifacts_dir, "fs_diff.patch")
    stdout_file = os.path.join(artifacts_dir, "stdout.log")
    stderr_file = os.path.join(artifacts_dir, "stderr.log")

    stdout_content = Path(stdout_file).read_text(encoding="utf-8", errors="ignore") if os.path.isfile(stdout_file) else ""
    stderr_content = Path(stderr_file).read_text(encoding="utf-8", errors="ignore") if os.path.isfile(stderr_file) else ""
    fs_diff_content = Path(fs_diff_file).read_text(encoding="utf-8", errors="ignore") if os.path.isfile(fs_diff_file) else ""
    mock_network_content = Path(mock_egress_file).read_text(encoding="utf-8", errors="ignore") if os.path.isfile(mock_egress_file) else ""

    canaries_file = os.path.join(trial_root, "harness_meta", "canaries.json")
    c_paths: List[str] = []
    c_tokens: List[str] = []
    if os.path.isfile(canaries_file):
        try:
            with open(canaries_file, "r", encoding="utf-8") as cf:
                canary_info = json.load(cf)
            c_paths = canary_info.get("paths", [])
            c_tokens = canary_info.get("tokens", [])
        except Exception:
            pass

    trace_events: List[Dict[str, Any]] = []
    if os.path.isfile(strace_log_file):
        s_events = parse_strace_to_events(
            strace_log_file,
            canary_paths=c_paths,
            mock_egress_path=mock_egress_file if os.path.isfile(mock_egress_file) else None,
        )
        if s_events:
            trace_events.extend(s_events)

    if c_tokens:
        exfil_events = detect_canary_content_exfiltration(
            canary_tokens=c_tokens,
            mock_egress_path=mock_egress_file if os.path.isfile(mock_egress_file) else None,
            written_files_dir=artifacts_dir,
            stdout_content=stdout_content,
            stderr_content=stderr_content,
            fs_diff_content=fs_diff_content,
        )
        if exfil_events:
            trace_events.extend(exfil_events)

    evidence, parsed_contracts = build_evidence_from_artifacts(
        artifacts_dir=artifacts_dir,
        skill_dir="/app/skill",
        trial_result_path=trial_result_path,
        contracts_override=contracts,
    )

    strace_info = parse_strace_telemetry(strace_log_file) if os.path.isfile(strace_log_file) else None
    triage_class, triage_sublabel, _ = classify_failure(
        exit_code=exit_code,
        stdout=stdout_content,
        stderr=stderr_content,
        traceback_str=stderr_content,
        events=trace_events,
        strace_info=strace_info,
        entry_point_reached=entry_reached,
    )

    return {
        "run_status": status,
        "entry_point_reached": entry_reached,
        "activation": activation if is_instruction_only else None,
        "script_execution": script_execution if is_instruction_only else None,
        "failure_type": failure_type or triage_class,
        "execution_error_sublabel": error_sublabel or triage_sublabel,
        "triage_class": triage_class,
        "triage_sublabel": triage_sublabel,
        "exit_code": exit_code,
        "auto_installed_packages": [],
        "agent_mode": agent_mode,
        "execution_time_sec": round(elapsed_sec, 3),
        "events": trace_events,
        "stdout": stdout_content,
        "stderr": stderr_content,
        "fs_diff": fs_diff_content,
        "mock_network": mock_network_content,
        "trial_dir": trial_root,
        "artifacts_dir": artifacts_dir,
        "evidence": evidence,
        "parsed_contracts": parsed_contracts,
        "is_instruction_only": is_instruction_only,
        "goal_drift_audit": goal_drift_audit,
        "converted_crlf_files": trial_result_data.get("converted_crlf_files", []),
        "missing_binaries": trial_result_data.get("missing_binaries", []),
        "backend": "harbor_docker",
        "valid_for_paper": True,
    }


def _write_no_agent_artifacts(artifacts_dir: str, key_env_var: str = "ANTHROPIC_API_KEY", agent_name: str = "claude-code") -> None:
    """Write clean NO_AGENT artifacts for instruction-only skills when no agent API key is configured (H6)."""
    os.makedirs(artifacts_dir, exist_ok=True)
    status_payload = {
        "run_status": "NOT_INVOKED",
        "entry_point_reached": False,
        "stage_at_exit": "no_agent_key",
        "failure_type": "NO_AGENT",
        "failure_signature": "NO_AGENT",
        "execution_error_sublabel": "NO_AGENT",
        "exit_code": None,
        "precondition_results": [],
        "check_results": [],
        "records": [],
        "ast_is_stub": False,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(os.path.join(artifacts_dir, "run_status.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(status_payload, f, indent=2)
    for fn, txt in (
        ("stdout.log", ""),
        ("stderr.log", f"Instruction-only skill requires {key_env_var} for {agent_name} agent."),
        ("strace.log", ""),
        ("fs_diff.patch", ""),
    ):
        with open(os.path.join(artifacts_dir, fn), "w", encoding="utf-8", newline="\n") as f:
            f.write(txt)


def execute_harbor_trial(
    task_dir: str,
    skill_dir: str,
    test_cases: List[Dict[str, Any]],
    contracts: Optional[List[Dict[str, Any]]] = None,
    refinement_attempt: int = 0,
    model: str = "anthropic/claude-3-5-sonnet-20241022",
    timeout_sec: Optional[int] = None,
) -> Dict[str, Any]:
    """Execute a single Harbor trial in Docker (R2: real Harbor/Docker only, no local subprocess fallback)."""
    job_id = f"job_{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    trial_id = f"trial_{uuid.uuid4().hex[:8]}"
    trial_root = os.path.abspath(os.path.join("jobs", job_id, trial_id))
    artifacts_dir = os.path.join(trial_root, "artifacts")
    verifier_dir = os.path.join(trial_root, "verifier")
    agent_dir = os.path.join(trial_root, "agent")

    os.makedirs(artifacts_dir, exist_ok=True)
    os.makedirs(verifier_dir, exist_ok=True)
    os.makedirs(agent_dir, exist_ok=True)

    # B3: Normalize CRLF in task directory before execution
    crlf_converted = normalize_crlf_in_directory(task_dir)
    # B5: Detect missing system binaries in skill
    missing_bins = detect_missing_binaries_in_skill(skill_dir)

    _write_task_fixtures(task_dir, artifacts_dir, test_cases)
    _copy_canaries_to_trial_meta(task_dir, trial_root)

    has_scripts = _has_runnable_scripts(task_dir, skill_dir)
    is_instruction_only = not has_scripts
    if contracts and not has_scripts:
        is_instruction_only = True

    if timeout_sec is None or timeout_sec <= 0:
        timeout_sec = AGENT_TIMEOUT_SEC if is_instruction_only else TRIAL_TIMEOUT_SEC

    t0 = time.time()
    instr_agent, instr_model, key_env_var, real_api_key = get_instruction_agent_config()
    agent_mode = instr_agent if is_instruction_only else "oracle"
    effective_model = instr_model if is_instruction_only else model

    trial_result_data: Dict[str, Any] = {
        "task_name": os.path.basename(task_dir),
        "agent_name": agent_mode,
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0)),
        "finished_at": None,
        "converted_crlf_files": crlf_converted,
        "missing_binaries": missing_bins,
        "agent_result": {},
        "verifier_result": {},
        "exception": None,
        "backend": "harbor_docker",
        "valid_for_paper": True,
    }

    # H6: Instruction-only path when no agent API key is set -> return Inconclusive(NO_AGENT) cleanly without faking a trajectory
    if is_instruction_only and (not real_api_key or "dummy" in real_api_key.lower() or "canary" in real_api_key.lower()):
        _write_no_agent_artifacts(artifacts_dir, key_env_var=key_env_var, agent_name=instr_agent)
        t1 = time.time()
        trial_result_data["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t1))
        return _finalize_trial_output(
            trial_root=trial_root,
            task_dir=task_dir,
            skill_dir=skill_dir,
            agent_mode=agent_mode,
            is_instruction_only=True,
            trial_result_data=trial_result_data,
            contracts=contracts,
            elapsed_sec=t1 - t0,
        )

    if not (is_harbor_cli_available() and is_docker_daemon_running()):
        raise RuntimeError(
            "Real Harbor (Docker) execution is required (Rule R2: no local-subprocess fallback), "
            "but Harbor CLI or Docker Linux daemon is unavailable."
        )

    jobs_abs_dir = os.path.abspath("jobs")
    os.makedirs(jobs_abs_dir, exist_ok=True)

    allow_host_args: List[str] = []
    if is_instruction_only:
        hosts_to_allow = list(PROVIDER_HOST_MAP.get(instr_agent, []))
        for h in dict.fromkeys(hosts_to_allow):
            allow_host_args.extend(["--allow-agent-host", h])

    harbor_cmd = _build_harbor_cli_cmd(
        [
            "run",
            "-p",
            task_dir,
            "-a",
            agent_mode,
            "--n-concurrent",
            "1",
            "--n-attempts",
            "1",
            "--jobs-dir",
            jobs_abs_dir,
            "--job-name",
            job_id,
            *(["-m", effective_model] if (is_instruction_only and effective_model) else []),
            *allow_host_args,
        ]
    )

    try:
        h_env = os.environ.copy()
        h_env["PYTHONIOENCODING"] = "utf-8"
        h_env["PYTHONUTF8"] = "1"
        proc = subprocess.run(
            harbor_cmd,
            env=h_env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
        )
        trial_result_data["agent_result"]["stdout"] = proc.stdout
        trial_result_data["agent_result"]["stderr"] = proc.stderr
        if proc.returncode != 0:
            trial_result_data["agent_result"]["exception"] = f"Harbor CLI returned non-zero exit code: {proc.returncode}"

        job_dir = os.path.abspath(os.path.join("jobs", job_id))
        if os.path.isdir(job_dir):
            trial_subdirs = [
                d
                for d in os.listdir(job_dir)
                if os.path.isdir(os.path.join(job_dir, d)) and not d.startswith(".") and d != trial_id
            ]
            for tsd in trial_subdirs:
                actual_trial_root = os.path.join(job_dir, tsd)
                _collect_harbor_trial_artifacts(
                    actual_trial_root=actual_trial_root,
                    trial_root=trial_root,
                    task_dir=task_dir,
                    trial_result_data=trial_result_data,
                )
    except subprocess.TimeoutExpired:
        trial_result_data["exception"] = f"Harbor execution timed out after {timeout_sec}s"
    except Exception as exc:
        trial_result_data["exception"] = str(exc)

    # Scrub any leaked API keys from collected trial artifacts and result data
    scrub_api_keys_in_dir(trial_root)
    trial_result_data = scrub_api_keys_in_object(trial_result_data)

    t1 = time.time()
    trial_result_data["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t1))
    return _finalize_trial_output(
        trial_root=trial_root,
        task_dir=task_dir,
        skill_dir=skill_dir,
        agent_mode=agent_mode,
        is_instruction_only=is_instruction_only,
        trial_result_data=trial_result_data,
        contracts=contracts,
        elapsed_sec=t1 - t0,
    )


def execute_harbor_batch(
    task_specs: List[Dict[str, Any]],
    batch_parent_dir: str,
    n_concurrent: Optional[int] = None,
    timeout_sec: Optional[int] = None,
) -> Dict[str, Dict[str, Any]]:
    """Execute multiple prepared Harbor tasks in a single `harbor run` invocation (H4, W4).

    Args:
        task_specs: List of dicts with keys `skill_id`, `task_dir`, `skill_dir`, `test_cases`, `contracts`.
        batch_parent_dir: Parent directory containing the task directories.
        n_concurrent: Number of concurrent trials (`--n-concurrent`, default 2 on Windows, 4 on Linux).
        timeout_sec: Overall batch timeout in seconds.

    Returns:
        Mapping `{skill_id: trial_result_dict}` with the exact same schema as `execute_harbor_trial`.
    """
    if not task_specs:
        return {}

    n_concurrent = n_concurrent if n_concurrent is not None else BATCH_CONCURRENCY_DEFAULT

    job_id = f"batch_{time.strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    results_by_skill: Dict[str, Dict[str, Any]] = {}
    runnable_specs: List[Dict[str, Any]] = []
    trial_roots_by_skill: Dict[str, str] = {}

    # Prepare clean staging directory containing only runnable tasks for this batch
    staging_dir = os.path.abspath(os.path.join(batch_parent_dir, f"_batch_stage_{job_id}"))
    os.makedirs(staging_dir, exist_ok=True)

    instr_agent, instr_model, key_env_var, real_api_key = get_instruction_agent_config()
    has_real_key = bool(real_api_key and "dummy" not in real_api_key.lower() and "canary" not in real_api_key.lower())

    for spec in task_specs:
        skill_id = spec["skill_id"]
        task_dir = spec["task_dir"]
        skill_dir = spec["skill_dir"]
        test_cases = spec.get("test_cases") or []
        contracts = spec.get("contracts") or []

        trial_id = f"trial_{skill_id}_{uuid.uuid4().hex[:6]}"
        trial_root = os.path.abspath(os.path.join("jobs", job_id, trial_id))
        artifacts_dir = os.path.join(trial_root, "artifacts")
        os.makedirs(artifacts_dir, exist_ok=True)
        os.makedirs(os.path.join(trial_root, "verifier"), exist_ok=True)
        os.makedirs(os.path.join(trial_root, "agent"), exist_ok=True)

        _write_task_fixtures(task_dir, artifacts_dir, test_cases)
        _copy_canaries_to_trial_meta(task_dir, trial_root)
        trial_roots_by_skill[skill_id] = trial_root

        has_scripts = _has_runnable_scripts(task_dir, skill_dir)
        is_instruction_only = not has_scripts
        if is_instruction_only and not has_real_key:
            _write_no_agent_artifacts(artifacts_dir, key_env_var=key_env_var, agent_name=instr_agent)
            t_now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            t_data = {
                "task_name": os.path.basename(task_dir),
                "agent_name": instr_agent,
                "started_at": t_now,
                "finished_at": t_now,
                "agent_result": {},
                "verifier_result": {},
                "exception": None,
                "backend": "harbor_docker",
                "valid_for_paper": True,
            }
            res_no_agent = _finalize_trial_output(
                trial_root=trial_root,
                task_dir=task_dir,
                skill_dir=skill_dir,
                agent_mode=instr_agent,
                is_instruction_only=True,
                trial_result_data=t_data,
                contracts=contracts,
                elapsed_sec=0.01,
            )
            res_no_agent["harbor_trial_count"] = 1
            results_by_skill[skill_id] = res_no_agent
        else:
            staged_task_dir = os.path.join(staging_dir, os.path.basename(task_dir))
            if os.path.exists(staged_task_dir):
                shutil.rmtree(staged_task_dir, ignore_errors=True)
            try:
                shutil.copytree(task_dir, staged_task_dir, copy_function=os.link)
            except Exception:
                shutil.copytree(task_dir, staged_task_dir, dirs_exist_ok=True)
            # B3: Normalize CRLF line endings in staged task dir
            crlf_converted = normalize_crlf_in_directory(staged_task_dir)
            # B5: Detect missing system binaries in skill
            missing_bins = detect_missing_binaries_in_skill(skill_dir)
            runnable_specs.append({
                **spec,
                "staged_task_dir": staged_task_dir,
                "converted_crlf_files": crlf_converted,
                "missing_binaries": missing_bins,
            })

    if not runnable_specs:
        shutil.rmtree(staging_dir, ignore_errors=True)
        return results_by_skill

    if not (is_harbor_cli_available() and is_docker_daemon_running()):
        shutil.rmtree(staging_dir, ignore_errors=True)
        raise RuntimeError(
            "Real Harbor (Docker) execution is required (Rule R2: no local-subprocess fallback), "
            "but Harbor CLI or Docker Linux daemon is unavailable."
        )

    is_any_instruction_only = any(not _has_runnable_scripts(s["task_dir"], s["skill_dir"]) for s in runnable_specs)
    batch_agent = instr_agent if is_any_instruction_only else "oracle"
    batch_model = instr_model if is_any_instruction_only else None

    if timeout_sec is None or timeout_sec <= 0:
        base_to = AGENT_TIMEOUT_SEC if is_any_instruction_only else TRIAL_TIMEOUT_SEC
        waves = max(1, (len(runnable_specs) + n_concurrent - 1) // n_concurrent)
        timeout_sec = base_to * waves + 60

    batch_allow_host_args: List[str] = []
    if is_any_instruction_only:
        for h in dict.fromkeys(PROVIDER_HOST_MAP.get(instr_agent, [])):
            batch_allow_host_args.extend(["--allow-agent-host", h])

    jobs_abs_dir = os.path.abspath("jobs")
    os.makedirs(jobs_abs_dir, exist_ok=True)
    harbor_cmd = _build_harbor_cli_cmd(
        [
            "run",
            "-p",
            staging_dir,
            "-a",
            batch_agent,
            "--n-concurrent",
            str(max(1, int(n_concurrent))),
            "--n-attempts",
            "1",
            "--jobs-dir",
            jobs_abs_dir,
            "--job-name",
            job_id,
            *(["-m", batch_model] if batch_model else []),
            *batch_allow_host_args,
        ]
    )

    t0 = time.time()
    batch_exception: Optional[str] = None
    batch_stdout = ""
    batch_stderr = ""
    try:
        h_env = os.environ.copy()
        h_env["PYTHONIOENCODING"] = "utf-8"
        h_env["PYTHONUTF8"] = "1"
        proc = subprocess.run(
            harbor_cmd,
            env=h_env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_sec,
        )
        batch_stdout = proc.stdout
        batch_stderr = proc.stderr
        if proc.returncode != 0:
            batch_exception = f"Harbor batch CLI returned non-zero exit code: {proc.returncode}"
    except subprocess.TimeoutExpired:
        batch_exception = f"Harbor batch execution timed out after {timeout_sec}s"
    except Exception as exc:
        batch_exception = str(exc)

    t1 = time.time()
    elapsed_per_task = (t1 - t0) / max(1, len(runnable_specs))

    # Map generated Harbor trial directories back to each task_name
    job_dir = os.path.abspath(os.path.join("jobs", job_id))
    reserved_trial_ids = {os.path.basename(p) for p in trial_roots_by_skill.values()}
    harbor_trials_by_task_name: Dict[str, List[str]] = {}
    if os.path.isdir(job_dir):
        for entry in sorted(os.listdir(job_dir)):
            full_entry = os.path.join(job_dir, entry)
            if not os.path.isdir(full_entry) or entry.startswith(".") or entry in reserved_trial_ids:
                continue
            t_name = None
            res_p = os.path.join(full_entry, "result.json")
            if os.path.isfile(res_p):
                try:
                    with open(res_p, "r", encoding="utf-8") as rf:
                        t_name = json.load(rf).get("task_name")
                except Exception:
                    t_name = None
            if not t_name and "__" in entry:
                t_name = entry.split("__", 1)[0]
            if t_name:
                harbor_trials_by_task_name.setdefault(t_name, []).append(full_entry)

    for spec in runnable_specs:
        skill_id = spec["skill_id"]
        task_dir = spec["task_dir"]
        skill_dir = spec["skill_dir"]
        contracts = spec.get("contracts") or []
        task_name = os.path.basename(task_dir)
        trial_root = trial_roots_by_skill[skill_id]

        is_spec_instr = not _has_runnable_scripts(task_dir, skill_dir)
        spec_agent = instr_agent if is_spec_instr else "oracle"

        t_data: Dict[str, Any] = {
            "task_name": task_name,
            "agent_name": spec_agent,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0)),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t1)),
            "converted_crlf_files": spec.get("converted_crlf_files", []),
            "missing_binaries": spec.get("missing_binaries", []),
            "agent_result": {"stdout": batch_stdout, "stderr": batch_stderr},
            "verifier_result": {},
            "exception": None,
            "backend": "harbor_docker",
            "valid_for_paper": True,
        }

        matched_dirs = harbor_trials_by_task_name.get(task_name, [])
        if not matched_dirs:
            for k_name, dirs in harbor_trials_by_task_name.items():
                if len(k_name) >= 16 and (task_name.startswith(k_name) or k_name.startswith(task_name)):
                    matched_dirs = dirs
                    break
        if matched_dirs:
            for m_dir in matched_dirs:
                _collect_harbor_trial_artifacts(
                    actual_trial_root=m_dir,
                    trial_root=trial_root,
                    task_dir=task_dir,
                    trial_result_data=t_data,
                )
        else:
            # B4: Task stalled or was skipped in batch; retry once individually
            try:
                retry_res = execute_harbor_trial(
                    task_dir=task_dir,
                    skill_dir=skill_dir,
                    test_cases=spec.get("test_cases") or [],
                    contracts=contracts,
                    timeout_sec=AGENT_TIMEOUT_SEC if is_spec_instr else TRIAL_TIMEOUT_SEC,
                )
                results_by_skill[skill_id] = retry_res
                continue
            except Exception as retry_exc:
                t_data["exception"] = batch_exception or f"Batch missed trial and single retry failed: {retry_exc}"

        scrub_api_keys_in_dir(trial_root)
        t_data = scrub_api_keys_in_object(t_data)

        res_dict = _finalize_trial_output(
            trial_root=trial_root,
            task_dir=task_dir,
            skill_dir=skill_dir,
            agent_mode=spec_agent,
            is_instruction_only=is_spec_instr,
            trial_result_data=t_data,
            contracts=contracts,
            elapsed_sec=elapsed_per_task,
        )
        res_dict["harbor_trial_count"] = len(matched_dirs)
        results_by_skill[skill_id] = res_dict

    shutil.rmtree(staging_dir, ignore_errors=True)
    return results_by_skill
