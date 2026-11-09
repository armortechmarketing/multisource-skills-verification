import os
import sys
import json
import sqlite3
import re
import ast
import shutil
import uuid
import random
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

sys.path.append(os.path.abspath("."))
from src.domain_classifier import classify_skill_domain
from src.dep_resolver import STDLIB_MODULES, PIP_ALIAS_MAP
from src.security.level1_scanner import scan_skill_for_level1_security

PAID_KEY_PATTERNS = [
    r'OPENAI_API_KEY', r'ANTHROPIC_API_KEY', r'AWS_SECRET_ACCESS_KEY',
    r'AZURE_OPENAI', r'SERPAPI_API_KEY', r'PINECONE_API_KEY',
    r'COHERE_API_KEY', r'REPLICATE_API_TOKEN', r'HUGGINGFACEHUB_API_TOKEN',
    r'GEMINI_API_KEY', r'GOOGLE_API_KEY', r'SLACK_BOT_TOKEN'
]
PAID_REGEX = re.compile('|'.join(PAID_KEY_PATTERNS), re.IGNORECASE)

TAXONOMY_MAP = {
    "B1": "Data Exfiltration",
    "B2": "Credential Theft",
    "B3": "Remote Code Execution",
    "B4": "Malware Delivery",
    "B5": "Persistence",
    "B6": "Reverse Shell",
    "B7": "Ransomware / File Tampering",
    "B8": "Resource Abuse",
    "B9": "Privilege Escalation",
    "B10": "Role Hijack",
    "B11": "Safety Bypass",
    "B12": "Instruction Override",
    "B13": "System Prompt Leak",
    "B14": "Goal Hijacking",
    "B15": "Content Manipulation"
}


# External Network / Web API call signatures to detect heavy network dependencies
EXTERNAL_NET_CALL_PATTERNS = [
    r'\brequests\.(?:get|post|put|delete|patch|head|request)\b',
    r'\burllib\.request\.urlopen\b',
    r'\bhttpx\.(?:get|post|put|delete|patch|head|request|Client|AsyncClient)\b',
    r'\baiohttp\.ClientSession\b',
    r'\bhttp\.client\.(?:HTTPConnection|HTTPSConnection)\b',
    r'\bsocket\.create_connection\b',
    r'\bftplib\.FTP\b'
]
EXTERNAL_NET_CALL_REGEX = re.compile('|'.join(EXTERNAL_NET_CALL_PATTERNS), re.IGNORECASE)


def inspect_runnable_code(code_files: Dict[str, str]) -> Tuple[bool, bool, int, str]:
    """
    Analyzes code files for:
    - has_runnable_entry: contains executable Python scripts with entrypoints or statements
    - is_stub: whether script is purely pass/NotImplementedError/empty
    - external_net_call_count: number of external HTTP/network API invocations
    - summary: descriptive string of findings
    """
    py_files = {k: v for k, v in code_files.items() if k.endswith('.py') and v and v.strip()}
    if not py_files:
        return False, True, 0, "No runnable Python (.py) scripts found"

    total_net_calls = 0
    has_substantive_code = False
    has_entrypoint = False

    for fn, code in py_files.items():
        if not code or not code.strip():
            continue

        # Count external network API calls
        net_calls = len(EXTERNAL_NET_CALL_REGEX.findall(code))
        total_net_calls += net_calls

        # Check for executable entrypoint
        if '__name__' in code or 'def main' in code:
            has_entrypoint = True

        # Check AST for substantive statements (not just pass/docstring)
        try:
            tree = ast.parse(code)
            non_trivial = [
                n for n in tree.body 
                if not isinstance(n, (ast.Pass, ast.Expr)) or (isinstance(n, ast.Expr) and not isinstance(n.value, ast.Constant))
            ]
            if non_trivial:
                has_substantive_code = True
        except Exception:
            if len(code.strip().splitlines()) >= 3:
                has_substantive_code = True

    is_runnable = (has_substantive_code or has_entrypoint)
    return is_runnable, not is_runnable, total_net_calls, "OK"


# =============================================================================
# KEY-ONLY (OPENAI / GEMINI) ELIGIBILITY FILTER CONSTANTS & HELPERS
# =============================================================================

KEY_ONLY_SHARED_BASE_PACKAGES = {
    "pytest", "pyyaml", "requests", "pandas", "chardet", "faker",
    "click", "typer", "rich", "jinja2", "beautifulsoup4", "uv"
}

KEY_ONLY_HEAVY_PACKAGES = {
    "torch", "tensorflow", "transformers", "cv2", "opencv-python",
    "opencv-python-headless", "diffusers", "timm", "vllm", "scipy",
    "sklearn", "scikit-learn", "keras", "jax", "spacy", "nltk",
    "torchvision", "torchaudio"
}

KEY_ONLY_ALLOWED_HOSTS = {
    "api.openai.com", "generativelanguage.googleapis.com", "localhost", "127.0.0.1"
}

KEY_ONLY_DOC_HOSTS = {
    "github.com", "api.github.com", "raw.githubusercontent.com",
    "python.org", "docs.python.org", "pypi.org", "pypi.python.org",
    "mit-license.org", "opensource.org", "apache.org", "w3.org",
    "developer.mozilla.org", "schema.org", "arxiv.org"
}

KEY_ONLY_CLOUD_OR_DB_PACKAGES = {
    "boto3", "botocore", "google-cloud-storage", "google-cloud-bigquery",
    "google-cloud", "azure", "azure-storage-blob", "psycopg2", "mysql",
    "pymongo", "redis", "sqlalchemy", "playwright", "selenium",
    "docker", "kubernetes", "cassandra", "neo4j"
}

KEY_ONLY_SYSTEM_BINARIES_PATTERNS = [
    r"\bffmpeg\b", r"\bsox\b", r"\bpandoc\b", r"\blibreoffice\b",
    r"\bgraphicsmagick\b", r"\bimagemagick\b", r"\btesseract\b"
]

KEY_ONLY_SECRET_PATTERN = re.compile(r"^[A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|URL)[A-Z0-9_]*$", re.IGNORECASE)

KEY_ONLY_STANDARD_ALLOWED_ENV = {
    "PATH", "PYTHONPATH", "HOME", "USER", "PWD", "TEMP", "TMP", "TMPDIR",
    "PYTHONUNBUFFERED", "LANG", "LC_ALL"
}


def analyze_ast_env_vars(code: str) -> Dict[str, bool]:
    """
    Parses Python source code with AST to identify all env vars read,
    mapping each var_name -> is_required (True if required/no default, False if optional with default).
    """
    env_reads: Dict[str, bool] = {}
    try:
        tree = ast.parse(code)
    except Exception:
        # Fallback regex scanning for unparseable snippets
        for m in re.finditer(r"os\.environ\[['\"]([a-zA-Z0-9_]+)['\"]\]", code):
            env_reads[m.group(1)] = True
        for m in re.finditer(r"os\.(?:getenv|environ\.get)\(['\"]([a-zA-Z0-9_]+)['\"](?:\s*,\s*([^)]+))?\)", code):
            var = m.group(1)
            default = m.group(2)
            has_default = bool(default and default.strip() and default.strip() != "None")
            env_reads[var] = env_reads.get(var, False) or (not has_default)
        return env_reads

    for node in ast.walk(tree):
        # 1. os.environ['VAR'] -> unconditional subscript access (required)
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute) and node.value.attr == "environ":
                if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                    env_reads[node.slice.value] = True
        # 2. os.getenv('VAR', default) or os.environ.get('VAR', default)
        elif isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Attribute) and fn.attr in ("getenv", "get"):
                is_env = False
                if isinstance(fn.value, ast.Name) and fn.value.id == "os" and fn.attr == "getenv":
                    is_env = True
                elif isinstance(fn.value, ast.Attribute) and fn.value.attr == "environ":
                    is_env = True
                if is_env and node.args:
                    arg0 = node.args[0]
                    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                        var_name = arg0.value
                        has_default = len(node.args) > 1 and not (
                            isinstance(node.args[1], ast.Constant) and node.args[1].value is None
                        )
                        env_reads[var_name] = env_reads.get(var_name, False) or (not has_default)

    return env_reads


def evaluate_key_only_eligibility(
    skill_id: str,
    skill_md: str,
    code_files: Dict[str, str],
    allowed_keys: str = "either",
    known_malicious: bool = False,
    src_dir: Optional[str] = None
) -> Dict[str, Any]:
    """
    Evaluates a candidate skill against the 6 strict eligibility criteria:
    1. Runnable script entry (not instruction-only).
    2. Reads OPENAI_API_KEY or GEMINI_API_KEY per allowed_keys (GOOGLE_API_KEY allowed only with genai libs).
    3. No OTHER required env var or secret.
    4. Hardcoded hosts subset of {api.openai.com, generativelanguage.googleapis.com, localhost, 127.0.0.1}.
    5. Third-party imports are stdlib or pip-installable; heavy/unsupported packages excluded.
    6. Level-1 risk is LOW or MEDIUM and not labeled malicious.
    """
    # 1. Check runnable script entry
    has_script_entry = False
    py_files = {k: v for k, v in code_files.items() if k.endswith(".py") and v and v.strip()}
    sh_files = {k: v for k, v in code_files.items() if k.endswith(".sh") and v and v.strip()}

    if py_files:
        for fn, code in py_files.items():
            if "__name__" in code or "def main" in code or len(code.strip().splitlines()) >= 3:
                has_script_entry = True
                break
    elif sh_files:
        for fn, code in sh_files.items():
            if "python" in code and len(code.strip().splitlines()) >= 2:
                has_script_entry = True
                break

    instruction_only = not has_script_entry

    # 2. Extract env vars read across Python and shell/other files
    all_env_reads: Dict[str, bool] = {}
    for fn, code in py_files.items():
        ast_reads = analyze_ast_env_vars(code)
        for k, req in ast_reads.items():
            all_env_reads[k] = all_env_reads.get(k, False) or req

    for fn, code in code_files.items():
        for m in re.finditer(r"process\.env\.([a-zA-Z0-9_]+)", code):
            all_env_reads[m.group(1)] = True
        for m in re.finditer(r"\$\{([A-Z0-9_]{3,})\}", code):
            var = m.group(1)
            if var not in KEY_ONLY_STANDARD_ALLOWED_ENV:
                all_env_reads[var] = True

    env_vars_read = sorted(all_env_reads.keys())

    # 3. Third-party imports extraction
    third_party_imports: Set[str] = set()
    local_mods = {Path(fn).stem for fn in code_files.keys()}
    for fn, code in py_files.items():
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top = alias.name.split(".")[0]
                        if top not in STDLIB_MODULES and top not in local_mods:
                            third_party_imports.add(PIP_ALIAS_MAP.get(top, top))
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        top = node.module.split(".")[0]
                        if top not in STDLIB_MODULES and top not in local_mods:
                            third_party_imports.add(PIP_ALIAS_MAP.get(top, top))
        except Exception:
            pass

    has_google_genai_lib = (
        any("google" in imp or "genai" in imp for imp in third_party_imports)
        or "google.generativeai" in " ".join(py_files.values())
        or "google.genai" in " ".join(py_files.values())
    )

    reads_openai = "OPENAI_API_KEY" in all_env_reads
    reads_gemini = "GEMINI_API_KEY" in all_env_reads or ("GOOGLE_API_KEY" in all_env_reads and has_google_genai_lib)

    if allowed_keys == "openai":
        key_ok = reads_openai
    elif allowed_keys == "gemini":
        key_ok = reads_gemini
    else:  # "either"
        key_ok = reads_openai or reads_gemini

    allowed_env_names = {"OPENAI_API_KEY", "GEMINI_API_KEY"}
    if has_google_genai_lib:
        allowed_env_names.add("GOOGLE_API_KEY")

    other_env_vars: List[str] = []
    secret_like_vars: List[str] = []

    for var, is_req in all_env_reads.items():
        if var in allowed_env_names:
            continue
        if var == "OPENAI_BASE_URL":
            if is_req:
                other_env_vars.append(var)
            continue
        if KEY_ONLY_SECRET_PATTERN.match(var):
            secret_like_vars.append(var)
        elif is_req and var not in KEY_ONLY_STANDARD_ALLOWED_ENV:
            other_env_vars.append(var)

    other_env_vars = sorted(set(other_env_vars))
    secret_like_vars = sorted(set(secret_like_vars))

    # 4. Check network hosts in code and documentation
    combined_code = " ".join(code_files.values())
    raw_hosts = re.findall(r"https?://([a-zA-Z0-9\.\-]+(?::\d+)?)", combined_code)
    clean_hosts = set()
    for h in raw_hosts:
        h_clean = h.split(":")[0].lower()
        if h_clean:
            clean_hosts.add(h_clean)

    hosts_found = sorted(clean_hosts)
    other_hosts = sorted([h for h in clean_hosts if h not in KEY_ONLY_ALLOWED_HOSTS and h not in KEY_ONLY_DOC_HOSTS])

    # 5. Classify dependency requirements
    heavy_or_unsupported_deps = sorted([imp for imp in third_party_imports if imp in KEY_ONLY_HEAVY_PACKAGES])
    imports_not_in_shared_base = sorted([
        imp for imp in third_party_imports
        if imp not in KEY_ONLY_SHARED_BASE_PACKAGES and imp not in KEY_ONLY_HEAVY_PACKAGES
    ])
    needs_other_services = sorted([imp for imp in third_party_imports if imp in KEY_ONLY_CLOUD_OR_DB_PACKAGES])

    # Check system binaries
    needs_system_binaries = []
    for pat in KEY_ONLY_SYSTEM_BINARIES_PATTERNS:
        if re.search(pat, combined_code, re.IGNORECASE):
            needs_system_binaries.append(pat.replace(r"\b", ""))

    # 6. Evaluation against exclusion rules
    exclusion_reasons: List[str] = []
    if instruction_only:
        exclusion_reasons.append("instruction_only_no_script")
    if not key_ok:
        exclusion_reasons.append(f"does_not_read_target_key({allowed_keys})")
    if other_env_vars:
        exclusion_reasons.append(f"requires_other_env_vars({','.join(other_env_vars[:3])})")
    if secret_like_vars:
        exclusion_reasons.append(f"has_secret_like_vars({','.join(secret_like_vars[:3])})")
    if other_hosts:
        exclusion_reasons.append(f"requires_other_hosts({','.join(other_hosts[:3])})")
    if heavy_or_unsupported_deps:
        exclusion_reasons.append(f"heavy_deps({','.join(heavy_or_unsupported_deps[:3])})")
    if needs_other_services:
        exclusion_reasons.append(f"needs_other_services({','.join(needs_other_services[:3])})")
    if needs_system_binaries:
        exclusion_reasons.append(f"needs_system_binaries({','.join(needs_system_binaries[:3])})")
    if known_malicious:
        exclusion_reasons.append("labeled_malicious")

    # Level 1 security scan: only run on candidates that pass criteria 1-5 and are not labeled malicious
    l1_risk = "LOW"
    if len(exclusion_reasons) == 0:
        try:
            import tempfile
            with tempfile.TemporaryDirectory() as td:
                Path(td, "SKILL.md").write_text(skill_md, encoding="utf-8", errors="ignore")
                s_dir_tmp = Path(td, "scripts")
                s_dir_tmp.mkdir(exist_ok=True)
                for fn, content in code_files.items():
                    target_p = s_dir_tmp / Path(fn).name
                    target_p.write_text(content, encoding="utf-8", errors="ignore")
                l1_rep = scan_skill_for_level1_security(td, declaration_text=skill_md)
                l1_risk = str(l1_rep.get("risk_level") or "LOW")
        except Exception:
            pass

        if l1_risk in ("HIGH", "CRITICAL"):
            exclusion_reasons.append(f"level1_risk_{l1_risk}")

    eligible = (len(exclusion_reasons) == 0)

    return {
        "skill_id": skill_id,
        "has_script_entry": has_script_entry,
        "instruction_only": instruction_only,
        "env_vars_read": ";".join(env_vars_read),
        "other_env_vars": ";".join(other_env_vars),
        "secret_like_vars": ";".join(secret_like_vars),
        "hosts_found": ";".join(hosts_found),
        "other_hosts": ";".join(other_hosts),
        "third_party_imports": ";".join(sorted(third_party_imports)),
        "heavy_or_unsupported_deps": ";".join(heavy_or_unsupported_deps),
        "imports_not_in_shared_base": ";".join(imports_not_in_shared_base),
        "needs_system_binaries": ";".join(needs_system_binaries),
        "needs_other_services": ";".join(needs_other_services),
        "level1_risk": l1_risk,
        "known_malicious": known_malicious,
        "eligible": eligible,
        "exclusion_reason": "; ".join(exclusion_reasons) if exclusion_reasons else ""
    }


class DynamicAgentSkillFetchAgent:
    """
    DynamicAgentSkillFetch Agent:
    Autonomous skill sampling and validation agent.
    Governed by its formal declarative specification in:
    src/agents/skills/DynamicAgentSkillFetch/SKILL.md
    """

    SKILL_NAME = "DynamicAgentSkillFetch"
    SKILL_SPEC_PATH = os.path.join(
        os.path.dirname(__file__), "skills", "DynamicAgentSkillFetch", "SKILL.md"
    )

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = os.path.abspath(base_dir or ".")
        self.db_path = os.path.join(self.base_dir, "gitskills_raw", "agent_skills_sample.db")
        self.malskillbench_dir = os.path.join(self.base_dir, "MalSkillBench", "Dataset", "Skills", "malware")
        self.skills_dataset_dir = os.path.join(self.base_dir, "skills_dataset")
        self.skill_spec = self._load_skill_specification()

    def _load_skill_specification(self) -> str:
        if os.path.exists(self.SKILL_SPEC_PATH):
            try:
                return Path(self.SKILL_SPEC_PATH).read_text(encoding="utf-8")
            except Exception:
                return ""
        return ""

    def validate_candidate_skill(
        self,
        skill_id: str,
        skill_md_text: str,
        code_files: Dict[str, str],
        exclude_external_api: bool = True,
        require_standalone_code: bool = False,
        max_external_api_calls: int = 1,
        exclude_instruction_only: bool = True,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Validates a candidate skill for integrity, parseability, and offline execution compatibility.
        - exclude_instruction_only (True by default): Requires runnable Python (.py) code.
        - require_standalone_code: Also enforces low/zero external web API calls.
        Returns: (is_valid, domain, rejection_reason)
        """
        if not skill_md_text or not skill_md_text.strip():
            return False, None, "SKILL.md missing or completely empty"

        # Check YAML frontmatter presence
        if not skill_md_text.startswith("---") or "---" not in skill_md_text[3:]:
            return False, None, "Corrupted or missing YAML frontmatter in SKILL.md"

        # Check external paid API key exclusion if enabled
        combined_text = skill_md_text + " \n " + " \n ".join(code_files.values())
        if exclude_external_api:
            match = PAID_REGEX.search(combined_text)
            if match:
                return False, None, f"Requires external paid API key: {match.group(0)}"

        # By default (or when standalone filter is active), require runnable Python code
        if exclude_instruction_only or require_standalone_code:
            is_runnable, is_stub, net_calls, reason = inspect_runnable_code(code_files)
            if not is_runnable or is_stub:
                return False, None, f"Lacks runnable Python code: {reason}"
            if require_standalone_code and net_calls > max_external_api_calls:
                return False, None, f"Too many external API calls ({net_calls} calls, max allowed: {max_external_api_calls})"

        # Classify functional domain
        domain = classify_skill_domain(skill_md_text, code_files)

        return True, domain, None

    def _read_fs_candidate(self, s_dir: str) -> Tuple[bool, str, Dict[str, str], Optional[str]]:
        """
        Safely reads SKILL.md and scripts from a filesystem directory.
        Protects against invalid characters, non-existent files, and permission errors.
        """
        try:
            skill_md_path = os.path.join(s_dir, "SKILL.md")
            md_text = ""
            if os.path.isfile(skill_md_path):
                md_text = Path(skill_md_path).read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            return False, "", {}, f"Failed reading SKILL.md: {e}"

        code_files = {}
        try:
            scripts_dir = os.path.join(s_dir, "scripts")
            if os.path.isdir(scripts_dir):
                for fn in os.listdir(scripts_dir):
                    if fn.endswith((".py", ".sh")):
                        script_p = os.path.join(scripts_dir, fn)
                        if os.path.isfile(script_p):
                            code_files[fn] = Path(script_p).read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            return False, "", {}, f"Failed reading scripts: {e}"

        return True, md_text, code_files, None

    def load_candidate_pool(self, include_instruction_only: bool = True) -> List[Dict[str, Any]]:
        """
        Loads the candidate pool across GitSkills DB, local skills_dataset, and MalSkillBench.
        - include_instruction_only: if False, restricts DB candidates to those with .py siblings.
        """
        candidate_pool: List[Dict[str, Any]] = []
        seen_ids = set()

        # 1. Local skills_dataset (benign)
        if os.path.exists(self.skills_dataset_dir):
            for d in sorted(os.listdir(self.skills_dataset_dir)):
                if d.startswith("benign_"):
                    s_path = os.path.join(self.skills_dataset_dir, d)
                    if os.path.isdir(s_path):
                        read_ok, md_text, code_files, _ = self._read_fs_candidate(s_path)
                        if read_ok and (include_instruction_only or any(f.endswith(".py") for f in code_files)):
                            seen_ids.add(d)
                            candidate_pool.append({
                                "skill_id": d,
                                "source": "gitskills",
                                "domain": "custom",
                                "known_malicious": False,
                                "src_type": "fs",
                                "src_path": s_path,
                                "md_content": md_text,
                                "code_files": code_files,
                                "all_siblings": dict(code_files)
                            })

        # 2. MalSkillBench (malware)
        if os.path.exists(self.malskillbench_dir):
            for d in sorted(os.listdir(self.malskillbench_dir)):
                s_path = os.path.join(self.malskillbench_dir, d)
                if os.path.isdir(s_path):
                    clean_id = re.sub(r'[^a-zA-Z0-9_-]', '_', d.replace('__', '_'))
                    s_id = f"mal_{clean_id}"
                    if s_id not in seen_ids:
                        read_ok, md_text, code_files, _ = self._read_fs_candidate(s_path)
                        if read_ok:
                            seen_ids.add(s_id)
                            candidate_pool.append({
                                "skill_id": s_id,
                                "source": "malskillbench",
                                "domain": "malware",
                                "known_malicious": True,
                                "src_type": "fs",
                                "src_path": s_path,
                                "md_content": md_text,
                                "code_files": code_files,
                                "all_siblings": dict(code_files)
                            })

        # 3. GitSkills SQLite DB
        if os.path.exists(self.db_path):
            try:
                conn = sqlite3.connect(self.db_path)
                cur = conn.cursor()
                query = """
                SELECT a.repo_full_name, a.path, a.name, a.content, s.entry_name, s.content
                FROM artifacts a
                LEFT JOIN artifact_siblings s ON a.repo_full_name = s.repo_full_name AND a.path = s.artifact_path
                WHERE a.dedup_primary = 1 AND a.frontmatter_valid = 1 AND a.content IS NOT NULL
                """
                cur.execute(query)
                grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
                for repo, path, name, md_content, s_name, s_content in cur:
                    k = (repo, path)
                    if k not in grouped:
                        grouped[k] = {
                            "type": "db",
                            "name": name,
                            "repo": repo,
                            "path": path,
                            "md_content": md_content,
                            "code_files": {},
                            "all_siblings": {}
                        }
                    if s_name and s_content is not None:
                        grouped[k]["all_siblings"][s_name] = s_content
                        if s_name.endswith((".py", ".sh")):
                            grouped[k]["code_files"][s_name] = s_content

                conn.close()

                for item in grouped.values():
                    if not include_instruction_only and not item["code_files"]:
                        continue
                    clean_name = re.sub(r'[^a-zA-Z0-9_-]', '_', item["name"] or "skill")
                    s_id = f"benign_{clean_name}"
                    orig_sid = s_id
                    ctr = 2
                    while s_id in seen_ids:
                        s_id = f"{orig_sid}_{ctr}"
                        ctr += 1
                    seen_ids.add(s_id)

                    candidate_pool.append({
                        "skill_id": s_id,
                        "source": "gitskills",
                        "domain": "general",
                        "known_malicious": False,
                        "src_type": "db",
                        "repo": item["repo"],
                        "artifact_path": item["path"],
                        "md_content": item["md_content"],
                        "code_files": item["code_files"],
                        "all_siblings": item["all_siblings"]
                    })
            except Exception:
                pass

        return candidate_pool

    def fetch_sample(
        self,
        total_count: int = 20,
        benign_ratio: Optional[float] = None,
        exclude_external_api: bool = True,
        exclude_instruction_only: bool = True,
        require_standalone_code: bool = True,
        max_external_api_calls: int = 1,
        domain_filters: Optional[List[str]] = None,
        seed: Optional[int] = None,
        output_base_dir: str = "dynamic_samples",
        key_only_filter: bool = False,
        allowed_keys: str = "either"
    ) -> Dict[str, Any]:
        """
        Executes the DynamicAgentSkillFetch operational instructions:
        1. Calculates benign vs malicious quotas.
        2. Inspects raw sources (GitSkills and MalSkillBench).
        3. Validates candidates against integrity and external dependency filters.
        4. Synthesizes a new isolated dynamic_samples/{run_id}/ workspace with empty ground-truth templates.
        5. Produces manifest.json and an auditable rationale.json.
        """
        if key_only_filter:
            # Opt-in Key-only sampling logic (OpenAI / Gemini)
            if seed is not None:
                random.seed(seed)

            openai_set = bool(os.getenv("OPENAI_API_KEY"))
            gemini_set = bool(os.getenv("GEMINI_API_KEY"))
            host_key_warnings = []
            if allowed_keys == "openai" and not openai_set:
                host_key_warnings.append("OPENAI_API_KEY is not set on the host environment.")
            elif allowed_keys == "gemini" and not gemini_set:
                host_key_warnings.append("GEMINI_API_KEY is not set on the host environment.")
            elif allowed_keys == "either" and not (openai_set or gemini_set):
                host_key_warnings.append("Neither OPENAI_API_KEY nor GEMINI_API_KEY is set on the host environment.")

            run_id = f"sample_{datetime.now().strftime('%Y%m%d_%H%M%S')}_keyonly"
            run_dir = os.path.join(self.base_dir, output_base_dir, run_id)
            skills_dest_dir = os.path.join(run_dir, "skills")
            os.makedirs(skills_dest_dir, exist_ok=True)

            candidates = self.load_candidate_pool(include_instruction_only=False)
            evaluations = []
            eligible_candidates = []
            for cand in candidates:
                res = evaluate_key_only_eligibility(
                    skill_id=cand["skill_id"],
                    skill_md=cand.get("md_content") or "",
                    code_files=cand.get("code_files") or {},
                    allowed_keys=allowed_keys,
                    known_malicious=cand.get("known_malicious", False),
                    src_dir=cand.get("src_path")
                )
                cand["eligibility"] = res
                evaluations.append(res)
                if res["eligible"]:
                    eligible_candidates.append(cand)

            shortfall_notes = list(host_key_warnings)
            if len(eligible_candidates) < total_count:
                shortfall_notes.append(
                    f"Eligible pool has {len(eligible_candidates)} skills (fewer than requested {total_count}); "
                    f"sampled all {len(eligible_candidates)} available."
                )

            # Sample up to total_count
            if seed is not None:
                random.seed(seed)
            shuffled_eligible = list(eligible_candidates)
            random.shuffle(shuffled_eligible)
            selected_skills = shuffled_eligible[:total_count]

            # Materialize selected skills
            manifest_skills = []
            for skill in selected_skills:
                sid = skill["skill_id"]
                dest_skill_dir = os.path.join(skills_dest_dir, sid)
                os.makedirs(dest_skill_dir, exist_ok=True)

                if skill.get("src_type") == "fs":
                    src_dir = skill["src_path"]
                    for item in os.listdir(src_dir):
                        if item in ("__pycache__", ".pytest_cache", ".git"):
                            continue
                        s_item = os.path.join(src_dir, item)
                        d_item = os.path.join(dest_skill_dir, item)
                        if os.path.isfile(s_item):
                            shutil.copy2(s_item, d_item)
                        elif os.path.isdir(s_item):
                            shutil.copytree(s_item, d_item, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".git"))
                elif skill.get("src_type") == "db":
                    with open(os.path.join(dest_skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
                        f.write(skill.get("md_content", ""))
                    siblings = skill.get("all_siblings") or skill.get("code_files") or {}
                    for fn, file_content in siblings.items():
                        clean_rel = fn.replace("\\", "/").strip().lstrip("/")
                        if clean_rel.startswith("./"):
                            clean_rel = clean_rel[2:]
                        if not clean_rel or ".." in clean_rel.split("/"):
                            continue
                        target_file = os.path.join(dest_skill_dir, clean_rel)
                        os.makedirs(os.path.dirname(target_file), exist_ok=True)
                        with open(target_file, "w", encoding="utf-8") as f:
                            f.write(file_content)
                    meta_path = os.path.join(dest_skill_dir, "metadata.json")
                    meta_payload = {
                        "skill_id": sid,
                        "repo_full_name": skill.get("repo"),
                        "artifact_path": skill.get("artifact_path"),
                        "source": "gitskills_db",
                    }
                    with open(meta_path, "w", encoding="utf-8") as f:
                        json.dump(meta_payload, f, indent=2)

                gt_template = {
                    "skill_id": sid,
                    "domain": skill["domain"],
                    "known_malicious": False,
                    "ground_truth_label": None,
                    "threat_category": None,
                    "notes": "Annotate ground_truth_label and notes here."
                }
                with open(os.path.join(dest_skill_dir, "ground_truth.json"), "w", encoding="utf-8") as f:
                    json.dump(gt_template, f, indent=2)

                rel_path = f"./dynamic_samples/{run_id}/skills/{sid}/"
                skill_entry = {
                    "skill_id": sid,
                    "source": skill["source"],
                    "domain": skill["domain"],
                    "known_malicious": False,
                    "path": rel_path
                }
                skill_entry.update(skill["eligibility"])
                manifest_skills.append(skill_entry)

            manifest_data = {
                "run_id": run_id,
                "created_at": datetime.now().isoformat(),
                "total_skills": len(manifest_skills),
                "target_count": total_count,
                "requested_size": total_count,
                "pool_size": len(candidates),
                "benign_count": len(manifest_skills),
                "malicious_count": 0,
                "filter_name": "key_only_openai_gemini",
                "allowed_keys": allowed_keys,
                "seed": seed,
                "skills": manifest_skills
            }
            manifest_path = os.path.join(run_dir, "manifest.json")
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest_data, f, indent=2)

            rationale_data = {
                "agent": self.SKILL_NAME,
                "version": "1.0.0",
                "run_id": run_id,
                "timestamp": datetime.now().isoformat(),
                "filter_name": "key_only_openai_gemini",
                "allowed_keys": allowed_keys,
                "inputs": {
                    "requested_size": total_count,
                    "seed": seed,
                    "allowed_keys": allowed_keys
                },
                "pool_size": len(candidates),
                "eligible_count": len(eligible_candidates),
                "selected_count": len(manifest_skills),
                "host_key_warnings": host_key_warnings,
                "shortfall_warnings": shortfall_notes,
                "agent_verdict": f"Key-only filter sampled {len(manifest_skills)} eligible skills from a candidate pool of {len(candidates)}."
            }
            rationale_path = os.path.join(run_dir, "rationale.json")
            with open(rationale_path, "w", encoding="utf-8") as f:
                json.dump(rationale_data, f, indent=2)

            return {
                "run_id": run_id,
                "sample_dir": run_dir,
                "manifest_path": manifest_path,
                "rationale_path": rationale_path,
                "total_skills": len(manifest_skills),
                "benign_count": len(manifest_skills),
                "malicious_count": 0,
                "shortfall_warnings": shortfall_notes,
                "skills": manifest_skills,
                "rationale": rationale_data
            }
        if seed is not None:
            random.seed(seed)

        if benign_ratio is None:
            benign_ratio = 0.95 if total_count >= 500 else 0.90

        target_benign = round(total_count * benign_ratio)
        target_malicious = total_count - target_benign

        run_id = f"sample_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        run_dir = os.path.join(self.base_dir, output_base_dir, run_id)
        skills_dest_dir = os.path.join(run_dir, "skills")
        os.makedirs(skills_dest_dir, exist_ok=True)

        rejections: List[Dict[str, str]] = []
        selected_benign: List[Dict[str, Any]] = []
        selected_malicious: List[Dict[str, Any]] = []
        selected_skill_ids: set = set()

        # ─────────────────────────────────────────────────────────────────────
        # STEP 1: Inspect & Harvest Benign Skills (GitSkills DB / skills_dataset)
        # ─────────────────────────────────────────────────────────────────────
        inspected_benign_count = 0
        candidate_benign_pool: List[Dict[str, Any]] = []

        # A. Query local skills_dataset benign subset first for instant availability
        if os.path.exists(self.skills_dataset_dir):
            for d in os.listdir(self.skills_dataset_dir):
                if d.startswith("benign_"):
                    s_path = os.path.join(self.skills_dataset_dir, d)
                    if os.path.isdir(s_path):
                        candidate_benign_pool.append({
                            "type": "fs",
                            "skill_id": d,
                            "path": s_path
                        })

        # B. Query SQLite database if needed to reach total target (including possible backfill)
        needed_benign_candidates = total_count + 200
        if len(candidate_benign_pool) < needed_benign_candidates and os.path.exists(self.db_path):
            try:
                conn = sqlite3.connect(self.db_path)
                cur = conn.cursor()
                limit_candidates = max(5000, total_count * 10)
                code_where = """AND EXISTS (
                    SELECT 1 FROM artifact_siblings s2 
                    WHERE s2.repo_full_name = artifacts.repo_full_name 
                      AND s2.artifact_path = artifacts.path 
                      AND s2.entry_name LIKE '%.py'
                )""" if exclude_instruction_only else ""

                query = f"""
                SELECT a.repo_full_name, a.path, a.name, a.content, s.entry_name, s.content
                FROM (
                    SELECT repo_full_name, path, name, content
                    FROM artifacts
                    WHERE dedup_primary = 1 AND frontmatter_valid = 1 AND content IS NOT NULL
                    {code_where}
                    LIMIT {limit_candidates}
                ) a
                LEFT JOIN artifact_siblings s ON a.repo_full_name = s.repo_full_name AND a.path = s.artifact_path
                """
                cur.execute(query)
                rows = cur.fetchall()
                conn.close()

                grouped = {}
                for repo, path, name, md_content, s_name, s_content in rows:
                    key = (repo, path)
                    if key not in grouped:
                        grouped[key] = {
                            "type": "db",
                            "name": name,
                            "repo": repo,
                            "path": path,
                            "md_content": md_content,
                            "code_files": {},
                            "all_siblings": {},
                        }
                    if s_name and s_content is not None:
                        grouped[key]["all_siblings"][s_name] = s_content
                        if s_name.endswith((".py", ".sh")):
                            grouped[key]["code_files"][s_name] = s_content

                for item in grouped.values():
                    candidate_benign_pool.append(item)
            except Exception as e:
                rejections.append({"skill_id": "sqlite_db", "reason": f"SQLite error: {str(e)}"})

        # Shuffle candidates
        random.shuffle(candidate_benign_pool)

        for cand in candidate_benign_pool:
            if len(selected_benign) >= target_benign:
                break
            inspected_benign_count += 1

            if cand["type"] == "fs":
                s_id = cand["skill_id"]
                if s_id in selected_skill_ids:
                    continue
                s_dir = cand["path"]
                read_ok, md_text, code_files, read_err = self._read_fs_candidate(s_dir)
                if not read_ok:
                    rejections.append({"skill_id": s_id, "reason": read_err or "Unreadable skill directory"})
                    continue

                is_valid, domain, rej_reason = self.validate_candidate_skill(
                    skill_id=s_id,
                    skill_md_text=md_text,
                    code_files=code_files,
                    exclude_external_api=exclude_external_api,
                    require_standalone_code=require_standalone_code,
                    max_external_api_calls=max_external_api_calls,
                    exclude_instruction_only=exclude_instruction_only,
                )

                if not is_valid:
                    rejections.append({"skill_id": s_id, "reason": rej_reason or "Invalid"})
                    continue

                if exclude_instruction_only and domain == "instruction_only":
                    continue

                if domain_filters and domain not in domain_filters:
                    rejections.append({"skill_id": s_id, "reason": f"Domain {domain} not in filters {domain_filters}"})
                    continue

                selected_benign.append({
                    "skill_id": s_id,
                    "source": "gitskills",
                    "domain": domain,
                    "known_malicious": False,
                    "src_type": "fs",
                    "src_path": s_dir
                })
                selected_skill_ids.add(s_id)

            elif cand["type"] == "db":
                s_id = f"benign_{re.sub(r'[^a-zA-Z0-9_-]', '_', cand['name'] or 'skill')}"
                if s_id in selected_skill_ids:
                    continue
                md_text = cand["md_content"]
                code_files = cand["code_files"]

                is_valid, domain, rej_reason = self.validate_candidate_skill(
                    skill_id=s_id,
                    skill_md_text=md_text,
                    code_files=code_files,
                    exclude_external_api=exclude_external_api,
                    require_standalone_code=require_standalone_code,
                    max_external_api_calls=max_external_api_calls,
                    exclude_instruction_only=exclude_instruction_only,
                )

                if not is_valid:
                    rejections.append({"skill_id": s_id, "reason": rej_reason or "Invalid"})
                    continue

                if exclude_instruction_only and domain == "instruction_only":
                    continue

                if domain_filters and domain not in domain_filters:
                    rejections.append({"skill_id": s_id, "reason": f"Domain {domain} not in filters {domain_filters}"})
                    continue

                selected_benign.append({
                    "skill_id": s_id,
                    "source": "gitskills",
                    "domain": domain,
                    "known_malicious": False,
                    "src_type": "db",
                    "repo": cand.get("repo"),
                    "artifact_path": cand.get("path"),
                    "md_content": md_text,
                    "code_files": code_files,
                    "all_siblings": cand.get("all_siblings", code_files),
                })
                selected_skill_ids.add(s_id)

        # ─────────────────────────────────────────────────────────────────────
        # STEP 2: Inspect & Harvest Malicious Skills (MalSkillBench / skills_dataset)
        # ─────────────────────────────────────────────────────────────────────
        inspected_malicious_count = 0
        candidate_mal_pool: List[Dict[str, Any]] = []

        # A. Query local skills_dataset mal_*
        if os.path.exists(self.skills_dataset_dir):
            for d in os.listdir(self.skills_dataset_dir):
                if d.startswith("mal_"):
                    s_path = os.path.join(self.skills_dataset_dir, d)
                    if os.path.isdir(s_path):
                        candidate_mal_pool.append({
                            "skill_id": d,
                            "path": s_path
                        })

        # B. Query MalSkillBench/Dataset/Skills/malware/
        if os.path.exists(self.malskillbench_dir):
            for d in os.listdir(self.malskillbench_dir):
                s_path = os.path.join(self.malskillbench_dir, d)
                if os.path.isdir(s_path):
                    clean_id = re.sub(r'[^a-zA-Z0-9_-]', '_', d.replace('__', '_'))
                    s_id = f"mal_{clean_id}"
                    if not any(c["skill_id"] == s_id for c in candidate_mal_pool):
                        candidate_mal_pool.append({
                            "skill_id": s_id,
                            "path": s_path
                        })

        random.shuffle(candidate_mal_pool)

        for cand in candidate_mal_pool:
            if len(selected_malicious) >= target_malicious:
                break
            inspected_malicious_count += 1
            s_id = cand["skill_id"]
            if s_id in selected_skill_ids:
                continue
            s_dir = cand["path"]
            read_ok, md_text, code_files, read_err = self._read_fs_candidate(s_dir)
            if not read_ok:
                rejections.append({"skill_id": s_id, "reason": read_err or "Unreadable skill directory"})
                continue

            is_valid, domain, rej_reason = self.validate_candidate_skill(
                skill_id=s_id,
                skill_md_text=md_text,
                code_files=code_files,
                exclude_external_api=exclude_external_api,
                require_standalone_code=require_standalone_code,
                max_external_api_calls=max_external_api_calls,
                exclude_instruction_only=exclude_instruction_only,
            )

            if not is_valid:
                rejections.append({"skill_id": s_id, "reason": rej_reason or "Invalid"})
                continue

            if exclude_instruction_only and domain == "instruction_only":
                rejections.append({"skill_id": s_id, "reason": "Excluded instruction_only skill (executable code required)"})
                continue

            if domain_filters and domain not in domain_filters:
                rejections.append({"skill_id": s_id, "reason": f"Domain {domain} not in filters {domain_filters}"})
                continue

            # Determine threat category if applicable from name using strict regex
            threat_cat = None
            code_match = re.search(r"_(B\d+)(?:_|$)", s_id)
            if code_match:
                b_code = code_match.group(1)
                threat_cat = TAXONOMY_MAP.get(b_code)

            selected_malicious.append({
                "skill_id": s_id,
                "source": "malskillbench",
                "domain": domain,
                "known_malicious": True,
                "threat_category": threat_cat,
                "src_type": "fs",
                "src_path": s_dir
            })
            selected_skill_ids.add(s_id)

        # ─────────────────────────────────────────────────────────────────────
        # STEP 3: Quota Shortfall & Auto-Backfill to Fulfill Total Count
        # ─────────────────────────────────────────────────────────────────────
        shortfall_notes = []
        current_total = len(selected_benign) + len(selected_malicious)
        needed_backfill = total_count - current_total

        if needed_backfill > 0:
            initial_benign_count = len(selected_benign)
            already_selected_ids = {s["skill_id"] for s in selected_benign} | {s["skill_id"] for s in selected_malicious}

            # Continue through candidate_benign_pool to fulfill requested total_count
            for cand in candidate_benign_pool:
                if len(selected_benign) >= (initial_benign_count + needed_backfill):
                    break

                if cand["type"] == "fs":
                    s_id = cand["skill_id"]
                    if s_id in already_selected_ids:
                        continue
                    s_dir = cand["path"]
                    read_ok, md_text, code_files, read_err = self._read_fs_candidate(s_dir)
                    if not read_ok:
                        continue
                    is_valid, domain, rej_reason = self.validate_candidate_skill(
                        skill_id=s_id,
                        skill_md_text=md_text,
                        code_files=code_files,
                        exclude_external_api=exclude_external_api,
                        require_standalone_code=require_standalone_code,
                        max_external_api_calls=max_external_api_calls
                    )
                    if not is_valid:
                        continue
                    if exclude_instruction_only and domain == "instruction_only":
                        continue
                    if domain_filters and domain not in domain_filters:
                        continue
                    selected_benign.append({
                        "skill_id": s_id,
                        "source": "gitskills",
                        "domain": domain,
                        "known_malicious": False,
                        "src_type": "fs",
                        "src_path": s_dir
                    })
                    already_selected_ids.add(s_id)

                elif cand["type"] == "db":
                    s_id = f"benign_{re.sub(r'[^a-zA-Z0-9_-]', '_', cand['name'] or 'skill')}"
                    if s_id in already_selected_ids:
                        continue
                    md_text = cand["md_content"]
                    code_files = cand["code_files"]
                    is_valid, domain, rej_reason = self.validate_candidate_skill(
                        skill_id=s_id,
                        skill_md_text=md_text,
                        code_files=code_files,
                        exclude_external_api=exclude_external_api,
                        require_standalone_code=require_standalone_code,
                        max_external_api_calls=max_external_api_calls
                    )
                    if not is_valid:
                        continue
                    if exclude_instruction_only and domain == "instruction_only":
                        continue
                    if domain_filters and domain not in domain_filters:
                        continue
                    selected_benign.append({
                        "skill_id": s_id,
                        "source": "gitskills",
                        "domain": domain,
                        "known_malicious": False,
                        "src_type": "db",
                        "repo": cand.get("repo"),
                        "artifact_path": cand.get("path"),
                        "md_content": md_text,
                        "code_files": code_files,
                        "all_siblings": cand.get("all_siblings", code_files),
                    })
                    already_selected_ids.add(s_id)

            backfilled_count = len(selected_benign) - initial_benign_count
            if backfilled_count > 0:
                shortfall_notes.append(
                    f"Malicious pool maximum reached ({len(selected_malicious)} available in MalSkillBench); "
                    f"automatically backfilled {backfilled_count} additional verified benign skills from GitSkills "
                    f"to fulfill the full requested sample quota of {len(selected_benign) + len(selected_malicious)}/{total_count} skills."
                )

        final_total = len(selected_benign) + len(selected_malicious)
        if final_total < total_count:
            shortfall_notes.append(
                f"Overall sample shortfall: Requested {total_count}, but only {final_total} valid skills satisfied all filter criteria."
            )

        # ─────────────────────────────────────────────────────────────────────
        # STEP 4: Materialize Clean Skills in dynamic_samples/{run_id}/
        # ─────────────────────────────────────────────────────────────────────
        all_selected = selected_benign + selected_malicious
        manifest_skills = []

        for skill in all_selected:
            sid = skill["skill_id"]
            dest_skill_dir = os.path.join(skills_dest_dir, sid)
            os.makedirs(dest_skill_dir, exist_ok=True)

            if skill.get("src_type") == "fs":
                src_dir = skill["src_path"]
                # Copy the ENTIRE skill directory tree preserving relative layout (H2)
                try:
                    for item in os.listdir(src_dir):
                        if item in ("__pycache__", ".pytest_cache", ".git"):
                            continue
                        s_item = os.path.join(src_dir, item)
                        d_item = os.path.join(dest_skill_dir, item)
                        if os.path.isfile(s_item):
                            shutil.copy2(s_item, d_item)
                        elif os.path.isdir(s_item):
                            shutil.copytree(
                                s_item,
                                d_item,
                                dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache", ".git"),
                            )
                except Exception as e:
                    shortfall_notes.append(f"Warning: partial copy issue for {sid}: {e}")

            elif skill.get("src_type") == "db":
                # Write SKILL.md
                with open(os.path.join(dest_skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
                    f.write(skill.get("md_content", ""))

                # Write all sibling files at their exact relative paths under dest_skill_dir (H2)
                siblings = skill.get("all_siblings") or skill.get("code_files") or {}
                for fn, file_content in siblings.items():
                    clean_rel = fn.replace("\\", "/").strip().lstrip("/")
                    if clean_rel.startswith("./"):
                        clean_rel = clean_rel[2:]
                    if not clean_rel or ".." in clean_rel.split("/"):
                        continue
                    target_file = os.path.join(dest_skill_dir, clean_rel)
                    os.makedirs(os.path.dirname(target_file), exist_ok=True)
                    with open(target_file, "w", encoding="utf-8") as f:
                        f.write(file_content)

                # Save unambiguous DB provenance in metadata.json
                meta_path = os.path.join(dest_skill_dir, "metadata.json")
                meta_payload = {
                    "skill_id": sid,
                    "repo_full_name": skill.get("repo"),
                    "artifact_path": skill.get("artifact_path"),
                    "source": "gitskills_db",
                }
                with open(meta_path, "w", encoding="utf-8") as f:
                    json.dump(meta_payload, f, indent=2)

            # Emit clean ground_truth.json template
            gt_template = {
                "skill_id": sid,
                "domain": skill["domain"],
                "known_malicious": skill["known_malicious"],
                "ground_truth_label": None,
                "threat_category": skill.get("threat_category"),
                "notes": "Annotate ground_truth_label and notes here."
            }
            with open(os.path.join(dest_skill_dir, "ground_truth.json"), "w", encoding="utf-8") as f:
                json.dump(gt_template, f, indent=2)

            rel_path = f"./dynamic_samples/{run_id}/skills/{sid}/"
            manifest_skills.append({
                "skill_id": sid,
                "source": skill["source"],
                "domain": skill["domain"],
                "known_malicious": skill["known_malicious"],
                "path": rel_path
            })

        # ─────────────────────────────────────────────────────────────────────
        # STEP 5: Emit Manifest & Agent Rationale Log
        # ─────────────────────────────────────────────────────────────────────
        manifest_data = {
            "run_id": run_id,
            "created_at": datetime.now().isoformat(),
            "total_skills": len(manifest_skills),
            "target_count": total_count,
            "benign_count": len(selected_benign),
            "malicious_count": len(selected_malicious),
            "benign_ratio_target": benign_ratio,
            "exclude_external_api": exclude_external_api,
            "require_standalone_code": require_standalone_code,
            "max_external_api_calls": max_external_api_calls,
            "skills": manifest_skills
        }
        manifest_path = os.path.join(run_dir, "manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)

        rationale_data = {
            "agent": self.SKILL_NAME,
            "version": "1.0.0",
            "run_id": run_id,
            "timestamp": datetime.now().isoformat(),
            "inputs": {
                "total_count": total_count,
                "benign_ratio": benign_ratio,
                "target_benign": target_benign,
                "target_malicious": target_malicious,
                "exclude_external_api": exclude_external_api,
                "require_standalone_code": require_standalone_code,
                "max_external_api_calls": max_external_api_calls,
                "domain_filters": domain_filters or "ALL"
            },
            "inspection_summary": {
                "inspected_benign_candidates": inspected_benign_count,
                "inspected_malicious_candidates": inspected_malicious_count,
                "selected_benign": len(selected_benign),
                "selected_malicious": len(selected_malicious),
                "total_selected": len(manifest_skills),
                "rejections_count": len(rejections)
            },
            "shortfall_warnings": shortfall_notes,
            "rejections_sample": rejections[:30],
            "agent_verdict": (
                f"Successfully synthesized dynamic sample manifest with {len(manifest_skills)} validated skills "
                f"({len(selected_benign)} benign, {len(selected_malicious)} malicious). "
                + (" ".join(shortfall_notes) if shortfall_notes else "Zero shortfall detected.")
            )
        }
        rationale_path = os.path.join(run_dir, "rationale.json")
        with open(rationale_path, "w", encoding="utf-8") as f:
            json.dump(rationale_data, f, indent=2)

        return {
            "run_id": run_id,
            "sample_dir": run_dir,
            "manifest_path": manifest_path,
            "rationale_path": rationale_path,
            "total_skills": len(manifest_skills),
            "benign_count": len(selected_benign),
            "malicious_count": len(selected_malicious),
            "shortfall_warnings": shortfall_notes,
            "skills": manifest_skills,
            "rationale": rationale_data
        }


# Global tool dispatcher instance
dynamic_agent_skill_fetch = DynamicAgentSkillFetchAgent()



def hydrate_skill_tree_from_db(
    skill_dir: str,
    db_path: str = "gitskills_raw/agent_skills_sample.db",
    target_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """Deterministically hydrate missing `artifact_siblings` for an extracted skill directory (`H2`, Clarification #3).

    Rules:
    1. Prefer `repo_full_name` + `artifact_path` from `metadata.json` if present.
    2. Otherwise match by exact `SKILL.md` content (`WHERE dedup_primary = 1 AND content = ?`).
       If 0 or >1 rows match, do NOT guess — return `ambiguous_or_not_found`.
    3. Write any missing `artifact_siblings` files at their exact relative paths inside `target_dir` (or `skill_dir`).
    4. Inspect scripts for parent-relative sibling references outside `skill_dir` (e.g.
       `parents[2] / "claude-skill-kit" / ...` or `../../claude-skill-kit/...`). If a script requires a
       parent-relative sibling directory that is absent both on disk and in the DB for `repo_full_name`,
       return `missing_external_siblings` so the harness records an explicit unmet precondition (`HARNESS`).
    """
    result: Dict[str, Any] = {
        "hydrated_files": [],
        "repo_full_name": None,
        "artifact_path": None,
        "missing_external_siblings": [],
    }
    if not skill_dir or not os.path.isdir(skill_dir):
        return result

    skill_path = Path(skill_dir)
    write_path = Path(target_dir) if target_dir else skill_path
    repo_full_name: Optional[str] = None
    artifact_path: Optional[str] = None

    meta_file = skill_path / "metadata.json"
    if meta_file.exists():
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8", errors="ignore"))
            repo_full_name = meta.get("repo_full_name")
            artifact_path = meta.get("artifact_path")
        except Exception:
            pass

    if os.path.exists(db_path) and ((repo_full_name and artifact_path) or skill_path.name.startswith("benign_")):
        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            if not (repo_full_name and artifact_path):
                skill_md_file = skill_path / "SKILL.md"
                if skill_md_file.exists():
                    md_text = skill_md_file.read_text(encoding="utf-8", errors="ignore")
                    cur.execute(
                        "SELECT repo_full_name, path FROM artifacts WHERE dedup_primary = 1 AND content = ?",
                        (md_text,),
                    )
                    matches = cur.fetchall()
                    if len(matches) == 1:
                        repo_full_name, artifact_path = matches[0][0], matches[0][1]

            if repo_full_name and artifact_path:
                result["repo_full_name"] = repo_full_name
                result["artifact_path"] = artifact_path
                cur.execute(
                    "SELECT entry_name, content FROM artifact_siblings WHERE repo_full_name = ? AND artifact_path = ?",
                    (repo_full_name, artifact_path),
                )
                for entry_name, content in cur.fetchall():
                    if not entry_name or content is None:
                        continue
                    clean_rel = str(entry_name).replace("\\", "/").strip().lstrip("/")
                    if clean_rel.startswith("./"):
                        clean_rel = clean_rel[2:]
                    if not clean_rel or ".." in clean_rel.split("/"):
                        continue
                    target_fp = write_path / clean_rel
                    if not target_fp.exists():
                        target_fp.parent.mkdir(parents=True, exist_ok=True)
                        target_fp.write_text(str(content), encoding="utf-8")
                        result["hydrated_files"].append(clean_rel)

            conn.close()
        except Exception:
            pass

    # Check scripts for parent-relative sibling paths outside skill_dir (e.g. parents[2] / 'claude-skill-kit' / 'scripts' / 'known_issues.py')
    for script_fp in skill_path.rglob("*.py"):
        try:
            src = script_fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        # Pattern 1: .parents[N] / "dir" / ... where resolved path escapes skill_path
        for m in re.finditer(
            r"\.parents\[(\d+)\](?:\s*/\s*['\"]([^'\"]+)['\"])+",
            src,
        ):
            full_expr = m.group(0)
            parent_idx = int(m.group(1))
            parts = re.findall(r"/\s*['\"]([^'\"]+)['\"]", full_expr)
            try:
                base_p = script_fp.resolve().parents[parent_idx]
                cand_target = base_p.joinpath(*parts)
                # If cand_target is outside skill_path and does not exist on disk
                if not str(cand_target).startswith(str(skill_path.resolve())) and not cand_target.exists():
                    rel_desc = "/".join(parts)
                    if rel_desc not in result["missing_external_siblings"]:
                        result["missing_external_siblings"].append(rel_desc)
            except Exception:
                pass
        # Pattern 2: explicit ../../sibling/... string literals
        for m2 in re.finditer(r"['\"](\.\./\.\./[a-zA-Z0-9_./-]+)['\"]", src):
            rel_up = m2.group(1)
            cand_target = (script_fp.parent / rel_up).resolve()
            if not str(cand_target).startswith(str(skill_path.resolve())) and not cand_target.exists():
                if rel_up not in result["missing_external_siblings"]:
                    result["missing_external_siblings"].append(rel_up)

    return result
