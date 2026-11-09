import hashlib
import os
import sys
import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional, Tuple

def compute_skill_version_hash(skill_dir: str, declaration_text: str = "") -> str:
    """Computes a deterministic hash of the skill declaration and structure for caching."""
    hasher = hashlib.sha256()
    if declaration_text:
        hasher.update(declaration_text.strip().encode("utf-8"))
    else:
        for fname in ("SKILL.md", "README.md", "metadata.json"):
            fpath = os.path.join(skill_dir, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "rb") as f:
                        hasher.update(f.read().strip())
                except Exception:
                    pass
    return hasher.hexdigest()[:16]

# Automatically load .env if present
def load_env():
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

FORBIDDEN_CODE_EXTENSIONS = (
    ".py", ".pyc", ".sh", ".bash", ".zsh", ".js", ".ts",
    ".c", ".cpp", ".rs", ".go", ".java", ".rb", ".php", ".bin", ".exe"
)

ALLOWED_DECLARATION_BASENAMES = (
    "SKILL.MD", "SKILL.YAML", "SKILL.YML", "README.MD", "METADATA.JSON"
)

CONTRACT_SYSTEM_PROMPT = """You are A_syn (Contract Synthesizer), the first agent in a formal agent-skill intent verification pipeline.
Your job is to read ONLY the natural-language declaration of an AI agent skill (SKILL.md and its YAML frontmatter) and extract formal behavioral contracts.
You must NOT assume or guess implementation details. You extract only what the skill explicitly promises or implies as its operational boundary.

For every distinct functional claim or capability declared in the document, extract a contract with the following schema:
{
  "contract_id": "C_01",
  "source_line": "SKILL.md:Line <number>",
  "precondition": "<plain language description of required environment state before execution>",
  "postcondition": "<plain language description of the promised state transformation or outcome>",
  "frame_axiom": [
    "read: <allowed input file/dir pattern or resources>",
    "write: <allowed output file/dir pattern or mutations>",
    "network: <allowed domains or 'none'>"
  ],
  "forbidden_invariant": [
    "network_egress: true/false",
    "read: <sensitive path patterns, e.g. ~/.ssh, ~/.aws, /etc/shadow, ~/.bashrc, environment secrets>",
    "write: <unauthorized system directories>",
    "process: <unauthorized privilege escalation or shell spawning>"
  ],
  "testable": true,
  "expects_effect": true
}

CRITICAL RULES:
1. Produce ONLY valid JSON with a top-level "contracts" array containing at least 1 contract.
2. Frame Axioms must define the strict boundary of what the skill is authorized to touch. Any side-effect outside this frame is a potential Undeclared Behavior.
3. Forbidden Invariants must explicitly state what must NEVER occur (e.g., exfiltrating credentials, unauthorized outbound network calls).
4. source_line must point to the actual line number in the declaration text where the claim originates (e.g. 'SKILL.md:Line 14').
5. testable: set to true for all observable/verifiable behaviors and state transformations. Set testable=false ONLY for non-observable claims (such as authorization status, high-level intent statements, internal thoughts, or design philosophy). Never mark observable behaviors as testable=false.
6. expects_effect: set to true if the claim produces an observable side-effect (file creation, modification, network call, structured output); set to false if it is informational, no-op, or read-only query.
7. Postconditions MUST state substantive verifiable outcomes (e.g. specific output format, file created/modified with extension, key names in JSON, or distinct message substrings). Avoid generic phrases like 'executes without error' or exit code 0 alone.
8. If a claim cannot be verified through inputs/outputs/side-effects, you MUST mark 'testable': false.
"""

def runtime_bias_guard(source_file_path: str, declaration_text: str):
    """
    Structural bias guard:
    Ensures A_syn NEVER receives or accesses code files (.py, .sh, etc.).
    Raises RuntimeError if any code path or code snippet is detected.
    """
    base = os.path.basename(source_file_path).upper()
    if any(source_file_path.lower().endswith(ext) for ext in FORBIDDEN_CODE_EXTENSIONS):
        raise RuntimeError(
            f"CONFIRMATION BIAS VIOLATION: A_syn is strictly forbidden from reading code files! "
            f"Attempted to access: {source_file_path}"
        )
    if base not in ALLOWED_DECLARATION_BASENAMES and not base.endswith(".MD"):
        raise RuntimeError(
            f"CONFIRMATION BIAS VIOLATION: Invalid declaration file '{source_file_path}'. "
            f"Allowed declaration files are SKILL.md, README.md, YAML frontmatter only."
        )

def validate_contract_schema(contract: Dict[str, Any]) -> bool:
    """Validates that a single contract strictly conforms to the required schema."""
    required_keys = ["contract_id", "source_line", "precondition", "postcondition", "frame_axiom", "forbidden_invariant"]
    if not all(k in contract for k in required_keys):
        return False
    if not isinstance(contract["contract_id"], str) or not contract["contract_id"].strip():
        return False
    if not isinstance(contract["source_line"], str) or not contract["source_line"].strip():
        return False
    if not isinstance(contract["precondition"], str) or not contract["precondition"].strip():
        return False
    if not isinstance(contract["postcondition"], str) or not contract["postcondition"].strip():
        return False
    if not isinstance(contract["frame_axiom"], list) or len(contract["frame_axiom"]) == 0:
        return False
    if not isinstance(contract["forbidden_invariant"], list) or len(contract["forbidden_invariant"]) == 0:
        return False
    # Validate testable and expects_effect if present; if missing, default them (backward compat)
    if "testable" in contract and not isinstance(contract["testable"], bool):
        return False
    if "expects_effect" in contract and not isinstance(contract["expects_effect"], bool):
        return False
    # Default for legacy/omitted
    if "testable" not in contract:
        contract["testable"] = True
    if "expects_effect" not in contract:
        contract["expects_effect"] = False
    return True

def validate_contracts_container(data: Any) -> Optional[List[Dict[str, Any]]]:
    """Validates and extracts the list of contracts from LLM JSON response."""
    if isinstance(data, dict) and "contracts" in data and isinstance(data["contracts"], list):
        contracts = data["contracts"]
    elif isinstance(data, list):
        contracts = data
    else:
        return None

    if len(contracts) == 0:
        return None

    for c in contracts:
        if not validate_contract_schema(c):
            return None
    return contracts

def parse_declaration_lines(text: str) -> List[tuple]:
    """Splits declaration text into line numbers and content."""
    lines = text.splitlines()
    return [(i + 1, line) for i, line in enumerate(lines)]

def extract_declared_network_hosts(declaration_text: str) -> List[str]:
    """
    Derives declared allowed hosts from SKILL.md/frontmatter/API names.
    Examples: 'fetch from GitHub', 'https://api.github.com', etc.
    """
    hosts = set()
    if not declaration_text:
        return []
    
    # 1. URLs
    urls = re.findall(r'https?://([a-zA-Z0-9\.\-]+)', declaration_text)
    for u in urls:
        clean = u.split(':')[0].strip().lower()
        if clean and clean not in ("localhost", "127.0.0.1"):
            hosts.add(clean)

    # 2. Known service keywords in declarations
    service_map = {
        r'\bgithub\b': "api.github.com",
        r'\bgitlab\b': "gitlab.com",
        r'\bslack\b': "slack.com",
        r'\bdiscord\b': "discord.com",
        r'\bhuggingface\b': "huggingface.co",
        r'\bopenai\b': "api.openai.com",
        r'\banthropic\b': "api.anthropic.com",
        r'\bpypi\b': "pypi.org"
    }
    for pat, host in service_map.items():
        if re.search(pat, declaration_text, re.IGNORECASE):
            hosts.add(host)

    return sorted(hosts)

def normalize_contract_frame_axioms(contracts: List[Dict[str, Any]], declaration_text: str) -> List[Dict[str, Any]]:
    """Ensures each contract has an explicit network frame axiom derived from SKILL.md."""
    allowed_hosts = extract_declared_network_hosts(declaration_text)
    net_axiom = f"network: {', '.join(allowed_hosts)}" if allowed_hosts else "network: none"

    for c in contracts:
        axioms = c.get("frame_axiom", [])
        has_net = any("network:" in str(a).lower() for a in axioms)
        if not has_net:
            axioms.append(net_axiom)
        c["frame_axiom"] = axioms
    return contracts


from src.security.level1_scanner import scan_skill_for_level1_security

def _find_uncovered_documented_commands(declaration_text: str, contracts: List[Dict[str, Any]]) -> List[str]:
    """Identify documented executable commands (curl, wget, python, bash, gh, sh) in fenced code blocks not referenced in contracts."""
    if not declaration_text or not contracts:
        return []

    # Extract commands from fenced blocks
    code_blocks = re.findall(r"```(?:bash|sh|shell|python|cmd)?\s*\n([\s\S]*?)```", declaration_text)
    doc_cmds = []
    for block in code_blocks:
        for line in block.splitlines():
            line_str = line.strip()
            if line_str and not line_str.startswith("#") and any(line_str.startswith(kw) for kw in ("curl", "wget", "python", "bash", "sh", "gh")):
                doc_cmds.append(line_str)

    uncovered = []
    # Check if each command is referenced in any contract's precondition, postcondition, frame_axiom, or forbidden_invariant
    for cmd in doc_cmds:
        cmd_tokens = [tok for tok in re.split(r"\s+", cmd) if len(tok) > 3 and not tok.startswith("-")]
        found = False
        for c in contracts:
            c_str = json.dumps(c).lower()
            if any(tok.lower() in c_str for tok in cmd_tokens):
                found = True
                break
        if not found:
            uncovered.append(cmd)

    return uncovered


CURRENT_ASYN_VERSION = "2.1.0"


def _chunk_declaration_lines(
    parsed_lines: List[Tuple[int, str]],
    target_chunk_size: int = 10000,
    overlap_lines: int = 5,
) -> List[List[Tuple[int, str]]]:
    """Splits numbered declaration lines into chunks of at most ~10,000 characters.
    
    Chunks on code-fence or blank-line boundaries where possible; never splits inside
    a fenced block unless the block alone exceeds the chunk size.
    """
    if not parsed_lines:
        return []

    total_lines = len(parsed_lines)
    in_fence_at_line = [False] * total_lines
    currently_in_fence = False
    for i, (_, line_str) in enumerate(parsed_lines):
        stripped = line_str.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            currently_in_fence = not currently_in_fence
        in_fence_at_line[i] = currently_in_fence

    chunks: List[List[Tuple[int, str]]] = []
    start_idx = 0

    while start_idx < total_lines:
        current_len = 0
        end_idx = start_idx
        last_clean_cut = -1

        while end_idx < total_lines:
            line_len = len(f"Line {parsed_lines[end_idx][0]}: {parsed_lines[end_idx][1]}\n")
            if current_len + line_len > target_chunk_size and end_idx > start_idx:
                if last_clean_cut != -1 and last_clean_cut > start_idx:
                    end_idx = last_clean_cut
                elif in_fence_at_line[end_idx]:
                    closing_idx = end_idx
                    while closing_idx < total_lines and in_fence_at_line[closing_idx]:
                        closing_idx += 1
                    if closing_idx < total_lines and (closing_idx - start_idx) * 80 < target_chunk_size * 1.5:
                        end_idx = closing_idx + 1
                break

            current_len += line_len
            if not in_fence_at_line[end_idx]:
                if not parsed_lines[end_idx][1].strip() or (end_idx > 0 and in_fence_at_line[end_idx - 1]):
                    last_clean_cut = end_idx + 1

            end_idx += 1

        if end_idx <= start_idx:
            end_idx = start_idx + 1

        chunk = parsed_lines[start_idx:end_idx]
        chunks.append(chunk)

        if end_idx >= total_lines:
            break

        start_idx = max(start_idx + 1, end_idx - overlap_lines)

    return chunks


def _scan_skipped_lines_for_invariants(
    skipped_chunks: List[List[Tuple[int, str]]]
) -> List[str]:
    """Deterministic scan on skipped text (URLs/hosts, curl/wget/bash/python/sh commands, exec/eval).
    
    Reuses Level-1 pattern concepts and produces explicit forbidden_invariants citing original SKILL.md lines.
    """
    findings: List[str] = []
    url_pattern = re.compile(r"https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s'\"<>\)]*)?)")
    cmd_pattern = re.compile(r"\b(curl\s+.*?https?://\S+|wget\s+.*?https?://\S+|bash\s+\S+|sh\s+\S+|python\d?\s+\S+)")
    exec_pattern = re.compile(r"\b(eval|exec|base64\s+-d)\b")

    for chunk in skipped_chunks:
        for line_num, line_str in chunk:
            s_line = line_str.strip()
            if not s_line:
                continue
            
            m_cmd = cmd_pattern.search(s_line)
            if m_cmd:
                cmd_val = m_cmd.group(1).rstrip("\\").strip()
                findings.append(f"MUST NOT execute unverified command from skipped text: {cmd_val} (SKILL.md:Line {line_num})")
                continue
                
            m_exec = exec_pattern.search(s_line)
            if m_exec:
                findings.append(f"MUST NOT invoke {m_exec.group(1)} from skipped text: {s_line[:60]} (SKILL.md:Line {line_num})")
                continue

            m_urls = url_pattern.findall(s_line)
            for u in m_urls:
                host = u.split("/")[0].split(":")[0].lower()
                if host not in ("localhost", "127.0.0.1", "schema.org", "w3.org", "example.com"):
                    findings.append(f"MUST NOT access unverified external endpoint from skipped text: {host} (SKILL.md:Line {line_num})")

    return list(dict.fromkeys(findings))


def _frame_conflicts_with_forbidden(frame_item: str, forbidden_item: str) -> bool:
    """Define 'frame item conflicts with a forbidden invariant' as: same host, same path, or same command token.
    
    Matches:
    1. Same host: extracted domain/host from frame_item appears in forbidden_item or vice-versa.
    2. Same path: normalized filesystem path in frame_item matches path in forbidden_item.
    3. Same command token: command binary/token (curl, wget, etc.) targeting the same resource.
    """
    f_low = frame_item.lower().strip()
    fb_low = forbidden_item.lower().strip()
    
    # 1. Host match
    hosts_f = re.findall(r"(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", f_low)
    hosts_fb = re.findall(r"(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", fb_low)
    for h in hosts_f:
        if any(h == hfb or h in hfb or hfb in h for hfb in hosts_fb):
            return True
            
    # 2. Path match
    paths_f = re.findall(r"(/[\w./-]+|\~[\w./-]+|[a-zA-Z]:\\[\w.\\-]+)", f_low)
    paths_fb = re.findall(r"(/[\w./-]+|\~[\w./-]+|[a-zA-Z]:\\[\w.\\-]+)", fb_low)
    for p in paths_f:
        norm_p = os.path.normpath(p.replace("\\", "/")).replace("\\", "/").rstrip("/").lower()
        for pfb in paths_fb:
            norm_pfb = os.path.normpath(pfb.replace("\\", "/")).replace("\\", "/").rstrip("/").lower()
            if norm_p == norm_pfb or (len(norm_p) > 3 and norm_p in norm_pfb):
                return True
                
    # 3. Command token match
    for cmd in ("curl", "wget", "bash", "sh", "python", "nc", "socat"):
        if re.search(rf"\b{cmd}\b", f_low) and re.search(rf"\b{cmd}\b", fb_low):
            toks_f = set(f_low.split())
            toks_fb = set(fb_low.split())
            if len(toks_f.intersection(toks_fb)) >= 2:
                return True
    return False


def call_openai_synthesizer(
    declaration_text: str, 
    api_key: str, 
    model: str = "gpt-4o-mini",
    security_context: Optional[List[Dict[str, Any]]] = None
) -> Tuple[Optional[List[Dict[str, Any]]], Dict[str, Any]]:
    """Invokes LLM via call_llm_json_with_meta to extract behavioral contracts across chunks.
    
    Splits long declarations into line-bounded chunks with overlap, enforces ASYN_MAX_CHUNKS (default 12),
    scans skipped text deterministically, merges and de-duplicates contracts, caps total contracts
    via ASYN_MAX_CONTRACTS (default 12), and validates full command coverage.
    """
    from src.llm_client import call_llm_json_with_meta
    from src.agent_skill_loader import get_agent_system_prompt

    parsed_lines = parse_declaration_lines(declaration_text)
    all_chunks = _chunk_declaration_lines(parsed_lines, target_chunk_size=10000, overlap_lines=5)
    
    max_chunks = int(os.environ.get("ASYN_MAX_CHUNKS", 12))
    total_chunks = len(all_chunks)
    
    if total_chunks <= max_chunks:
        selected_indices = list(range(total_chunks))
    else:
        step = (total_chunks - 1) / max(1, max_chunks - 1)
        selected_indices = sorted(list(set(round(i * step) for i in range(max_chunks))))
        if 0 not in selected_indices:
            selected_indices.insert(0, 0)
        if (total_chunks - 1) not in selected_indices:
            selected_indices.append(total_chunks - 1)
        selected_indices = sorted(list(set(selected_indices)))

    skipped_indices = [i for i in range(total_chunks) if i not in selected_indices]
    chunks_processed = len(selected_indices)
    chunks_skipped = len(skipped_indices)
    truncated = chunks_skipped > 0

    # Deterministic scan of skipped chunks (Amendment B1)
    skipped_chunks_data = [all_chunks[idx] for idx in skipped_indices]
    skipped_forbidden = _scan_skipped_lines_for_invariants(skipped_chunks_data)

    sec_advisory = ""
    if security_context:
        findings_str = "\n".join(f"- {f.get('rule_id')}: {f.get('evidence')}" for f in security_context)
        sec_advisory = (
            f"\n\nSECURITY GATE ADVISORY (Detected Static Signals):\n{findings_str}\n"
            f"NOTE: Ensure extracted contracts contain explicit Forbidden Invariants prohibiting these behaviors."
        )

    sys_prompt = get_agent_system_prompt("a_syn", fallback_prompt=CONTRACT_SYSTEM_PROMPT)

    raw_contracts_all: List[Dict[str, Any]] = []
    combined_meta: Dict[str, Any] = {
        "mode": "llm",
        "model": model,
        "asyn_version": CURRENT_ASYN_VERSION,
        "chunks_total": total_chunks,
        "chunks_processed": chunks_processed,
        "chunks_skipped": chunks_skipped,
        "truncated": truncated,
        "latency_ms": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "fallback_reason": None,
    }

    for chunk_idx in selected_indices:
        chunk = all_chunks[chunk_idx]
        lines_subset = "\n".join(f"Line {num}: {line}" for num, line in chunk)
        prompt = f"Extract all formal behavioral contracts from the following SKILL.md declaration text:\n\n{lines_subset}{sec_advisory}"

        parsed, meta = call_llm_json_with_meta(
            prompt=prompt,
            system_prompt=sys_prompt,
            api_key=api_key,
            model=model,
            temperature=0.1,
        )
        if meta:
            combined_meta["latency_ms"] += meta.get("latency_ms", 0)
            if meta.get("input_tokens") is not None:
                combined_meta["input_tokens"] += meta.get("input_tokens", 0)
            if meta.get("output_tokens") is not None:
                combined_meta["output_tokens"] += meta.get("output_tokens", 0)

        chunk_contracts = validate_contracts_container(parsed) if parsed else None
        if chunk_contracts:
            raw_contracts_all.extend(chunk_contracts)

    if not raw_contracts_all:
        return None, combined_meta

    # Merge contracts:
    # 1. Deduplicate by (source_line, normalized postcondition)
    seen_keys = set()
    deduped_contracts: List[Dict[str, Any]] = []
    all_forbidden: List[str] = list(skipped_forbidden)

    for c in raw_contracts_all:
        for fi in c.get("forbidden_invariant", []) or ():
            if str(fi) not in all_forbidden:
                all_forbidden.append(str(fi))

        norm_post = re.sub(r"\s+", " ", str(c.get("postcondition", "")).strip().lower())
        norm_src = str(c.get("source_line", "")).strip()
        key = (norm_src, norm_post)
        if key not in seen_keys:
            seen_keys.add(key)
            deduped_contracts.append(c)

    # 2. Cap total number of contracts (env ASYN_MAX_CONTRACTS, default 12), prioritizing contracts with explicit effects
    max_contracts = int(os.environ.get("ASYN_MAX_CONTRACTS", 12))
    deduped_contracts.sort(
        key=lambda x: (not bool(x.get("expects_effect")), not bool(x.get("testable", True)))
    )
    final_contracts = deduped_contracts[:max_contracts]

    # 3. Amendment B2: The contract cap applies to contracts only. Never cap or drop forbidden_invariants.
    # Distribute the merged union of all_forbidden to all contracts so J1 receives the full set.
    # Also prune frame_axiom of each contract against all_forbidden using _frame_conflicts_with_forbidden (Amendment B3).
    for idx, c in enumerate(final_contracts):
        c["contract_id"] = f"C_{idx+1:02d}"
        c["forbidden_invariant"] = list(all_forbidden)
        current_frame = c.get("frame_axiom", []) or []
        pruned_frame = [
            f_item for f_item in current_frame
            if not any(_frame_conflicts_with_forbidden(str(f_item), fb) for fb in all_forbidden)
        ]
        c["frame_axiom"] = pruned_frame

    # Schema-level validation: check for uncovered documented commands over FULL document text
    uncovered_cmds = _find_uncovered_documented_commands(declaration_text, final_contracts)
    if uncovered_cmds:
        feedback_prompt = (
            "VALIDATION FEEDBACK: The following documented commands across SKILL.md were not covered in your contracts:\n"
            + "\n".join(f"- {cmd}" for cmd in uncovered_cmds[:5])
            + "\nPer Critical Rule 7: Every documented executable step/command in SKILL.md MUST become either a contract (if part of stated purpose) "
            "or an explicit forbidden_invariant citing its SKILL.md line (if external/unrelated, e.g. curl download). Provide the missing contracts/forbidden_invariants in standard JSON."
        )
        re_parsed, re_meta = call_llm_json_with_meta(
            prompt=feedback_prompt,
            system_prompt=sys_prompt,
            api_key=api_key,
            model=model,
            temperature=0.1,
        )
        re_contracts = validate_contracts_container(re_parsed) if re_parsed else None
        if re_contracts:
            for rc in re_contracts:
                for fi in rc.get("forbidden_invariant", []) or ():
                    if str(fi) not in all_forbidden:
                        all_forbidden.append(str(fi))
                norm_post = re.sub(r"\s+", " ", str(rc.get("postcondition", "")).strip().lower())
                norm_src = str(rc.get("source_line", "")).strip()
                if (norm_src, norm_post) not in seen_keys and len(final_contracts) < max_contracts:
                    seen_keys.add((norm_src, norm_post))
                    final_contracts.append(rc)
            for idx, c in enumerate(final_contracts):
                c["contract_id"] = f"C_{idx+1:02d}"
                c["forbidden_invariant"] = list(all_forbidden)
                current_frame = c.get("frame_axiom", []) or []
                c["frame_axiom"] = [
                    f_item for f_item in current_frame
                    if not any(_frame_conflicts_with_forbidden(str(f_item), fb) for fb in all_forbidden)
                ]

    return final_contracts, combined_meta


def synthesize_contracts_with_security(
    skill_dir: str, 
    skill_id: str, 
    api_key: str, 
    declaration_text: str = ""
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Dict[str, Any]]:
    """
    Unified Contract & Level-1 Security Synthesizer:
    1. Reads and guards the skill declaration.
    2. Runs static security scan across declaration and AST in the same ingestion pass.
    3. Synthesizes behavioral contracts (passing security findings to LLM for enhanced Forbidden Invariants).
    Returns (contracts, level1_report, llm_meta).
    """
    skill_md_path = os.path.join(skill_dir, "SKILL.md")
    if not declaration_text and os.path.exists(skill_md_path):
        runtime_bias_guard(skill_md_path, "")
        with open(skill_md_path, "r", encoding="utf-8", errors="ignore") as f:
            declaration_text = f.read()

    if declaration_text:
        runtime_bias_guard(skill_md_path, declaration_text)

    # 1. Level-1 Static Security Scan in the same reading pass
    l1_report = scan_skill_for_level1_security(skill_dir, declaration_text=declaration_text)
    triggered_rules = l1_report.get("triggered_rules", [])

    contracts = None
    llm_meta = {
        "mode": "deterministic",
        "model": None,
        "asyn_version": CURRENT_ASYN_VERSION,
        "chunks_total": 1,
        "chunks_processed": 1,
        "chunks_skipped": 0,
        "truncated": False,
        "latency_ms": 0,
        "input_tokens": None,
        "output_tokens": None,
        "fallback_reason": "No API key configured",
    }
    # 2. Extract contracts with security context if API key available
    if api_key:
        for attempt in range(1, 4):
            contracts, meta = call_openai_synthesizer(
                declaration_text, 
                api_key, 
                security_context=triggered_rules if triggered_rules else None
            )
            llm_meta = meta
            if contracts is not None:
                break
            time.sleep(0.5 * attempt)

    # Fallback default contract if LLM extraction unavailable or skipped
    if not contracts:
        contracts = [{
            "contract_id": "C_01",
            "source_line": "SKILL.md:Line 1",
            "precondition": f"Environment initialized for skill {skill_id}",
            "postcondition": "Expected skill operation executes without unhandled exceptions",
            "frame_axiom": [
                "read: workspace",
                "write: workspace",
                "network: none"
            ],
            "forbidden_invariant": [
                "network_egress: true",
                "read: sensitive_credentials",
                "write: system_persistence",
                "process: unauthorized_spawning"
            ],
            "testable": True,
            "expects_effect": False,
        }]

    # Auto-inject any high/critical security findings into contracts as explicit forbidden invariants
    for c in contracts:
        for rule in triggered_rules:
            inv_text = f"MUST NOT violate {rule['rule_id']}: {rule['evidence']}"
            if inv_text not in c.get("forbidden_invariant", []):
                c.setdefault("forbidden_invariant", []).append(inv_text)

    contracts = normalize_contract_frame_axioms(contracts, declaration_text)

    # Resolve authoritative IntentRef objects using DeclarationIndex across all declarative files
    try:
        from src.declaration_index import DeclarationIndex, resolve_contract_intent_refs
        decl_idx = DeclarationIndex(skill_dir)
        for c in contracts:
            c_refs = resolve_contract_intent_refs(c, decl_idx)
            c["intent_refs"] = [r.to_dict() for r in c_refs]
    except Exception:
        pass

    return contracts, l1_report, llm_meta

def extract_contracts_for_skill(skill_dir: str, skill_id: str, api_key: str) -> Optional[List[Dict[str, Any]]]:
    """
    Backwards-compatible entry point for A_syn Contract Synthesizer.
    Invokes the unified synthesize_contracts_with_security and returns contracts.
    """
    contracts, _, _ = synthesize_contracts_with_security(skill_dir, skill_id, api_key)
    return contracts

def process_single_skill(folder: str, dataset_dir: str, api_key: str) -> tuple:
    skill_dir = os.path.join(dataset_dir, folder)
    contracts, _, llm_meta = synthesize_contracts_with_security(skill_dir, folder, api_key)
    if contracts is not None:
        contract_output = {
            "skill_id": folder,
            "asyn_version": CURRENT_ASYN_VERSION,
            "chunks_total": llm_meta.get("chunks_total", 1),
            "chunks_processed": llm_meta.get("chunks_processed", 1),
            "chunks_skipped": llm_meta.get("chunks_skipped", 0),
            "truncated": llm_meta.get("truncated", False),
            "declaration_source": "SKILL.md",
            "total_contracts": len(contracts),
            "synthesized_by": "A_syn (OpenAI gpt-4o-mini)",
            "contracts": contracts
        }
        out_path = os.path.join(skill_dir, "contracts.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(contract_output, f, indent=2)
        return (folder, True, len(contracts))
    else:
        return (folder, False, 0)

def run_contract_synthesis_batch(dataset_dir: str = "./skills_dataset", max_workers: int = 5):
    """
    Runs A_syn over all 100 skills in skills_dataset/ using OpenAI API and writes contracts.json.
    """
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        print("ERROR: OPENAI_API_KEY is not set in environment or .env file!")
        sys.exit(1)

    folders = sorted([f for f in os.listdir(dataset_dir) if os.path.isdir(os.path.join(dataset_dir, f))])
    print("=================================================================")
    print("RUNNING A_SYN (CONTRACT SYNTHESIZER) VIA OPENAI (gpt-4o-mini)")
    print(f"Total skills to process: {len(folders)} | Worker threads: {max_workers}")
    print("=================================================================")

    start_time = time.time()
    results = []
    completed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_skill = {
            executor.submit(process_single_skill, folder, dataset_dir, api_key): folder
            for folder in folders
        }
        for future in as_completed(future_to_skill):
            res = future.result()
            results.append(res)
            completed += 1
            status_str = f"SUCCESS ({res[2]} contracts)" if res[1] else "FAILED"
            if completed % 10 == 0 or completed == len(folders):
                print(f"[{completed:3d}/{len(folders)}] Processed: {res[0]} -> {status_str}")

    elapsed = time.time() - start_time
    success_count = sum(1 for r in results if r[1])
    failure_count = sum(1 for r in results if not r[1])

    print("\n=================================================================")
    print("A_SYN OPENAI BATCH SYNTHESIS COMPLETE")
    print("=================================================================")
    print(f"Total skills processed: {len(folders)}")
    print(f"Successfully generated valid contracts: {success_count} / {len(folders)}")
    print(f"Failed after 3 retries: {failure_count}")
    print(f"Elapsed time: {elapsed:.2f} seconds ({elapsed/len(folders):.2f}s per skill)")
    print("=================================================================\n")

    return success_count, failure_count


def normalize_intent_unit(contract: Dict[str, Any], skill_id: str) -> Dict[str, Any]:
    """Normalizes a contract dict into an intent unit representation."""
    c_id = contract.get("contract_id") or contract.get("id") or "C_01"
    src_line = contract.get("source_line") or "SKILL.md:Line 1"
    fa = contract.get("frame_axiom", [])
    fa_list = fa if isinstance(fa, list) else []
    forb = contract.get("forbidden_invariant", [])
    forb_list = forb if isinstance(forb, list) else []
    return {
        "id": c_id,
        "source_line": src_line,
        "capability": "general",
        "inputs": {},
        "expected_effects": [],
        "expected_outcome": {"description": contract.get("postcondition", ""), "check": "exit_0"},
        "allowed_resources": fa_list,
        "forbidden": forb_list,
    }


if __name__ == "__main__":
    run_contract_synthesis_batch()
