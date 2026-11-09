import ast
import hashlib
import json
import os
import re
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple, Union

from src.judge import (
    BehaviorUnit,
    CheckResult,
    Contract,
    Evidence,
    JudgeConfig,
    RunStatus,
    judge,
    parse_contract_dict,
)
from src.llm_client import call_llm_json
from src.telemetry_parser import build_evidence_from_artifacts


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

J2_GUARD_VERSION = "2.1.0"

# Keep may/might/possibly/... ; do NOT fire on "could not" / cannot / did not / unable to
_SPECULATIVE_PATTERN = re.compile(
    r"\b(?:may|might|possibly|potentially|perhaps|suggest|suggests|suggesting|appears\s+to|seems|likely|probably|unclear)\b"
    r"|\bcould\b(?!\s+not\b)",
    re.IGNORECASE,
)
ACTIVE_VIOLATION_KINDS = {"file_write", "file_delete", "exec", "net_connect", "net_dns"}

POSTCONDITION_JUDGE_SYSTEM_PROMPT = """You are the Semantic Postcondition Judge (J2) in a formal intent-behavior verification pipeline.
Your ONLY role is to evaluate whether a single contract's declared `postcondition` was satisfied by the skill's observed `behavior_units` and `stdout`/`stderr`.

STRICT RULES:
1. You may ONLY return a status in {"PASS", "CONTRADICTED", "INDETERMINATE"}.
2. You can NEVER emit "Undeclared_Behavior" (security/frame violations are evaluated deterministically in J1).
3. If you return "PASS" or "CONTRADICTED", you MUST cite at least one valid `id` from the provided `behavior_units` list in `cited_unit_ids`, OR include non-empty `cited_outputs` (subset of ["stdout", "stderr", "fs_diff"]).
4. NO SPECULATION: You must never use speculative language (e.g. may, might, could, possibly, potentially, perhaps, suggest, suggests, suggesting, appears to, seems, likely, probably, unclear). Speculative explanations will be downgraded to INDETERMINATE.
5. CONTRADICTED requires direct active evidence (file_write, file_delete, exec, net_connect, net_dns) or non-empty cited_outputs. Citing only file_read of skill scripts or exit codes is insufficient.
6. If the provided `behavior_units` and outputs are insufficient to prove either satisfaction or contradiction, return "INDETERMINATE".

Respond ONLY with valid JSON conforming to this exact schema:
{
  "status": "PASS" | "CONTRADICTED" | "INDETERMINATE",
  "cited_unit_ids": ["<unit_id_1>", ...],
  "cited_outputs": ["stdout" | "stderr" | "fs_diff"],
  "reason": "<concise explanation quoting observed fields without speculation>"
}
"""

DEFAULT_POSTCONDITION_CACHE_PATH = os.path.join("artifacts", "cache", "llm_postcondition_cache.json")
_MEMORY_POSTCONDITION_CACHE: Dict[str, Dict[str, Any]] = {}


def _serialize_unit_for_hash(u: Union[BehaviorUnit, Dict[str, Any]]) -> Dict[str, Any]:
    if isinstance(u, BehaviorUnit):
        return {
            "id": u.id,
            "kind": u.kind,
            "target": u.target,
            "evidence_ref": u.evidence_ref,
        }
    return {
        "id": str(u.get("id") or ""),
        "kind": str(u.get("kind") or ""),
        "target": str(u.get("target") or ""),
        "evidence_ref": str(u.get("evidence_ref") or ""),
    }


def compute_postcondition_cache_key(
    contract_id: str,
    postcondition: str,
    behavior_units: Sequence[Union[BehaviorUnit, Dict[str, Any]]],
    stdout: str,
    stderr: str,
    skill_version_hash: str = "",
    agent_skill_hash: str = "",
    model: str = "",
    guard_version: str = J2_GUARD_VERSION,
) -> str:
    """Compute deterministic SHA-256 key for `(contract_id, postcondition, behavior_units, stdout[:4096], stderr[:4096], skill_version_hash, agent_skill_hash, model, guard_version)`."""
    payload = {
        "contract_id": str(contract_id),
        "postcondition": str(postcondition),
        "behavior_units": [_serialize_unit_for_hash(u) for u in behavior_units],
        "stdout": (stdout or "")[:4096],
        "stderr": (stderr or "")[:4096],
        "skill_version_hash": str(skill_version_hash or ""),
        "agent_skill_hash": str(agent_skill_hash or ""),
        "model": str(model or ""),
        "guard_version": str(guard_version or J2_GUARD_VERSION),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_disk_cache(cache_path: str) -> Dict[str, Dict[str, Any]]:
    if not cache_path or not os.path.isfile(cache_path):
        return {}
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_disk_cache(cache_path: str, cache_data: Dict[str, Dict[str, Any]]) -> None:
    if not cache_path:
        return
    try:
        os.makedirs(os.path.dirname(os.path.abspath(cache_path)), exist_ok=True)
        with open(cache_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(cache_data, f, indent=2, sort_keys=True)
    except Exception:
        pass


def _validate_and_normalize_postcondition_response(
    raw: Any,
    valid_unit_ids: Set[str],
    units_by_id: Optional[Dict[str, Any]] = None,
    stdout: str = "",
    stderr: str = "",
    fs_diff: Any = None,
    contract: Optional[Any] = None,
) -> Dict[str, Any]:
    """Enforce J2 invariants on LLM postcondition output:
    - status in {PASS, CONTRADICTED, INDETERMINATE} (never Undeclared_Behavior)
    - PASS/CONTRADICTED must cite >=1 valid BehaviorUnit.id or valid cited_outputs
    - Speculative language downgraded to INDETERMINATE (j2_downgraded_speculative)
    - CONTRADICTED requires active evidence (file_write/delete, exec, net) or non-empty cited_outputs (j2_downgraded_irrelevant_citation)
    - CONTRADICTED requires contract to have observable effect element and exercised (j2_downgraded_unexercised_or_no_observable_effect)
    """
    if not isinstance(raw, dict):
        return {
            "status": "INDETERMINATE",
            "cited_unit_ids": [],
            "cited_outputs": [],
            "reason": "LLM returned non-JSON or empty response.",
            "downgrade_reason": None,
        }

    raw_status = str(raw.get("status") or "INDETERMINATE").strip().upper()
    reason = str(raw.get("reason") or "LLM semantic postcondition evaluation")

    if raw_status not in ("PASS", "CONTRADICTED", "INDETERMINATE"):
        return {
            "status": "INDETERMINATE",
            "cited_unit_ids": [],
            "cited_outputs": [],
            "reason": f"Disallowed LLM postcondition status '{raw_status}' downgraded to INDETERMINATE ({reason})",
            "downgrade_reason": None,
        }

    raw_cited = raw.get("cited_unit_ids")
    if not isinstance(raw_cited, (list, tuple)):
        raw_cited = []
    valid_cited = [str(uid) for uid in raw_cited if str(uid) in valid_unit_ids]

    raw_outputs = raw.get("cited_outputs")
    if not isinstance(raw_outputs, (list, tuple)):
        raw_outputs = []
    valid_outputs = [str(out).lower() for out in raw_outputs if str(out).lower() in ("stdout", "stderr", "fs_diff")]

    if raw_status in ("PASS", "CONTRADICTED") and not valid_cited and not valid_outputs:
        return {
            "status": "INDETERMINATE",
            "cited_unit_ids": [],
            "cited_outputs": [],
            "reason": f"LLM returned {raw_status} without citing any valid BehaviorUnit.id or output -> downgraded to INDETERMINATE ({reason})",
            "downgrade_reason": None,
        }

    # Fix 3a: Speculative language check
    if raw_status in ("PASS", "CONTRADICTED") and _SPECULATIVE_PATTERN.search(reason):
        return {
            "status": "INDETERMINATE",
            "cited_unit_ids": valid_cited,
            "cited_outputs": valid_outputs,
            "reason": f"Downgraded to INDETERMINATE due to speculative language: {reason}",
            "downgrade_reason": "j2_downgraded_speculative",
        }

    # Fix 3b / Amendment B4: Direct evidence requirement for CONTRADICTED
    if raw_status == "CONTRADICTED":
        has_active_unit = False
        if units_by_id:
            for uid in valid_cited:
                u = units_by_id.get(uid)
                if u is not None:
                    u_kind = getattr(u, "kind", None) or (u.get("kind") if isinstance(u, dict) else None)
                    if u_kind in ACTIVE_VIOLATION_KINDS:
                        has_active_unit = True
                        break

        has_valid_output = False
        for out in valid_outputs:
            if out == "stdout" and bool(stdout and stdout.strip()):
                has_valid_output = True
                break
            elif out == "stderr" and bool(stderr and stderr.strip()):
                has_valid_output = True
                break
            elif out == "fs_diff" and bool(fs_diff):
                has_valid_output = True
                break

        if not has_active_unit and not has_valid_output:
            return {
                "status": "INDETERMINATE",
                "cited_unit_ids": valid_cited,
                "cited_outputs": valid_outputs,
                "reason": f"CONTRADICTED cited only irrelevant evidence or empty outputs -> downgraded to INDETERMINATE ({reason})",
                "downgrade_reason": "j2_downgraded_irrelevant_citation",
            }

        # Fix 3c: Observable effect & exercised requirement for CONTRADICTED
        if contract is not None:
            has_effect_elem = False
            if getattr(contract, "expects_effect", False) or (isinstance(contract, dict) and contract.get("expects_effect")):
                has_effect_elem = True
            else:
                fa = getattr(contract, "frame_axiom", None) or (contract.get("frame_axiom") if isinstance(contract, dict) else None)
                if fa:
                    writes = getattr(fa, "write", ()) if hasattr(fa, "write") else (fa.get("write", ()) if isinstance(fa, dict) else ())
                    hosts = getattr(fa, "hosts", ()) if hasattr(fa, "hosts") else (fa.get("hosts", ()) if isinstance(fa, dict) else ())
                    execs = getattr(fa, "exec", ()) if hasattr(fa, "exec") else (fa.get("exec", ()) if isinstance(fa, dict) else ())
                    if writes or hosts or execs:
                        has_effect_elem = True
                checks = getattr(contract, "checks", ()) if hasattr(contract, "checks") else (contract.get("checks", ()) if isinstance(contract, dict) else ())
                if any((getattr(chk, "kind", "") if hasattr(chk, "kind") else chk.get("kind", "")) != "exit_code" for chk in checks):
                    has_effect_elem = True
                p_text = str(getattr(contract, "postcondition", "") if hasattr(contract, "postcondition") else contract.get("postcondition", "")).lower()
                effect_kws = ("write", "create", "delete", "remove", "modify", "send", "post", "fetch", "download", "upload", "connect", "listen", "output", "print", "display", "return", "emit", "generate", "save", "record", "execute", "run", "spawn")
                if any(re.search(rf"\b{kw}\b", p_text) for kw in effect_kws):
                    has_effect_elem = True

            has_effect_observed = bool(valid_cited) or bool(stdout and stdout.strip()) or bool(fs_diff)
            if not has_effect_elem or not has_effect_observed:
                return {
                    "status": "INDETERMINATE",
                    "cited_unit_ids": valid_cited,
                    "cited_outputs": valid_outputs,
                    "reason": f"CONTRADICTED not allowed on unexercised contract or contract without observable effect element -> downgraded to INDETERMINATE ({reason})",
                    "downgrade_reason": "j2_downgraded_unexercised_or_no_observable_effect",
                }

    return {
        "status": raw_status,
        "cited_unit_ids": valid_cited,
        "cited_outputs": valid_outputs,
        "reason": reason,
        "downgrade_reason": None,
    }


def judge_postcondition(
    contract: Union[Contract, Dict[str, Any]],
    behavior_units: Sequence[Union[BehaviorUnit, Dict[str, Any]]],
    stdout: str = "",
    stderr: str = "",
    *,
    cache_path: Optional[str] = DEFAULT_POSTCONDITION_CACHE_PATH,
    llm_caller: Optional[Callable[..., Optional[Dict[str, Any]]]] = None,
    skill_version_hash: str = "",
    agent_skill_hash: str = "",
    model: str = "",
    fs_diff: Any = None,
    failure_info: Any = None,
    test_args: Optional[Sequence[Any]] = None,
    flags_used: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """J2 Semantic Postcondition Judge (`temperature=0`, JSON schema, cached by SHA-256 hash).

    Args:
        contract: `Contract` dataclass or contract dict containing `id`/`contract_id` and `postcondition`.
        behavior_units: Sequence of `BehaviorUnit` dataclasses (or dicts) from the entry process tree.
        stdout: Captured stdout string.
        stderr: Captured stderr string.
        cache_path: Optional file path for persistent SHA-256 JSON cache.
        llm_caller: Optional override for `call_llm_json` (used for deterministic testing).
        skill_version_hash: Optional skill content version hash for cache invalidation.
        agent_skill_hash: Optional agent skill hash for cache invalidation.
        model: Optional LLM model identifier.
        fs_diff: Optional filesystem diff.
        failure_info: Optional FailureInfo / dict from classify_failure.
        test_args: Optional trial CLI arguments.
        flags_used: Optional trial flags.

    Returns:
        Dict `{"status": "PASS"|"CONTRADICTED"|"INDETERMINATE", "cited_unit_ids": [...], "cited_outputs": [...], "reason": "...", "downgrade_reason": ...}`.
    """
    from src.agent_skill_loader import get_agent_system_prompt, get_agent_skill_version_hash
    effective_agent_hash = agent_skill_hash or get_agent_skill_version_hash("a_adj_j2")
    active_sys_prompt = get_agent_system_prompt("a_adj_j2", fallback_prompt=POSTCONDITION_JUDGE_SYSTEM_PROMPT)

    if isinstance(contract, Contract):
        cid = contract.id
        precond = contract.precondition
        postcond = contract.postcondition
    else:
        cid = str(contract.get("contract_id") or contract.get("id") or "C_01")
        precond = str(contract.get("precondition") or "")
        postcond = str(contract.get("postcondition") or "")

    serialized_units = [_serialize_unit_for_hash(u) for u in behavior_units]
    valid_unit_ids = {u["id"] for u in serialized_units if u["id"]}
    units_by_id = {u.id if hasattr(u, "id") else u.get("id"): u for u in behavior_units}

    fi_dict: Dict[str, Any] = {}
    if failure_info is not None:
        if hasattr(failure_info, "to_dict"):
            fi_dict = failure_info.to_dict()
        elif isinstance(failure_info, dict):
            fi_dict = dict(failure_info)

    cache_key = compute_postcondition_cache_key(
        cid,
        postcond,
        behavior_units,
        stdout,
        stderr,
        skill_version_hash=skill_version_hash,
        agent_skill_hash=effective_agent_hash,
        model=model,
        guard_version=J2_GUARD_VERSION,
    )

    if cache_key in _MEMORY_POSTCONDITION_CACHE:
        return _validate_and_normalize_postcondition_response(
            _MEMORY_POSTCONDITION_CACHE[cache_key],
            valid_unit_ids,
            units_by_id=units_by_id,
            stdout=stdout,
            stderr=stderr,
            fs_diff=fs_diff,
            contract=contract,
        )

    if cache_path:
        disk_cache = _load_disk_cache(cache_path)
        if cache_key in disk_cache:
            _MEMORY_POSTCONDITION_CACHE[cache_key] = disk_cache[cache_key]
            return _validate_and_normalize_postcondition_response(
                disk_cache[cache_key],
                valid_unit_ids,
                units_by_id=units_by_id,
                stdout=stdout,
                stderr=stderr,
                fs_diff=fs_diff,
                contract=contract,
            )
    else:
        disk_cache = {}

    prompt = (
        f"Contract ID: {cid}\n"
        f"Precondition: {precond}\n"
        f"Declared Postcondition: {postcond}\n\n"
        f"Observed Entry-Tree Behavior Units ({len(serialized_units)}):\n"
        f"{json.dumps(serialized_units, indent=2)}\n\n"
        f"STDOUT (first 4096 chars):\n{(stdout or '')[:4096]}\n\n"
        f"STDERR (first 4096 chars):\n{(stderr or '')[:4096]}\n\n"
        f"Failure Info: {json.dumps(fi_dict) if fi_dict else 'NONE'}\n"
        f"Test Args: {json.dumps(list(test_args or []))}\n"
        f"Flags Used: {json.dumps(list(flags_used or []))}\n\n"
        "Determine if the Declared Postcondition is PASS, CONTRADICTED, or INDETERMINATE.\n"
        "Remember: PASS and CONTRADICTED MUST cite valid unit IDs from the Observed Entry-Tree Behavior Units, "
        "OR cite non-empty output in cited_outputs (subset of [\"stdout\", \"stderr\", \"fs_diff\"]).\n"
        "NEVER use speculative wording (may, might, could, possibly, potentially, perhaps, suggest, appears to, seems, likely, probably, unclear). "
        "Factual negated ability phrases (could not, cannot, did not, unable to) are allowed.\n"
        "Do NOT return CONTRADICTED solely because stdout/stderr matches a harness/infra failure class."
    )

    from src.llm_client import call_llm_json_with_meta

    target_model = model or os.environ.get("AADJ_MODEL", "gpt-4o-mini")
    effective_key = os.environ.get("OPENAI_API_KEY", "").strip() or os.environ.get("GEMINI_API_KEY", "").strip()

    if llm_caller:
        try:
            try:
                raw_resp = llm_caller(
                    prompt=prompt,
                    system_prompt=active_sys_prompt,
                    temperature=0.0,
                )
            except TypeError:
                raw_resp = llm_caller(prompt=prompt, system_prompt=active_sys_prompt)
            meta = {
                "mode": "llm",
                "model": target_model,
                "latency_ms": 0,
                "input_tokens": None,
                "output_tokens": None,
                "fallback_reason": None,
            }
        except Exception as exc:
            return {
                "status": "INDETERMINATE",
                "cited_unit_ids": [],
                "cited_outputs": [],
                "reason": f"LLM postcondition call failed: {exc}",
                "downgrade_reason": None,
                "_meta": {
                    "mode": "llm_failed_fallback",
                    "model": target_model,
                    "latency_ms": 0,
                    "input_tokens": None,
                    "output_tokens": None,
                    "fallback_reason": str(exc),
                },
            }
    else:
        try:
            raw_resp, meta = call_llm_json_with_meta(
                prompt=prompt,
                system_prompt=active_sys_prompt,
                model=target_model,
                api_key=effective_key,
                temperature=0.0,
            )
        except Exception as exc:
            return {
                "status": "INDETERMINATE",
                "cited_unit_ids": [],
                "cited_outputs": [],
                "reason": f"LLM postcondition call failed: {exc}",
                "downgrade_reason": None,
                "_meta": {
                    "mode": "llm_failed_fallback",
                    "model": target_model,
                    "latency_ms": 0,
                    "input_tokens": None,
                    "output_tokens": None,
                    "fallback_reason": str(exc),
                },
            }

    if raw_resp is None:
        return {
            "status": "INDETERMINATE",
            "cited_unit_ids": [],
            "cited_outputs": [],
            "reason": "LLM unavailable or returned None.",
            "downgrade_reason": None,
            "_meta": meta,
        }

    normalized = _validate_and_normalize_postcondition_response(
        raw_resp,
        valid_unit_ids,
        units_by_id=units_by_id,
        stdout=stdout,
        stderr=stderr,
        fs_diff=fs_diff,
        contract=contract,
    )
    normalized["_meta"] = meta
    _MEMORY_POSTCONDITION_CACHE[cache_key] = normalized
    if cache_path:
        disk_cache[cache_key] = normalized
        _save_disk_cache(cache_path, disk_cache)
    return normalized


LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "127.0.0.11", "0.0.0.0"}


def extract_declared_hosts_from_skill(skill_dir: str, contracts: Any) -> Set[str]:
    """Extract declared allowed hosts from SKILL.md and contract frame axioms using urllib.parse (E4, K6)."""
    declared: Set[str] = set()
    if isinstance(contracts, dict):
        contracts = contracts.get("contracts", [])
    if not isinstance(contracts, list):
        contracts = []

    skill_md_path = os.path.join(skill_dir, "SKILL.md")
    text = ""
    if os.path.exists(skill_md_path):
        try:
            text = Path(skill_md_path).read_text(encoding="utf-8", errors="ignore")
        except Exception:
            pass

    if text:
        for u in re.findall(r"https?://[^\s)\"'>`]+", text):
            parsed = urllib.parse.urlparse(u)
            clean = (parsed.hostname or "").strip().lower()
            if clean and clean not in LOOPBACK_HOSTS:
                declared.add(clean)

    for c in contracts:
        parsed_c = parse_contract_dict(c) if isinstance(c, dict) else c
        if isinstance(parsed_c, Contract):
            for h in parsed_c.frame_axiom.hosts:
                if h and h not in LOOPBACK_HOSTS:
                    declared.add(h.lower())

    return declared


def adjudicate_skill_behavior(
    contracts: List[Dict[str, Any]],
    traces: List[Dict[str, Any]],
    skill_dir: str,
    run_status: Optional[str] = None,
    entry_point_reached: bool = False,
    activation: Optional[bool] = None,
    script_execution: Optional[bool] = None,
    failure_type: Optional[str] = None,
    execution_error_sublabel: Optional[str] = None,
    fs_diff: Optional[str] = None,
    level1_risk: Optional[str] = None,
    harbor_trial_dir: Optional[str] = None,
    supervisor_directive: Optional[str] = None,
    domain: str = "general",
    assertion_results: Optional[List[Dict[str, Any]]] = None,
    stdout: Optional[str] = None,
    stderr: Optional[str] = None,
    use_llm_postcondition: bool = False,
) -> Dict[str, Any]:
    """Backward-compatible wrapper delegating directly to `src.judge.judge(contracts, evidence, config)` (`K5`)."""
    skill_dir = os.path.abspath(skill_dir)
    skill_id = os.path.basename(skill_dir)
    if isinstance(contracts, dict):
        contracts = contracts.get("contracts", [])
    if not isinstance(contracts, list):
        contracts = []

    if level1_risk == "CRITICAL":
        return {
            "skill_id": skill_id,
            "gating_status": "SKIPPED_LEVEL1_CRITICAL",
            "predicted_label": "Blocked_Static_CRITICAL",
            "level2_verdict": None,
            "verdict": "Blocked_Static_CRITICAL",
            "no_verdict_reason": None,
            "run_status": "NOT_INVOKED",
            "confidence": 1.0,
            "coverage": 0.0,
            "coverage_score": 0.0,
            "total_contracts": len(contracts),
            "exercised_contracts": 0,
            "uncovered_contracts": [str(c.get("contract_id") or c.get("id") or f"C_{i+1:02d}") for i, c in enumerate(contracts)],
            "contract_status": [],
            "contract_verdicts": [],
            "violations": [],
            "behavior_units": [],
            "intent_to_behavior": {},
            "execution_error_note": None,
            "evidence": ["Blocked at Level-1 static gate"],
            "reasoning": "Execution blocked at Level-1 static security gate due to CRITICAL risk.",
            "supervisor_recommendation": "conclude",
            "needs_rerun": False,
            "execution_error_sublabel": None,
            "adjudicated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    # Build Evidence from Harbor trial artifacts if available
    is_usage_only = False
    if harbor_trial_dir and os.path.isdir(harbor_trial_dir):
        artifacts_dir = os.path.join(harbor_trial_dir, "artifacts")
        if not os.path.isdir(artifacts_dir):
            artifacts_dir = harbor_trial_dir
        trial_res_p = os.path.join(harbor_trial_dir, "result.json")
        evidence, parsed_contracts = build_evidence_from_artifacts(
            artifacts_dir=artifacts_dir,
            skill_dir="/app/skill",
            trial_result_path=trial_res_p if os.path.isfile(trial_res_p) else None,
            contracts_override=contracts,
        )
    else:
        enriched_contracts: List[Dict[str, Any]] = []
        for idx, c in enumerate(contracts):
            mc = dict(c)
            cid = str(mc.get("contract_id") or mc.get("id") or f"C_{idx + 1:02d}")
            mc["contract_id"] = cid
            if not mc.get("checks") and not assertion_results:
                mc["checks"] = [{"id": f"{cid}_exit_0", "contract_id": cid, "kind": "exit_code", "expect": 0}]
            enriched_contracts.append(mc)
        parsed_contracts = tuple(parse_contract_dict(c, idx + 1) for idx, c in enumerate(enriched_contracts))

        units: List[BehaviorUnit] = []
        canary_tokens_list: List[str] = []
        outbound_payloads_list: List[str] = []
        idx_counter = 1
        for tr in traces or []:
            for ev in tr.get("events", []):
                ev_t = str(ev.get("event_type") or "")
                det = ev.get("details") or {}
                if ev_t == "confirmed_exfil":
                    tok = str(det.get("token") or "CANARY_EXFIL_TOKEN")
                    canary_tokens_list.append(tok)
                    outbound_payloads_list.append(tok)
                    dest = str(ev.get("destination") or det.get("destination") or "attacker.example")
                    units.append(
                        BehaviorUnit(
                            id=f"u_{idx_counter:04d}",
                            kind="net_connect",
                            target=dest,
                            ts=float(idx_counter),
                            evidence_ref=f"strace.log:{ev.get('first_line') or idx_counter}",
                        )
                    )
                    idx_counter += 1
                    continue

                kind_map = {
                    "file_read": "file_read",
                    "file_write": "file_write",
                    "canary_read": "file_read",
                    "persistence_write": "file_write",
                    "net_connect": "net_connect",
                    "network": "net_connect",
                    "exec": "exec",
                    "os_command": "exec",
                }
                u_kind = kind_map.get(ev_t)
                if ev_t == "filesystem":
                    u_kind = "file_write" if det.get("operation") == "write" else "file_read"
                if u_kind:
                    target = str(
                        ev.get("destination")
                        or ev.get("path")
                        or ev.get("file")
                        or ev.get("host")
                        or det.get("destination")
                        or det.get("path")
                        or det.get("file")
                        or det.get("command")
                        or ""
                    ).strip()
                    if u_kind in ("file_read", "file_write") and target and not target.startswith("/") and not target.startswith("~"):
                        if ev_t == "canary_read" and target == ".env":
                            target = "/home/agent/.env"
                        else:
                            target = f"/app/skill/{target.lstrip('./')}"
                    units.append(
                        BehaviorUnit(
                            id=f"u_{idx_counter:04d}",
                            kind=u_kind,
                            target=target,
                            ts=float(idx_counter),
                            evidence_ref=f"strace.log:{ev.get('first_line') or idx_counter}",
                        )
                    )
                    idx_counter += 1

        combined_out = ((stdout or "") + "\n" + (stderr or "")).strip().lower()
        if (
            run_status == "INVOKED_SUCCEEDED"
            and not units
            and combined_out
            and any(sig in combined_out for sig in ("usage:", "show this help message and exit", "options:"))
        ):
            is_usage_only = True

        if (stdout or "").strip() and not is_usage_only:
            units.append(
                BehaviorUnit(
                    id=f"u_{idx_counter:04d}",
                    kind="stdout",
                    target=(stdout or "").strip()[:200],
                    ts=float(idx_counter),
                    evidence_ref="stdout.log:1",
                )
            )
            idx_counter += 1

        exit_c = 0 if run_status == "INVOKED_SUCCEEDED" else (1 if entry_point_reached else None)
        if execution_error_sublabel == "bad_args":
            exit_c = 2
        if run_status == "INFRA_FAILURE" or failure_type in ("ImportError", "ModuleNotFoundError", "INFRA", "INFRA_ERROR") or (execution_error_sublabel and "No module named" in execution_error_sublabel):
            sig = "INFRA"
        else:
            sig = failure_type or execution_error_sublabel
        ast_stub = bool(failure_type in ("STUB", "NotImplementedError") or execution_error_sublabel in ("NotImplementedError", "STUB"))

        chk_results: List[CheckResult] = []
        for idx_a, ar in enumerate(assertion_results or [], 1):
            chk_results.append(
                CheckResult(
                    check_id=str(ar.get("check_id") or ar.get("name") or f"chk_{idx_a}"),
                    contract_id=str(ar.get("contract_id") or (parsed_contracts[0].id if parsed_contracts else "C_01")),
                    passed=bool(ar.get("passed", False)),
                    detail=str(ar.get("message") or ar.get("detail") or ""),
                    effect_observed=ar.get("attempted", True),
                )
            )

        evidence = Evidence(
            run_status=RunStatus(
                entry_reached=bool(entry_point_reached),
                exit_code=exit_c,
                failure_signature=sig,
                ast_is_stub=ast_stub,
            ),
            behavior_units=tuple(units),
            check_results=tuple(chk_results),
            stdout=stdout or "",
            stderr=stderr or (execution_error_sublabel if sig == "INFRA" else ""),
            fs_diff=(),
            canary_tokens=tuple(canary_tokens_list),
            outbound_payloads=tuple(outbound_payloads_list),
        )

    config = JudgeConfig(
        postcondition_judge_fn=judge_postcondition if use_llm_postcondition else None,
    )
    j_res = judge(parsed_contracts, evidence, config)
    j_dict = j_res.to_dict()

    is_inconc = j_res.verdict == "Inconclusive"
    out_verdict = j_res.verdict
    out_nvr = j_res.no_verdict_reason
    if is_usage_only and j_res.verdict in ("Unimplemented_Intent", "Aligned"):
        is_inconc = True
        out_verdict = "INCONCLUSIVE_NO_ACTION"
        out_nvr = "LOW_COVERAGE"
    elif is_inconc:
        if failure_type == "SKILL_BUG" or out_nvr == "SKILL_CRASH":
            out_verdict = "INCONCLUSIVE_CRASH"
        elif out_nvr == "HARNESS":
            out_verdict = "Not_Executed(HARNESS)"
        elif out_nvr == "INFRA":
            out_verdict = "Not_Executed(INFRA)"
        elif out_nvr == "LOW_COVERAGE":
            out_verdict = "INCONCLUSIVE_LOW_COVERAGE"

    uncovered_ids = [
        cs.contract_id
        for cs in j_res.contract_status
        if cs.status == "NOT_EXERCISED"
    ]
    can_refine = is_inconc and out_nvr in ("HARNESS", "SKILL_CRASH", "LOW_COVERAGE", "INFRA")

    if is_inconc:
        if out_nvr == "INFRA":
            gating = "Not_Executed(INFRA)"
        elif out_nvr == "HARNESS":
            gating = "Not_Executed(HARNESS)"
        elif out_nvr == "SKILL_CRASH":
            gating = "Not_Executed(EARLY_CRASH)"
        else:
            gating = f"INCONCLUSIVE_{out_nvr}" if out_nvr else "INVOKED"
    else:
        gating = "INVOKED"

    explanation = generate_grounded_explanation(
        verdict=out_verdict,
        contract_status=j_dict["contract_status"],
        violations=j_dict["violations"],
        evidence_scope=j_res.evidence_scope,
        execution_error_note=j_res.execution_error_note,
        dtc=j_res.dtc,
        csr_c=j_res.csr_c,
        attributions=j_dict.get("attribution", []),
    )

    return {
        "skill_id": skill_id,
        "gating_status": gating,
        "predicted_label": None if is_inconc else out_verdict,
        "level2_verdict": None if is_inconc else out_verdict,
        "verdict": out_verdict,
        "no_verdict_reason": out_nvr,
        "run_status": run_status or ("INVOKED_SUCCEEDED" if evidence.run_status.exit_code == 0 else "INVOKED_FAILED"),
        "coverage": j_res.coverage,
        "coverage_score": j_res.coverage,
        "total_contracts": len(parsed_contracts),
        "contracts_total": getattr(j_res, "contracts_total", len(parsed_contracts)),
        "contracts_testable": getattr(j_res, "contracts_testable", sum(1 for c in parsed_contracts if getattr(c, "testable", True))),
        "contracts_non_testable": getattr(j_res, "contracts_non_testable", sum(1 for c in parsed_contracts if not getattr(c, "testable", True))),
        "exercised_contracts": sum(1 for cs in j_res.contract_status if cs.status == "PASS"),
        "uncovered_contracts": uncovered_ids,
        "contract_status": j_dict["contract_status"],
        "contract_verdicts": [
            {
                "contract_id": cs.contract_id,
                "verdict": cs.status,
                "status": cs.status,
                "exercised": cs.status != "NOT_EXERCISED",
                "violation_evidence": [cs.reason] if cs.status == "CONTRADICTED" else [],
                "cited_unit_ids": list(cs.cited_unit_ids),
            }
            for cs in j_res.contract_status
        ],
        "violations": j_dict["violations"],
        "behavior_units": j_dict["behavior_units"],
        "intent_to_behavior": j_dict["intent_to_behavior"],
        "execution_error_note": j_res.execution_error_note,
        "explanation": explanation,
        "evidence": [v.detail or v.rule_id for v in j_res.violations] or [j_res.evidence_scope],
        "reasoning": j_res.evidence_scope,
        "supervisor_recommendation": "refine" if can_refine else "conclude",
        "needs_rerun": can_refine,
        "execution_error_sublabel": execution_error_sublabel or out_nvr,
        "adjudicated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def generate_grounded_explanation(
    verdict: str,
    contract_status: List[Dict[str, Any]],
    violations: List[Dict[str, Any]],
    evidence_scope: str = "",
    execution_error_note: Optional[str] = None,
    dtc: float = 0.0,
    csr_c: float = 0.0,
    api_key: Optional[str] = None,
    skill_id: str = "",
    **kwargs: Any,
) -> Dict[str, Any]:
    """Generates an objective post-verdict explanation grounded in cited contracts and telemetry.

    Strict Invariant: This function NEVER modifies or overrides the verdict or contract statuses.
    """
    passed = [c["contract_id"] for c in contract_status if c.get("status") == "PASS"]
    contradicted = [c["contract_id"] for c in contract_status if c.get("status") == "CONTRADICTED"]
    unimplemented = [c["contract_id"] for c in contract_status if c.get("status") in ("STUB", "EFFECT_ABSENT")]
    not_exercised = [c["contract_id"] for c in contract_status if c.get("status") == "NOT_EXERCISED"]

    cited_units = set()
    for c in contract_status:
        cited_units.update(c.get("cited_unit_ids", []))
    for v in violations:
        if v.get("behavior_unit_id"):
            cited_units.add(v["behavior_unit_id"])

    detail_points = []
    if violations:
        for v in violations[:5]:
            detail_points.append(f"Security/Frame violation {v.get('rule_id')}: {v.get('detail')} ({v.get('evidence_ref')})")
    if contradicted:
        for c in contract_status:
            if c.get("status") == "CONTRADICTED":
                detail_points.append(f"Contract {c.get('contract_id')} contradicted: {c.get('reason')}")
    if unimplemented:
        for c in contract_status:
            if c.get("status") in ("STUB", "EFFECT_ABSENT"):
                detail_points.append(f"Contract {c.get('contract_id')} unimplemented: {c.get('reason')}")

    summary_text = (
        f"Verdict: {verdict}. "
        f"DTC coverage: {round(dtc * 100, 1)}%, CSR: {round(csr_c * 100, 1)}%. "
        f"Passed: {len(passed)}, Contradicted: {len(contradicted)}, Unimplemented: {len(unimplemented)}, Violations: {len(violations)}."
    )
    if detail_points:
        summary_text += " Key findings: " + "; ".join(detail_points[:3])

    # Auto-fill limitations from facts (Fix 3.4 & Fix 4)
    lim_facts = []
    if dtc < 1.0 and dtc > 0.0:
        lim_facts.append(f"DTC coverage < 1.0 ({round(dtc * 100, 1)}%)")
    elif dtc == 0.0:
        lim_facts.append("Zero dynamic test coverage (DTC = 0.0%)")
    # FIX 1.d: Compute "events without verified code site" strictly from the final attribution output
    final_attrs = kwargs.get("attributions") or kwargs.get("attribution") or []
    if final_attrs:
        unattr_count = 0
        for a in final_attrs:
            cs_list = a.get("code_sites", []) if isinstance(a, dict) else getattr(a, "code_sites", ())
            if not cs_list:
                unattr_count += 1
    else:
        unattr_count = sum(1 for v in violations if not v.get("code_sites"))
    if unattr_count > 0:
        lim_facts.append(f"{unattr_count} event(s) without verified skill code site")
    if execution_error_note and "NO_AGENT" in execution_error_note:
        lim_facts.append("Instruction-only skill without agent credentials")

    explanation: Dict[str, Any] = {
        "headline": evidence_scope or f"Verdict reached: {verdict}",
        "verdict": verdict,
        "summary": summary_text,
        "limitations": "; ".join(lim_facts),
        "cited_contracts": {
            "passed": passed,
            "contradicted": contradicted,
            "unimplemented": unimplemented,
            "not_exercised": not_exercised,
        },
        "cited_behavior_units": sorted(list(cited_units)),
        "violations_cited": [v.get("rule_id") for v in violations if v.get("rule_id")],
        "execution_error_note": execution_error_note,
    }

    from src.llm_client import call_llm_json_with_meta

    effective_key = api_key or os.environ.get("OPENAI_API_KEY", "").strip() or os.environ.get("GEMINI_API_KEY", "").strip()
    use_llm = os.environ.get("USE_LLM_EXPLAINER", "1") != "0" and bool(effective_key)
    target_model = os.environ.get("AADJ_MODEL", "gpt-4o-mini").strip()

    explainer_meta: Dict[str, Any] = {
        "mode": "deterministic",
        "model": None,
        "latency_ms": 0,
        "input_tokens": None,
        "output_tokens": None,
        "fallback_reason": "USE_LLM_EXPLAINER set to 0" if os.environ.get("USE_LLM_EXPLAINER") == "0" else "No API key configured",
    }

    if use_llm:
        try:
            from src.agent_skill_loader import get_agent_system_prompt
            sys_prompt = get_agent_system_prompt("a_adj_explainer", fallback_prompt=get_agent_system_prompt("a_adj", fallback_prompt="You are A_adj Explainer."))
            cited_u_list = sorted(list(cited_units))[:8]
            prompt = (
                f"Explain the following deterministic verdict objectively without altering it:\n"
                f"Verdict: {verdict}\n"
                f"Summary: {summary_text}\n"
                f"Evidence: {evidence_scope}\n"
                f"Cited Behavior Unit IDs: {cited_u_list}\n"
                f"Violations: {json.dumps(violations[:3])}\n"
                f"Contracts: {json.dumps(contract_status[:5])}\n\n"
                f"REQUIREMENT: Provide a grounded narrative in 2 to 4 sentences explaining why this verdict was reached, "
                f"explicitly referencing the cited behavior units or missing artifacts. Do NOT simply echo the verdict label."
            )
            llm_res, meta = call_llm_json_with_meta(
                prompt=prompt,
                system_prompt=sys_prompt,
                api_key=effective_key,
                model=target_model,
                temperature=0.0,
            )
            explainer_meta = dict(meta)

            def _extract_narrative(res_obj: Any) -> Optional[str]:
                if not isinstance(res_obj, dict):
                    return None
                val = res_obj.get("explanation") or res_obj.get("narrative") or res_obj.get("reason")
                if not val:
                    val = next((v for v in res_obj.values() if isinstance(v, str) and len(v) > 15), None)
                if val and isinstance(val, str):
                    val_clean = val.strip()
                    # Reject trivial echoes of verdict label
                    if val_clean.lower() in (verdict.lower(), f"verdict: {verdict.lower()}", f"assigned {verdict.lower()}"):
                        return None
                    return val_clean
                return None

            narrative = _extract_narrative(llm_res)

            # Retry once if output only echoed verdict or failed
            if not narrative and meta.get("mode") == "llm":
                retry_prompt = (
                    f"{prompt}\n\n"
                    f"PREVIOUS ATTEMPT REJECTED: Your response merely repeated the verdict label. "
                    f"You MUST write 2 to 4 complete, informative sentences explaining the root causal evidence."
                )
                re_res, re_meta = call_llm_json_with_meta(
                    prompt=retry_prompt,
                    system_prompt=sys_prompt,
                    api_key=effective_key,
                    model=target_model,
                    temperature=0.2,
                )
                narrative = _extract_narrative(re_res)
                if re_meta:
                    explainer_meta = dict(re_meta)

            if narrative:
                explanation["llm_narrative"] = narrative
            else:
                explanation["llm_narrative"] = summary_text
        except Exception as exc:
            explainer_meta = {
                "mode": "llm_failed_fallback",
                "model": target_model,
                "latency_ms": 0,
                "input_tokens": None,
                "output_tokens": None,
                "fallback_reason": str(exc),
            }
            explanation["llm_narrative"] = summary_text

    explanation["_meta"] = explainer_meta
    return explanation


def symbolic_audit(*args, **kwargs) -> Dict[str, Any]:
    """Backward compatibility shim for legacy test harnesses."""
    return {}


def evaluate_symbolic_findings(*args, **kwargs) -> Dict[str, Any]:
    """Backward compatibility shim for legacy test harnesses."""
    return {}


def extract_declared_hosts_from_skill(skill_dir: str) -> List[str]:
    """Extract declared network hosts from skill SKILL.md."""
    from src.a_syn_contract_synthesizer import extract_declared_network_hosts
    p = os.path.join(skill_dir, "SKILL.md")
    if os.path.exists(p):
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            return extract_declared_network_hosts(f.read())
    return []
