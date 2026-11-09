"""Level-2 Attribution Layer (src/attribution.py).

Implements causal linkage and verification for Level-2 labels:
- Undeclared_Behavior
- Semantically_Divergent
- Unimplemented_Intent (Stubs & Absence)

Guarantees:
- R1 Real evidence only: Every emitted CodeSite is verified against files on disk.
- R2 Verdict invariance: Attribution never changes a judging verdict.
- R3 Deterministic first: Zero hardcoded skill IDs, AST + callsite correlation.
- R5 Explicit nullability: Clearly marks uninstrumented/unattributed events with reasons.
"""
from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.declaration_index import DeclarationIndex, IntentRef


VALID_HOW_KINDS = {
    "audit_hook_stack",
    "traceback",
    "strace_execve",
    "shell_xtrace",
    "ast_stub",
    "static_candidate",
}


@dataclass(frozen=True)
class CodeSite:
    file: str  # Relative to skill root
    function: Optional[str]
    qualname: Optional[str]
    line: int
    snippet: str  # +- 2 lines around `line`
    how: str  # audit_hook_stack | traceback | strace_execve | shell_xtrace | ast_stub | static_candidate
    confidence: float = 0.9
    call_chain: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["call_chain"] = list(self.call_chain)
        return d


@dataclass(frozen=True)
class Attribution:
    contract_id: Optional[str]
    verdict: str  # Undeclared_Behavior | Semantically_Divergent | Unimplemented_Intent
    rule_id: Optional[str]
    intent_refs: Tuple[IntentRef, ...]
    code_sites: Tuple[CodeSite, ...]  # ordered call chain (outermost -> innermost, innermost is actor)
    expected: Optional[Any]
    observed: Optional[Any]
    explanation: str
    absence: Optional[Dict[str, Any]] = None
    localization: Optional[Dict[str, Any]] = None
    unattributed_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "contract_id": self.contract_id,
            "verdict": self.verdict,
            "rule_id": self.rule_id,
            "intent_refs": [ir.to_dict() for ir in self.intent_refs],
            "code_sites": [cs.to_dict() for cs in self.code_sites],
            "expected": self.expected,
            "observed": self.observed,
            "explanation": self.explanation,
            "absence": self.absence,
            "localization": self.localization,
            "unattributed_reason": self.unattributed_reason,
        }


# ---------------------------------------------------------------------------
# R1 Real Evidence Verification Pass
# ---------------------------------------------------------------------------

def verify_code_site(
    skill_dir: str,
    file_rel: str,
    line: int,
    function: Optional[str] = None,
    qualname: Optional[str] = None,
    how: str = "audit_hook_stack",
    confidence: float = 0.9,
    call_chain: Sequence[str] = (),
) -> Optional[CodeSite]:
    """Verify that file exists on disk, line is within bounds, and build CodeSite with snippet."""
    if not skill_dir or not file_rel:
        return None
    
    # Normalize paths
    abs_skill = os.path.abspath(skill_dir).replace("\\", "/").rstrip("/")
    norm_rel = file_rel.replace("\\", "/")
    if norm_rel.startswith("/app/skill/"):
        norm_rel = norm_rel[len("/app/skill/"):]
    elif norm_rel.startswith("/app/"):
        norm_rel = norm_rel[len("/app/"):]
    
    # Check if file_rel is already an absolute path
    if os.path.isabs(norm_rel):
        abs_path = os.path.abspath(norm_rel).replace("\\", "/")
        if not (abs_path == abs_skill or abs_path.startswith(abs_skill + "/")):
            # External file (e.g. python standard library, site-packages, system lib)
            return None
        norm_rel = os.path.relpath(abs_path, abs_skill).replace("\\", "/")
    else:
        abs_path = os.path.abspath(os.path.join(abs_skill, norm_rel.lstrip("/"))).replace("\\", "/")
        if not os.path.isfile(abs_path):
            candidate = os.path.join(abs_skill, os.path.basename(norm_rel))
            if os.path.isfile(candidate):
                abs_path = os.path.abspath(candidate).replace("\\", "/")
                norm_rel = os.path.relpath(abs_path, abs_skill).replace("\\", "/")
            else:
                return None

    if not os.path.isfile(abs_path):
        return None

    try:
        with open(abs_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return None

    total_lines = len(lines)
    if total_lines == 0 or line < 1 or line > total_lines:
        return None

    # Extract +- 2 lines snippet around target line (1-indexed)
    start_idx = max(0, line - 3)
    end_idx = min(total_lines, line + 2)
    snippet_lines = [
        f"{idx + 1:4d} | {lines[idx].rstrip()}"
        for idx in range(start_idx, end_idx)
    ]
    snippet_str = "\n".join(snippet_lines)

    valid_how = how if how in VALID_HOW_KINDS else "audit_hook_stack"

    return CodeSite(
        file=norm_rel,
        function=function or "<module>",
        qualname=qualname or function or "<module>",
        line=line,
        snippet=snippet_str,
        how=valid_how,
        confidence=confidence,
        call_chain=tuple(call_chain),
    )


# ---------------------------------------------------------------------------
# Callsite and Trace Parsing
# ---------------------------------------------------------------------------

def parse_callsites_log(log_path_or_content: str) -> List[Dict[str, Any]]:
    """Parse JSONL callsites log from disk path or string content."""
    entries: List[Dict[str, Any]] = []
    if not log_path_or_content:
        return entries

    if os.path.isfile(log_path_or_content):
        try:
            with open(log_path_or_content, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(json.loads(line))
        except Exception:
            pass
    else:
        for line in log_path_or_content.strip().splitlines():
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
    return entries


def parse_shell_xtrace_log(log_path_or_content: str) -> List[Dict[str, Any]]:
    """Parse shell xtrace log produced by BASH_XTRACEFD and PS4='+${BASH_SOURCE[0]}:${LINENO}:${FUNCNAME[0]}: '."""
    entries: List[Dict[str, Any]] = []
    if not log_path_or_content:
        return entries

    lines: List[str] = []
    if os.path.isfile(log_path_or_content):
        try:
            with open(log_path_or_content, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            pass
    else:
        lines = log_path_or_content.splitlines()

    # Pattern: +<source>:<line>:<func>: <command> (handles multiple leading + for subshells)
    pattern = re.compile(r"^\++([^:]+):(\d+):([^:]*):\s*(.*)$")
    for line in lines:
        m = pattern.match(line.strip())
        if m:
            src, lineno_str, func, cmd = m.groups()
            norm_src = src.replace("\\", "/")
            if norm_src.startswith("/app/skill/"):
                norm_src = norm_src[len("/app/skill/"):]
            elif norm_src.startswith("/app/"):
                norm_src = norm_src[len("/app/"):]
            try:
                entries.append({
                    "file": norm_src,
                    "line": int(lineno_str),
                    "function": func or "<script>",
                    "cmd": cmd,
                })
            except Exception:
                pass
    return entries


def parse_executed_functions(log_path_or_content: str) -> List[Dict[str, Any]]:
    """Parse executed_functions.json list."""
    if not log_path_or_content:
        return []
    if os.path.isfile(log_path_or_content):
        try:
            with open(log_path_or_content, "r", encoding="utf-8", errors="replace") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
        except Exception:
            pass
    else:
        try:
            data = json.loads(log_path_or_content)
            if isinstance(data, list):
                return data
        except Exception:
            pass
    return []


# ---------------------------------------------------------------------------
# Callsite Correlation Engine
# ---------------------------------------------------------------------------

def _is_write_event(event: str, args: Sequence[Any]) -> bool:
    """Check if a callsite event corresponds to a write/modification operation."""
    if event in ("os.rename", "shutil.copyfile", "os.remove", "os.unlink", "os.mkdir"):
        return True
    if event == "open":
        mode = "r"
        if len(args) > 1 and isinstance(args[1], str):
            mode = args[1].lower()
        return any(m in mode for m in ("w", "a", "+", "x"))
    return False


def _is_read_event(event: str, args: Sequence[Any]) -> bool:
    """Check if a callsite event corresponds to a read-only operation."""
    if event == "open":
        mode = "r"
        if len(args) > 1 and isinstance(args[1], str):
            mode = args[1].lower()
        return "w" not in mode and "a" not in mode and "+" not in mode and "x" not in mode
    return False


def _normalize_home_rel(p: str) -> Optional[str]:
    """Extract relative path inside user home directory, handling cross-platform /root vs ~ vs user home."""
    if not p:
        return None
    p_norm = p.replace("\\", "/").rstrip("/").lower()
    try:
        user_home = os.path.expanduser("~").replace("\\", "/").rstrip("/").lower()
    except Exception:
        user_home = ""
    if user_home and p_norm.startswith(user_home + "/"):
        return p_norm[len(user_home) + 1:]
    if p_norm.startswith("/root/"):
        return p_norm[len("/root/"):]
    if p_norm.startswith("~/"):
        return p_norm[2:]
    if p_norm.startswith("/home/"):
        parts = p_norm.split("/", 3)
        if len(parts) >= 4:
            return parts[3]
    return None


def match_unit_to_callsite(
    unit_kind: str,
    unit_target: str,
    unit_ts: float,
    callsites: Sequence[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Find best matching entry in callsites for a behavior unit using BOTH syscall kind and mode, plus strict normalized path equality."""
    if not callsites:
        return None

    norm_target = os.path.normpath(unit_target.replace("\\", "/")).replace("\\", "/").rstrip("/").lower()
    if norm_target.startswith("/app/skill/"):
        norm_target_rel = norm_target[len("/app/skill/"):]
    elif norm_target.startswith("/app/"):
        norm_target_rel = norm_target[len("/app/"):]
    else:
        norm_target_rel = norm_target

    target_home_rel = _normalize_home_rel(norm_target)

    candidates: List[Tuple[float, Dict[str, Any]]] = []

    for entry in callsites:
        event = entry.get("event", "")
        args = entry.get("args", [])
        
        # Check event and mode compatibility
        compatible = False
        if unit_kind == "file_write":
            compatible = _is_write_event(event, args)
        elif unit_kind == "file_read":
            compatible = _is_read_event(event, args)
        elif unit_kind == "net_connect":
            compatible = event in ("socket.connect", "socket.getaddrinfo", "socket.__new__", "http.client.connect", "urllib.Request")
        elif unit_kind == "exec":
            compatible = event in ("subprocess.Popen", "os.system")

        if not compatible:
            continue

        # Strict normalized target match in args (no loose substring/basename fallback)
        target_score = 0.0
        for a in args:
            if not isinstance(a, str) or len(a) < 2:
                continue
            a_norm = os.path.normpath(a.replace("\\", "/")).replace("\\", "/").rstrip("/").lower()
            if a_norm.startswith("/app/skill/"):
                a_norm_rel = a_norm[len("/app/skill/"):]
            elif a_norm.startswith("/app/"):
                a_norm_rel = a_norm[len("/app/"):]
            else:
                a_norm_rel = a_norm

            # Exact normalized path equality (either absolute or relative to skill root)
            if a_norm == norm_target or a_norm_rel == norm_target_rel or a_norm == norm_target_rel or a_norm_rel == norm_target:
                target_score = 1.0
                break

            # Cross-platform home dotfile equality (~ / /root / user home)
            a_home_rel = _normalize_home_rel(a_norm)
            if a_home_rel and target_home_rel and a_home_rel == target_home_rel:
                target_score = 1.0
                break

        if target_score > 0.0:
            e_ts = entry.get("ts", 0.0)
            score = target_score
            if e_ts > 1e8 and unit_ts > 1e8:
                ts_diff = abs(e_ts - unit_ts)
                score -= min(0.5, ts_diff * 0.01)
            candidates.append((score, entry))

    if candidates:
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]

    return None


def match_unit_to_shell_xtrace(
    unit_target: str,
    xtraces: Sequence[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Match behavior unit to shell xtrace line."""
    if not xtraces:
        return None
    norm_target = os.path.basename(unit_target.replace("\\", "/").rstrip("/")).lower()
    for entry in xtraces:
        cmd = entry.get("cmd", "").lower()
        if norm_target in cmd:
            return entry
    return None


def _is_skill_frame(frame: Dict[str, Any], abs_skill: str) -> bool:
    """Check if a stack frame points to a real Python file inside skill_dir (ignoring <string>, <frozen>, <module> wrappers)."""
    fn = str(frame.get("file", "")).strip()
    abs_fn = str(frame.get("abs_file", "")).strip()
    norm_skill = os.path.normpath(abs_skill.replace("\\", "/")).replace("\\", "/") if abs_skill else ""
    for candidate in (abs_fn, fn):
        if not candidate or candidate.startswith("<") or candidate.endswith(">") or "sitecustomize" in candidate or "callsite_hook" in candidate:
            continue
        norm_fn = os.path.normpath(candidate.replace("\\", "/")).replace("\\", "/")
        if norm_fn.startswith("/app/skill/"):
            return True
        if norm_skill and norm_fn.startswith(norm_skill):
            return True
        if not os.path.isabs(norm_fn) and norm_skill:
            if os.path.isfile(os.path.join(norm_skill, norm_fn)):
                return True
    return False


def _order_chain_outer_to_inner(raw_chain: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Order callsite frames outermost -> innermost so the last frame (`[-1]`) is the innermost actor function."""
    clean: List[Dict[str, Any]] = []
    for f in raw_chain:
        fn = str(f.get("file", ""))
        _func = str(f.get("function", ""))
        _ = _func
        if fn.startswith("<frozen") or "callsite_hook.py" in fn or "sitecustomize.py" in fn or fn.endswith("/runner.py"):
            continue
        # Skip <string> frames from exec()
        if fn == "<string>":
            continue
        clean.append(f)
    if not clean:
        return list(raw_chain)
    # If the first frame is `<module>` and the last frame is a named function, it is already outer -> inner.
    if len(clean) >= 2 and clean[0].get("function") == "<module>" and clean[-1].get("function") != "<module>":
        return clean
    # If the first frame is a named function and the last frame is `<module>` (legacy innermost->outermost log), reverse it.
    if len(clean) >= 2 and clean[0].get("function") != "<module>" and clean[-1].get("function") == "<module>":
        return list(reversed(clean))
    return clean


def _extract_line_from_snippet(site: CodeSite) -> str:
    """Extract the exact source code statement at `site.line` from `site.snippet`."""
    prefix = f"{site.line:4d} |"
    for line in site.snippet.splitlines():
        if line.startswith(prefix):
            return line.split("|", 1)[1].strip()
    return site.snippet.splitlines()[0].split("|", 1)[-1].strip() if site.snippet else ""


GENERIC_TARGET_TOKENS = {
    "/tmp", "/etc", "/var", "/dev", "/usr", "/bin", "/app", "/app/skill",
    "python", "python3", "bash", "sh", "curl", "wget", "true", "false", "none", "null"
}


def _search_target_in_declaration(
    target: str,
    decl_index: Optional[DeclarationIndex],
    rule_id: Optional[str] = None,
) -> Optional[Tuple[IntentRef, str]]:
    """Search for the violation target (host, URL, path, command) in SKILL.md/README with strict token matching."""
    if not target or not decl_index or not getattr(decl_index, "entries", None):
        return None

    clean_t = target.strip().strip("'\"").replace("\\", "/")
    if not clean_t or len(clean_t) < 4:
        return None

    norm_lower = clean_t.lower()
    if norm_lower in GENERIC_TARGET_TOKENS or os.path.basename(norm_lower) in GENERIC_TARGET_TOKENS:
        return None

    # Search in SKILL.md first, then README
    skill_doc = decl_index.get_entry("SKILL.md") or next(iter(decl_index.entries.values()), None)
    if not skill_doc or not skill_doc.lines:
        return None

    # Escape for token/word boundary matching
    pat = re.compile(rf"(?:\b|/){re.escape(clean_t)}(?:\b|/)", re.IGNORECASE)

    for idx, line in enumerate(skill_doc.lines, start=1):
        line_clean = line.strip()
        if not line_clean or line_clean == "---":
            continue
        if pat.search(line_clean) or clean_t.lower() in line_clean.lower():
            label = f"documented at {skill_doc.rel_path}:{idx} but not part of the skill's stated purpose / forbidden by {rule_id or 'security rules'}"
            iref = IntentRef(
                file=skill_doc.rel_path,
                line_start=idx,
                line_end=idx,
                quote=line_clean,
                kind=skill_doc.kind,
            )
            return iref, label

    return None


def _resolve_verified_intent_refs(
    contract: Any,
    decl_index: Optional[DeclarationIndex],
    skill_dir: str,
    rule_id: Optional[str] = None,
    target: Optional[str] = None,
) -> Tuple[List[IntentRef], Optional[str]]:
    """Resolve only real, disk-verified `IntentRef` records (Rule R1: never fabricate SKILL.md:1 quotes)."""
    # First: Check if the specific violation target appears in declaration
    if target and decl_index:
        res = _search_target_in_declaration(target, decl_index, rule_id)
        if res:
            iref, custom_label = res
            return [iref], custom_label

    intent_refs: List[IntentRef] = []

    # 1. Check explicit intent_refs attached to contract
    raw_irefs = getattr(contract, "intent_refs", None) if contract is not None else None
    if raw_irefs:
        for item in raw_irefs:
            if isinstance(item, IntentRef):
                if not item.quote.startswith("Contract boundary invariant ["):
                    intent_refs.append(item)
            elif isinstance(item, dict) and item.get("file") and item.get("quote"):
                q = str(item.get("quote"))
                if not q.startswith("Contract boundary invariant ["):
                    intent_refs.append(
                        IntentRef(
                            file=str(item["file"]),
                            line_start=int(item.get("line_start") or 1),
                            line_end=int(item.get("line_end") or item.get("line_start") or 1),
                            quote=q,
                            kind=str(item.get("kind") or "skill_md"),
                        )
                    )

    # 2. Check contract.source_line or postcondition/precondition against real files via DeclarationIndex
    if not intent_refs and decl_index and getattr(decl_index, "entries", None):
        src_line = int(getattr(contract, "source_line", 0) or 0) if contract is not None else 0
        skill_doc = decl_index.get_entry("SKILL.md") or next(iter(decl_index.entries.values()), None)
        if skill_doc and skill_doc.lines:
            total = len(skill_doc.lines)
            if 1 <= src_line <= total:
                target_ln = src_line
                quote_txt = skill_doc.lines[target_ln - 1].strip()
                if not quote_txt or quote_txt == "---":
                    for offset in (1, -1, 2, -2):
                        cand_ln = src_line + offset
                        if 1 <= cand_ln <= total and skill_doc.lines[cand_ln - 1].strip() and skill_doc.lines[cand_ln - 1].strip() != "---":
                            target_ln = cand_ln
                            quote_txt = skill_doc.lines[cand_ln - 1].strip()
                            break
                if quote_txt and quote_txt != "---":
                    intent_refs.append(
                        IntentRef(
                            file=skill_doc.rel_path,
                            line_start=target_ln,
                            line_end=target_ln,
                            quote=quote_txt,
                            kind=skill_doc.kind,
                        )
                    )

        if not intent_refs and contract is not None:
            for q_cand in (getattr(contract, "postcondition", ""), getattr(contract, "precondition", "")):
                if q_cand:
                    found = decl_index.find_quote(str(q_cand))
                    if found:
                        intent_refs.extend(found)
                        break

        # Check frame axioms or forbidden invariants for explicit declaration in SKILL.md
        if not intent_refs and contract is not None:
            for fa in getattr(contract, "frame_axiom", ()) or ():
                found = decl_index.find_quote(str(fa))
                if found:
                    intent_refs.extend(found)
                    break
            if not intent_refs:
                for fi in getattr(contract, "forbidden_invariant", ()) or ():
                    found = decl_index.find_quote(str(fi))
                    if found:
                        intent_refs.extend(found)
                        break

    # Filter out any internal files (src/* or system_baseline) so only skill declaration files remain
    intent_refs = [
        ir for ir in intent_refs
        if ir.file and not ir.file.startswith("src/") and "system_baseline" not in ir.file
    ]

    return intent_refs, None


# ---------------------------------------------------------------------------
# Work Package A3: Undeclared Behavior Violation Attribution
# ---------------------------------------------------------------------------

def attribute_single_violation(
    violation: Any,
    unit: Any,
    contract: Any,
    skill_dir: str,
    callsites: Sequence[Dict[str, Any]],
    xtraces: Sequence[Dict[str, Any]],
    decl_index: Optional[DeclarationIndex] = None,
) -> Attribution:
    """Attributes a single undeclared behavior violation to code site(s) and intent reference(s)."""
    code_sites: List[CodeSite] = []
    unattributed_reason: Optional[str] = None
    target_str = getattr(unit, "target", "")

    matched_callsite = match_unit_to_callsite(
        unit_kind=getattr(unit, "kind", ""),
        unit_target=target_str,
        unit_ts=getattr(unit, "ts", 0.0),
        callsites=callsites,
    )

    full_call_chain: List[str] = []
    ordered_chain: List[Dict[str, Any]] = []
    if matched_callsite and matched_callsite.get("chain"):
        ordered_chain = _order_chain_outer_to_inner(matched_callsite["chain"])
        # Format full file:function:line call chain
        full_call_chain = [
            f"{os.path.basename(f.get('file', '').replace('\\', '/'))}:{f.get('function', '<func>')}:{f.get('line', '?')}"
            for f in ordered_chain
            if f.get("file")
        ]

    # Rule (b): When violation's behavior_unit already carries verified details["code_site"], use as primary code_site
    unit_details = getattr(unit, "details", {}) or {}
    pre_site = unit_details.get("code_site") if isinstance(unit_details, dict) else None
    if isinstance(pre_site, dict) and pre_site.get("file"):
        pre_chain = pre_site.get("call_chain") or full_call_chain or ()
        site = verify_code_site(
            skill_dir=skill_dir,
            file_rel=pre_site.get("file", ""),
            line=pre_site.get("line", 1),
            function=pre_site.get("function"),
            qualname=pre_site.get("qualname"),
            how=pre_site.get("how", "audit_hook_stack"),
            confidence=float(pre_site.get("confidence", 0.95)),
            call_chain=tuple(pre_chain),
        )
        if site:
            code_sites.append(site)

    if not code_sites and ordered_chain:
        abs_skill = os.path.abspath(skill_dir).replace("\\", "/")
        # Find root sink: innermost real skill frame, skipping virtual wrappers
        root_sink_frame = None
        for frame in reversed(ordered_chain):
            if _is_skill_frame(frame, abs_skill):
                root_sink_frame = frame
                break

        if root_sink_frame:
            site = verify_code_site(
                skill_dir=skill_dir,
                file_rel=root_sink_frame.get("file", ""),
                line=root_sink_frame.get("line", 1),
                function=root_sink_frame.get("function"),
                qualname=root_sink_frame.get("qualname"),
                how="audit_hook_stack",
                confidence=0.95,
                call_chain=tuple(full_call_chain),
            )
            if site:
                code_sites.append(site)

    if not code_sites:
        # Try shell xtrace
        matched_xtrace = match_unit_to_shell_xtrace(target_str, xtraces)
        if matched_xtrace:
            site = verify_code_site(
                skill_dir=skill_dir,
                file_rel=matched_xtrace.get("file", ""),
                line=matched_xtrace.get("line", 1),
                function=matched_xtrace.get("function"),
                how="shell_xtrace",
                confidence=0.90,
            )
            if site:
                code_sites.append(site)

    if not code_sites:
        if getattr(unit, "kind", "") == "exec":
            unattributed_reason = "Non-instrumented child process without skill frame (how: strace_execve)"
        else:
            unattributed_reason = f"No verified code site found in callsites.jsonl or xtrace for {target_str}"

    rule_id_str = getattr(violation, "rule_id", "UNDECLARED")
    intent_refs, custom_label = _resolve_verified_intent_refs(
        contract=contract,
        decl_index=decl_index,
        skill_dir=skill_dir,
        rule_id=rule_id_str,
        target=target_str,
    )

    action_str = "wrote to" if getattr(unit, "kind", "") == "file_write" else (
        "read from" if getattr(unit, "kind", "") == "file_read" else (
            "connected to" if getattr(unit, "kind", "") == "net_connect" else "executed"
        )
    )
    first_intent = intent_refs[0] if intent_refs else None
    if custom_label:
        intent_desc = f"({custom_label})"
    elif first_intent:
        intent_desc = f"(stated purpose at {first_intent.file}:{first_intent.line_start})"
    else:
        intent_desc = "(No declaration covers this)"

    if code_sites:
        actor = code_sites[-1]  # Root sink
        code_stmt = _extract_line_from_snippet(actor)
        explanation = (
            f"Assigned Undeclared_Behavior because file '{actor.file}' in function '{actor.qualname}()' "
            f"at line {actor.line} executed `{code_stmt}`: "
            f"{actor.qualname}() in {actor.file}:{actor.line} {action_str} {target_str}, "
            f"outside frame_axiom/forbidden_invariant [{rule_id_str}] {intent_desc}."
        )
    else:
        explanation = (
            f"Skill execution {action_str} {target_str}, "
            f"outside frame_axiom/forbidden_invariant [{rule_id_str}] {intent_desc} "
            f"({unattributed_reason or 'unattributed'})."
        )

    return Attribution(
        contract_id=getattr(contract, "id", None),
        verdict="Undeclared_Behavior",
        rule_id=rule_id_str,
        intent_refs=tuple(intent_refs),
        code_sites=tuple(code_sites),
        expected=f"Disallow unauthorized access to {target_str}",
        observed=f"{action_str} {target_str}",
        explanation=explanation,
        unattributed_reason=unattributed_reason,
    )


# ---------------------------------------------------------------------------
# Work Package A4: Semantically Divergent Localization
# ---------------------------------------------------------------------------

def extract_ast_candidates_for_divergence(
    skill_dir: str,
    executed_funcs: Sequence[Dict[str, Any]],
    expected_val: Any,
    observed_val: Any,
) -> List[CodeSite]:
    """Extract and rank candidate functions from AST that could have produced divergent values."""
    candidates: List[Tuple[float, CodeSite]] = []
    
    exp_str = str(expected_val).strip() if expected_val is not None else ""
    obs_str = str(observed_val).strip() if observed_val is not None else ""

    # Set of executed function identifiers: (rel_file, qualname)
    exec_set = {
        (f.get("file", "").replace("\\", "/"), f.get("qualname"))
        for f in executed_funcs
    }

    # Find all python files under skill_dir
    py_files: List[str] = []
    for root, _, files in os.walk(skill_dir):
        for f in files:
            if f.endswith(".py"):
                rel_f = os.path.relpath(os.path.join(root, f), skill_dir).replace("\\", "/")
                py_files.append(rel_f)

    for rel_f in py_files:
        abs_p = os.path.join(skill_dir, rel_f)
        try:
            with open(abs_p, "r", encoding="utf-8", errors="replace") as src_f:
                tree = ast.parse(src_f.read(), filename=rel_f)
        except Exception:
            continue

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_name = node.name
                line = node.lineno
                is_executed = (rel_f, func_name) in exec_set or any(rel_f.endswith(f[0]) and f[1] == func_name for f in exec_set)

                score = 0.0
                if is_executed:
                    score += 0.5

                # Search node body for literal matches
                target_line = line
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Constant):
                        c_val = str(sub.value).strip()
                        if (exp_str and exp_str in c_val) or (obs_str and obs_str in c_val):
                            target_line = getattr(sub, "lineno", line)
                            score += 0.4
                            break

                site = verify_code_site(
                    skill_dir=skill_dir,
                    file_rel=rel_f,
                    line=target_line,
                    function=func_name,
                    qualname=func_name,
                    how="static_candidate",
                    confidence=min(1.0, score + 0.3),
                )
                if site and score > 0.0:
                    candidates.append((score, site))

    candidates.sort(key=lambda x: x[0], reverse=True)
    return [c[1] for c in candidates]


def attribute_divergence(
    contract: Any,
    check_result: Any,
    evidence: Any,
    skill_dir: str,
    callsites: Sequence[Dict[str, Any]],
    executed_funcs: Sequence[Dict[str, Any]],
    decl_index: Optional[DeclarationIndex] = None,
) -> Attribution:
    """Attributes a failed check / semantically divergent outcome to writer callsite or AST candidate."""
    code_sites: List[CodeSite] = []
    unattributed_reason: Optional[str] = None

    expected_val = getattr(check_result, "expected", getattr(check_result, "detail", ""))
    observed_val = getattr(check_result, "observed", None)

    # Stage 1: Writer attribution in callsites.jsonl
    target_file = None
    if isinstance(expected_val, dict) and "path" in expected_val:
        target_file = str(expected_val["path"])
    elif isinstance(expected_val, str) and any(expected_val.endswith(x) for x in (".json", ".txt", ".csv", ".yaml", ".md")):
        target_file = expected_val

    if not target_file and hasattr(contract, "checks"):
        for chk in getattr(contract, "checks", ()):
            if getattr(chk, "id", None) == getattr(check_result, "check_id", None):
                if isinstance(chk.expect, dict) and chk.expect.get("path"):
                    target_file = str(chk.expect["path"])
                    break

    if not target_file and hasattr(contract, "frame_axiom") and getattr(contract.frame_axiom, "write", None):
        target_file = contract.frame_axiom.write[0]

    if not target_file:
        detail_str = getattr(check_result, "detail", "")
        for ext in (".json", ".txt", ".csv", ".yaml", ".md"):
            m = re.search(rf"([\w\-./]+\{ext})", detail_str)
            if m:
                target_file = m.group(1)
                break

    if target_file:
        tf_base = os.path.basename(target_file.replace("\\", "/")).lower()
        for entry in callsites:
            if entry.get("event") in ("open", "os.rename", "shutil.copyfile"):
                args_str = " ".join(str(a).replace("\\", "/").lower() for a in entry.get("args", []))
                if tf_base in args_str:
                    ordered = _order_chain_outer_to_inner(entry.get("chain", []))
                    caller_chain = [
                        os.path.basename(f.get("file", "").replace("\\", "/"))
                        for f in ordered
                        if f.get("file")
                    ]
                    for f in ordered:
                        site = verify_code_site(
                            skill_dir=skill_dir,
                            file_rel=f.get("file", ""),
                            line=f.get("line", 1),
                            function=f.get("function"),
                            qualname=f.get("qualname"),
                            how="audit_hook_stack",
                            confidence=0.95,
                            call_chain=caller_chain,
                        )
                        if site:
                            code_sites.append(site)
                    if code_sites:
                        break

    # Stage 2: AST candidate extraction
    if not code_sites:
        ast_candidates = extract_ast_candidates_for_divergence(
            skill_dir=skill_dir,
            executed_funcs=executed_funcs,
            expected_val=expected_val,
            observed_val=observed_val,
        )
        if ast_candidates:
            code_sites.append(ast_candidates[0])

    if not code_sites:
        unattributed_reason = "No executed function matched failing output key or literal"

    intent_refs, _ = _resolve_verified_intent_refs(
        contract=contract,
        decl_index=decl_index,
        skill_dir=skill_dir,
        rule_id=None,
    )

    first_intent = intent_refs[0] if intent_refs else None
    intent_loc = f"{first_intent.file}:{first_intent.line_start}" if first_intent else "SKILL.md:1"
    exp_summary = str(expected_val)[:80]
    obs_summary = str(observed_val)[:80] if observed_val is not None else "unexpected output"

    if code_sites:
        actor = code_sites[-1]
        code_stmt = _extract_line_from_snippet(actor)
        explanation = (
            f"Assigned Semantically_Divergent because file '{actor.file}' in function '{actor.qualname}()' "
            f"at line {actor.line} executed `{code_stmt}`: "
            f"{actor.qualname}() in {actor.file}:{actor.line} produced divergent output "
            f"(observed {obs_summary}); {intent_loc} promises {exp_summary}."
        )
    else:
        explanation = (
            f"Execution produced divergent output (observed {obs_summary}); "
            f"{intent_loc} promises {exp_summary} ({unattributed_reason})."
        )

    return Attribution(
        contract_id=getattr(contract, "id", None),
        verdict="Semantically_Divergent",
        rule_id="POSTCONDITION_MISMATCH",
        intent_refs=tuple(intent_refs),
        code_sites=tuple(code_sites),
        expected=expected_val,
        observed=observed_val,
        explanation=explanation,
        unattributed_reason=unattributed_reason,
    )


# ---------------------------------------------------------------------------
# Work Package A5: Unimplemented Intent Attribution (Stubs & Absence)
# ---------------------------------------------------------------------------

def extract_traceback_stub(skill_dir: str, stderr: str) -> Optional[CodeSite]:
    """Extract innermost skill frame from stderr traceback."""
    if not stderr:
        return None
    pattern = re.compile(r'File "([^"]+)", line (\d+), in (\w+)')
    matches = pattern.findall(stderr)
    for filepath, lineno_str, func in reversed(matches):
        try:
            line = int(lineno_str)
            site = verify_code_site(
                skill_dir=skill_dir,
                file_rel=filepath,
                line=line,
                function=func,
                how="traceback",
                confidence=0.95,
            )
            if site:
                return site
        except Exception:
            pass
    return None


def extract_ast_stub(skill_dir: str) -> Optional[CodeSite]:
    """Find AST function definition whose body is only pass, ellipsis, docstring, or NotImplementedError."""
    for root, _, files in os.walk(skill_dir):
        for f in files:
            if f.endswith(".py"):
                rel_f = os.path.relpath(os.path.join(root, f), skill_dir).replace("\\", "/")
                abs_p = os.path.join(skill_dir, rel_f)
                try:
                    with open(abs_p, "r", encoding="utf-8", errors="replace") as src_f:
                        tree = ast.parse(src_f.read(), filename=rel_f)
                except Exception:
                    continue

                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        body = node.body
                        is_stub = False
                        if len(body) == 1:
                            stmt = body[0]
                            if isinstance(stmt, ast.Pass):
                                is_stub = True
                            elif isinstance(stmt, ast.Expr) and isinstance(stmt.value, (ast.Constant, ast.Ellipsis)):
                                is_stub = True
                            elif isinstance(stmt, ast.Raise):
                                if isinstance(stmt.exc, ast.Call) and getattr(stmt.exc.func, "id", "") == "NotImplementedError":
                                    is_stub = True
                                elif getattr(stmt.exc, "id", "") == "NotImplementedError":
                                    is_stub = True

                        if is_stub:
                            site = verify_code_site(
                                skill_dir=skill_dir,
                                file_rel=rel_f,
                                line=node.lineno,
                                function=node.name,
                                qualname=node.name,
                                how="ast_stub",
                                confidence=0.90,
                            )
                            if site:
                                return site
    return None


def attribute_unimplemented(
    contract: Any,
    status_record: Any,
    evidence: Any,
    skill_dir: str,
    executed_funcs: Sequence[Dict[str, Any]],
    decl_index: Optional[DeclarationIndex] = None,
) -> Attribution:
    """Attributes an unimplemented intent (either a Stub or an Absent Effect)."""
    is_stub = getattr(status_record, "status", "") == "STUB" or getattr(evidence.run_status, "ast_is_stub", False)
    
    code_sites: List[CodeSite] = []
    absence: Optional[Dict[str, Any]] = None
    unattributed_reason: Optional[str] = None

    intent_refs, _ = _resolve_verified_intent_refs(
        contract=contract,
        decl_index=decl_index,
        skill_dir=skill_dir,
        rule_id=None,
    )

    first_intent = intent_refs[0] if intent_refs else None
    intent_loc = f"{first_intent.file}:{first_intent.line_start}" if first_intent else "SKILL.md:1"
    claim_str = (first_intent.quote if first_intent else getattr(contract, "postcondition", "Contract promise"))[:80]

    if is_stub:
        stub_site = extract_traceback_stub(skill_dir, getattr(evidence, "stderr", ""))
        if not stub_site:
            stub_site = extract_ast_stub(skill_dir)

        if stub_site:
            code_sites.append(stub_site)
            code_stmt = _extract_line_from_snippet(stub_site)
            explanation = (
                f"Assigned Unimplemented_Intent because file '{stub_site.file}' in function '{stub_site.qualname}()' "
                f"at line {stub_site.line} executed `{code_stmt}`: "
                f"{stub_site.qualname}() in {stub_site.file}:{stub_site.line} "
                f"raises NotImplementedError/is a stub; {intent_loc} promises {claim_str}."
            )
        else:
            unattributed_reason = "Stub detected but could not pinpoint AST or traceback line"
            explanation = (
                f"Skill contains an unimplemented stub; {intent_loc} promises {claim_str} "
                f"({unattributed_reason})."
            )
    else:
        searched_files: List[str] = []
        for root, _, files in os.walk(skill_dir):
            for f in files:
                if f.endswith((".py", ".sh", ".json", ".yaml", ".md")):
                    searched_files.append(os.path.relpath(os.path.join(root, f), skill_dir).replace("\\", "/"))

        exec_qnames = {f.get("qualname") for f in executed_funcs}
        candidate_symbols: List[str] = []

        # Scope candidate symbols to functions related to the contract's entry point, subcommand, or postcondition terms
        contract_keywords = set()
        c_post = str(getattr(contract, "postcondition", "")).lower()
        c_pre = str(getattr(contract, "precondition", "")).lower()
        for word in re.findall(r"[a-zA-Z_]\w{3,}", f"{c_post} {c_pre}"):
            contract_keywords.add(word)

        for rel_f in [f for f in searched_files if f.endswith(".py")]:
            abs_p = os.path.join(skill_dir, rel_f)
            try:
                with open(abs_p, "r", encoding="utf-8", errors="replace") as src_f:
                    tree = ast.parse(src_f.read(), filename=rel_f)
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if node.name not in exec_qnames:
                            # Only include if function name or its body shares keywords with the contract
                            fn_lower = node.name.lower()
                            if contract_keywords and any(kw in fn_lower for kw in contract_keywords):
                                candidate_symbols.append(
                                    f"defined at {rel_f}:{node.lineno} ({node.name}) but never invoked"
                                )
                            elif not contract_keywords:
                                candidate_symbols.append(
                                    f"defined at {rel_f}:{node.lineno} ({node.name}) but never invoked"
                                )
            except Exception:
                pass

        expected_effect = getattr(contract, "postcondition", "Expected side-effect")
        absence = {
            "expected_artifact_or_effect": expected_effect,
            "searched_files": searched_files[:20],
            "executed_functions_count": len(executed_funcs),
            "candidate_symbols": candidate_symbols[:10],
        }
        explanation = (
            f"Assigned Unimplemented_Intent because {intent_loc} promises {claim_str}; no executed code path produced it "
            f"(expected {expected_effect[:40]}; searched {len(searched_files)} files, "
            f"{len(executed_funcs)} functions executed)."
        )

    return Attribution(
        contract_id=getattr(contract, "id", None),
        verdict="Unimplemented_Intent",
        rule_id="STUB" if is_stub else "EFFECT_ABSENT",
        intent_refs=tuple(intent_refs),
        code_sites=tuple(code_sites),
        expected=claim_str,
        observed="stub" if is_stub else "no effect produced",
        explanation=explanation,
        absence=absence,
        unattributed_reason=unattributed_reason,
    )


# ---------------------------------------------------------------------------
# Unified Attribution Entry Point
# ---------------------------------------------------------------------------

def build_attributions(
    verdict: str,
    violations: Sequence[Any],
    contract_statuses: Sequence[Any],
    check_results: Sequence[Any],
    behavior_units: Sequence[Any],
    contracts: Sequence[Any],
    evidence: Any,
    skill_dir: str,
    callsites_log: Optional[str] = None,
    shell_xtrace_log: Optional[str] = None,
    executed_funcs_log: Optional[str] = None,
) -> Tuple[Attribution, ...]:
    """Generates complete attribution records for a judged result.
    
    Guarantees R2: verdict is never modified.
    """
    if verdict in ("Aligned", "Inconclusive") or not verdict:
        return ()

    # Load logs if available
    callsites = parse_callsites_log(callsites_log or "")
    xtraces = parse_shell_xtrace_log(shell_xtrace_log or "")
    executed_funcs = parse_executed_functions(executed_funcs_log or "")

    # Index skill declarative documentation
    decl_index = None
    try:
        decl_index = DeclarationIndex(skill_dir)
    except Exception:
        pass

    attributions: List[Attribution] = []

    contracts_by_id = {getattr(c, "id", ""): c for c in contracts}
    bu_by_id = {getattr(u, "id", ""): u for u in behavior_units}

    if verdict == "Undeclared_Behavior":
        for v in violations:
            bu = bu_by_id.get(getattr(v, "behavior_unit_id", ""))
            contract = contracts[0] if contracts else None
            attr = attribute_single_violation(
                violation=v,
                unit=bu,
                contract=contract,
                skill_dir=skill_dir,
                callsites=callsites,
                xtraces=xtraces,
                decl_index=decl_index,
            )
            attributions.append(attr)

    elif verdict == "Semantically_Divergent":
        # Find contradicted contract records or failing checks
        failing_checks = [cr for cr in check_results if not getattr(cr, "passed", True)]
        if failing_checks:
            for cr in failing_checks:
                cid = getattr(cr, "contract_id", "")
                c = contracts_by_id.get(cid, contracts[0] if contracts else None)
                attr = attribute_divergence(
                    contract=c,
                    check_result=cr,
                    evidence=evidence,
                    skill_dir=skill_dir,
                    callsites=callsites,
                    executed_funcs=executed_funcs,
                    decl_index=decl_index,
                )
                attributions.append(attr)
        else:
            for cs in contract_statuses:
                if getattr(cs, "status", "") == "CONTRADICTED":
                    c = contracts_by_id.get(getattr(cs, "contract_id", ""), None)
                    dummy_check = type("DummyCheck", (), {
                        "expected": getattr(c, "postcondition", ""),
                        "observed": "divergent",
                        "detail": getattr(cs, "reason", "postcondition contradicted"),
                        "passed": False,
                    })()
                    attr = attribute_divergence(
                        contract=c,
                        check_result=dummy_check,
                        evidence=evidence,
                        skill_dir=skill_dir,
                        callsites=callsites,
                        executed_funcs=executed_funcs,
                        decl_index=decl_index,
                    )
                    attributions.append(attr)

    elif verdict == "Unimplemented_Intent":
        for cs in contract_statuses:
            status = getattr(cs, "status", "")
            if status in ("STUB", "EFFECT_ABSENT"):
                c = contracts_by_id.get(getattr(cs, "contract_id", ""), contracts[0] if contracts else None)
                attr = attribute_unimplemented(
                    contract=c,
                    status_record=cs,
                    evidence=evidence,
                    skill_dir=skill_dir,
                    executed_funcs=executed_funcs,
                    decl_index=decl_index,
                )
                attributions.append(attr)

    return tuple(attributions)
