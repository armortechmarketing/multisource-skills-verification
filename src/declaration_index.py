"""Declaration Index and Intent Reference Resolution for Skills.

Indexes all declarative documentation and configuration files in a skill:
- SKILL.md, README*, *.md docs
- config.json, config.yaml, config.toml
- metadata.json, YAML frontmatter, mcp.json/tool manifests

Never indexes executable code files (.py, .sh, .js, .bin, etc.).
Provides authoritative line mapping and verified quote localization.
"""
from __future__ import annotations

import difflib
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

FORBIDDEN_CODE_EXTENSIONS = (
    ".py", ".pyc", ".sh", ".bash", ".zsh", ".js", ".ts", ".mjs", ".cjs",
    ".c", ".cpp", ".rs", ".go", ".java", ".rb", ".php", ".bin", ".exe",
    ".so", ".dylib", ".dll", ".class"
)

DECLARATIVE_EXTENSIONS = (
    ".md", ".markdown", ".json", ".yaml", ".yml", ".toml", ".txt"
)


@dataclass(frozen=True)
class IntentRef:
    file: str
    line_start: int
    line_end: int
    quote: str
    kind: str  # skill_md | readme | config | metadata | frontmatter | tool_manifest | default_forbidden

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DeclarativeFileEntry:
    rel_path: str
    abs_path: str
    kind: str
    lines: Tuple[str, ...]
    raw_content: str


def classify_declarative_kind(rel_path: str) -> str:
    norm = rel_path.replace("\\", "/").lower()
    base = os.path.basename(norm)
    if base == "skill.md" or base.startswith("skill."):
        return "skill_md"
    if "frontmatter" in norm:
        return "frontmatter"
    if base.startswith("readme"):
        return "readme"
    if "metadata" in base:
        return "metadata"
    if "manifest" in base or "mcp.json" in base or "tool" in base:
        return "tool_manifest"
    if any(base.startswith(k) for k in ("config", "settings", "params")):
        return "config"
    return "skill_md" if base.endswith(".md") else "config"


class DeclarationIndex:
    """Indexes all declarative text/config files in a skill without reading code."""

    def __init__(self, skill_dir: str):
        self.skill_dir = os.path.abspath(skill_dir)
        self.entries: Dict[str, DeclarativeFileEntry] = {}
        self._build_index()

    def _build_index(self) -> None:
        if not os.path.isdir(self.skill_dir):
            return

        for root, dirs, files in os.walk(self.skill_dir):
            # Skip hidden dirs, caches, git, and python envs
            dirs[:] = [d for d in dirs if not d.startswith((".", "__")) and d not in ("venv", "node_modules")]
            for f in sorted(files):
                if f.lower() in (
                    "contracts.json",
                    "trajectory.json",
                    "executed_functions.json",
                    "callsites.jsonl",
                    "shell_xtrace.log",
                    "run_status.json",
                    "result.json",
                    "reward.json",
                    "fixtures.json",
                ):
                    continue
                # Strictly reject any executable code extension
                if any(f.lower().endswith(ext) for ext in FORBIDDEN_CODE_EXTENSIONS):
                    continue
                if not any(f.lower().endswith(ext) for ext in DECLARATIVE_EXTENSIONS):
                    continue

                full_p = os.path.join(root, f)
                rel_p = os.path.relpath(full_p, self.skill_dir).replace("\\", "/")

                try:
                    with open(full_p, "r", encoding="utf-8", errors="ignore") as fh:
                        raw = fh.read()
                    lines = tuple(raw.splitlines())
                    kind = classify_declarative_kind(rel_p)
                    self.entries[rel_p] = DeclarativeFileEntry(
                        rel_path=rel_p,
                        abs_path=full_p,
                        kind=kind,
                        lines=lines,
                        raw_content=raw,
                    )
                except Exception:
                    pass

    def get_entry(self, rel_path: str) -> Optional[DeclarativeFileEntry]:
        norm = rel_path.replace("\\", "/")
        if norm in self.entries:
            return self.entries[norm]
        # Match case-insensitively or by basename
        for k, v in self.entries.items():
            if k.lower() == norm.lower() or os.path.basename(k).lower() == os.path.basename(norm).lower():
                return v
        return None

    def find_quote(self, quote: str) -> List[IntentRef]:
        """Finds quote across all indexed declarative files."""
        ref = self.locate_quote(target_file=None, quote=quote)
        return [ref] if ref else []

    def locate_quote(
        self,
        target_file: Optional[str],
        quote: str,
        hint_line: Optional[int] = None,
        default_kind: Optional[str] = None
    ) -> Optional[IntentRef]:
        """Locates quote with 3-tier matching: Exact match -> Whitespace normalized -> Fuzzy >= 0.9.

        If target_file is not found, searches all indexed declarative files.
        Unlocatable quote => returns None (caller drops ref, avoiding hallucination).
        """
        clean_q = quote.strip()
        if not clean_q or len(clean_q) < 3:
            return None

        # Identify candidate entries
        candidates: List[DeclarativeFileEntry] = []
        if target_file:
            ent = self.get_entry(target_file)
            if ent:
                candidates.append(ent)
        if not candidates:
            # Prefer SKILL.md, then README, then others
            sorted_entries = sorted(
                self.entries.values(),
                key=lambda e: (0 if "skill.md" in e.rel_path.lower() else (1 if "readme" in e.rel_path.lower() else 2))
            )
            candidates.extend(sorted_entries)

        for entry in candidates:
            # Tier 1: Exact match in raw content
            if clean_q in entry.raw_content:
                ref = self._find_lines_for_span(entry, clean_q, default_kind)
                if ref:
                    return ref

            # Tier 2: Whitespace-normalized matching
            norm_q = " ".join(clean_q.split())
            ref = self._find_whitespace_normalized(entry, norm_q, default_kind)
            if ref:
                return ref

            # Tier 3: Fuzzy matching (>= 0.9 similarity) on line windows
            ref = self._find_fuzzy_match(entry, clean_q, default_kind)
            if ref:
                return ref

        return None

    def _find_lines_for_span(
        self, entry: DeclarativeFileEntry, exact_sub: str, default_kind: Optional[str]
    ) -> Optional[IntentRef]:
        start_char = entry.raw_content.find(exact_sub)
        if start_char == -1:
            return None
        end_char = start_char + len(exact_sub)

        # 1-indexed line numbers
        l_start = entry.raw_content[:start_char].count("\n") + 1
        l_end = entry.raw_content[:end_char].count("\n") + 1

        kind = default_kind or entry.kind
        return IntentRef(
            file=entry.rel_path,
            line_start=l_start,
            line_end=l_end,
            quote=exact_sub,
            kind=kind,
        )

    def _find_whitespace_normalized(
        self, entry: DeclarativeFileEntry, norm_q: str, default_kind: Optional[str]
    ) -> Optional[IntentRef]:
        lines = entry.lines
        for i in range(len(lines)):
            accum = []
            for j in range(i, min(i + 8, len(lines))):
                accum.append(lines[j])
                joined = " ".join(" ".join(accum).split())
                if norm_q in joined:
                    matched_slice = "\n".join(accum)
                    return IntentRef(
                        file=entry.rel_path,
                        line_start=i + 1,
                        line_end=j + 1,
                        quote=matched_slice.strip(),
                        kind=default_kind or entry.kind,
                    )
        return None

    def _find_fuzzy_match(
        self, entry: DeclarativeFileEntry, clean_q: str, default_kind: Optional[str]
    ) -> Optional[IntentRef]:
        q_lines = [l.strip() for l in clean_q.splitlines() if l.strip()]
        if not q_lines:
            return None
        window_size = max(1, len(q_lines))

        best_ratio = 0.0
        best_range: Optional[Tuple[int, int, str]] = None

        lines = entry.lines
        for i in range(len(lines)):
            for sz in (window_size, window_size + 1):
                j = min(len(lines), i + sz)
                chunk = "\n".join(lines[i:j])
                clean_chunk = " ".join(chunk.split())
                ratio = difflib.SequenceMatcher(None, " ".join(clean_q.split()), clean_chunk).ratio()
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_range = (i + 1, j, chunk)

        if best_ratio >= 0.90 and best_range is not None:
            return IntentRef(
                file=entry.rel_path,
                line_start=best_range[0],
                line_end=best_range[1],
                quote=best_range[2].strip(),
                kind=default_kind or entry.kind,
            )
        return None


def resolve_contract_intent_refs(
    contract: Dict[str, Any],
    declaration_index: DeclarationIndex,
    system_baseline_path: str = "src/system_baseline.py",
) -> List[IntentRef]:
    """Resolves authoritative IntentRef items for a contract from its claims and forbidden invariants."""
    intent_refs: List[IntentRef] = []
    seen = set()

    # 1. Process explicit source_refs if provided by LLM / contract
    for sref in contract.get("source_refs", []):
        f = sref.get("file")
        q = sref.get("quote", "")
        ref = declaration_index.locate_quote(f, q)
        if ref and (ref.file, ref.line_start, ref.line_end) not in seen:
            seen.add((ref.file, ref.line_start, ref.line_end))
            intent_refs.append(ref)

    # 2. Parse legacy source_line (e.g. 'SKILL.md:Line 14')
    source_line_str = str(contract.get("source_line", ""))
    m = re.search(r"([^:]+):Line\s*(\d+)", source_line_str, re.IGNORECASE)
    if m:
        target_f = m.group(1).strip()
        try:
            line_num = int(m.group(2))
        except ValueError:
            line_num = 1
        entry = declaration_index.get_entry(target_f)
        if entry:
            actual_line = max(1, min(line_num, len(entry.lines)))
            quote = entry.lines[actual_line - 1] if entry.lines else ""
            key = (entry.rel_path, actual_line, actual_line)
            if key not in seen:
                seen.add(key)
                intent_refs.append(
                    IntentRef(
                        file=entry.rel_path,
                        line_start=actual_line,
                        line_end=actual_line,
                        quote=quote.strip(),
                        kind=entry.kind,
                    )
                )

    # 3. Postcondition or Precondition quote match if still empty
    if not intent_refs:
        for claim in (contract.get("postcondition"), contract.get("precondition")):
            if claim and isinstance(claim, str):
                ref = declaration_index.locate_quote(None, claim)
                if ref and (ref.file, ref.line_start, ref.line_end) not in seen:
                    seen.add((ref.file, ref.line_start, ref.line_end))
                    intent_refs.append(ref)
                    break

    return intent_refs
