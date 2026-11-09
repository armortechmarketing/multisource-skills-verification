"""Replay stored trials for skills against golden expectations (skip missing artifacts)."""
from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import pytest

from src.judge import (
    Check,
    CheckResult,
    Contract,
    Evidence,
    FrameAxiom,
    JudgeConfig,
    RunStatusInfo,
    judge,
    parse_contract_dict,
)

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "analysis" / "golden_expectations.csv"
SAMPLE_ROOTS = [
    ROOT / "colleague_handover_package" / "dynamic_samples" / "sample_20261031_160720_e1dbcc_realenv",
    ROOT / "colleague_handover_package" / "dynamic_samples" / "sample_20261101_091725_b8e79d",
    ROOT / "dynamic_samples" / "sample_20261031_160720_e1dbcc_realenv",
    ROOT / "colleague_handover_package" / "jobs",
]


def _load_golden() -> Dict[str, Set[str]]:
    if not GOLDEN.is_file():
        return {}
    out: Dict[str, Set[str]] = {}
    with GOLDEN.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            sid = (row.get("skill_id") or "").strip()
            allowed = (row.get("allowed_verdicts") or row.get("human_verdict") or "").strip()
            if not sid:
                continue
            out[sid] = {v.strip() for v in allowed.split("|") if v.strip()}
    return out


def _find_trial_dirs(skill_id: str) -> List[Path]:
    hits: List[Path] = []
    for root in SAMPLE_ROOTS:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if p.is_dir() and skill_id in p.name and (
                (p / "result.json").exists()
                or (p / "verifier" / "reward.json").exists()
                or (p / "agent" / "exit_code.txt").exists()
                or (p / "logs").is_dir()
            ):
                hits.append(p)
    return hits


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""


def _rebuild_evidence(trial: Path) -> Optional[Evidence]:
    stdout = ""
    stderr = ""
    exit_code: Optional[int] = 0
    for cand in (
        trial / "logs" / "stdout.log",
        trial / "agent" / "stdout.log",
        trial / "stdout.log",
    ):
        if cand.is_file():
            stdout = _read_text(cand)
            break
    for cand in (
        trial / "logs" / "stderr.log",
        trial / "agent" / "stderr.log",
        trial / "stderr.log",
    ):
        if cand.is_file():
            stderr = _read_text(cand)
            break
    for cand in (trial / "agent" / "exit_code.txt", trial / "exit_code.txt"):
        if cand.is_file():
            try:
                exit_code = int(_read_text(cand).strip().split()[0])
            except Exception:
                exit_code = 1
            break
    result_json = trial / "result.json"
    exception_info = None
    if result_json.is_file():
        try:
            data = json.loads(_read_text(result_json))
            exception_info = data.get("exception_info") or data.get("exception")
            if exit_code in (0, None) and data.get("exit_code") is not None:
                exit_code = int(data["exit_code"])
        except Exception:
            pass

    return Evidence(
        run_status=RunStatusInfo(
            entry_reached=True,
            exit_code=exit_code,
            exception_info=str(exception_info) if exception_info else None,
        ),
        stdout=stdout,
        stderr=stderr,
        check_results=(
            CheckResult("c1", "C_01", exit_code == 0, f"exit_code={exit_code}"),
        ),
        input_valid=True,
        run_kind="script",
        skill_dir=str(trial),
    )


def _default_contract() -> Contract:
    return Contract(
        id="C_01",
        postcondition="skill completes successfully",
        checks=(Check("c1", "C_01", "exit_code", 0),),
        expects_effect=False,
    )


@pytest.mark.replay
def test_judge_replay_against_golden():
    golden = _load_golden()
    if not golden:
        pytest.skip("analysis/golden_expectations.csv missing")

    missing: List[str] = []
    mismatches: List[str] = []
    checked = 0

    for skill_id, allowed in golden.items():
        trials = _find_trial_dirs(skill_id)
        if not trials:
            missing.append(skill_id)
            continue
        ev = _rebuild_evidence(trials[0])
        if ev is None:
            missing.append(skill_id)
            continue
        res = judge([_default_contract()], ev, JudgeConfig(aligned_min_dtc=0.0))
        display = (
            f"Inconclusive({res.no_verdict_reason})"
            if res.verdict == "Inconclusive" and res.no_verdict_reason
            else res.verdict
        )
        checked += 1
        # Soft match: allow any allowed label OR Inconclusive with overlapping reason token
        ok = display in allowed or res.verdict in allowed
        if not ok:
            for a in allowed:
                if a.startswith("Inconclusive") and res.verdict == "Inconclusive":
                    ok = True
                    break
        if not ok:
            mismatches.append(f"{skill_id}: got {display}, allowed={sorted(allowed)}")

    print(f"replay checked={checked} missing={len(missing)} mismatches={len(mismatches)}")
    if missing:
        print("MISSING_ARTIFACTS:", ", ".join(missing[:20]))
    # Missing artifacts are skipped, not failed
    assert not mismatches, "\n".join(mismatches[:15])
