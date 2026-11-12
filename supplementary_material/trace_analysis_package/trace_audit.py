"""
Trace Audit and Automated Flag Extractor for Agent Skills Verification Pipeline.

This script performs read-only analysis of trial artifacts and outputs:
1. analysis/automatic_checks.csv for Level-2 skills
2. Historical symptom distributions on 500 and 700 samples (log-only)
"""

import os
import sys
import json
import glob
import re
import csv
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from collections import Counter

PROJECT_ROOT = Path(r"D:\research")
REALENV_SAMPLE_DIR = PROJECT_ROOT / "dynamic_samples" / "sample_20261031_160720_e1dbcc_realenv"
INSTR_SAMPLE_DIR = PROJECT_ROOT / "dynamic_samples" / "sample_20261101_091725_b8e79d"
SAMPLE_500_DIR = PROJECT_ROOT / "dynamic_samples" / "sample_20261022_171355_fbe71f"
SAMPLE_700_DIR = PROJECT_ROOT / "dynamic_samples" / "sample_20261023_080636_8921f7"
ANALYSIS_DIR = PROJECT_ROOT / "analysis"


def classify_symptoms(text: str, exit_code: Optional[int] = None) -> str:
    """Classify execution failure into a standard symptom class."""
    if not text and exit_code in (0, None):
        return "NONE"

    lower = text.lower()

    if "modulenotfounderror" in lower or "no module named" in lower or "cannot import name" in lower:
        return "MISSING_MODULE"
    if "docker" in lower and "timed out" in lower or "timed out after" in lower or "timeout" in lower:
        return "TIMEOUT"
    if "permission denied" in lower or "eacces" in lower:
        return "PERMISSION"
    if "filenotfounderror" in lower or "no such file or directory" in lower:
        return "FILE_NOT_FOUND"
    if "connection refused" in lower or "connectionrefusederror" in lower or "failed to establish a new connection" in lower or "socket.gaierror" in lower:
        return "NETWORK_ERROR"
    if "unrecognized arguments" in lower or "the following arguments are required" in lower or "error: argument" in lower or "usage:" in lower:
        return "USAGE_ERROR"
    if "missing api key" in lower or "api key not provided" in lower or "not configured" in lower or "environment variable not set" in lower or "401 unauthorized" in lower:
        return "MISSING_CONFIG"
    if "traceback (most recent call last)" in lower or "recursionerror" in lower or "maximum recursion depth exceeded" in lower:
        return "TRACEBACK_IN_SKILL_CODE"
    if exit_code not in (0, None):
        if exit_code == 2:
            return "USAGE_ERROR"
        return "TRACEBACK_IN_SKILL_CODE"
    return "NONE"


def check_script_entry_point(skill_dir: Path, entry_point_rel: str) -> Tuple[bool, bool]:
    """Check if entry point exists and has __main__ or argparse."""
    if not entry_point_rel:
        return False, False
    ep_path = skill_dir / entry_point_rel
    if not ep_path.is_file():
        return False, False
    try:
        content = ep_path.read_text(encoding="utf-8", errors="ignore")
        has_main = ("if __name__" in content or "def main" in content)
        has_argparse = ("argparse" in content or "click" in content or "sys.argv" in content or "typer" in content)
        return True, (has_main or has_argparse)
    except Exception:
        return True, False


def check_required_flags(skill_dir: Path, cli_args: List[str]) -> List[str]:
    """Scan SKILL.md for required flags and check if cli_args include them."""
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.is_file():
        return []
    text = skill_md.read_text(encoding="utf-8", errors="ignore")
    missing = []
    req_matches = re.findall(r"(--[a-zA-Z0-9_-]+)[^\n.]*(?:required|MUST|mandatory)", text, re.IGNORECASE)
    cli_str = " ".join(cli_args)
    for flag in set(req_matches):
        if flag not in cli_str:
            missing.append(flag)
    return sorted(missing)


def check_input_files(skill_dir: Path, test_case: Dict[str, Any]) -> List[str]:
    """Check if input files referenced in CLI args or mock_files actually exist."""
    missing = []
    cli_args = test_case.get("cli_args", [])
    mock_files = test_case.get("mock_files", {})

    for arg in cli_args:
        if any(arg.endswith(ext) for ext in [".json", ".txt", ".csv", ".md", ".yaml", ".yml", ".py", ".pdf"]):
            p = skill_dir / arg
            in_mock = arg in mock_files or f"/{arg}" in mock_files or arg.lstrip("./") in mock_files
            if not p.is_file() and not in_mock and not os.path.isabs(arg):
                missing.append(arg)
    return sorted(missing)


def evaluate_oracles(test_cases: List[Dict[str, Any]]) -> Tuple[int, int, float]:
    """Calculate weak oracle count and total checks."""
    weak_count = 0
    total_count = 0

    for tc in test_cases:
        checks = tc.get("checks", [])
        for chk in checks:
            total_count += 1
            kind = chk.get("kind", "")
            expect = str(chk.get("expect", ""))
            if kind == "exit_code":
                weak_count += 1
            elif kind == "stdout_regex" and expect in (r"\S+", r".+", r".*"):
                weak_count += 1
            elif kind == "file_exists":
                weak_count += 1
    share = (weak_count / total_count) if total_count > 0 else 0.0
    return weak_count, total_count, round(share, 3)


def find_trial_dir_for_skill(skill_id: str, batch_pattern: str) -> Optional[Path]:
    """Locate the trial directory for a skill across jobs."""
    batches = sorted(glob.glob(str(PROJECT_ROOT / "jobs" / batch_pattern)))
    for b in batches:
        for entry in os.listdir(b):
            if entry.startswith(f"trial_{skill_id}_"):
                return Path(b) / entry
    return None


def run_realenv_automatic_checks() -> List[Dict[str, Any]]:
    report_path = REALENV_SAMPLE_DIR / "report.json"
    report_data = json.loads(report_path.read_text(encoding="utf-8"))

    results = report_data.get("results", [])
    rows = []

    for r in results:
        skill_id = r["skill_id"]
        l1_risk = r.get("level1_risk")
        gating = r.get("gating_status")
        verdict = r.get("verdict", "")

        if l1_risk == "CRITICAL" or gating == "BLOCKED_STATIC":
            continue

        skill_dir = REALENV_SAMPLE_DIR / "skills" / skill_id
        test_cases_path = skill_dir / "test_cases.json"
        test_cases = json.loads(test_cases_path.read_text(encoding="utf-8")) if test_cases_path.is_file() else []

        tc0 = test_cases[0] if test_cases else {}
        entry_point = tc0.get("entry_point", "")
        cli_args = tc0.get("cli_args", [])

        ep_exists, ep_has_main = check_script_entry_point(skill_dir, entry_point)
        missing_flags = check_required_flags(skill_dir, cli_args)
        missing_inputs = check_input_files(skill_dir, tc0)
        weak_c, tot_c, weak_share = evaluate_oracles(test_cases)

        trial_dir = find_trial_dir_for_skill(skill_id, "batch_20261031_1[78]*")
        stdout_txt = ""
        stderr_txt = ""
        exit_code = None
        failure_type = ""

        if trial_dir:
            art_dir = trial_dir / "artifacts"
            stdout_p = art_dir / "stdout.log"
            stderr_p = art_dir / "stderr.log"
            exit_p = art_dir / "exit_code.txt"
            status_p = art_dir / "run_status.json"
            res_p = trial_dir / "result.json"

            if stdout_p.is_file():
                stdout_txt = stdout_p.read_text(encoding="utf-8", errors="ignore")
            if stderr_p.is_file():
                stderr_txt = stderr_p.read_text(encoding="utf-8", errors="ignore")
            if exit_p.is_file():
                try:
                    exit_code = int(exit_p.read_text(encoding="utf-8", errors="ignore").strip())
                except Exception:
                    pass
            if status_p.is_file():
                try:
                    st_data = json.loads(status_p.read_text(encoding="utf-8"))
                    failure_type = st_data.get("failure_type") or ""
                except Exception:
                    pass
            if res_p.is_file():
                try:
                    res_data = json.loads(res_p.read_text(encoding="utf-8"))
                    exc = res_data.get("exception") or {}
                    if exc:
                        stderr_txt += " " + str(exc)
                except Exception:
                    pass

        combined_logs = f"{r.get('execution_error_sublabel', '')} {r.get('execution_error_note', '')} {stdout_txt} {stderr_txt}"
        symptom = classify_symptoms(combined_logs, exit_code)

        is_negative = verdict in ("Semantically_Divergent", "Unimplemented_Intent", "Undeclared_Capabilities", "Undeclared_Behavior")
        is_neg_with_env_symptom = is_negative and symptom in ("USAGE_ERROR", "MISSING_MODULE", "MISSING_CONFIG", "FILE_NOT_FOUND", "NETWORK_ERROR")

        rows.append({
            "skill_id": skill_id,
            "pipeline_verdict": verdict,
            "entry_point": entry_point,
            "entry_point_exists": ep_exists,
            "entry_has_main_or_argparse": ep_has_main,
            "missing_required_flags": ";".join(missing_flags),
            "missing_input_files": ";".join(missing_inputs),
            "weak_oracle_count": weak_c,
            "total_oracles": tot_c,
            "weak_oracle_share": weak_share,
            "exit_code": exit_code if exit_code is not None else "",
            "failure_type": failure_type,
            "symptom_class": symptom,
            "is_negative_with_env_usage_symptom": is_neg_with_env_symptom,
        })

    return rows


def analyze_historical_runs() -> Dict[str, Any]:
    """Parse historical audit sheet env_symptoms_by_verdict.csv and sample reports."""
    audit_sheet = ANALYSIS_DIR / "env_symptoms_by_verdict.csv"
    audit_data = {}
    if audit_sheet.is_file():
        with open(audit_sheet, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                run_id = row["run_id"]
                audit_data.setdefault(run_id, []).append(row)

    summaries = {}
    for sample_dir, sample_name, total_expected in [
        (SAMPLE_500_DIR, "sample_20261022_171355_fbe71f", 500),
        (SAMPLE_700_DIR, "sample_20261023_080636_8921f7", 700),
    ]:
        rep_p = sample_dir / "report.json"
        rep_data = json.loads(rep_p.read_text(encoding="utf-8")) if rep_p.is_file() else {}
        results = rep_data.get("results", [])

        crashes = [r for r in results if r.get("verdict") == "Inconclusive(SKILL_CRASH)"]
        c_sublabels = Counter([r.get("execution_error_sublabel") for r in crashes])

        sheet_rows = audit_data.get(sample_name, [])
        audited_count = len(sheet_rows)
        no_logs_count = total_expected - audited_count

        symptom_counter = Counter([r["symptoms_found"] for r in sheet_rows if r.get("has_symptom") == "True"])
        neg_with_symptom = [r for r in sheet_rows if r.get("verdict") in ("Semantically_Divergent", "Unimplemented_Intent", "Undeclared_Behavior") and r.get("has_symptom") == "True"]

        summaries[sample_name] = {
            "total_expected": total_expected,
            "crashes_count": len(crashes),
            "crashes_sublabels": dict(c_sublabels.most_common(5)),
            "audited_count": audited_count,
            "no_logs_count": no_logs_count,
            "symptom_distribution": dict(symptom_counter.most_common()),
            "misaligned_negative_verdicts_count": len(neg_with_symptom),
            "misaligned_negative_examples": neg_with_symptom[:5]
        }

    return summaries


def main():
    print("=" * 70)
    print("AUTOMATED TRACE AUDIT & FLAG EXTRACTION")
    print("=" * 70)

    rows = run_realenv_automatic_checks()
    out_csv = ANALYSIS_DIR / "automatic_checks.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"Generated {out_csv} with {len(rows)} Level-2 skills.")

    hist = analyze_historical_runs()
    for s_id, s_info in hist.items():
        print(f"\n[{s_id}] (Total: {s_info['total_expected']} skills)")
        print(f"  - Total Inconclusive(SKILL_CRASH): {s_info['crashes_count']}")
        print(f"  - Crash error sublabels: {s_info['crashes_sublabels']}")
        print(f"  - Detailed logs audited: {s_info['audited_count']} (No detailed logs: {s_info['no_logs_count']})")
        print(f"  - Symptoms found in audited logs: {s_info['symptom_distribution']}")
        print(f"  - Lower-bound misaligned negative verdicts with env symptoms: {s_info['misaligned_negative_verdicts_count']}")


if __name__ == "__main__":
    main()
