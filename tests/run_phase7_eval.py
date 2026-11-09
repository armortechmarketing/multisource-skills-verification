import os
import sys
import json
import time

sys.path.insert(0, ".")
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["PYTHONUTF8"] = "1"
os.environ["EXEC_BACKEND"] = "harbor"
os.environ["AUTO_INSTALL_DEPS"] = "true"

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from src.preflight import run_preflight
from src.pipeline_runner import execute_manifest_pipeline

def run_evaluation(manifest_path: str, run_label: str = "Evaluation"):
    print("=" * 80, flush=True)
    print(f"STARTING {run_label.upper()} ON REAL HARBOR (DOCKER LINUX)", flush=True)
    print(f"Manifest: {manifest_path}", flush=True)
    print("=" * 80, flush=True)

    # 1. Run Preflight
    print("[1/3] Running preflight checks...", flush=True)
    run_preflight()
    print("Preflight passed.\n", flush=True)

    # 2. Progress callback
    def on_start(idx, total, skill_id):
        print(f"[{idx:02d}/{total:02d}] Executing skill: {skill_id}...", flush=True)

    def on_complete(idx, total, result):
        sid = result.get("skill_id")
        l1 = result.get("level1_risk")
        gating = result.get("gating_status")
        verdict = result.get("verdict")
        backend = result.get("backend")
        v_paper = result.get("valid_for_paper")
        cov = result.get("coverage_score", 0.0)
        print(f"[{idx:02d}/{total:02d}] DONE {sid[:35]:<35} | L1={l1:<8} | Gate={gating:<22} | Verdict={str(verdict):<20} | Cov={cov:.2f} | Backend={backend} | Valid={v_paper}", flush=True)

    # 3. Execute Manifest
    print(f"[2/3] Executing pipeline across skills in {manifest_path}...", flush=True)
    t0 = time.time()
    report = execute_manifest_pipeline(
        manifest_path=manifest_path,
        force_refresh=True,
        resume=False,
        on_skill_start=on_start,
        on_skill_complete=on_complete
    )
    t1 = time.time()

    # 4. Print Summary
    print("\n" + "=" * 80)
    print(f"RUN SUMMARY FOR {run_label}")
    print("=" * 80)
    print(f"Total skills: {report.get('total_skills')}")
    print(f"Execution time: {t1 - t0:.2f}s")
    print(f"Gating distribution: {json.dumps(report.get('gating_status_distribution'), indent=2)}")
    print(f"Run status distribution: {json.dumps(report.get('run_status_distribution'), indent=2)}")
    print(f"Verdict distribution: {json.dumps(report.get('verdict_distribution'), indent=2)}")
    print(f"Average coverage: {report.get('average_coverage_score', 0.0):.3f}")
    
    # Compute Success Criteria:
    results = report.get("results", [])
    non_blocked = [r for r in results if r.get("gating_status") != "SKIPPED_LEVEL1_CRITICAL"]
    succeeded_exec = [r for r in non_blocked if r.get("run_status") == "INVOKED_SUCCEEDED"]
    exec_rate = (len(succeeded_exec) / len(non_blocked)) * 100 if non_blocked else 0.0
    
    # Unproven Aligned on crashed skills:
    crashed_skills = [r for r in results if r.get("run_status") in ["INVOKED_FAILED", "INFRA_FAILURE"]]
    unproven_aligned = [r for r in crashed_skills if r.get("verdict") == "Aligned" or r.get("level2_verdict") == "Aligned"]
    
    # False positive rate on benign skills:
    benign_skills = [r for r in results if not r.get("known_malicious")]
    benign_fp = [r for r in benign_skills if r.get("verdict") == "Undeclared_Behavior" or r.get("level2_verdict") == "Undeclared_Behavior"]
    benign_fp_rate = (len(benign_fp) / len(benign_skills)) * 100 if benign_skills else 0.0
    
    print("\nSUCCESS CRITERIA CHECK:")
    print(f"1. Execution rate of non-blocked skills: {exec_rate:.1f}% ({len(succeeded_exec)}/{len(non_blocked)}) [Target: >= 70%]")
    print(f"2. Unproven Aligned on crashed skills: {len(unproven_aligned)} [Target: 0]")
    print(f"3. Benign False Positive Rate: {benign_fp_rate:.1f}% ({len(benign_fp)}/{len(benign_skills)}) [Target: <= 10%]")
    
    # mal_Implementing_Database_Caching check:
    mal_cache = next((r for r in results if "Implementing_Database_Caching" in r.get("skill_id", "")), None)
    if mal_cache:
        print(f"4. mal_Implementing_Database_Caching verdict: {mal_cache.get('verdict')} (L2={mal_cache.get('level2_verdict')}, Gate={mal_cache.get('gating_status')}) [Target: NOT Aligned]")
    
    return report

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "dynamic_samples/sample_20261003_121603_f2d12e/manifest.json"
    label = sys.argv[2] if len(sys.argv) > 2 else "sample_20261003_121603_f2d12e"
    run_evaluation(target, label)
