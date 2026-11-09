import time
import os
import sys

sys.path.append(os.path.abspath("."))
from src.agents.dynamic_agent_skill_fetch import dynamic_agent_skill_fetch
from src.pipeline_runner import execute_manifest_pipeline

print("=== 1. FETCHING SAMPLE N=10 (5 Benign / 5 Malicious) ===")
sample = dynamic_agent_skill_fetch.fetch_sample(total_count=10, benign_ratio=0.5, seed=123)
print("Run ID:", sample["run_id"])
print("Total skills fetched:", sample["total_skills"])
print("Benign count:", sample["benign_count"])
print("Malicious count:", sample["malicious_count"])
print("Manifest path:", sample["manifest_path"])

print("\n=== 2. RUNNING MULTI-AGENT VERIFICATION PIPELINE ON DYNAMIC SAMPLE ===")
t0 = time.time()
def progress_cb(curr, total, skill_res):
    sid = skill_res["skill_id"]
    l1 = skill_res["level1_risk"]
    v = skill_res.get("verdict") or skill_res.get("gating_status")
    print(f"[{curr:2d}/{total:2d}] {sid} -> L1:{l1} | Verdict:{v}")

report = execute_manifest_pipeline(
    manifest_path=sample["manifest_path"],
    on_skill_complete=progress_cb
)
elapsed = time.time() - t0
print("\n=== 3. SMOKE TEST RESULTS ===")
print("Total skills processed:", report["total_skills"])
print("Blocked at Level-1:", report["blocked_static_count"])
print("Proceeded to Level-2:", report["proceeded_to_level2"])
print("Verdict Distribution:", report["verdict_distribution"])
print("Gating Status Distribution:", report["gating_status_distribution"])
print("Total Elapsed Time:", round(elapsed, 2), "s")
if report["total_skills"] > 0:
    print("Avg Time per Skill:", round(elapsed / report["total_skills"], 2), "s")
