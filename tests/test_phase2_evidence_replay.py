import os
import sys
import json
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.a_adj_adjudicator import evaluate_symbolic_findings, extract_declared_hosts_from_skill
from src.telemetry_parser import detect_canary_content_exfiltration

SAMPLE_DIR = "dynamic_samples/sample_20261007_202014_4a8104/skills"
TARGET_SKILLS = [
    "benign_x",
    "benign_senior-architect",
    "benign_game-voice-content-inspiration",
    "benign_trace",
    "benign_strategic-planning-manager",
    "benign_alpha-insights",
    "benign_session-handoff",
    "benign_next-bundle-analyzer",
    "mal_V3_Security_Overhaul_MIXED_B8",
    "mal_3d-games_CI_B2"
]

def main():
    print("=== PHASE 2: OFFLINE EVIDENCE REPLAY OF 10 AUDITED SKILLS ===")
    
    for skill_name in TARGET_SKILLS:
        skill_dir = os.path.join(SAMPLE_DIR, skill_name)
        trace_file = os.path.join(skill_dir, "trace.jsonl")
        contracts_file = os.path.join(skill_dir, "contracts.json")
        skill_md = os.path.join(skill_dir, "SKILL.md")
        
        contracts = []
        if os.path.exists(contracts_file):
            try:
                with open(contracts_file, "r", encoding="utf-8") as f:
                    cdata = json.load(f)
                    contracts = cdata.get("contracts", []) if isinstance(cdata, dict) else cdata
            except Exception:
                pass
                
        declared_hosts = extract_declared_hosts_from_skill(skill_dir, contracts)
        
        raw_events = []
        if os.path.exists(trace_file):
            with open(trace_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        raw_events.append(json.loads(line))
                        
        # 1. Before: Evaluate with old raw events (which included canaries.json false positives)
        before_actionable, _ = evaluate_symbolic_findings(raw_events, declared_hosts)
        before_types = [a.get("type") for a in before_actionable]
        
        # 2. After: Re-evaluate filtering out harness-owned artifacts from exfiltration detection
        filtered_events = []
        for ev in raw_events:
            if ev.get("event_type") == "confirmed_exfil":
                det = ev.get("details", {})
                evidence_text = str(det.get("evidence", "")) + str(det.get("file", ""))
                if "canaries.json" in evidence_text or "manifest.json" in evidence_text:
                    continue  # Filtered by HARNESS_OWNED_FILES fix
            filtered_events.append(ev)
            
        after_actionable, after_ignored = evaluate_symbolic_findings(filtered_events, declared_hosts)
        after_types = [a.get("type") for a in after_actionable]
        
        print(f"\n--- Skill: {skill_name} ---")
        print(f"Declared Hosts: {declared_hosts}")
        print(f"BEFORE Units: {before_types} -> Actionable Findings: {len(before_actionable)}")
        print(f"AFTER  Units: {after_types} -> Actionable Findings: {len(after_actionable)}")
        if after_actionable:
            for act in after_actionable:
                print(f"  [ACTIONABLE] {act.get('type')} ({act.get('severity')}): {act.get('detail')}")

if __name__ == "__main__":
    main()
