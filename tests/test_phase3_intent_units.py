import os
import sys
import json
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.a_syn_contract_synthesizer import normalize_intent_unit, synthesize_contracts_with_security

TEST_SKILLS = [
    {
        "id": "benign_repo-learning-kit",
        "path": "dynamic_samples/sample_20261008_204736_fd8a31/skills/benign_repo-learning-kit"
    },
    {
        "id": "benign_kit",
        "path": "dynamic_samples/sample_20261008_204736_fd8a31/skills/benign_kit"
    },
    {
        "id": "benign_exmail-io",
        "path": "dynamic_samples/sample_20261008_204736_fd8a31/skills/benign_exmail-io"
    },
    {
        "id": "benign_job-tracker",
        "path": "dynamic_samples/sample_20261008_204736_fd8a31/skills/benign_job-tracker"
    },
    {
        "id": "benign_x",
        "path": "dynamic_samples/sample_20261007_202014_4a8104/skills/benign_x"
    }
]

def main():
    print("=== PHASE 3: INTENT UNITS (A_syn) VERIFICATION ===")
    
    for item in TEST_SKILLS:
        skill_id = item["id"]
        skill_dir = os.path.abspath(item["path"])
        contracts_file = os.path.join(skill_dir, "contracts.json")
        skill_md_file = os.path.join(skill_dir, "SKILL.md")
        
        # Load existing contracts if present, or synthesize
        raw_contracts = []
        if os.path.exists(contracts_file):
            with open(contracts_file, "r", encoding="utf-8") as f:
                cdata = json.load(f)
                raw_contracts = cdata.get("contracts", []) if isinstance(cdata, dict) else cdata
                
        if not raw_contracts:
            decl_text = Path(skill_md_file).read_text(encoding="utf-8", errors="ignore") if os.path.exists(skill_md_file) else ""
            raw_contracts, _ = synthesize_contracts_with_security(skill_dir, skill_id, api_key="", declaration_text=decl_text)
            
        intent_units = [normalize_intent_unit(c, skill_id) for c in raw_contracts]
        
        print(f"\n--- Skill: {skill_id} ({len(intent_units)} units) ---")
        for u in intent_units:
            assert "id" in u, f"Missing id in {u}"
            assert "source_line" in u, f"Missing source_line in {u}"
            assert "SKILL.md" in u["source_line"], f"source_line does not cite SKILL.md: {u['source_line']}"
            assert "capability" in u, f"Missing capability in {u}"
            assert "inputs" in u, f"Missing inputs in {u}"
            assert "expected_effects" in u, f"Missing expected_effects in {u}"
            assert "expected_outcome" in u, f"Missing expected_outcome in {u}"
            assert "allowed_resources" in u, f"Missing allowed_resources in {u}"
            assert "forbidden" in u, f"Missing forbidden in {u}"
            
            print(f"  Unit [{u['id']}] from {u['source_line']}")
            print(f"    Capability: {u['capability']}")
            print(f"    Effects: {len(u['expected_effects'])} effects ({[e.get('kind') for e in u['expected_effects']]})")
            print(f"    Outcome: {u['expected_outcome']['description'][:70]}... (check={u['expected_outcome']['check']})")
            print(f"    Frame: {u['allowed_resources']}")
            
    print("\nPhase 3 Check PASSED: All units have valid Intent Unit schema and cite SKILL.md lines.")

if __name__ == "__main__":
    main()
