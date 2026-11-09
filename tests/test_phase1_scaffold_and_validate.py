import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import json
import tomllib
from pathlib import Path
from harbor.models.task.config import TaskConfig
from src.adapters.skills_adapter import SkillHarborAdapter, validate_task_toml_schema
from src.harbor_runner import execute_harbor_trial

AUDITED_SKILLS = [
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
    },
    {
        "id": "benign_acp",
        "path": "harbor_tasks/benign_acp/environment/skill_package"
    },
    {
        "id": "mal_airflow-dag-patterns_CI_B8",
        "path": "dynamic_samples/sample_20261008_204736_fd8a31/skills/mal_airflow-dag-patterns_CI_B8"
    }
]

def main():
    adapter = SkillHarborAdapter(base_output_dir="harbor_tasks")
    print("=== PHASE 1: SCAFFOLD & SCHEMA VALIDATION ===")
    
    scaffolded_tasks = {}
    for item in AUDITED_SKILLS:
        skill_id = item["id"]
        skill_dir = os.path.abspath(item["path"])
        
        skill_md_path = os.path.join(skill_dir, "SKILL.md")
        decl_text = Path(skill_md_path).read_text(encoding="utf-8", errors="ignore") if os.path.exists(skill_md_path) else ""
        
        contracts_path = os.path.join(skill_dir, "contracts.json")
        contracts = []
        if os.path.exists(contracts_path):
            try:
                with open(contracts_path, "r", encoding="utf-8") as f:
                    contracts = json.load(f)
            except Exception:
                pass
                
        test_cases_path = os.path.join(skill_dir, "test_cases.json")
        test_cases = []
        if os.path.exists(test_cases_path):
            try:
                with open(test_cases_path, "r", encoding="utf-8") as f:
                    test_cases = json.load(f)
            except Exception:
                pass
                
        task_dir = adapter.scaffold_task(
            skill_id=skill_id,
            skill_dir=skill_dir,
            declaration_text=decl_text,
            contracts=contracts
        )
        
        task_toml_path = os.path.join(task_dir, "task.toml")
        task_toml_content = Path(task_toml_path).read_text(encoding="utf-8")
        
        # Harbor 0.23.0 TaskConfig validation
        parsed_toml = tomllib.loads(task_toml_content)
        validated_config = TaskConfig.model_validate(parsed_toml)
        
        print(f"\n--- SKILL: {skill_id} ---")
        print(f"Task Directory: {task_dir}")
        print("Validation: PASSED (TaskConfig valid)")
        print(f"Task Config: schema_version={validated_config.schema_version}, artifacts={len(validated_config.artifacts or [])}")
        print("task.toml:\n" + task_toml_content.strip())
        
        scaffolded_tasks[skill_id] = {
            "task_dir": task_dir,
            "skill_dir": skill_dir,
            "test_cases": test_cases,
            "contracts": contracts
        }
        
    print("\nAll 7 skills scaffolded and validated successfully against Harbor 0.23.0 schema.")

if __name__ == "__main__":
    main()
