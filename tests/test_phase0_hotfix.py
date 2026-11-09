import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import json
import unittest
from unittest.mock import patch, MagicMock

# Import pipeline runner
from src.pipeline_runner import execute_manifest_pipeline

class TestPhase0VerdictLeak(unittest.TestCase):
    def test_verdict_leakage_and_unbound_local(self):
        """
        Sequence:
        1. CRITICAL skill (Level-1 CRITICAL)
        2. Benign Aligned skill (Level-1 LOW, run_status INVOKED_SUCCEEDED, predicted_label Aligned)
        3. Benign Crashed skill (Level-1 LOW, run_status INVOKED_FAILED, predicted_label Partially_Executed)
        4. Skill that raises Exception during run_skill
        """
        skills = [
            {"skill_id": "skill_1_critical", "domain": "security", "known_malicious": True},
            {"skill_id": "skill_2_aligned", "domain": "data_processing", "known_malicious": False},
            {"skill_id": "skill_3_crashed", "domain": "data_processing", "known_malicious": False},
            {"skill_id": "skill_4_raises", "domain": "data_processing", "known_malicious": False},
        ]
        manifest_data = {"run_id": "test_run", "skills": skills}
        manifest_path = "research_sandbox/test_p0_manifest.json"
        os.makedirs("research_sandbox", exist_ok=True)
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f)

        def mock_run_skill(s_id, manifest_file=None, force_refresh=False):
            if s_id == "skill_1_critical":
                return {
                    "level1_report": {"risk_level": "CRITICAL", "reason": "Hardcoded backdoor found."},
                    "gating_status": "SKIPPED_LEVEL1_CRITICAL",
                    "run_status": "NOT_INVOKED",
                    "prediction": {}
                }
            elif s_id == "skill_2_aligned":
                return {
                    "level1_report": {"risk_level": "LOW", "reason": "Clean."},
                    "gating_status": "INVOKED",
                    "run_status": "INVOKED_SUCCEEDED",
                    "prediction": {"predicted_label": "Aligned", "contract_verdicts": []}
                }
            elif s_id == "skill_3_crashed":
                return {
                    "level1_report": {"risk_level": "LOW", "reason": "Clean."},
                    "gating_status": "INVOKED",
                    "run_status": "INVOKED_FAILED",
                    "prediction": {"predicted_label": "Partially_Executed", "execution_error_sublabel": "crash"}
                }
            elif s_id == "skill_4_raises":
                raise RuntimeError("Unexpected pipeline crash during skill execution")

        with patch("tests.controls.test_calibration_controls.run_calibration_controls", return_value=True), \
             patch("src.pipeline_runner.run_skill", side_effect=mock_run_skill):
            
            report = execute_manifest_pipeline(manifest_path, output_report_path="research_sandbox/test_p0_out.json", resume=False)
            
            # Check results
            res = report["results"]
            self.assertEqual(len(res), 4)
            
            # Skill 1 must be Blocked_Static_CRITICAL
            self.assertEqual(res[0]["verdict"], "Blocked_Static_CRITICAL")
            
            # Skill 2 MUST be Aligned, NOT Blocked_Static_CRITICAL!
            self.assertEqual(res[1]["verdict"], "Aligned", f"Skill 2 verdict leaked: {res[1]['verdict']}")
            
            # Skill 3 MUST be Partially_Executed
            self.assertEqual(res[2]["verdict"], "Partially_Executed", f"Skill 3 verdict leaked: {res[2]['verdict']}")
            
            # Skill 4 was an exception
            self.assertIn(res[3]["verdict"], [None, "ERROR"])
            
            # Distribution must sum to 4
            self.assertEqual(sum(report["verdict_distribution"].values()), 4)

if __name__ == "__main__":
    unittest.main()
