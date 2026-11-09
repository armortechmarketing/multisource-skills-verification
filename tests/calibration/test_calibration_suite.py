import os
import sys
import unittest
from typing import List, Dict, Any

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath("."))

from src.unit_adjudicator import adjudicate_intent_execution, label_skill_behavior

class TestLevel2CalibrationSuite(unittest.TestCase):
    """
    Phase 9 Calibration Suite: 12 comprehensive unit tests covering
    every target model decision boundary and priority level.
    """

    def test_01_clean_benign_fully_aligned(self):
        """Case 1: Clean benign fully aligned -> Aligned"""
        intent = [{
            "id": "I_01",
            "source_line": "SKILL.md:Line 10",
            "capability": "write+output",
            "inputs": "data input",
            "expected_effects": [{"kind": "file_write", "target_pattern": "output.json"}],
            "expected_outcome": {"description": "Writes output.json", "check": None},
            "allowed_resources": ["write: output.json"],
            "forbidden": ["network_egress: true"]
        }]
        exec_units = [{
            "id": "B_01",
            "kind": "FILE_WRITE",
            "target": "output.json",
            "summary": "File write to output.json",
            "pid": 12,
            "ts": 1000.0,
            "evidence_ref": "fs_after.json: output.json",
            "facts": {"size_bytes": 1024}
        }]
        res = adjudicate_intent_execution(
            intent_units=intent,
            execution_units=exec_units,
            run_status="INVOKED_SUCCEEDED",
            entry_reached=True,
            exit_code=0
        )
        self.assertEqual(res["label"], "Aligned")
        self.assertEqual(res["exec_status"], "FULL")
        self.assertEqual(res["coverage"], 1.0)
        self.assertEqual(len(res["matches"]), 1)

    def test_02_partial_exit_no_violations(self):
        """Case 2: Partial non-zero exit with no violations -> Partially_Executed"""
        intent = [
            {
                "id": "I_01",
                "source_line": "SKILL.md:Line 5",
                "capability": "write+output",
                "inputs": "",
                "expected_effects": [{"kind": "file_write", "target_pattern": "output.json"}],
                "expected_outcome": {"description": "Writes output.json", "check": None},
                "allowed_resources": ["write: output.json"],
                "forbidden": []
            },
            {
                "id": "I_02",
                "source_line": "SKILL.md:Line 12",
                "capability": "write+audit_log",
                "inputs": "",
                "expected_effects": [{"kind": "file_write", "target_pattern": "audit.log"}],
                "expected_outcome": {"description": "Writes audit.log", "check": None},
                "allowed_resources": ["write: audit.log"],
                "forbidden": []
            }
        ]
        exec_units = [{
            "id": "B_01",
            "kind": "FILE_WRITE",
            "target": "output.json",
            "summary": "File write to output.json",
            "pid": 20,
            "ts": 1000.0,
            "evidence_ref": "strace.log:10",
            "facts": {}
        }]
        res = adjudicate_intent_execution(
            intent_units=intent,
            execution_units=exec_units,
            run_status="INVOKED_FAILED",
            entry_reached=True,
            exit_code=1
        )
        self.assertEqual(res["label"], "Partially_Executed")
        self.assertEqual(res["exec_status"], "PARTIAL")
        self.assertEqual(res["coverage"], 0.5)

    def test_03_partial_exit_with_violation(self):
        """Case 3: Partial exit with violation -> Undeclared_Behavior"""
        intent = [{
            "id": "I_01",
            "source_line": "SKILL.md:Line 5",
            "capability": "write+data",
            "inputs": "",
            "expected_effects": [{"kind": "file_write", "target_pattern": "data.csv"}],
            "expected_outcome": {"description": "Writes data.csv", "check": None},
            "allowed_resources": ["write: data.csv", "network: none"],
            "forbidden": ["network_egress: true"]
        }]
        exec_units = [
            {
                "id": "B_01",
                "kind": "FILE_WRITE",
                "target": "data.csv",
                "summary": "Write data.csv",
                "pid": 30,
                "ts": 1000.0,
                "evidence_ref": "strace.log:20",
                "facts": {}
            },
            {
                "id": "B_02",
                "kind": "NET",
                "target": "evil-c2.com",
                "summary": "Outbound connect to evil-c2.com",
                "pid": 30,
                "ts": 1001.0,
                "evidence_ref": "strace.log:35",
                "facts": {}
            }
        ]
        res = adjudicate_intent_execution(
            intent_units=intent,
            execution_units=exec_units,
            run_status="INVOKED_FAILED",
            entry_reached=True,
            exit_code=1
        )
        self.assertEqual(res["label"], "Undeclared_Behavior")
        self.assertEqual(res["exec_status"], "PARTIAL")

    def test_04_undeclared_network_host(self):
        """Case 4: Undeclared network host -> Undeclared_Behavior"""
        intent = [{
            "id": "I_01",
            "source_line": "SKILL.md:Line 8",
            "capability": "fetch+data",
            "inputs": "",
            "expected_effects": [{"kind": "net", "target_pattern": "api.github.com"}],
            "expected_outcome": {"description": "Fetches from GitHub", "check": None},
            "allowed_resources": ["network: api.github.com"],
            "forbidden": []
        }]
        exec_units = [{
            "id": "B_01",
            "kind": "NET",
            "target": "unauthorized-tracker.io",
            "summary": "Connection to unauthorized-tracker.io",
            "pid": 40,
            "ts": 1000.0,
            "evidence_ref": "mock_egress.jsonl:1",
            "facts": {}
        }]
        res = adjudicate_intent_execution(
            intent_units=intent,
            execution_units=exec_units,
            run_status="INVOKED_SUCCEEDED",
            entry_reached=True,
            exit_code=0
        )
        self.assertEqual(res["label"], "Undeclared_Behavior")

    def test_05_persistence_write(self):
        """Case 5: Persistence write -> Undeclared_Behavior"""
        intent = [{
            "id": "I_01",
            "source_line": "SKILL.md:Line 10",
            "capability": "setup+tools",
            "inputs": "",
            "expected_effects": [{"kind": "file_write", "target_pattern": "config.yaml"}],
            "expected_outcome": {"description": "Writes config.yaml", "check": None},
            "allowed_resources": ["write: config.yaml"],
            "forbidden": ["write: /root/.bashrc"]
        }]
        exec_units = [{
            "id": "B_01",
            "kind": "PERSIST",
            "target": "/root/.bashrc",
            "summary": "Persistence write to /root/.bashrc",
            "pid": 50,
            "ts": 1000.0,
            "evidence_ref": "strace.log:120",
            "facts": {"is_persistence": True}
        }]
        res = adjudicate_intent_execution(
            intent_units=intent,
            execution_units=exec_units,
            run_status="INVOKED_SUCCEEDED",
            entry_reached=True,
            exit_code=0
        )
        self.assertEqual(res["label"], "Undeclared_Behavior")

    def test_06_canary_exfiltration(self):
        """Case 6: Canary exfiltration -> Undeclared_Behavior"""
        intent = [{
            "id": "I_01",
            "source_line": "SKILL.md:Line 4",
            "capability": "process+job",
            "inputs": "",
            "expected_effects": [],
            "expected_outcome": {"description": "Processes job", "check": None},
            "allowed_resources": ["read: job.txt"],
            "forbidden": ["network_egress: true"]
        }]
        exec_units = [{
            "id": "B_01",
            "kind": "NET",
            "target": "CANARY_TOKEN_XYZ",
            "summary": "Canary exfiltration detected via mock_egress",
            "pid": 60,
            "ts": 1000.0,
            "evidence_ref": "mock_egress.jsonl:2",
            "facts": {"token": "CANARY_TOKEN_XYZ"}
        }]
        res = adjudicate_intent_execution(
            intent_units=intent,
            execution_units=exec_units,
            run_status="INVOKED_SUCCEEDED",
            entry_reached=True,
            exit_code=0
        )
        self.assertEqual(res["label"], "Undeclared_Behavior")

    def test_07_measurable_check_failure(self):
        """Case 7: Measurable check failure -> Semantically_Divergent"""
        intent = [{
            "id": "I_01",
            "source_line": "SKILL.md:Line 15",
            "capability": "generate+report",
            "inputs": "",
            "expected_effects": [{"kind": "file_write", "target_pattern": "report.json"}],
            "expected_outcome": {
                "description": "Generates report.json with 10 rows",
                "check": {"type": "row_count", "spec": {"count": 10}}
            },
            "allowed_resources": ["write: report.json"],
            "forbidden": []
        }]
        exec_units = [{
            "id": "B_01",
            "kind": "FILE_WRITE",
            "target": "report.json",
            "summary": "Writes report.json",
            "pid": 70,
            "ts": 1000.0,
            "evidence_ref": "fs_after.json: report.json",
            "facts": {}
        }]
        assertions = [{
            "unit_id": "I_01",
            "passed": False,
            "observed": 0,
            "expected": 10
        }]
        res = adjudicate_intent_execution(
            intent_units=intent,
            execution_units=exec_units,
            run_status="INVOKED_SUCCEEDED",
            entry_reached=True,
            exit_code=0,
            assertion_results=assertions
        )
        self.assertEqual(res["label"], "Semantically_Divergent")

    def test_08_full_exit_missing_intent(self):
        """Case 8: Full exit with missing intent -> Unimplemented_Intent"""
        intent = [
            {
                "id": "I_01",
                "source_line": "SKILL.md:Line 5",
                "capability": "write+step1",
                "inputs": "",
                "expected_effects": [{"kind": "file_write", "target_pattern": "step1.txt"}],
                "expected_outcome": {"description": "Writes step1.txt", "check": None},
                "allowed_resources": ["write: step1.txt"],
                "forbidden": []
            },
            {
                "id": "I_02",
                "source_line": "SKILL.md:Line 20",
                "capability": "write+step2",
                "inputs": "",
                "expected_effects": [{"kind": "file_write", "target_pattern": "step2.txt"}],
                "expected_outcome": {"description": "Writes step2.txt", "check": None},
                "allowed_resources": ["write: step2.txt"],
                "forbidden": []
            }
        ]
        # Only step1 was executed
        exec_units = [{
            "id": "B_01",
            "kind": "FILE_WRITE",
            "target": "step1.txt",
            "summary": "Writes step1.txt",
            "pid": 80,
            "ts": 1000.0,
            "evidence_ref": "strace.log:5",
            "facts": {}
        }]
        res = adjudicate_intent_execution(
            intent_units=intent,
            execution_units=exec_units,
            run_status="INVOKED_SUCCEEDED",
            entry_reached=True,
            exit_code=0
        )
        self.assertEqual(res["label"], "Unimplemented_Intent")
        self.assertEqual(len(res["gaps"]), 1)
        self.assertEqual(res["gaps"][0]["id"], "I_02")

    def test_09_stub_script(self):
        """Case 9: Stub script -> Unimplemented_Intent"""
        intent = [{
            "id": "I_01",
            "source_line": "SKILL.md:Line 3",
            "capability": "execute+stub",
            "inputs": "",
            "expected_effects": [{"kind": "file_write", "target_pattern": "res.txt"}],
            "expected_outcome": {"description": "Generates res.txt", "check": None},
            "allowed_resources": ["write: res.txt"],
            "forbidden": []
        }]
        res = adjudicate_intent_execution(
            intent_units=intent,
            execution_units=[],
            run_status="INVOKED_SUCCEEDED",
            entry_reached=True,
            exit_code=0,
            is_stub=True
        )
        self.assertEqual(res["label"], "Unimplemented_Intent")

    def test_10_harness_failure_bad_args(self):
        """Case 10: Harness failure (bad_args) -> Not_Executed(HARNESS)"""
        intent = [{
            "id": "I_01",
            "source_line": "SKILL.md:Line 1",
            "capability": "run+cli",
            "inputs": "",
            "expected_effects": [],
            "expected_outcome": {"description": "Runs CLI", "check": None},
            "allowed_resources": [],
            "forbidden": []
        }]
        res = adjudicate_intent_execution(
            intent_units=intent,
            execution_units=[],
            run_status="INVOKED_FAILED",
            entry_reached=True,
            exit_code=2,
            failure_type="bad_args"
        )
        self.assertEqual(res["label"], "Not_Executed(HARNESS)")
        self.assertEqual(res["exec_status"], "NONE")
        self.assertTrue(res["needs_rerun"])

    def test_11_infra_failure_timeout(self):
        """Case 11: Infra failure (Timeout) -> Not_Executed(INFRA)"""
        intent = [{
            "id": "I_01",
            "source_line": "SKILL.md:Line 1",
            "capability": "run+task",
            "inputs": "",
            "expected_effects": [],
            "expected_outcome": {"description": "Runs task", "check": None},
            "allowed_resources": [],
            "forbidden": []
        }]
        res = adjudicate_intent_execution(
            intent_units=intent,
            execution_units=[],
            run_status="INFRA_FAILURE",
            entry_reached=False,
            failure_type="Timeout"
        )
        self.assertEqual(res["label"], "Not_Executed(INFRA)")
        self.assertEqual(res["exec_status"], "NONE")
        self.assertTrue(res["needs_rerun"])

    def test_12_level1_critical(self):
        """Case 12: Level-1 CRITICAL -> Blocked_Static_CRITICAL"""
        intent = [{
            "id": "I_01",
            "source_line": "SKILL.md:Line 1",
            "capability": "exploit+shell",
            "inputs": "",
            "expected_effects": [],
            "expected_outcome": {"description": "Exploit payload", "check": None},
            "allowed_resources": [],
            "forbidden": []
        }]
        res = adjudicate_intent_execution(
            intent_units=intent,
            execution_units=[],
            level1_risk="CRITICAL",
            run_status="NOT_INVOKED",
            entry_reached=False
        )
        self.assertEqual(res["label"], "Blocked_Static_CRITICAL")
        self.assertFalse(res["needs_rerun"])

def run_calibration_suite():
    suite = unittest.TestLoader().loadTestsFromTestCase(TestLevel2CalibrationSuite)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print("\n" + "="*50)
    print(f"CALIBRATION SUITE SUMMARY: {result.testsRun} tests run.")
    print(f"Passed: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failed: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*50)
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_calibration_suite()
    sys.exit(0 if success else 1)
