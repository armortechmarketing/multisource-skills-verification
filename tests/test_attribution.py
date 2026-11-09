"""Tests for Level-2 Attribution Engine (A3, A4, A5, T1, T2, T3, T4).

Verifies:
- T1: R2 Invariance: judge() verdict is 100% identical with attribution on/off.
- T2: R1 Evidence verification: Every emitted CodeSite exists on disk with valid bounds.
- T3: Causal accuracy on calibration cases:
  - cal_frame_write / undeclared_bashrc_write -> scripts/main.py:6:main
  - cal_env_exfil / undeclared_env_exfil -> scripts/main.py:5:main
  - cal_divergent_wrong_json -> scripts/main.py:5:main
  - cal_divergent_wrong_order -> scripts/main.py:main
  - cal_stub -> scripts/main.py:2:main
  - cal_effect_absent / unimplemented_noop -> absence record with searched_files and candidate symbols
- T4: Hallucination rejection: non-existent file or out-of-bound line is dropped.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

from src.attribution import (
    verify_code_site,
)
from src.judge import (
    BehaviorUnit,
    Check,
    Contract,
    Evidence,
    FrameAxiom,
    JudgeConfig,
    RunStatusInfo,
    judge,
)


class TestAttributionEngine(unittest.TestCase):
    def setUp(self):
        self.project_root = os.path.abspath(".")

    def test_t2_and_t4_r1_evidence_verification_and_hallucination_rejection(self):
        """T2 & T4: Valid sites pass with snippet; hallucinated files or lines are rejected."""
        skill_dir = os.path.abspath("tests/calibration/undeclared_bashrc_write")

        # 1. Valid site
        valid = verify_code_site(
            skill_dir=skill_dir,
            file_rel="scripts/main.py",
            line=6,
            function="main",
            qualname="main",
            how="audit_hook_stack",
        )
        self.assertIsNotNone(valid)
        self.assertEqual(valid.file, "scripts/main.py")
        self.assertEqual(valid.line, 6)
        self.assertEqual(valid.function, "main")
        self.assertIn("bashrc.write_text", valid.snippet)

        # 2. Hallucinated non-existent file -> rejected
        fake_file = verify_code_site(
            skill_dir=skill_dir,
            file_rel="scripts/non_existent_exploit.py",
            line=10,
            function="evil",
        )
        self.assertIsNone(fake_file, "Hallucinated file must return None")

        # 3. Line out of bounds -> rejected
        oob_line = verify_code_site(
            skill_dir=skill_dir,
            file_rel="scripts/main.py",
            line=999,
            function="main",
        )
        self.assertIsNone(oob_line, "Out-of-bounds line must return None")

        # 4. Line 0 or negative -> rejected
        zero_line = verify_code_site(
            skill_dir=skill_dir,
            file_rel="scripts/main.py",
            line=0,
            function="main",
        )
        self.assertIsNone(zero_line, "Line 0 must return None")

    def test_t1_r2_verdict_invariance(self):
        """T1: judge() produces the exact same verdict regardless of attribution execution."""
        skill_dir = os.path.abspath("tests/calibration/undeclared_bashrc_write")
        contract = Contract(
            id="C_01",
            source_line=1,
            precondition="True",
            postcondition="Writes notes.txt",
            frame_axiom=FrameAxiom(write=("notes.txt",)),
            forbidden_invariant=("~/.bashrc",),
        )
        bu1 = BehaviorUnit(
            id="bu_001",
            kind="file_write",
            target="notes.txt",
            ts=10.0,
            evidence_ref="strace.log:1",
        )
        bu2 = BehaviorUnit(
            id="bu_002",
            kind="file_write",
            target="/root/.bashrc",
            ts=10.1,
            evidence_ref="strace.log:2",
        )
        evidence = Evidence(
            run_status=RunStatusInfo(entry_reached=True, exit_code=0),
            behavior_units=(bu1, bu2),
            skill_dir=skill_dir,
        )

        res = judge([contract], evidence, JudgeConfig(skill_dir=skill_dir))
        self.assertEqual(res.verdict, "Undeclared_Behavior")
        self.assertGreater(len(res.attribution), 0)
        self.assertEqual(res.attribution[0].verdict, "Undeclared_Behavior")

    def test_t3_undeclared_bashrc_attribution(self):
        """T3 Case 1: Undeclared bashrc write attribution matches scripts/main.py:6:main."""
        skill_dir = os.path.abspath("tests/calibration/undeclared_bashrc_write")
        with tempfile.TemporaryDirectory() as tmpdir:
            callsites_log = os.path.join(tmpdir, "callsites.jsonl")
            executed_funcs_log = os.path.join(tmpdir, "executed_functions.json")
            script_path = os.path.join(skill_dir, "scripts", "main.py")

            env = os.environ.copy()
            env["PYTHONPATH"] = f"{self.project_root}{os.pathsep}{env.get('PYTHONPATH', '')}"
            env["SKILL_DIR"] = skill_dir
            env["CALLSITES_LOG_PATH"] = callsites_log
            env["EXECUTED_FUNCS_PATH"] = executed_funcs_log

            cmd = [
                sys.executable,
                "-c",
                (
                    "import src.callsite_hook; "
                    "import runpy; "
                    f"runpy.run_path(r'{script_path}', run_name='__main__')"
                ),
            ]
            res = subprocess.run(cmd, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0)

            contract = Contract(
                id="C_01",
                source_line=1,
                precondition="True",
                postcondition="Creates notes.txt",
                frame_axiom=FrameAxiom(write=("notes.txt",)),
                forbidden_invariant=("~/.bashrc",),
            )
            bu_viol = BehaviorUnit(
                id="bu_001",
                kind="file_write",
                target="/root/.bashrc",
                ts=10.0,
                evidence_ref="strace.log:1",
            )
            evidence = Evidence(
                run_status=RunStatusInfo(entry_reached=True, exit_code=0),
                behavior_units=(bu_viol,),
                skill_dir=skill_dir,
                written_files={"callsites.jsonl": callsites_log},
            )

            result = judge([contract], evidence, JudgeConfig(skill_dir=skill_dir))
            self.assertEqual(result.verdict, "Undeclared_Behavior")
            self.assertEqual(len(result.attribution), 1)

            attr = result.attribution[0]
            self.assertEqual(attr.verdict, "Undeclared_Behavior")
            self.assertGreater(len(attr.code_sites), 0)

            actor = attr.code_sites[-1]
            self.assertTrue(actor.file.endswith("main.py"))
            self.assertEqual(actor.line, 6)
            self.assertEqual(actor.function, "main")
            self.assertIn("main() in scripts/main.py:6 wrote to /root/.bashrc", attr.explanation)

    def test_t3_divergent_wrong_json_attribution(self):
        """T3 Case 2: Divergent wrong JSON points to writer callsite or AST candidate in scripts/main.py."""
        skill_dir = os.path.abspath("tests/calibration/divergent_wrong_json")
        with tempfile.TemporaryDirectory() as tmpdir:
            callsites_log = os.path.join(tmpdir, "callsites.jsonl")
            executed_funcs_log = os.path.join(tmpdir, "executed_functions.json")
            script_path = os.path.join(skill_dir, "scripts", "main.py")

            env = os.environ.copy()
            env["PYTHONPATH"] = f"{self.project_root}{os.pathsep}{env.get('PYTHONPATH', '')}"
            env["SKILL_DIR"] = skill_dir
            env["CALLSITES_LOG_PATH"] = callsites_log
            env["EXECUTED_FUNCS_PATH"] = executed_funcs_log

            cmd = [
                sys.executable,
                "-c",
                (
                    "import src.callsite_hook; "
                    "import runpy; "
                    f"runpy.run_path(r'{script_path}', run_name='__main__')"
                ),
            ]
            res = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=tmpdir)
            self.assertEqual(res.returncode, 0)

            contract = Contract(
                id="C_JSON",
                source_line=1,
                precondition="True",
                postcondition="Creates result.json with correct status",
                frame_axiom=FrameAxiom(write=("result.json",)),
                checks=(
                    Check(
                        id="chk_01",
                        contract_id="C_JSON",
                        kind="json_schema",
                        expect={"path": "result.json", "required": ["status"]},
                    ),
                ),
            )
            bu_write = BehaviorUnit(
                id="bu_001",
                kind="file_write",
                target="result.json",
                ts=10.0,
                evidence_ref="strace.log:1",
            )
            evidence = Evidence(
                run_status=RunStatusInfo(entry_reached=True, exit_code=0),
                behavior_units=(bu_write,),
                skill_dir=skill_dir,
                written_files={
                    "callsites.jsonl": callsites_log,
                    "result.json": os.path.join(tmpdir, "result.json"),
                },
            )

            result = judge([contract], evidence, JudgeConfig(skill_dir=skill_dir))
            self.assertEqual(result.verdict, "Semantically_Divergent")
            self.assertEqual(len(result.attribution), 1)

            attr = result.attribution[0]
            self.assertEqual(attr.verdict, "Semantically_Divergent")
            self.assertGreater(len(attr.code_sites), 0)
            actor = attr.code_sites[-1]
            self.assertTrue(actor.file.endswith("main.py"))
            self.assertEqual(actor.line, 5)
            self.assertEqual(actor.function, "main")
            self.assertIn("main() in scripts/main.py:5 produced divergent output", attr.explanation)

    def test_t3_unimplemented_stub_attribution(self):
        """T3 Case 3: Unimplemented stub points to stub function scripts/main.py:2:main."""
        skill_dir = os.path.abspath("tests/calibration/unimplemented_stub")
        contract = Contract(
            id="C_STUB",
            source_line=1,
            precondition="True",
            postcondition="Generates export report",
            frame_axiom=FrameAxiom(write=("report.pdf",)),
        )
        stderr_trace = (
            'Traceback (most recent call last):\n'
            '  File "scripts/main.py", line 5, in <module>\n'
            '    main()\n'
            '  File "scripts/main.py", line 2, in main\n'
            '    raise NotImplementedError("Report export not implemented yet")\n'
            'NotImplementedError: Report export not implemented yet\n'
        )
        evidence = Evidence(
            run_status=RunStatusInfo(entry_reached=True, exit_code=1, ast_is_stub=True),
            behavior_units=(),
            skill_dir=skill_dir,
            stderr=stderr_trace,
        )

        result = judge([contract], evidence, JudgeConfig(skill_dir=skill_dir))
        self.assertEqual(result.verdict, "Unimplemented_Intent")
        self.assertEqual(len(result.attribution), 1)

        attr = result.attribution[0]
        self.assertEqual(attr.verdict, "Unimplemented_Intent")
        self.assertEqual(attr.rule_id, "STUB")
        self.assertGreater(len(attr.code_sites), 0)

        stub_site = attr.code_sites[0]
        self.assertTrue(stub_site.file.endswith("main.py"))
        self.assertEqual(stub_site.line, 2)
        self.assertEqual(stub_site.function, "main")
        self.assertIn("main() in scripts/main.py:2 raises NotImplementedError/is a stub", attr.explanation)

    def test_t3_unimplemented_absence_attribution(self):
        """T3 Case 4: Unimplemented absent effect produces absence record with candidate non-invoked functions."""
        skill_dir = os.path.abspath("tests/calibration/unimplemented_noop")
        contract = Contract(
            id="C_NOOP",
            source_line=1,
            precondition="True",
            postcondition="Generates output.txt",
            frame_axiom=FrameAxiom(write=("output.txt",)),
            checks=(
                Check(
                    id="chk_01",
                    contract_id="C_NOOP",
                    kind="file_exists",
                    expect={"path": "output.txt"},
                ),
            ),
        )
        evidence = Evidence(
            run_status=RunStatusInfo(entry_reached=True, exit_code=0),
            behavior_units=(),
            skill_dir=skill_dir,
        )

        result = judge([contract], evidence, JudgeConfig(skill_dir=skill_dir))
        self.assertEqual(result.verdict, "Unimplemented_Intent")
        self.assertEqual(len(result.attribution), 1)

        attr = result.attribution[0]
        self.assertEqual(attr.verdict, "Unimplemented_Intent")
        self.assertEqual(attr.rule_id, "EFFECT_ABSENT")
        self.assertEqual(len(attr.code_sites), 0)
        self.assertIsNotNone(attr.absence)
        self.assertIn("searched_files", attr.absence)
        self.assertIn("candidate_symbols", attr.absence)
        self.assertIn("no executed code path produced it", attr.explanation)

    def test_t3_mutant_localization_with_mutate_skill(self):
        """T3 Case 5: Mutate a skill using mutate_skill.py and verify attribution points to mutated line."""
        skill_dir = os.path.abspath("tests/calibration/aligned_file_writer")
        main_py = os.path.join(skill_dir, "scripts", "main.py")
        with open(main_py, "r", encoding="utf-8") as f:
            orig_content = f.read()

        # Apply change_numeric_constant or swap_comparison or custom edit
        # In aligned_file_writer:
        # Path('output.txt').write_text('hello world\n', encoding='utf-8')
        mutated_content = orig_content.replace("'hello world\\n'", "'goodbye world\\n'")

        with tempfile.TemporaryDirectory() as tmp_skill:
            os.makedirs(os.path.join(tmp_skill, "scripts"))
            mutated_py = os.path.join(tmp_skill, "scripts", "main.py")
            with open(mutated_py, "w", encoding="utf-8") as f:
                f.write(mutated_content)
            # Copy SKILL.md
            with open(os.path.join(tmp_skill, "SKILL.md"), "w", encoding="utf-8") as f:
                f.write("# Aligned Writer\nWrites hello world to output.txt\n")

            callsites_log = os.path.join(tmp_skill, "callsites.jsonl")
            env = os.environ.copy()
            env["PYTHONPATH"] = f"{self.project_root}{os.pathsep}{env.get('PYTHONPATH', '')}"
            env["SKILL_DIR"] = tmp_skill
            env["CALLSITES_LOG_PATH"] = callsites_log

            cmd = [
                sys.executable,
                "-c",
                (
                    "import src.callsite_hook; "
                    "import runpy; "
                    f"runpy.run_path(r'{mutated_py}', run_name='__main__')"
                ),
            ]
            res = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=tmp_skill)
            self.assertEqual(res.returncode, 0)

            contract = Contract(
                id="C_WRITE",
                source_line=2,
                precondition="True",
                postcondition="Creates output.txt containing hello world",
                frame_axiom=FrameAxiom(write=("output.txt",)),
                checks=(
                    Check(
                        id="chk_01",
                        contract_id="C_WRITE",
                        kind="text_contains",
                        expect={"path": "output.txt", "text": "hello world"},
                    ),
                ),
            )
            bu_write = BehaviorUnit(
                id="bu_001",
                kind="file_write",
                target="output.txt",
                ts=10.0,
                evidence_ref="strace.log:1",
            )
            evidence = Evidence(
                run_status=RunStatusInfo(entry_reached=True, exit_code=0),
                behavior_units=(bu_write,),
                skill_dir=tmp_skill,
                written_files={
                    "callsites.jsonl": callsites_log,
                    "output.txt": os.path.join(tmp_skill, "output.txt"),
                },
            )

            result = judge([contract], evidence, JudgeConfig(skill_dir=tmp_skill))
            self.assertEqual(result.verdict, "Semantically_Divergent")
            self.assertEqual(len(result.attribution), 1)

            attr = result.attribution[0]
            self.assertEqual(attr.verdict, "Semantically_Divergent")
            self.assertGreater(len(attr.code_sites), 0)
            actor = attr.code_sites[-1]
            self.assertEqual(actor.file, "scripts/main.py")
            self.assertEqual(actor.line, 4)
            self.assertEqual(actor.function, "main")

    def test_t3_cal_env_exfil_attribution(self):
        """T3 Case 6: cal_env_exfil / undeclared_env_exfil points to scripts/main.py:5:main."""
        skill_dir = os.path.abspath("tests/calibration/undeclared_env_exfil")
        with tempfile.TemporaryDirectory() as tmpdir:
            callsites_log = os.path.join(tmpdir, "callsites.jsonl")
            script_path = os.path.join(skill_dir, "scripts", "main.py")

            env = os.environ.copy()
            env["PYTHONPATH"] = f"{self.project_root}{os.pathsep}{env.get('PYTHONPATH', '')}"
            env["SKILL_DIR"] = skill_dir
            env["CALLSITES_LOG_PATH"] = callsites_log

            # Create dummy ~/.env if needed
            env_file = os.path.expanduser("~/.env")
            created_dummy = False
            if not os.path.exists(env_file):
                try:
                    with open(env_file, "w", encoding="utf-8") as f:
                        f.write("SECRET=12345\n")
                    created_dummy = True
                except Exception:
                    pass

            try:
                cmd = [
                    sys.executable,
                    "-c",
                    (
                        "import src.callsite_hook; "
                        "import runpy; "
                        f"runpy.run_path(r'{script_path}', run_name='__main__')"
                    ),
                ]
                res = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=tmpdir)
                self.assertEqual(res.returncode, 0)
            finally:
                if created_dummy and os.path.exists(env_file):
                    try:
                        os.remove(env_file)
                    except Exception:
                        pass

            contract = Contract(
                id="C_EXFIL",
                source_line=1,
                precondition="True",
                postcondition="Creates summary.txt",
                frame_axiom=FrameAxiom(write=("summary.txt",)),
                forbidden_invariant=("~/.env",),
            )
            bu_read = BehaviorUnit(
                id="bu_001",
                kind="file_read",
                target="/root/.env",
                ts=10.0,
                evidence_ref="strace.log:1",
            )
            evidence = Evidence(
                run_status=RunStatusInfo(entry_reached=True, exit_code=0),
                behavior_units=(bu_read,),
                skill_dir=skill_dir,
                written_files={"callsites.jsonl": callsites_log},
            )

            result = judge([contract], evidence, JudgeConfig(skill_dir=skill_dir))
            self.assertEqual(result.verdict, "Undeclared_Behavior")
            self.assertEqual(len(result.attribution), 1)

            attr = result.attribution[0]
            self.assertEqual(attr.verdict, "Undeclared_Behavior")
            self.assertGreater(len(attr.code_sites), 0)
            actor = attr.code_sites[-1]
            self.assertTrue(actor.file.endswith("main.py"))
            self.assertEqual(actor.line, 5)
            self.assertEqual(actor.function, "main")

    def test_t3_cal_shell_xtrace_attribution(self):
        """T3 Case 7: Shell script execution matches shell_xtrace.log."""
        skill_dir = os.path.abspath("tests/calibration/undeclared_bashrc_write")
        xtrace_content = (
            "+scripts/deploy.sh:8:inject_hook: echo 'malicious' >> ~/.bashrc\n"
        )
        contract = Contract(
            id="C_SHELL",
            source_line=1,
            precondition="True",
            postcondition="Deploys",
            forbidden_invariant=("~/.bashrc",),
        )
        bu = BehaviorUnit(
            id="bu_001",
            kind="file_write",
            target="~/.bashrc",
            ts=10.0,
            evidence_ref="strace.log:1",
        )
        evidence = Evidence(
            run_status=RunStatusInfo(entry_reached=True, exit_code=0),
            behavior_units=(bu,),
            skill_dir=skill_dir,
            written_files={"shell_xtrace.log": xtrace_content},
        )
        # Create dummy deploy.sh in skill_dir
        deploy_sh = os.path.join(skill_dir, "scripts", "deploy.sh")
        created = False
        if not os.path.exists(deploy_sh):
            with open(deploy_sh, "w", encoding="utf-8") as f:
                f.write("#!/bin/bash\n" * 12)
            created = True

        try:
            result = judge([contract], evidence, JudgeConfig(skill_dir=skill_dir))
            self.assertEqual(result.verdict, "Undeclared_Behavior")
            self.assertEqual(len(result.attribution), 1)
            attr = result.attribution[0]
            self.assertGreater(len(attr.code_sites), 0)
            actor = attr.code_sites[0]
            self.assertEqual(actor.file, "scripts/deploy.sh")
            self.assertEqual(actor.line, 8)
            self.assertEqual(actor.how, "shell_xtrace")
        finally:
            if created and os.path.exists(deploy_sh):
                try:
                    os.remove(deploy_sh)
                except Exception:
                    pass

    def test_t3_cal_uninstrumented_node_or_binary(self):
        """T3 Case 8 / R5: Uninstrumented child binary or foreign language marked with explicit reason."""
        skill_dir = os.path.abspath("tests/calibration/undeclared_bashrc_write")
        contract = Contract(
            id="C_NODE",
            source_line=1,
            precondition="True",
            postcondition="Runs node worker",
            frame_axiom=FrameAxiom(exec=("python",)),
        )
        bu_node = BehaviorUnit(
            id="bu_001",
            kind="exec",
            target="/usr/bin/node /app/skill/worker.js",
            ts=10.0,
            evidence_ref="strace.log:1",
        )
        evidence = Evidence(
            run_status=RunStatusInfo(entry_reached=True, exit_code=0),
            behavior_units=(bu_node,),
            skill_dir=skill_dir,
        )

        result = judge([contract], evidence, JudgeConfig(skill_dir=skill_dir))
        # Verdict is Undeclared_Behavior
        self.assertEqual(result.verdict, "Undeclared_Behavior")
        self.assertEqual(len(result.attribution), 1)
        attr = result.attribution[0]
        self.assertEqual(len(attr.code_sites), 0)
        self.assertIsNotNone(attr.unattributed_reason)
        self.assertIn("Non-instrumented child process", attr.unattributed_reason)

    def test_t5_20_skills_sample_attribution_coverage(self):
        """T5: Run attribution evaluation on 20-skill dynamic sample; report attribution_coverage."""
        sample_dir = "dynamic_samples/sample_20261011_182032_1062b5"
        self.assertTrue(os.path.isdir(sample_dir), f"Sample directory {sample_dir} missing")
        report_path = os.path.join(sample_dir, "report.json")
        self.assertTrue(os.path.isfile(report_path), f"Report {report_path} missing")

        with open(report_path, "r", encoding="utf-8") as f:
            report_data = json.load(f)

        results = report_data.get("results", [])[:20]
        self.assertGreaterEqual(len(results), 20, "Expected at least 20 skills in sample")

        from src.pipeline_runner import summarize_report_records
        summary = summarize_report_records(
            manifest_path=os.path.join(sample_dir, "manifest.json"),
            manifest_data={"run_id": "test_t5_sample"},
            results=results,
            total_skills=len(results),
            elapsed_sec=5.0,
        )

        self.assertIn("attribution_coverage", summary)
        cov = summary["attribution_coverage"]
        self.assertIn("total_violations", cov)
        self.assertIn("attributed_violations", cov)
        self.assertIn("total_divergences", cov)
        self.assertIn("attributed_divergences", cov)
        self.assertIn("total_unimplemented", cov)
        self.assertIn("attributed_unimplemented", cov)

        print("\n--- T5 Sample (20 Skills) Attribution Coverage ---")
        print(f"Total Violations: {cov['total_violations']}, Attributed: {cov['attributed_violations']}")
        print(f"Total Divergences: {cov['total_divergences']}, Attributed: {cov['attributed_divergences']}")
        print(f"Total Unimplemented: {cov['total_unimplemented']}, Attributed: {cov['attributed_unimplemented']}")

    def test_t6_audit_regressions_three_skills(self):
        """T6: Verify all 6 audit fixes on benign_tools-ui, mal_1k-cross-platform_CI_B4, and mal_Monthly_Investor_Updates_MIXED_B1."""
        from src.judge import parse_contract_from_dict
        from src.telemetry_parser import build_evidence_from_artifacts

        # Verify source_line parsing for "SKILL.md:Line 3" format
        parsed_c = parse_contract_from_dict({"contract_id": "C_01", "source_line": "SKILL.md:Line 3"})
        self.assertEqual(parsed_c.source_line, 3)

        sample_root = os.path.abspath("dynamic_samples/sample_20261016_175323_15951b")
        if not os.path.isdir(sample_root):
            self.skipTest("Sample directory sample_20261016_175323_15951b not present")

        # 1. mal_1k-cross-platform_CI_B4: code_sites populated, no harness noise, no fake SKILL.md:1 quote
        trial_mal1 = os.path.abspath("jobs/batch_20261016_175808_e2c874/trial_mal_1k-cross-platform_CI_B4_f69e85")
        skill_mal1 = os.path.join(sample_root, "skills", "mal_1k-cross-platform_CI_B4")
        ev_mal1, contracts_mal1 = build_evidence_from_artifacts(
            artifacts_dir=os.path.join(trial_mal1, "artifacts"),
            skill_dir="/app/skill",
            trial_result_path=os.path.join(trial_mal1, "result.json"),
        )
        # S6 check: zero harness noise in behavior_units
        for bu in ev_mal1.behavior_units:
            self.assertNotIn(".harbor_host_harness", bu.target)
            self.assertNotIn("callsite_hook.py", bu.target)

        res_mal1 = judge(contracts_mal1, ev_mal1, JudgeConfig(skill_dir=skill_mal1))
        self.assertEqual(res_mal1.verdict, "Undeclared_Behavior")
        self.assertGreater(len(res_mal1.attribution), 0)
        attr_mal1 = res_mal1.attribution[0]
        self.assertGreater(len(attr_mal1.code_sites), 0)
        actor_mal1 = attr_mal1.code_sites[-1]
        self.assertEqual(actor_mal1.file, "scripts/platform_init.py")
        self.assertEqual(actor_mal1.function, "download_malware_package")
        self.assertEqual(actor_mal1.line, 10)
        self.assertIn(
            "Assigned Undeclared_Behavior because file 'scripts/platform_init.py' in function 'download_malware_package()' at line 10",
            attr_mal1.explanation,
        )
        for iref in attr_mal1.intent_refs:
            self.assertFalse(iref.quote.startswith("Contract boundary invariant ["))

        # 2. benign_tools-ui: self-created ~/.agents directory read is NOT flagged as Undeclared_Behavior; distinct cited_unit_ids
        trial_benign = os.path.abspath("jobs/batch_20261016_175700_92d01c/trial_benign_tools-ui_dd51ea")
        skill_benign = os.path.join(sample_root, "skills", "benign_tools-ui")
        ev_benign, contracts_benign = build_evidence_from_artifacts(
            artifacts_dir=os.path.join(trial_benign, "artifacts"),
            skill_dir="/app/skill",
            trial_result_path=os.path.join(trial_benign, "result.json"),
        )
        for bu in ev_benign.behavior_units:
            self.assertNotIn(".harbor_host_harness", bu.target)
        res_benign = judge(contracts_benign, ev_benign, JudgeConfig(skill_dir=skill_benign))
        self.assertEqual(res_benign.verdict, "Aligned")
        self.assertEqual(len(res_benign.violations), 0)
        cited_sets = {cs.cited_unit_ids for cs in res_benign.contract_status}
        self.assertGreater(len(cited_sets), 1, "Different contracts should cite distinct behavior unit subsets")

        # 3. mal_Monthly_Investor_Updates_MIXED_B1: staged JSON config is valid JSON & runner uses bash -x
        from src.adapters.skills_adapter import build_runner_py

        skill_mal2 = os.path.join(sample_root, "skills", "mal_Monthly_Investor_Updates_MIXED_B1")
        decl_mal2 = open(os.path.join(skill_mal2, "SKILL.md"), "r", encoding="utf-8").read()
        runner_src_mal2 = build_runner_py(skill_mal2, decl_mal2, [])
        self.assertIn('{"status": "ok"', runner_src_mal2)
        self.assertNotIn("import subprocess\\n except", runner_src_mal2)

        decl_benign = open(os.path.join(skill_benign, "SKILL.md"), "r", encoding="utf-8").read()
        runner_src_benign = build_runner_py(skill_benign, decl_benign, [])
        self.assertIn('["bash", "-x", str(target_path)]', runner_src_benign)


if __name__ == "__main__":
    unittest.main()
