import json
import os
import subprocess
import sys
import tempfile
import unittest

class TestCallsiteHook(unittest.TestCase):
    def test_callsite_capture_and_profile(self):
        project_root = os.path.abspath(".")
        with tempfile.TemporaryDirectory() as tmpdir:
            callsites_log = os.path.join(tmpdir, "callsites.jsonl")
            executed_funcs_log = os.path.join(tmpdir, "executed_functions.json")
            skill_dir = os.path.abspath("tests/calibration/undeclared_bashrc_write")
            script_path = os.path.join(skill_dir, "scripts", "main.py")

            env = os.environ.copy()
            env["PYTHONPATH"] = f"{project_root}{os.pathsep}{env.get('PYTHONPATH', '')}"
            env["SKILL_DIR"] = skill_dir
            env["CALLSITES_LOG_PATH"] = callsites_log
            env["EXECUTED_FUNCS_PATH"] = executed_funcs_log

            # Run with sitecustomize / callsite_hook pre-loaded
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
            self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}")

            # Verify callsites.jsonl exists and contains the expected callsite
            self.assertTrue(os.path.exists(callsites_log), "callsites.jsonl was not created")
            with open(callsites_log, "r", encoding="utf-8") as f:
                lines = [json.loads(line) for line in f if line.strip()]

            self.assertGreater(len(lines), 0, "No callsites recorded")
            # Look for line 6 in scripts/main.py
            found_target = False
            for entry in lines:
                chain = entry.get("chain", [])
                for frame in chain:
                    norm_file = frame.get("file", "").replace("\\", "/")
                    if "main.py" in norm_file and frame.get("line") == 6 and frame.get("function") == "main":
                        found_target = True
                        break
                if found_target:
                    break

            self.assertTrue(found_target, f"Did not find main.py:6 in callsites: {lines}")

            # Verify executed_functions.json
            self.assertTrue(os.path.exists(executed_funcs_log), "executed_functions.json was not created")
            with open(executed_funcs_log, "r", encoding="utf-8") as f:
                funcs = json.load(f)
            func_names = [f["qualname"] for f in funcs]
            self.assertIn("main", func_names, f"Expected 'main' in executed functions: {funcs}")

    def test_aligned_file_writer_callsite(self):
        project_root = os.path.abspath(".")
        with tempfile.TemporaryDirectory() as tmpdir:
            callsites_log = os.path.join(tmpdir, "callsites.jsonl")
            executed_funcs_log = os.path.join(tmpdir, "executed_functions.json")
            skill_dir = os.path.abspath("tests/calibration/aligned_file_writer")
            script_path = os.path.join(skill_dir, "scripts", "main.py")

            env = os.environ.copy()
            env["PYTHONPATH"] = f"{project_root}{os.pathsep}{env.get('PYTHONPATH', '')}"
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
            self.assertEqual(res.returncode, 0, f"Script failed: {res.stderr}")

            self.assertTrue(os.path.exists(callsites_log), "callsites.jsonl was not created")
            with open(callsites_log, "r", encoding="utf-8") as f:
                lines = [json.loads(line) for line in f if line.strip()]

            found_target = False
            for entry in lines:
                for frame in entry.get("chain", []):
                    norm_file = frame.get("file", "").replace("\\", "/")
                    if "main.py" in norm_file and frame.get("line") == 4 and frame.get("function") == "main":
                        found_target = True
                        break
                if found_target:
                    break

            self.assertTrue(found_target, f"Did not find main.py:4 in callsites: {lines}")

if __name__ == "__main__":
    unittest.main()
