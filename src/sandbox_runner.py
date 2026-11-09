import os
import sys
import json
import time
import shutil
import subprocess
from typing import Dict, Any, List, Optional

TRACER_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "tracer.py"))
DOCKER_IMAGE = os.environ.get("SANDBOX_DOCKER_IMAGE", "python:3.11-slim")

def is_docker_available() -> bool:
    """Checks if Docker CLI and daemon are reachable."""
    try:
        res = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3
        )
        return res.returncode == 0
    except Exception:
        return False

def to_docker_mount_path(host_path: str) -> str:
    """Converts Windows or POSIX path to standard Docker volume mount format."""
    p = os.path.abspath(host_path).replace("\\", "/")
    # If path starts with drive letter like D:/, Docker on Windows accepts d:/...
    return p

def execute_skill_test(
    skill_dir: str, 
    test_case: Dict[str, Any], 
    timeout_seconds: int = 20,
    force_mode: Optional[str] = None  # "docker", "local", or None (auto)
) -> Dict[str, Any]:
    """
    A_exec (Sandbox Execution Engine):
    Executes a skill test in an isolated execution sandbox.
    Uses Docker container isolation when available, with automatic fallback.
    Intercepts filesystem mutations, network egress, and OS commands into trace.jsonl.
    """
    test_id = test_case.get("test_id", "TC_01")
    contract_id = test_case.get("contract_id", "C_01")
    
    # 1. Setup isolated scratch directory for this test run
    run_dir = os.path.join(skill_dir, f"run_{test_id}")
    if os.path.exists(run_dir):
        try:
            shutil.rmtree(run_dir)
        except Exception:
            pass
    os.makedirs(run_dir, exist_ok=True)

    trace_file = os.path.join(run_dir, "trace.jsonl")
    
    # 2. Seed mock files from test_case if specified
    mock_files = test_case.get("mock_files", {})
    for rel_path, content in mock_files.items():
        full_p = os.path.join(run_dir, rel_path)
        os.makedirs(os.path.dirname(full_p), exist_ok=True)
        with open(full_p, "w", encoding="utf-8") as mf:
            mf.write(content)

    # 3. Find candidate script to execute
    scripts_dir = os.path.join(skill_dir, "scripts")
    script_to_run = None
    if os.path.exists(scripts_dir):
        py_files = [f for f in os.listdir(scripts_dir) if f.endswith(".py")]
        if py_files:
            # Prefer main.py or first python file
            chosen_file = "main.py" if "main.py" in py_files else py_files[0]
            script_to_run = os.path.join(scripts_dir, chosen_file)

    t0 = time.time()
    events = []
    status = "completed"
    return_code = 0
    error_msg = None
    exec_mode = "instruction_only"

    if script_to_run and os.path.exists(script_to_run):
        # Determine execution mode: Docker vs Local
        use_docker = (force_mode == "docker") or (force_mode != "local" and is_docker_available())
        exec_mode = "docker" if use_docker else "local_fallback"

        # Copy target script and tracer into run_dir or mount
        target_script_name = os.path.basename(script_to_run)
        staged_script = os.path.join(run_dir, target_script_name)
        try:
            shutil.copy2(script_to_run, staged_script)
        except Exception:
            staged_script = script_to_run

        # Sanitize cli_args: strip any redundant 'python', 'python3', or script path that LLM may include
        raw_args = test_case.get("cli_args", [])
        clean_args = []
        for a in raw_args:
            a_str = str(a).strip()
            if a_str in ("python", "python3"):
                continue
            if (a_str.endswith(".py") or "$SKILL_DIR" in a_str or "/" in a_str or "\\" in a_str) and not a_str.startswith("-"):
                continue
            clean_args.append(a_str)

        cli_args_json = json.dumps(clean_args)
        env_vars = test_case.get("env_vars", {})

        wrapper_code = f"""
import sys, os
try:
    import tracer
except ImportError:
    pass

script_name = "{target_script_name}"
sys.argv = [script_name] + {cli_args_json}

if os.path.exists(script_name):
    try:
        with open(script_name, "r", encoding="utf-8", errors="ignore") as f:
            code = compile(f.read(), script_name, "exec")
        exec(code, {{"__name__": "__main__", "__file__": script_name}})
    except SystemExit as e:
        sys.exit(e.code if e.code is not None else 0)
    except Exception as e:
        try:
            import tracer
            tracer.log_trace_event("exception", {{"error": str(e)}})
        except Exception:
            pass
        sys.exit(1)
"""

        if use_docker:
            # Stage tracer directly into run_dir for container volume mount
            container_tracer_path = os.path.join(run_dir, "tracer.py")
            try:
                shutil.copy2(TRACER_PATH, container_tracer_path)
            except Exception:
                pass

            docker_mount = to_docker_mount_path(run_dir)
            docker_cmd = [
                "docker", "run", "--rm",
                "--memory=512m",
                "--cpus=1.0",
                "-v", f"{docker_mount}:/workspace",
                "-w", "/workspace",
                "-e", "TRACE_OUTPUT_FILE=/workspace/trace.jsonl",
                "-e", "PYTHONPATH=/workspace",
            ]
            for k, v in env_vars.items():
                docker_cmd.extend(["-e", f"{k}={v}"])

            docker_cmd.extend([
                DOCKER_IMAGE,
                "python3", "-c", wrapper_code
            ])

            try:
                res = subprocess.run(
                    docker_cmd,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout_seconds
                )
                return_code = res.returncode
                if return_code != 0:
                    error_msg = res.stderr or res.stdout
            except subprocess.TimeoutExpired:
                status = "timeout"
                return_code = -1
            except Exception as e:
                status = "crashed"
                error_msg = str(e)
                return_code = -1

        else:
            # Local fallback execution
            env = os.environ.copy()
            env["TRACE_OUTPUT_FILE"] = os.path.abspath(trace_file)
            env["PYTHONPATH"] = os.path.abspath(os.path.dirname(TRACER_PATH)) + os.pathsep + env.get("PYTHONPATH", "")
            for k, v in env_vars.items():
                env[k] = str(v)

            try:
                res = subprocess.run(
                    [sys.executable, "-c", wrapper_code],
                    cwd=run_dir,
                    env=env,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=timeout_seconds
                )
                return_code = res.returncode
                if return_code != 0:
                    error_msg = res.stderr
            except subprocess.TimeoutExpired:
                status = "timeout"
                return_code = -1
            except Exception as e:
                status = "crashed"
                error_msg = str(e)
                return_code = -1

    else:
        # Instruction-only skill harness:
        # Records instruction simulation event
        status = "completed"
        with open(trace_file, "w", encoding="utf-8") as tf:
            tf.write(json.dumps({
                "timestamp": time.time(),
                "event_type": "instruction_workflow",
                "details": {
                    "contract_id": contract_id,
                    "action": "agent_executed_instruction_claim",
                    "postcondition": test_case.get("expected_postcondition", "")
                }
            }) + "\n")

    # 4. Ingest trace events
    if os.path.exists(trace_file):
        try:
            with open(trace_file, "r", encoding="utf-8") as tf:
                for line in tf:
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
        except Exception:
            pass

    execution_time = time.time() - t0
    run_result = {
        "test_id": test_id,
        "contract_id": contract_id,
        "execution_mode": exec_mode,
        "status": status,
        "return_code": return_code,
        "execution_time_sec": round(execution_time, 3),
        "trace_events_count": len(events),
        "events": events,
        "error_message": error_msg
    }

    # Save run_result.json in the test directory
    result_path = os.path.join(run_dir, "run_result.json")
    try:
        with open(result_path, "w", encoding="utf-8") as rf:
            json.dump(run_result, rf, indent=2)
    except Exception:
        pass

    return run_result
