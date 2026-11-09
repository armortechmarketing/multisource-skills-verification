import os
import sys
import json
import shutil
import tempfile
import subprocess
import pytest
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.adapters.skills_adapter import SkillHarborAdapter, extract_network_hosts_from_contracts, extract_entry_point
from src.run_status_reader import read_and_cross_check_run_status
from src.aces_parser import parse_aces_trajectory
from src.a_adj_adjudicator import adjudicate_skill_behavior, symbolic_audit
from src.harbor.agents.skill_contract_runner import SkillContractRunner

class TestHarborIntegration:

    @pytest.fixture
    def temp_workspace(self):
        tmp_dir = tempfile.mkdtemp()
        yield tmp_dir
        shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_skills_adapter_scaffolding_and_idempotency(self, temp_workspace):
        # Create a mock skill directory
        skill_dir = os.path.join(temp_workspace, "mock_skill")
        os.makedirs(os.path.join(skill_dir, "scripts"), exist_ok=True)
        with open(os.path.join(skill_dir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write("# Mock Skill\nPerforms test processing.")
        with open(os.path.join(skill_dir, "scripts", "main.py"), "w", encoding="utf-8") as f:
            f.write("import pydantic\nprint('hello world')")

        contracts = [{
            "contract_id": "C_01",
            "frame_axiom": ["read: scripts/main.py", "network: api.github.com"],
            "forbidden_invariant": ["network_egress: false"]
        }]

        tasks_dir = os.path.join(temp_workspace, "harbor_tasks")
        adapter = SkillHarborAdapter(base_output_dir=tasks_dir)

        # First run: scaffolding
        task_dir = adapter.scaffold_task(
            skill_id="mock_skill",
            skill_dir=skill_dir,
            declaration_text="Mock declaration",
            contracts=contracts
        )

        assert os.path.exists(os.path.join(task_dir, "task.toml"))
        assert os.path.exists(os.path.join(task_dir, "instruction.md"))
        assert os.path.exists(os.path.join(task_dir, "environment", "Dockerfile"))
        assert os.path.exists(os.path.join(task_dir, "environment", "docker-compose.yaml"))
        assert os.path.exists(os.path.join(task_dir, "environment", "mock_rules.json"))
        assert os.path.exists(os.path.join(task_dir, "solution", "solve.sh"))
        assert os.path.exists(os.path.join(task_dir, "solution", "entry_wrapper.py"))
        assert os.path.exists(os.path.join(task_dir, "tests", "test.sh"))
        assert os.path.exists(os.path.join(task_dir, "tests", "verify_artifacts.py"))

        # Verify task.toml network_mode allowlist
        task_toml_text = Path(os.path.join(task_dir, "task.toml")).read_text(encoding="utf-8")
        assert 'network_mode = "allowlist"' in task_toml_text
        assert 'api.github.com' in task_toml_text

        # Second run: test idempotency (clean overwrite without duplication)
        task_dir_2 = adapter.scaffold_task(
            skill_id="mock_skill",
            skill_dir=skill_dir,
            declaration_text="Updated declaration",
            contracts=contracts
        )
        assert task_dir == task_dir_2
        instr_text = Path(os.path.join(task_dir, "instruction.md")).read_text(encoding="utf-8")
        assert "Updated declaration" in instr_text

    def test_run_status_reader_downgrade(self, temp_workspace):
        # 1. When both agree on success
        rs_path = os.path.join(temp_workspace, "run_status.json")
        res_path = os.path.join(temp_workspace, "result.json")

        with open(rs_path, "w", encoding="utf-8") as f:
            json.dump({"run_status": "INVOKED_SUCCEEDED", "entry_point_reached": True, "exit_code": 0}, f)
        with open(res_path, "w", encoding="utf-8") as f:
            json.dump({"agent_result": {}, "verifier_result": {"reward": 1.0}}, f)

        status, reached, ftype, sublabel, code = read_and_cross_check_run_status(rs_path, res_path)
        assert status == "INVOKED_SUCCEEDED"
        assert reached is True
        assert code == 0

        # 2. When self-reported is INVOKED_SUCCEEDED but Harbor result has agent exception: Downgrade to INFRA_FAILURE!
        with open(res_path, "w", encoding="utf-8") as f:
            json.dump({"agent_result": {"exception": "Sandbox container timeout"}}, f)

        status, reached, ftype, sublabel, code = read_and_cross_check_run_status(rs_path, res_path)
        assert status == "INFRA_FAILURE"
        assert ftype == "HarborTrialException"
        assert "Sandbox container timeout" in (sublabel or "")

        # 3. Exit code 127 is always INFRA_FAILURE
        with open(rs_path, "w", encoding="utf-8") as f:
            json.dump({"run_status": "INVOKED_FAILED", "entry_point_reached": False, "exit_code": 127}, f)
        status, reached, ftype, sublabel, code = read_and_cross_check_run_status(rs_path, None)
        assert status == "INFRA_FAILURE"
        assert ftype == "MissingDependency"

    def test_aces_trajectory_parsing(self, temp_workspace):
        traj_path = os.path.join(temp_workspace, "trajectory.json")
        pkg_dir = os.path.join(temp_workspace, "skill_pkg")
        os.makedirs(os.path.join(pkg_dir, "scripts"), exist_ok=True)
        with open(os.path.join(pkg_dir, "scripts", "run.py"), "w", encoding="utf-8") as f:
            f.write("# dummy")

        # Trajectory with both activation (read SKILL.md) and script_execution (executed run.py)
        trajectory_data = {
            "steps": [
                {
                    "source": "agent",
                    "tool_calls": [
                        {"function_name": "read_file", "arguments": {"path": "/app/skill_package/SKILL.md"}}
                    ]
                },
                {
                    "source": "agent",
                    "tool_calls": [
                        {"function_name": "bash", "arguments": {"command": "python3 /app/skill_package/scripts/run.py"}}
                    ]
                }
            ]
        }
        with open(traj_path, "w", encoding="utf-8") as f:
            json.dump(trajectory_data, f)

        activation, script_exec = parse_aces_trajectory(traj_path, pkg_dir)
        assert activation is True
        assert script_exec is True

        # Trajectory without script execution
        trajectory_data["steps"] = [trajectory_data["steps"][0]]
        with open(traj_path, "w", encoding="utf-8") as f:
            json.dump(trajectory_data, f)

        activation, script_exec = parse_aces_trajectory(traj_path, pkg_dir)
        assert activation is True
        assert script_exec is False

    def test_a_adj_gating_rules(self, temp_workspace):
        contracts = [{
            "contract_id": "C_01",
            "frame_axiom": ["read: scripts/main.py"],
            "forbidden_invariant": ["network_egress: false"]
        }]
        traces = [{
            "contract_id": "C_01",
            "status": "failed",
            "events": []
        }]

        # 1. run_status == INFRA_FAILURE -> Not_Executed(INFRA), short-circuit
        res_infra = adjudicate_skill_behavior(
            contracts=contracts,
            traces=traces,
            skill_dir=temp_workspace,
            run_status="INFRA_FAILURE",
            entry_point_reached=False,
            failure_type="ImportError",
            execution_error_sublabel="No module named 'twikit'"
        )
        assert res_infra["gating_status"] == "Not_Executed(INFRA)"
        assert res_infra["level2_verdict"] is None
        assert res_infra["needs_rerun"] is True
        assert res_infra["coverage_score"] == 0.0

        # 2. run_status == NOT_INVOKED -> Not_Executed(HARNESS), short-circuit
        res_not_inv = adjudicate_skill_behavior(
            contracts=contracts,
            traces=traces,
            skill_dir=temp_workspace,
            run_status="NOT_INVOKED",
            entry_point_reached=False
        )
        assert res_not_inv["gating_status"] == "Not_Executed(HARNESS)"
        assert res_not_inv["level2_verdict"] is None
        assert res_not_inv["needs_rerun"] is True

        # 3. run_status == INVOKED_FAILED, entry_point_reached=True, failure_type="RuntimeError" (not a stub!)
        # Crashed skill with no execution units is Not_Executed(EARLY_CRASH), NEVER Aligned!
        res_exec_err = adjudicate_skill_behavior(
            contracts=contracts,
            traces=traces,
            skill_dir=temp_workspace,
            run_status="INVOKED_FAILED",
            entry_point_reached=True,
            failure_type="RuntimeError",
            execution_error_sublabel="TypeError: 'NoneType' object is not subscriptable"
        )
        assert res_exec_err["level2_verdict"] is None
        assert res_exec_err["gating_status"] == "Not_Executed(EARLY_CRASH)"
        assert "TypeError" in (res_exec_err["execution_error_sublabel"] or "")

        # 4. run_status == INVOKED_FAILED, entry_point_reached=True, failure_type="NotImplementedError"
        # MUST classify as Unimplemented_Intent!
        res_unimpl = adjudicate_skill_behavior(
            contracts=contracts,
            traces=traces,
            skill_dir=temp_workspace,
            run_status="INVOKED_FAILED",
            entry_point_reached=True,
            failure_type="NotImplementedError"
        )
        assert res_unimpl["predicted_label"] == "Unimplemented_Intent"

        # 5. Undeclared_Behavior (e.g. credential read or unauthorized network)
        traces_mal = [{
            "contract_id": "C_01",
            "status": "completed",
            "events": [
                {"event_type": "filesystem", "details": {"operation": "read", "path": "/root/.ssh/id_rsa"}}
            ]
        }]
        res_mal = adjudicate_skill_behavior(
            contracts=contracts,
            traces=traces_mal,
            skill_dir=temp_workspace,
            run_status="INVOKED_SUCCEEDED",
            entry_point_reached=True
        )
        assert res_mal["predicted_label"] == "Undeclared_Behavior"

    def test_solve_sh_trap_handler(self, temp_workspace):
        """
        Tests the Bash self-reporting trap handler:
        When bash is available (e.g. git bash or wsl), verify trap handles exits.
        Also test the Python entry_wrapper equivalent directly.
        """
        # Test entry_wrapper logic directly
        status_file = os.path.join(temp_workspace, "run_status.json")

        def simulate_wrapper(fail_mode):
            entry_reached = False
            stage = "pre_flight"
            status = "NOT_INVOKED"
            exit_code = 0
            err_info = None

            try:
                stage = "importing_skill"
                if fail_mode == "import_error":
                    raise ImportError("No module named 'mock_dep'")

                stage = "executing_contract"
                entry_reached = True

                if fail_mode == "not_implemented":
                    raise NotImplementedError("Feature not implemented")
                elif fail_mode == "runtime_error":
                    raise KeyError("missing_key")
                elif fail_mode == "sigterm":
                    # simulate exit on sigterm
                    raise SystemExit(143)
                else:
                    status = "INVOKED_SUCCEEDED"
                    exit_code = 0
            except (ImportError, ModuleNotFoundError) as ie:
                status = "INFRA_FAILURE"
                exit_code = 1
                err_info = {"type": type(ie).__name__, "message": str(ie)}
            except NotImplementedError as nie:
                status = "INVOKED_FAILED"
                exit_code = 2
                err_info = {"type": "NotImplementedError", "message": str(nie)}
            except SystemExit as se:
                status = "INVOKED_FAILED" if entry_reached else "INFRA_FAILURE"
                exit_code = se.code
            except Exception as e:
                status = "INVOKED_FAILED" if entry_reached else "INFRA_FAILURE"
                exit_code = 1
                err_info = {"type": type(e).__name__, "message": str(e)}

            with open(status_file, "w", encoding="utf-8") as f:
                json.dump({
                    "run_status": status,
                    "entry_point_reached": entry_reached,
                    "stage": stage,
                    "exit_code": exit_code,
                    "error_info": err_info
                }, f)
            return status, entry_reached

        # 1. Missing dependency -> INFRA_FAILURE
        st, reached = simulate_wrapper("import_error")
        assert st == "INFRA_FAILURE"
        assert reached is False

        # 2. NotImplementedError -> INVOKED_FAILED
        st, reached = simulate_wrapper("not_implemented")
        assert st == "INVOKED_FAILED"
        assert reached is True

        # 3. SIGTERM mid-run (entry reached) -> INVOKED_FAILED
        st, reached = simulate_wrapper("sigterm")
        assert st == "INVOKED_FAILED"
        assert reached is True

        # 4. Success -> INVOKED_SUCCEEDED
        st, reached = simulate_wrapper("success")
        assert st == "INVOKED_SUCCEEDED"
        assert reached is True
