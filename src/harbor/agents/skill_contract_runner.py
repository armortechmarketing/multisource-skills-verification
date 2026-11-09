from pathlib import Path
import json
import os
import sys
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

# UNVERIFIED — confirm against live Harbor: Behavior of environment.exec() on Heavy Syscall Streams

try:
    from harbor.agents.base import BaseAgent
    from harbor.environments.base import BaseEnvironment
    from harbor.models.agent.context import AgentContext
    from harbor.models.agent.capabilities import AgentCapabilities
except ImportError:
    # Graceful fallback definitions for standalone/local test execution
    class AgentCapabilities:
        pass

    class BaseAgent:
        capabilities = AgentCapabilities()
        @staticmethod
        def name() -> str:
            return "base-agent"
        def version(self) -> Optional[str]:
            return "1.0.0"
        async def setup(self, environment: Any) -> None:
            pass
        async def run(self, instruction: str, environment: Any, context: Any) -> None:
            pass

    class BaseEnvironment:
        async def exec(self, command: List[str], timeout_sec: int = 60) -> Any:
            pass

    class AgentContext:
        pass


class SkillContractRunner(BaseAgent):
    """
    Deterministic programmatic runner executing multiple A_gen test vectors
    directly against the environment via environment.exec().
    """
    capabilities = AgentCapabilities()

    @staticmethod
    def name() -> str:
        return "skill-contract-runner"

    def version(self) -> Optional[str]:
        return "1.0.0"

    async def setup(self, environment: BaseEnvironment) -> None:
        # Pre-execution environment sanity check
        pass

    async def run(
        self,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext
    ) -> None:
        # Instruction passes serialized JSON array of test cases from A_gen
        try:
            test_cases = json.loads(instruction)
            if not isinstance(test_cases, list):
                test_cases = [test_cases]
        except Exception:
            test_cases = [{"test_id": "TC_01", "cli_args": [], "env_vars": {}}]

        execution_records = []
        overall_exit_code = 0
        entry_point_reached = False
        all_stdout = []
        all_stderr = []
        run_status = "INVOKED_SUCCEEDED"

        for tc in test_cases:
            t_id = tc.get("test_id", tc.get("id", "TC_01"))
            entry_path = tc.get("entry_point", "scripts/main.py")
            cli_args = tc.get("cli_args", [])
            mock_files = tc.get("mock_files", {})

            # Write mock files for this specific test case immediately before execution
            created_paths = []
            for rel_p, content in mock_files.items():
                if not rel_p:
                    continue
                clean_rel = rel_p.lstrip("~/\\")
                target_container_path = f"/app/skill_package/{clean_rel}"
                created_paths.append(target_container_path)
                # Escape content for bash heredoc
                await environment.exec(
                    command=["bash", "-c", f"mkdir -p $(dirname '{target_container_path}') && cat << 'EOF' > '{target_container_path}'\n{content}\nEOF"],
                    timeout_sec=10
                )
                if rel_p.startswith("~"):
                    home_container_path = f"/root/{clean_rel}"
                    created_paths.append(home_container_path)
                    await environment.exec(
                        command=["bash", "-c", f"mkdir -p $(dirname '{home_container_path}') && cat << 'EOF' > '{home_container_path}'\n{content}\nEOF"],
                        timeout_sec=10
                    )

            # Expand $PWD, ${PWD}, and ~ in cli_args
            expanded_args = []
            for a in cli_args:
                s_a = str(a).replace("${PWD}", "/app/skill_package").replace("$PWD", "/app/skill_package")
                if s_a.startswith("~"):
                    s_a = "/root" + s_a[1:]
                expanded_args.append(s_a)
            cli_str = " ".join(f'"{a}"' for a in expanded_args)

            # Attach strace to capture network/filesystem syscalls independently of app exception handling
            cmd = [
                "bash", "-c",
                f"cd /app/skill_package && if command -v strace >/dev/null 2>&1; then strace -f -tt -e trace=file,network,process -o /logs/artifacts/strace.log python3 /app/skill_package/{entry_path} {cli_str}; else python3 /app/skill_package/{entry_path} {cli_str}; fi"
            ]

            # environment.exec returns an object with exit_code, stdout, stderr
            exec_result = await environment.exec(
                command=cmd,
                timeout_sec=60
            )

            rec = {
                "test_id": t_id,
                "exit_code": exec_result.exit_code,
                "stdout": getattr(exec_result, "stdout", "") or "",
                "stderr": getattr(exec_result, "stderr", "") or ""
            }
            execution_records.append(rec)
            all_stdout.append(rec["stdout"])
            all_stderr.append(rec["stderr"])

            if rec["exit_code"] != 0:
                overall_exit_code = rec["exit_code"]

            # Cleanup mock files for this test case to avoid cross-test contamination
            if created_paths:
                rm_cmd = "rm -f " + " ".join(f"'{p}'" for p in created_paths)
                await environment.exec(command=["bash", "-c", rm_cmd], timeout_sec=10)

        entry_point_reached = len(execution_records) > 0
        if overall_exit_code != 0:
            run_status = "INVOKED_FAILED"

        # Capture filesystem mutations via git diff
        await environment.exec(
            command=["bash", "-c", "cd /app/skill_package && git diff HEAD > /logs/artifacts/fs_diff.patch 2>/dev/null || true"],
            timeout_sec=10
        )

        # Write execution summary to host-mounted artifacts directory
        summary_payload = json.dumps(execution_records, indent=2)
        status_payload = json.dumps({
            "run_status": run_status,
            "entry_point_reached": entry_point_reached,
            "stage_at_exit": "completed",
            "exit_code": overall_exit_code,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, indent=2)

        combined_stdout = "\n".join(all_stdout)
        combined_stderr = "\n".join(all_stderr)

        await environment.exec(
            command=["bash", "-c", f"mkdir -p /logs/artifacts && cat << 'EOF' > /logs/artifacts/multi_run_results.json\n{summary_payload}\nEOF"]
        )
        await environment.exec(
            command=["bash", "-c", f"cat << 'EOF' > /logs/artifacts/run_status.json\n{status_payload}\nEOF"]
        )
        await environment.exec(
            command=["bash", "-c", f"echo {overall_exit_code} > /logs/artifacts/exit_code.txt"]
        )
        await environment.exec(
            command=["bash", "-c", f"cat << 'EOF' > /logs/artifacts/stdout.log\n{combined_stdout}\nEOF"]
        )
        await environment.exec(
            command=["bash", "-c", f"cat << 'EOF' > /logs/artifacts/stderr.log\n{combined_stderr}\nEOF"]
        )
