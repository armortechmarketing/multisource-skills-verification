"""Generate random synthetic Evidence invariants for judge smoke testing."""
from __future__ import annotations

import random
from typing import List, Tuple

from src.judge import (
    BehaviorUnit,
    Check,
    CheckResult,
    Contract,
    Evidence,
    FrameAxiom,
    JudgeConfig,
    RunStatusInfo,
    judge,
)


def make_random_case(rng: random.Random) -> Tuple[List[Contract], Evidence]:
    cid = "C_01"
    exit_code = rng.choice([0, 0, 0, 1, 2, 127, 124])
    entry = rng.choice([True, True, True, False])
    stderr = ""
    if exit_code == 2:
        stderr = "usage: tool.py [-h]"
    elif exit_code == 127:
        stderr = "command not found: jq"
    elif exit_code == 124:
        stderr = "TimeoutExpired"
    elif exit_code == 1 and rng.random() < 0.5:
        stderr = "ModuleNotFoundError: No module named 'x'"

    checks = (Check("c1", cid, "exit_code", 0),)
    contracts = [
        Contract(
            id=cid,
            postcondition="exit zero",
            frame_axiom=FrameAxiom(),
            checks=checks,
            expects_effect=False,
        )
    ]
    units = ()
    if exit_code == 0 and entry and rng.random() < 0.6:
        units = (BehaviorUnit("u1", "stdout", "ok"),)
    ev = Evidence(
        run_status=RunStatusInfo(entry_reached=entry, exit_code=exit_code),
        stderr=stderr,
        stdout="ok" if exit_code == 0 else "",
        behavior_units=units,
        check_results=(CheckResult("c1", cid, exit_code == 0 and entry, f"exit_code={exit_code}"),),
        input_valid=True,
        run_kind="script",
    )
    return contracts, ev


def main(n: int = 30, seed: int = 42) -> None:
    rng = random.Random(seed)
    for i in range(n):
        contracts, ev = make_random_case(rng)
        res = judge(contracts, ev, JudgeConfig(aligned_min_dtc=0.0))
        # Invariants
        assert res.verdict in (
            "Aligned",
            "Semantically_Divergent",
            "Undeclared_Behavior",
            "Unimplemented_Intent",
            "Inconclusive",
        )
        if res.failure_class in (
            "USAGE_ERROR",
            "MISSING_MODULE",
            "MISSING_BINARY",
            "TIMEOUT",
            "FILE_NOT_FOUND_INPUT",
            "AGENT_NO_TELEMETRY",
        ):
            assert res.verdict in ("Inconclusive", "Undeclared_Behavior")
            assert res.verdict != "Semantically_Divergent"
            assert res.verdict != "Unimplemented_Intent" or False
        print(f"case {i:02d}: verdict={res.verdict} nvr={res.no_verdict_reason} fc={res.failure_class}")


if __name__ == "__main__":
    main()
