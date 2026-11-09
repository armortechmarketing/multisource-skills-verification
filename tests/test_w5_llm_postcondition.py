from pathlib import Path
from typing import Any, Dict, Optional

from src.a_adj_adjudicator import (
    _MEMORY_POSTCONDITION_CACHE,
    adjudicate_skill_behavior,
    compute_postcondition_cache_key,
    judge_postcondition,
)
from src.judge import (
    BehaviorUnit,
    Contract,
    Evidence,
    FrameAxiom,
    JudgeConfig,
    RunStatus,
    judge,
)


def _sample_contract_and_units():
    contract = Contract(
        id="C_01",
        precondition="Input file exists",
        postcondition="Writes sorted JSON summary to /app/skill/summary.json",
        frame_axiom=FrameAxiom(read=("/app/skill/**",), write=("/app/skill/summary.json",)),
        forbidden_invariant=(),
        source_line="SKILL.md:10",
        checks=(),
    )
    units = (
        BehaviorUnit(
            id="u_0001",
            kind="file_write",
            target="/app/skill/summary.json",
            ts=1.0,
            evidence_ref="strace.log:42",
        ),
        BehaviorUnit(
            id="u_0002",
            kind="stdout",
            target='{"items": [3, 1, 2]}',
            ts=2.0,
            evidence_ref="stdout.log:1",
        ),
    )
    return contract, units


def test_w5_pass_and_contradicted_with_valid_citations(tmp_path: Path) -> None:
    _MEMORY_POSTCONDITION_CACHE.clear()
    contract, units = _sample_contract_and_units()
    cache_file = str(tmp_path / "cache.json")

    def fake_llm_pass(prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.0) -> Dict[str, Any]:
        assert temperature == 0.0
        return {
            "status": "PASS",
            "cited_unit_ids": ["u_0001", "u_0002"],
            "reason": "Summary written and sorted properly.",
        }

    res_pass = judge_postcondition(
        contract,
        units,
        stdout='{"items": [1, 2, 3]}',
        stderr="",
        cache_path=cache_file,
        llm_caller=fake_llm_pass,
    )
    assert res_pass["status"] == "PASS"
    assert res_pass["cited_unit_ids"] == ["u_0001", "u_0002"]

    def fake_llm_contradicted(prompt: str, system_prompt: Optional[str] = None, temperature: float = 0.0) -> Dict[str, Any]:
        return {
            "status": "CONTRADICTED",
            "cited_unit_ids": ["u_0002"],
            "reason": "Output items [3, 1, 2] are unsorted.",
        }

    res_contra = judge_postcondition(
        contract,
        units,
        stdout='{"items": [3, 1, 2]}',
        stderr="",
        cache_path=cache_file,
        llm_caller=fake_llm_contradicted,
    )
    assert res_contra["status"] == "CONTRADICTED"
    assert res_contra["cited_unit_ids"] == ["u_0002"]


def test_w5_uncited_or_hallucinated_unit_ids_downgraded_to_indeterminate(tmp_path: Path) -> None:
    _MEMORY_POSTCONDITION_CACHE.clear()
    contract, units = _sample_contract_and_units()

    # Empty cited_unit_ids -> must be INDETERMINATE
    res_empty = judge_postcondition(
        contract,
        units,
        stdout="empty citation test",
        cache_path=str(tmp_path / "c1.json"),
        llm_caller=lambda **kw: {"status": "PASS", "cited_unit_ids": [], "reason": "Looks good"},
    )
    assert res_empty["status"] == "INDETERMINATE"
    assert res_empty["cited_unit_ids"] == []

    # Hallucinated unit ID not in behavior_units -> must be INDETERMINATE
    res_hallucinated = judge_postcondition(
        contract,
        units,
        stdout="hallucinated citation test",
        cache_path=str(tmp_path / "c2.json"),
        llm_caller=lambda **kw: {"status": "CONTRADICTED", "cited_unit_ids": ["u_9999"], "reason": "Bad unit"},
    )
    assert res_hallucinated["status"] == "INDETERMINATE"
    assert res_hallucinated["cited_unit_ids"] == []


def test_w5_llm_cannot_emit_undeclared_behavior_and_handles_outage(tmp_path: Path) -> None:
    _MEMORY_POSTCONDITION_CACHE.clear()
    contract, units = _sample_contract_and_units()

    # Attempt to emit Undeclared_Behavior -> downgraded to INDETERMINATE
    res_undecl = judge_postcondition(
        contract,
        units,
        stdout="undeclared attempt",
        cache_path=str(tmp_path / "c3.json"),
        llm_caller=lambda **kw: {
            "status": "Undeclared_Behavior",
            "cited_unit_ids": ["u_0001"],
            "reason": "Suspicious write",
        },
    )
    assert res_undecl["status"] == "INDETERMINATE"

    # LLM down (returns None) -> INDETERMINATE
    res_down = judge_postcondition(
        contract,
        units,
        stdout="outage none",
        cache_path=str(tmp_path / "c4.json"),
        llm_caller=lambda **kw: None,
    )
    assert res_down["status"] == "INDETERMINATE"

    # LLM raises exception -> INDETERMINATE
    def raising_caller(**kw):
        raise RuntimeError("API timeout")

    res_exc = judge_postcondition(
        contract,
        units,
        stdout="outage exc",
        cache_path=str(tmp_path / "c5.json"),
        llm_caller=raising_caller,
    )
    assert res_exc["status"] == "INDETERMINATE"
    assert "API timeout" in res_exc["reason"]


def test_w5_sha256_cache_prevents_duplicate_llm_calls(tmp_path: Path) -> None:
    _MEMORY_POSTCONDITION_CACHE.clear()
    contract, units = _sample_contract_and_units()
    cache_file = str(tmp_path / "persistent_cache.json")
    calls = {"count": 0}

    def counting_llm(**kw) -> Dict[str, Any]:
        calls["count"] += 1
        return {
            "status": "PASS",
            "cited_unit_ids": ["u_0001"],
            "reason": "Cached evaluation",
        }

    r1 = judge_postcondition(contract, units, stdout="same_out", stderr="", cache_path=cache_file, llm_caller=counting_llm)
    r2 = judge_postcondition(contract, units, stdout="same_out", stderr="", cache_path=cache_file, llm_caller=counting_llm)
    assert r1["status"] == "PASS"
    assert r2["status"] == "PASS"
    assert calls["count"] == 1

    # Clear memory cache and verify disk cache is hit without calling counting_llm
    _MEMORY_POSTCONDITION_CACHE.clear()
    r3 = judge_postcondition(contract, units, stdout="same_out", stderr="", cache_path=cache_file, llm_caller=counting_llm)
    assert r3["status"] == "PASS"
    assert calls["count"] == 1

    key = compute_postcondition_cache_key(contract.id, contract.postcondition, units, "same_out", "")
    assert len(key) == 64


def test_w5_integration_with_pure_judge_and_wrapper(tmp_path: Path) -> None:
    _MEMORY_POSTCONDITION_CACHE.clear()
    contract, units = _sample_contract_and_units()
    evidence = Evidence(
        run_status=RunStatus(entry_reached=True, exit_code=0),
        behavior_units=units,
        check_results=(),
        stdout='{"items": [3, 1, 2]}',
        stderr="",
        fs_diff=(),
    )

    cfg_contra = JudgeConfig(
        postcondition_judge_fn=lambda c, bu, out, err: judge_postcondition(
            c,
            bu,
            out,
            err,
            cache_path=str(tmp_path / "j_contra.json"),
            llm_caller=lambda **kw: {
                "status": "CONTRADICTED",
                "cited_unit_ids": ["u_0002"],
                "reason": "Items are not sorted",
            },
        )
    )
    j_res = judge((contract,), evidence, cfg_contra)
    assert j_res.verdict == "Semantically_Divergent"
    assert j_res.contract_status[0].status == "CONTRADICTED"
    assert j_res.contract_status[0].cited_unit_ids == ("u_0002",)

    # Verify backward-compatible adjudicate_skill_behavior wrapper delegates to judge()
    legacy_out = adjudicate_skill_behavior(
        contracts=[
            {
                "contract_id": "C_01",
                "precondition": "Workspace writable",
                "postcondition": "Writes output.txt",
                "frame_axiom": ["write: /app/skill/output.txt"],
                "forbidden_invariant": [],
            }
        ],
        traces=[
            {
                "events": [
                    {
                        "event_type": "filesystem",
                        "first_line": 12,
                        "details": {"operation": "write", "path": "/app/skill/output.txt"},
                    }
                ]
            }
        ],
        skill_dir=str(tmp_path),
        run_status="INVOKED_SUCCEEDED",
        entry_point_reached=True,
        assertion_results=[{"check_id": "chk_1", "contract_id": "C_01", "passed": True, "attempted": True}],
        stdout="done",
        stderr="",
    )
    assert legacy_out["verdict"] == "Aligned"
    assert legacy_out["coverage"] == 1.0
