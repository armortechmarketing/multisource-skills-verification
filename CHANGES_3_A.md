# CHANGES_3_A — Agent A Judge-Side Verdict Quality

## Summary

Judge-side fixes for false negatives from failed invocations, invalid exercise, agent telemetry gaps, speculative J2 guards, and weak oracles. New canonical classifier: `src/failure_classifier.py`. Agent B modules were not modified.

## A1 — `src/failure_classifier.py`

- New `FailureInfo` + `classify_failure(stdout, stderr, exit_code, run_status, harbor_exception, skill_dir, test_args)`.
- Classes: `NONE | USAGE_ERROR | FILE_NOT_FOUND_INPUT | MISSING_* | PERMISSION | NETWORK_ERROR | TIMEOUT | HARNESS_EXCEPTION | AGENT_NO_TELEMETRY | SKILL_TRACEBACK | UNKNOWN_FAILURE`.
- Maps to `no_verdict_reason`: USAGE/FILE_NOT_FOUND → `HARNESS`; MISSING_*/PERMISSION/NETWORK/TIMEOUT/HARNESS_EXCEPTION → `INFRA`; AGENT_NO_TELEMETRY → `TELEMETRY_GAP`; SKILL_TRACEBACK/UNKNOWN → `SKILL_CRASH` (+ `low_confidence` for UNKNOWN).
- Tests: `tests/test_failure_classifier.py`.

## A2 — J0 wire (`src/judge.py` `classify_run_health`)

- Calls `_build_failure_info` / `classify_failure` on every Evidence.
- Failed-invocation classes → `RunHealth(NOT_RUN, reason=mapped)` (CRLF shebang still wins over MISSING_BINARY).
- J3 hard gate: failed-invocation never emits Semantically_Divergent / Unimplemented_Intent; J1 Undeclared still wins when violations observed.
- `JudgeResult` carries `failure_class`, `failure_symptom`, `missing`, `low_confidence`.

## A3 — Valid-exercise gate

- `Evidence` optional Agent-B fields: `entry_kind`, `targets_contracts`, `preconditions_satisfied`, `flags_used`, `passive_flags_used`, `placeholder_inputs_used`, `secret_args_used`, `run_kind`, `trajectory_*`, `agent_messages`, `harbor_exception`, `test_args`.
- `ContractStatusRecord`: `exercise_valid`, `exercise_reason`, `strength`.
- CONTRADICTED / EFFECT_ABSENT / STUB demoted to `NOT_EXERCISED` when exercise invalid (STUB kept for NotImplemented/AST when not a failed-invocation class).
- Legacy Evidence (Agent-B fields unset) uses `exercise_valid_legacy` when entry reached + `failure_cls==NONE` + input valid.
- DTC prefers `exercise_valid` contracts.

## A4 — Agent path

- `run_kind==agent` / instruction-only: never script EFFECT_ABSENT/STUB.
- `trajectory_present && trajectory_units==0` → `Inconclusive(TELEMETRY_GAP)`.
- Agent timeout remains INFRA/TIMEOUT via classifier.

## A5 — J2 LLM / speculative guard

- Speculative regex no longer fires on `could not` (negative lookahead). Factual `cannot` / `did not` / `unable to` were never matched as speculative tokens.
- `judge_postcondition` accepts `failure_info`, `test_args`, `flags_used`; prompt includes them; CONTRADICTED must not rest solely on failure-class stderr.
- `agent_skills/a_adj_j2` version **1.2.0**; `J2_GUARD_VERSION` **2.1.0** included in cache key.

## A6 — Oracle strength

- `classify_check_strength(check)` → `strong` | `weak`.
- Env `ALIGNED_REQUIRE_STRONG` (default `0`): when `1`, Aligned requires ≥1 strong PASS else `Inconclusive(LOW_COVERAGE)` with `weak_oracles_only`.
- Prediction emits `strong_pass_count` / `weak_pass_count`.

## A7 — Engrenagem / same-trial

- Finding: human sheet PARTIAL — earlier exit-2 trials mixed with exit_code=0 PASS oracles.
- `assert_same_trial_consistency`: detects check detail `exit_code=0` PASS while `run_status.exit_code != 0`. Soft by default; `JUDGE_STRICT_TRIAL=1` raises.
- Regression: `tests/test_engrenagem_same_trial.py`.

## A8 — Plumbing

- `pipeline_runner.derive_gating_status` / `_infer_no_verdict_reason`: `TELEMETRY_GAP` → `INCONCLUSIVE_TELEMETRY_GAP`; skill records include `failure_class`.
- `orch_policy`: `TELEMETRY_GAP` non-refinable (with INFRA/NO_ENTRY/NO_AGENT).
- `streamlit_app`: `Inconclusive(TELEMETRY_GAP)` in `CANONICAL_LABELS`; findings show `failure_class` / `exercise_reason`.
- README §7.2 documents TELEMETRY_GAP + failure_class.

## New env vars

| Var | Default | Meaning |
|-----|---------|---------|
| `ALIGNED_REQUIRE_STRONG` | `0` | Require ≥1 strong oracle for Aligned |
| `JUDGE_STRICT_TRIAL` | `0` | Raise on same-trial exit_code inconsistency |

## Control expectation change (C7)

- **Before:** usage + exit 0 → `INCONCLUSIVE_NO_ACTION` / `Not_Executed(USAGE_ONLY)`.
- **After:** classifier `USAGE_ERROR` → `Not_Executed(HARNESS)` / `Inconclusive(HARNESS)`.
- Justification: usage/argparse is a harness/invocation failure (refinable HARNESS), not “no action”. Spec `expected_verdicts` updated to accept both.

## Calibration status

- `run_controls_check.py`: **C1–C11 all PASS** after C7 expectation update.
- New unit tests: failure_classifier, judge_validity (1–19), engrenagem, differential — PASS.
- `tests/fixtures/make_cases.py` (30 random): invariants hold.
- Replay: soft match against `analysis/golden_expectations.csv` (33 skills); missing trial artifacts skipped.

## Differential (new vs `HEAD:src/judge.py`)

Allowed deltas only: negative→Inconclusive, SKILL_CRASH→HARNESS/INFRA/TELEMETRY_GAP, Aligned unchanged. Table exercised in `tests/test_judge_differential.py` (PASS).

## Attribution / env notes (not Agent A regressions of verdict taxonomy)

- `test_t3_undeclared_bashrc_attribution` / `test_t3_cal_env_exfil_attribution`: verdict Undeclared OK; empty `code_sites` on this Windows host (callsite localization).
- `test_t5_20_skills_sample_attribution_coverage`: missing `dynamic_samples/sample_20261011_182032_1062b5`.
- `_resolve_target_file_content` now materializes path-valued `written_files` entries so json_schema calibration can CONTRADICT.

## Agent B issues found but not fixed

- `telemetry_parser.py` / `nodes.py` do not yet populate Agent-B Evidence fields (`entry_kind`, `targets_contracts`, …); judge uses legacy-compat until they do.
- Production Evidence without those fields cannot apply the strict exercise gate.
- Harbor/redirect empty stderr for some ENV misses remains a harness packaging issue.

## Deliverables

- Code + tests as above
- `analysis/golden_expectations.csv`
- `CHANGES_3_A.md` (this file)
- `changes_agentA.patch` (via `git add -N` + `git diff`)
