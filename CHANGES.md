# CHANGES.md — Step 1, Step 2, and Step 3 Implementation Report

## Summary of Completed Work
This document details all code changes, architectural enhancements, environment variables, security considerations, and verification procedures implemented across Steps 1, 2, and 3.

---

## 1. Step 1: Judge Correctness & Calibration
### 1.A DTC Split & Aligned Rule
- **Previous conflated definition**: `coverage = pass_count / total_contracts` conflated "exercised" with "passed", treating unexercised contracts and failed contracts identically.
- **New split definition**:
  - `dtc = exercised_contracts / testable_contracts` where `exercised = (status != "NOT_EXERCISED")`.
  - `csr_c = pass_count / testable_contracts` (contract satisfaction rate among testable contracts).
  - Denominator excludes non-testable contracts (`testable == False`).
- **Aligned Rule**:
  - Requires `pass_count >= 1`, 0 `CONTRADICTED`, 0 `UNIMPLEMENTED` (`STUB` or `EFFECT_ABSENT`), 0 `VIOLATIONS`, and `dtc >= ALIGNED_MIN_DTC` (default `0.8`).
  - Below threshold yields `Inconclusive(no_verdict_reason="LOW_COVERAGE")`, triggering the supervisor refinement loop.
  - Default `MAX_REFINEMENT_ATTEMPTS` raised from `2` to `3`.
- **Legacy Contracts**:
  - Contracts lacking `testable` default to `testable = True`.
  - Contracts lacking `expects_effect` default to `expects_effect = False` (or infer `True` if `frame_axiom.write` or substantive checks exist).
- **Files Modified**:
  - `src/judge.py`: lines ~66-67 (`Contract.testable`, `Contract.expects_effect`), lines ~153-178 (`JudgeConfig`), lines ~1450-1530 (`_aggregate_verdict`).
  - `src/a_syn_contract_synthesizer.py`: lines ~340-390 (schema validation enforces `testable` and `expects_effect`).
  - `src/nodes.py`: lines ~520-550 (exporting `dtc` and `csr_c`).
  - `src/pipeline_runner.py`: lines ~245-275, 390-410 (DTC & CSR_C reporting in summaries and records).
  - `streamlit_app.py`: lines ~400-450 (KPI cards for DTC & CSR_C).

### 1.B EFFECT_ABSENT Guard
- **Specification**: Emit `EFFECT_ABSENT` (yielding `Unimplemented_Intent`) ONLY if:
  1. Entry point reached (`entry_reached == True`);
  2. Exit code is 0 (`exit_code == 0`);
  3. Test input was valid (`_is_test_input_valid(evidence) == True`, rejecting CLI usage/help/argparse error strings);
  4. Contract expects an observable effect (`contract.expects_effect == True`, or substantive write/check declared).
  Otherwise status is marked `NOT_EXERCISED` so the supervisor refines test inputs.
- **Files Modified**:
  - `src/judge.py`: lines ~1070-1095 (`_is_test_input_valid`, `_can_emit_effect_absent`), lines ~1180-1200, 1270-1285.

### 1.C Static Level-1 Signal Isolation
- Verified and enforced that static Level-1 signals (`MEDIUM`/`HIGH`) added to `forbidden_invariant` NEVER trigger `Undeclared_Behavior` on their own; only observed runtime OS `BehaviorUnit` events can trigger runtime violations.
- **Files Tested**: `tests/test_step1_judge.py`.

### 1.D AST Stub & Call-Path Detection
- `ast_is_stub` triggers `STUB` only if the stub function is the entry point or appears in the executed call path (verified via `callsites.jsonl` or stack traceback).
- `NotImplementedError` triggers `STUB` only if the exception originates within the skill package directory (ignoring external library or harness internals).
- **Files Modified**: `src/judge.py`: lines ~1010-1045.

---

## 2. Step 2: Provider-Agnostic Harbor Agent
### 2.A Dynamic Model & Provider Key Dispatch
- **Architecture**: Mapped CLI agents and model provider credentials cleanly without hardcoding vendor secrets:
  - `claude-code`: maps to `ANTHROPIC_API_KEY` (allowing `api.anthropic.com`)
  - `codex`: maps to `OPENAI_API_KEY` (allowing `api.openai.com`)
  - `gemini-cli`: maps to `GEMINI_API_KEY` (allowing `generativelanguage.googleapis.com`)
  - `qwen-coder`: maps to `DASHSCOPE_API_KEY`
- **Dynamic Config**: `get_instruction_agent_config()` dynamically resolves agent, target model, secret key environment variable name, and secret token value.
- **Security & Residual Key Exposure Risk**:
  - Keys are passed strictly via subprocess environment dictionary (`env=h_env`). Key values are NEVER placed on the CLI command line.
  - Egress filtering uses `--allow-agent-host` for declared endpoints and model provider host.
  - *Residual Key-Exposure Risk*: Inside the container, any subprocess running under the agent account inherits the container's environment variables. If an untrusted skill executes code within the same container user context, it could inspect `/proc/self/environ` to read API keys. To mitigate this in multi-tenant environments, run Harbor with isolated credential helper proxies.
- **Key Scrubbing**:
  - Comprehensive recursive scrubbing functions: `get_keys_to_scrub()`, `scrub_api_keys()`, `scrub_api_keys_in_object()`, and `scrub_api_keys_in_dir()`.
  - Scrub all trial directories, artifacts, logs, stderr, stdout, and telemetry prior to reporting.
- **Clean Inconclusive Fallback**:
  - When keys are missing or contain dummy tokens, emit `Inconclusive(NO_AGENT)` cleanly with explanatory stderr logs without creating fake trajectories.
- **Canary Exfiltration Protection**:
  - `detect_canary_content_exfiltration` updated to accept `written_files_dir`, inspecting skill-written files while ignoring harness metadata.
- **Files Modified**:
  - `src/harbor_runner.py`: lines ~50-130, 260-310, 680-790, 870-930.
  - `src/telemetry_parser.py`: lines ~80-120.
  - `tests/test_step2_harbor_agent.py`: 5 unit tests validating provider dispatch, CLI scrubbing, and file scanning.

---

## 3. Step 3: Multi-Agent Alignment & Verification
### 3.A Standardized Agent Skills Directory (`agent_skills/`)
- Created standardized agent packages with `SKILL.md` frontmatter and `schemas/output.schema.json`:
  1. `agent_skills/a_syn/`: Contract synthesis and Level-1 security specification.
  2. `agent_skills/a_gen/`: Dynamic test fixture and AST-grounded test generation.
  3. `agent_skills/a_orch/`: Orchestration supervisor tool-calling and directive loop.
  4. `agent_skills/a_adj/`: Adjudication and grounded explanation generation.

### 3.B Skill Loader & Versioning (`src/agent_skill_loader.py`)
- `list_agent_skills(base_dir)`: Discovers installed agent skill directories.
- `load_agent_skill(agent_name, base_dir)`: Parses frontmatter metadata, extracts markdown body, computes SHA-256 `skill_version_hash`, and loads `output_schema`.
- `get_agent_system_prompt(agent_name, fallback_prompt)`: Dynamic system prompt retriever.

### 3.C AST Schema & Parameter Grounding in A_gen
- AST grounding extracts parameters for `argparse`, `click`, and `sys.argv` from Python entry points, allowing test generator to synthesize valid CLI arguments and mock fixtures.

### 3.D Grounded Adjudication Explanation (`src/a_adj_adjudicator.py`)
- `generate_grounded_explanation(...)` generates an objective finding summary citing valid `BehaviorUnit.id`s, contract statuses, and violation rules.
- **Invariant**: Strictly preserves `assert result.verdict == verdict_before`. Adjudication explanations never mutate or override the deterministic judge verdict.

### 3.E Extended Call Chains in Attribution (`src/attribution.py`)
- `CodeSite`: Added `call_chain: Tuple[str, ...] = ()` representing the stack chain (`"file:function:line"`).
- `verify_code_site`, `attribute_undeclared_behavior`, and `attribute_semantically_divergent` extract the caller hierarchy from `callsites.jsonl`.
- Surfaced in `streamlit_app.py` under the Causal Attribution inspector.

### 3.F Dynamic Supervisor Agent & Orch Policy (`src/orch_policy.py`, `src/orch_supervisor.py`)
- **Deterministic Policy**: `orch_policy.py` defines `ALLOWED_SUPERVISOR_TOOLS` and deterministic rules (`deterministic_policy_decision`, `validate_supervisor_decision`).
- **Tool-Calling Supervisor**: `supervisor_step` queries LLM (`AORCH_MODEL`, temperature 0) when enabled, validates decision against `orch_policy` guardrails, logs every decision to `agent_messages`, and produces tactical directives with stderr snippets.
- **Shared Implementation**: LangGraph nodes (`supervisor_eval_node` in `src/nodes.py`) and batch wave engine (`_execute_manifest_batch_waves` in `src/pipeline_runner.py`) share the exact same `supervisor_step` implementation.
- **Inter-Agent Messages**: `agent_messages: List[Dict[str, Any]]` recorded across all nodes and serialized in `report.json` and Streamlit UI.

### 3.G Verification of Goal-Drift Auditor & Unwired Modules
- Verified `goal_drift_auditor.py` is invoked during instruction-only trajectory evaluation in `src/harbor_runner.py` and `src/nodes.py:adjudicate_node`. Trajectory hijacking markers trigger `Undeclared_Behavior`.
- `repair_controller.py`: Per Amendment A6, `repair_controller.py` is preserved unwired in `src/` to prevent unwanted auto-modification of harnesses.

---

## 4. Environment Variables Added / Updated

| Variable | Default | Purpose |
|---|---|---|
| `ALIGNED_MIN_DTC` | `0.8` | Minimum DTC (Dynamic Test Coverage) required for `Aligned` verdict. |
| `ALIGNED_MIN_COVERAGE` | `0.8` | Deprecated alias maintained for backward compatibility. |
| `MAX_REFINEMENT_ATTEMPTS` | `3` | Maximum number of refinement iterations (raised from 2 to 3). |
| `USE_LLM_AORCH` | `0` | Enable LLM tool-calling for A_orch supervisor (`1` = ON, `0` = deterministic). |
| `AORCH_MODEL` | `gpt-4o-mini` | LLM model for supervisor agent decisions (temperature 0). |
| `USE_LLM_EXPLAINER` | `0` | Enable LLM narrative generation in post-verdict explanation. |
| `AADJ_MODEL` | `gpt-4o-mini` | LLM model for adjudication explanations. |
| `ASYN_MODEL` | `gpt-4o-mini` | LLM model for contract synthesis. |
| `AGEN_MODEL` | `gpt-4o-mini` | LLM model for test fixture generation. |

### LLM Defaults Status
- **Deterministic First**: In all default environments without explicit LLM flags, `USE_LLM_AORCH=0`, `USE_LLM_EXPLAINER=0`, and `USE_LLM_POSTCONDITION=0`. All decisions fall back safely and deterministically to the formal rules in `orch_policy.py`, `judge.py`, and `attribution.py`.
- **LLM-Enabled**: When API keys are set and `USE_LLM_*=1`, agents call LLM with temperature 0.0 and validate all outputs against JSON schemas and policy guardrails.

---

## 5. How to Test and Verify

1. **Preflight Calibration Controls (Must Pass 100%)**:
   ```powershell
   & d:\research\venv\Scripts\python.exe run_controls_check.py
   ```
   *Expected*: `ALL CONTROLS PASSED: True` (C1 through C11).

2. **Step 1 Unit Tests**:
   ```powershell
   & d:\research\venv\Scripts\python.exe -m pytest tests/test_step1_judge.py -v
   ```
   *Expected*: 4 passed.

3. **Step 2 Unit Tests**:
   ```powershell
   & d:\research\venv\Scripts\python.exe -m pytest tests/test_step2_harbor_agent.py -v
   ```
   *Expected*: 5 passed.

4. **Step 3 Unit Tests**:
   ```powershell
   & d:\research\venv\Scripts\python.exe -m pytest tests/test_step3_multi_agent.py -v
   ```
   *Expected*: 6 passed.

5. **Acceptance and Attribution Tests**:
   ```powershell
   & d:\research\venv\Scripts\python.exe -m pytest tests/test_attribution.py -k test_t3_unimplemented_absence_attribution
   & d:\research\venv\Scripts\python.exe -m pytest tests/test_w1_judge.py -k "test_21 or test_24"
   & d:\research\venv\Scripts\python.exe -m pytest tests/test_w7_acceptance.py -k test_w7_supervisor_refinement_loop_recovers_harness_and_stops_on_violation
   ```
   *Expected*: All passed.

6. **Full Dynamic Sample Run**:
   ```powershell
   & d:\research\venv\Scripts\python.exe verify_step3_sample20.py
   ```
   *Expected*: Completes all 20 skills, records `agent_messages` per skill, and computes DTC / CSR_C metrics.
