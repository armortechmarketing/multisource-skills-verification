# Remediated Trace Analysis Package (Complete 63-Skill Evaluation)

This package contains the complete, self-contained forensic review and trace analysis for all **63 skills** evaluated across the remediated verification pipeline.

## Structure
- `review_cards/`: Individual markdown cards for all **63 skills** following the strict 7-section review structure (0. Summary, 1. CONTRACTS, 2. TESTS, 3. EXECUTION, 4. TRACES, 5. JUDGMENT, 6. ROOT CAUSE).
- `review_summary.csv`: Reviewer ratings, pipeline vs reviewer verdicts, and root causes for all 63 skills.
- `human_review_sheet.csv`: Independent review template for human evaluators.
- `automatic_checks.csv`: Automated sanity metrics computed across all skills.
- `dynamic_samples/`: Complete sample directories for Sample 1 (Script RealEnv, 30 skills), Sample 2 (Instruction Codex, 30 skills), and Extra Skills (3 skills).
- `jobs/`: All **27 Job Batches** containing the dynamic trial logs (stdout, stderr, callsites.jsonl, strace.log, run_status.json).
- `harbor_tasks/`: All **27 Harbor Task Waves** containing adapted environments, test definitions, and task configs.

## Evaluation Breakdown (63 Skills Total)
- **Script Skills (Sample 1):** 30 skills (22 Level-2 Executed + 8 Level-1 Static Blocked)
- **Instruction Skills (Sample 2):** 30 skills (23 Level-2 Executed + 7 Level-1 Static Blocked)
- **Extra Skills:** 3 skills (All 3 Level-2 Executed)
- **Total Executed at Level-2:** 48 skills
- **Total Blocked at Level-1 (Static CRITICAL Security Gate):** 15 skills

## Summary Verdict Distribution
- **`Inconclusive(INFRA)`:** 16 skills
- **`Blocked_Static_CRITICAL`:** 15 skills
- **`Inconclusive(SKILL_CRASH)`:** 11 skills
- **`Inconclusive(LOW_COVERAGE)`:** 9 skills
- **`Aligned`:** 4 skills
- **`Undeclared_Behavior`:** 3 skills
- **`Inconclusive(TELEMETRY_GAP)`:** 3 skills
- **`Inconclusive(HARNESS)`:** 2 skills
