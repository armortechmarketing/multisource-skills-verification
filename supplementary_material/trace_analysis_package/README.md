# Baseline Trace Analysis Package (Original System 63-Skill Suite)

This package contains the complete baseline trace review across all **63 skills** as recorded under the **original (un-remediated) pipeline** between October 31 and November 1, 2026.

## Structure
- `review_cards/`: Individual markdown cards for all **63 skills** documenting baseline pipeline verdicts, evidence, and false negative failure modes.
- `review_summary.csv`: Reviewer ratings and root cause analysis across all 63 baseline skills. 
- `human_review_sheet.csv`: Independent review template for human evaluators.
- `automatic_checks.csv`: Automated sanity metrics computed across all baseline skills.
- `dynamic_samples/`: Baseline dynamic samples (`sample_20261031_160720_e1dbcc_realenv` and `sample_20261101_091725_b8e79d`).
- `jobs/`: Exactly **22 Baseline Job Batches** (raw logs, stdout, stderr, callsites).
- `harbor_tasks/`: Exactly **20 Baseline Harbor Task Waves** (task configurations from Oct 31 / Nov 1).

## Key Baseline Pipeline Failure Modes Documented
1. **False `Unimplemented_Intent` (18 skills):** The baseline pipeline failed to separate execution crashes (e.g. `RecursionError` in `benign_bank-t184`, missing local files in `benign_free-imagegen`) from intent disobedience.
2. **False `Semantically_Divergent` (2 skills):** Missing Python runtime dependencies or `--dry-run` traps were falsely scored as semantic divergence.
3. **Low Agreement Rate:** Human reviewer agreed with only **12.1%** of baseline pipeline verdicts.
