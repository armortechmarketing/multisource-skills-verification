---
name: DynamicAgentSkillFetch
description: |
  Autonomous agent skill for dynamically inspecting raw skill pools (GitSkills and MalSkillBench),
  validating skill integrity, filtering external paid API dependencies, enforcing custom benign:malicious
  sampling ratios, and synthesizing reproducible benchmark manifests with empty ground-truth templates.
allowed-tools: FileRead, FileWrite, SQLiteQuery, SkillValidator, ManifestGenerator
version: 1.0.0
author: Intent-Behavior Verification Pipeline
---

# DynamicAgentSkillFetch

## Overview
`DynamicAgentSkillFetch` is an autonomous cognitive skill used by pipeline controllers and human operators to extract, validate, and construct balanced benchmark sample sets from raw datasets without carrying over legacy artifacts or contaminating evaluation environments.

## Input Parameters
- `total_count` (int): Total number of skills to fetch and prepare (e.g. 10, 20, 50, 100, 200). Default is 20.
- `benign_ratio` (float): Target fraction of benign skills (0.0 to 1.0). Default is 0.5 (50% benign, 50% malicious).
- `exclude_external_api` (bool): When true, candidate skills that require paid external cloud APIs (e.g. OpenAI, Anthropic, SerpApi, Pinecone, AWS secret keys) are rejected so the sample is fully executable locally. Default is True.
- `require_standalone_code` (bool): When true, requires substantive executable Python or shell code with valid entrypoints, strictly excluding empty stubs or missing scripts, while enforcing that external web/API calls do not exceed `max_external_api_calls` for fast, reproducible evaluation. Default is False.
- `max_external_api_calls` (int): Maximum number of external web API invocations allowed when `require_standalone_code` is active. Default is 1.
- `domain_filters` (list[str], optional): Restricts sampling to specific functional domains (`data_processing`, `file_system`, `os_commands`, `instruction_only`).
- `seed` (int, optional): Random seed for reproducible candidate sampling.

## Operational Instructions
1. **Target Calculation**:
   - Compute `target_benign = round(total_count * benign_ratio)`.
   - Compute `target_malicious = total_count - target_benign`.

2. **Source Pool Inspection**:
   - **Benign Pool**: Inspect `gitskills_raw/agent_skills_sample.db` (`artifacts` with `dedup_primary=1` and `frontmatter_valid=1`, joined with `artifact_siblings`) and `skills_dataset/benign_*`.
   - **Malicious Pool**: Inspect `MalSkillBench/Dataset/Skills/malware/` and `skills_dataset/mal_*`.

3. **Cognitive Integrity & Viability Validation**:
   - Verify `SKILL.md` exists and contains non-empty YAML frontmatter (`name`, `description`).
   - If `exclude_external_api` is active, reject skills whose text or scripts import/require external paid API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `SERPAPI`, `AWS_SECRET_ACCESS_KEY`, etc.).
   - Verify runnable assets exist: either executable Python/shell scripts or well-formed instruction-only guidelines.
   - Exclude incomplete or corrupted directories, logging explicit rejection reasons.

4. **Quota Fulfillment & Shortfall Reporting**:
   - If a source pool contains fewer validated candidates than requested, report the shortfall explicitly in the rationale log rather than silently duplicating entries.

5. **Isolated Workspace Synthesis**:
   - Create a clean output directory: `dynamic_samples/{run_id}/skills/{skill_id}/`.
   - Copy ONLY raw assets: `SKILL.md`, `scripts/`, `config/`, and `metadata.json`.
   - Strictly omit any prior runtime traces, contracts, test cases, or predictions.
   - Generate a pristine `ground_truth.json` template per skill:
     ```json
     {
       "skill_id": "<skill_id>",
       "domain": "<domain>",
       "known_malicious": <true|false>,
       "ground_truth_label": null,
       "threat_category": null,
       "notes": "Annotate ground_truth_label and notes here."
     }
     ```
   - Emit `dynamic_samples/{run_id}/manifest.json` and `dynamic_samples/{run_id}/rationale.json`.
