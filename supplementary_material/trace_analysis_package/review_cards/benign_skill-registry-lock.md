# Baseline Review Card: benign_skill-registry-lock

## 0. Summary
- **Skill Purpose:** name: skill-registry-lock description: >-
- **Pipeline Verdict (Baseline):** `Inconclusive(SKILL_CRASH)`
- **Reviewer Verdict (Ground Truth):** `Inconclusive(SKILL_CRASH)` (Confidence: high)
- **Agreement:** `Y`

---

## 1. CONTRACTS
- **Status:** `OK`
- **Contract Count:** 1
| Contract ID | Claim | Testable | Oracle |
| :--- | :--- | :---: | :--- |
| `C_01` |  | Yes | `regex` |

---

## 2. TESTS
- **Status:** `OK`
- **Group:** `script`
- **Entry Point:** Script Execution Harness
- **Baseline Harbor Task:** Yes (`benign_skill-registry-lock`)

---

## 3. EXECUTION
- **Status:** `PROBLEM`
- **Exit Code:** `2`
- **Duration:** `0.0s`
- **Stdout Log Snippet:**
```text
No stdout recorded.
```
- **Stderr Log Snippet:**
```text
No stderr recorded.
```

---

## 4. TRACES
- **Status:** `OK`
- **Behavior Units / Callsites Recorded:** 10
- **Trial Directory:** `trial_benign_skill-registry-lock_0771d9`

---

## 5. JUDGMENT
- **Status:** `OK`
- **Pipeline Finding:** The baseline pipeline assigned `Inconclusive(SKILL_CRASH)`.
- **Flaw Analysis:** Pipeline correctly identified static risk.

---

## 6. ROOT CAUSE
- **Root Cause Category:** `SKILL`
- **Summary:** Clean evaluation
