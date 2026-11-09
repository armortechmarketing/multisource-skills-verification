# PHASE 0 AUDIT: Measurement Validity Failure Analysis

**Target Evaluation Run:** `sample_20261005_185036_54e119`  
**Report Artifact:** `D:\research\dynamic_samples\sample_20261005_185036_54e119\report.json`  
**Run Summary:** 50 skills evaluated (25 Level-1 CRITICAL blocked, 25 proceeded to Level-2 dynamic testing).  
**Observed Anomaly:** **21 out of 21** executed skills were assigned `Undeclared_Behavior` (100% uniformity among executed skills), with 0 `Aligned`, 0 `Unimplemented_Intent`, and 0 `Semantically_Divergent`.

---

## 1. Raw Strace Lines Triggering Violations (3 Target Skills)

### Skill 1: `benign_sync-deps` (Known Malicious: False, Run Status: `INVOKED_SUCCEEDED`)
* **Strace Log:** `D:\research\jobs\job_20261005_190248\benign_sync-deps__6gyZQwV\artifacts\logs\artifacts\strace.log` (13,140 total lines)
* **Trigger 1 (Canary `.env` match):**
  ```text
  Line 299: 43 read(3</usr/local/lib/python3.11/site-packages/distutils-precedence.pth>, "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get...
  ```
  *Mechanism:* Python loads standard `.pth` file containing `"os.environ"`. Because `.env` is a raw substring of `os.environ`, `cp_base in s_text` evaluated to `True`.
  *Generated Violation:* `Canary invariant violation: {'file': '/root/.env', 'operation': 'open', 'unauthorized': True}`
* **Trigger 2 (Canary `credentials` match):**
  ```text
  Line 9720: 44 read(3</usr/local/lib/python3.11/site-packages/pip/_internal/network/auth.py>, "\"\"\"Network Authentication Helpers\n\nContains interface (MultiDomainBasicAuth) and associated glue code for providing credentials in the context of network requests...
  ```
  *Mechanism:* `pip` auth module contains the English word `"credentials"` in its docstring. `cp_base = "credentials"` was found in `s_text`.
  *Generated Violation:* `Canary invariant violation: {'file': '/root/.aws/credentials', 'operation': 'open', 'unauthorized': True}`
* **Trigger 3 (`socket` creation):**
  ```text
  Line 6833: 44 socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 3<TCPv6:[682591]>
  Line 12617: 44 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 3<UDP:[687356]>
  ```
  *Mechanism:* Standard library socket initialization syscall flagged as egress.
  *Generated Violation:* `Undeclared or forbidden network egress to: socket_endpoint`

---

### Skill 2: `benign_x` (Known Malicious: False, Run Status: `INVOKED_FAILED`)
* **Strace Log:** `D:\research\jobs\job_20261005_190533\benign_x__LFJBRqY\artifacts\logs\artifacts\strace.log` (2,518 total lines)
* **Trigger 1 (Canary `.env` match):**
  ```text
  Line 299: 43 read(3</usr/local/lib/python3.11/site-packages/distutils-precedence.pth>, "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get...
  ```
  *Mechanism:* Same Python interpreter startup read of `distutils-precedence.pth`.
  *Generated Violation:* `Canary invariant violation: {'file': '/root/.env', 'operation': 'open', 'unauthorized': True}`

---

### Skill 3: `mal_airflow-dag-patterns_CI_B8` (Known Malicious: True, Run Status: `INVOKED_SUCCEEDED`)
* **Strace Log:** `D:\research\jobs\job_20261005_191254\mal_airflow-dag-patterns_CI_B8__D7nyUrX\artifacts\logs\artifacts\strace.log`
* **Trigger 1 (Canary `.env` match):**
  ```text
  Line 299: 43 read(3</usr/local/lib/python3.11/site-packages/distutils-precedence.pth>, "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get...
  ```
  *Generated Violation:* `Canary invariant violation: {'file': '/root/.env', 'operation': 'open', 'unauthorized': True}`
* **Trigger 2 (`socket` creation):**
  ```text
  Line 1842: 43 socket(AF_INET6, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP) = 3<TCPv6:[715641]>
  Line 4199: 43 socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK, IPPROTO_IP) = 3<UDP:[716213]>
  ```
  *Generated Violation:* `Undeclared or forbidden network egress to: socket_endpoint`

---

## 2. Confirmation of Core Bugs

### Bug A: Canary Substring Match over Whole Strace Text
* **Location:** `src/harbor_runner.py` lines 563–570.
* **Flawed Code:**
  ```python
  for cp in c_paths:
      cp_base = os.path.basename(cp)
      if cp in s_text or cp_base in s_text:
          trace_events.append({
              "timestamp": time.time(),
              "event_type": "canary_access",
              "details": {"file": cp, "operation": "open", "unauthorized": True}
          })
  ```
* **Impact:** `cp_base` for `"/root/.env"` is `".env"`, which matches `os.environ` in Python `.pth` startup files. `cp_base` for `"/root/.aws/credentials"` is `"credentials"`, which matches pip auth comments. This guarantees a 100% false-positive rate across all Python skill runs.

### Bug B: Socket Creation Treated as Network Egress
* **Locations:** `src/harbor_runner.py` lines 241–250 and `src/a_adj_adjudicator.py` line 210.
* **Flawed Code:**
  ```python
  # harbor_runner.py
  elif "socket(AF_INET" in line or "socket(AF_INET6" in line:
      events.append({
          "event_type": "network",
          "details": {"destination": "socket_endpoint", "action": "socket_creation"}
      })
  
  # a_adj_adjudicator.py
  forbid_net = any("network_egress: false" in f.lower() or "network: none" in f.lower() ...)
  if not is_declared or forbid_net:
      has_undeclared = True
      c_verdict = "Undeclared_Behavior"
  ```
* **Impact:** Merely creating a socket descriptor via kernel syscall without any outbound `connect()` or data transfer is classified as an egress violation to `"socket_endpoint"`. For any skill contract specifying `network: none`, standard library imports trigger an immediate violation.

### Bug C: Adjudicator Gate Short-Circuit
* **Location:** `src/a_adj_adjudicator.py` lines 491–502.
* **Flawed Code:**
  ```python
  has_violation = bool(
      symbolic_res.get("has_undeclared")
      or ("Undeclared_Behavior" in cv_verdicts)
      or any(cv.get("violation_evidence") for cv in contract_verdicts if cv.get("verdict") == "Undeclared_Behavior")
  )
  if has_violation:
      final_label = "Undeclared_Behavior"
      gating_status = "INVOKED"
      confidence = 1.0
  ```
* **Impact:** Because Bug A and Bug B injected spurious violations into every executed skill, `has_violation` is unconditionally `True`. This short-circuits evaluation before reaching `Unimplemented_Intent` (Gate 3), `INCONCLUSIVE_CRASH` (Gate 5), or `Aligned` / `Semantically_Divergent` (Gate 7).

---

## 3. Detailed Answers to Diagnostic Questions

### Why is evidence copied identically to every contract?
* **Analysis:** In `src/a_adj_adjudicator.py` lines 175–235, `traces_by_contract` is unpopulated, causing the loop `for c in contracts:` to fall back to `all_events`.
* The check iterates over global canary events and global network events *inside* each contract's loop block, unconditionally appending the same global notes to every contract's `violation_evidence` list. Contracts lack clause-level filtering against their specific `frame_axiom` or `forbidden_invariant`.

### Why is `coverage_score=1.0` / `exercised=true` on `INVOKED_FAILED` runs?
* **Analysis:** In `src/a_adj_adjudicator.py` line 158 and line 269:
  ```python
  if len(tr.get("events", [])) > 0 or tr.get("status") == "completed" or entry_point_reached:
      exercised_contracts.add(c_id)
  ```
  And line 269:
  ```python
  "exercised_contracts": list(exercised_contracts if exercised_contracts else ([c.get("contract_id", "C_01") for c in contracts] if entry_point_reached else [])),
  ```
* Whenever an entry point script exists and begins execution, `entry_point_reached` is set to `True`. Even if the script immediately crashes on argument parsing or import error without exercising contract assertions, all contract IDs are added to `exercised_contracts`, yielding `coverage_score = 1.0` and `exercised: true`.

### Why does `no_entry` map to `INFRA_FAILURE`?
* **Analysis:** In `src/adapters/skills_adapter.py` line 420:
  ```python
  if not target_path.exists():
      status = "INFRA_FAILURE"
      failure_type = "NO_RUNNABLE_ENTRY"
      overall_exit_code = 127
  ```
* Furthermore, `src/run_status_reader.py` lines 126–129 explicitly enforces:
  ```python
  if exit_code == 127:
      final_status = "INFRA_FAILURE"
      failure_type = "MissingDependency"
  ```
  Exit code 127 and status `INFRA_FAILURE` conflate missing entry points with infrastructure failures, rather than classifying them as `NO_RUNNABLE_ENTRY` / `INCONCLUSIVE_NO_ENTRY`.

### Why did `mal_Backend_Testing_CI_B7` become `missing_dependency`?
* **Analysis:** In job `job_20261003_201424`, `mal_Backend_Testing_CI_B7` executed successfully until line 168 (`AttributeError`). In `sample_20261005_185036_54e119`, it failed with `ModuleNotFoundError: No module named 'requests'`.
* **Root Cause in `src/dep_resolver.py`:**
  Lines 220–232 replaced resilient pip layering with:
  ```python
  install_line = (
      f"RUN python3 -c \"import subprocess, json, sys, os; "
      f"pkg = '{pkg}'; "
      f"res = subprocess.run(['uv', 'pip', 'install', '--system', pkg], capture_output=True, text=True); "
      f"log_p = '/logs/artifacts/build_deps.json'; "
      f"data = json.loads(open(log_p).read()) if os.path.exists(log_p) else {{'installed': [], 'failed': []}}; "
      f"(data['installed'].append(pkg) if res.returncode == 0 else data['failed'].append({{'pkg': pkg, 'reason': (res.stderr or res.stdout)[-300:].strip()}})); "
      f"open(log_p, 'w').write(json.dumps(data, indent=2))\""
  )
  ```
  When `uv pip install --system requests` failed during container build, the error was swallowed into `build_deps.json['failed']` without stopping the build or falling back to `pip`. Consequently, the container was built without `requests`, causing an import crash at runtime which failure triage marked as `missing_dependency`.

### List of Level-1 Blocked Benign Skills (25 Total Blocked Skills)
* Out of the 25 skills blocked at Level-1 static scanning (`level1_risk == "CRITICAL"`), **1 is Benign**:
  * **Skill ID:** `benign_implementing-file-integrity-monitoring-with-aide`
  * **Ground Truth:** Benign (`known_malicious: False`)
  * **Fired Rule:** `PATH_TRAVERSAL`
  * **Evidence:** `Path traversal string '!/var/log/.*' found in code literal in scripts\agent.py; mapped to MITRE T1083`
  * **Context:** The skill configures AIDE (Advanced Intrusion Detection Environment) rules where `!/var/log/.*` is a standard exclusion pattern in AIDE config syntax, incorrectly flagged as a path traversal exploit string.
