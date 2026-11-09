import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

logger = logging.getLogger(__name__)

RUN_STATUS_VALID_STATES = {"NOT_INVOKED", "INFRA_FAILURE", "INVOKED_FAILED", "INVOKED_SUCCEEDED"}

def clean_evidence_string(val: Optional[str]) -> Optional[str]:
    """Sanitizes evidence strings to prevent literal '(None)' from leaking."""
    if val is None:
        return None
    s = str(val).strip()
    if s in ("(None)", "None", "null", ""):
        return None
    return s

def read_and_cross_check_run_status(
    run_status_path: Optional[str],
    harbor_result_path: Optional[str]
) -> Tuple[str, bool, Optional[str], Optional[str], Optional[int]]:
    """
    Reads BOTH run_status.json (self-reported) AND Harbor's result.json
    (jobs/<job_id>/<trial_id>/result.json).

    Propagates triage class as the sublabel (bad_args, missing_fixture, etc.)
    and sanitizes out '(None)' strings.

    Returns:
        (final_run_status, entry_point_reached, failure_type, execution_error_sublabel, exit_code)
    """
    self_status = "NOT_INVOKED"
    entry_point_reached = False
    failure_type = None
    execution_error_sublabel = None
    exit_code = None

    # 1. Read self-reported run_status.json
    if run_status_path and os.path.exists(run_status_path):
        try:
            with open(run_status_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                status_candidate = data.get("run_status")
                if status_candidate in RUN_STATUS_VALID_STATES:
                    self_status = status_candidate
                entry_point_reached = bool(data.get("entry_point_reached", False))
                exit_code = data.get("exit_code")

                # Read both failure_type/execution_error_sublabel and error_type
                raw_ftype = clean_evidence_string(data.get("failure_type"))
                raw_sublabel = clean_evidence_string(data.get("execution_error_sublabel"))
                raw_errtype = clean_evidence_string(data.get("error_type"))
                triage_class = clean_evidence_string(data.get("triage_class"))

                if raw_ftype:
                    failure_type = raw_ftype
                elif raw_errtype:
                    if raw_errtype in ["NotImplementedError", "AbstractMethodStub", "MissingReturnState", "TargetSinkUncalled"]:
                        failure_type = raw_errtype
                    else:
                        failure_type = "RuntimeError"

                if raw_sublabel:
                    execution_error_sublabel = raw_sublabel
                elif triage_class:
                    execution_error_sublabel = triage_class
                elif raw_errtype and raw_errtype != failure_type:
                    execution_error_sublabel = raw_errtype
        except Exception as e:
            logger.warning(f"Failed to read self-reported run_status.json: {e}")
            self_status = "INFRA_FAILURE"
            failure_type = "HarnessParseError"

    # 2. Read Harbor's native result.json
    harbor_has_exception = False
    harbor_exception_msg = None
    if harbor_result_path and os.path.exists(harbor_result_path):
        try:
            with open(harbor_result_path, "r", encoding="utf-8") as f:
                hdata = json.load(f)

            # Check agent_result for exceptions
            agent_res = hdata.get("agent_result") or {}
            agent_exc = agent_res.get("exception") or agent_res.get("agent_exception")
            if agent_exc:
                harbor_has_exception = True
                harbor_exception_msg = f"Agent exception: {agent_exc}"

            # Check environment / trial exceptions
            env_exc = hdata.get("environment_result", {}).get("exception") if isinstance(hdata.get("environment_result"), dict) else None
            top_exc = hdata.get("exception")
            if env_exc or top_exc:
                harbor_has_exception = True
                harbor_exception_msg = f"Environment/Trial exception: {env_exc or top_exc}"

            # Check verifier result for crash
            verifier_res = hdata.get("verifier_result") or {}
            if verifier_res.get("exception") or verifier_res.get("infra_error"):
                harbor_has_exception = True
                harbor_exception_msg = f"Verifier crash: {verifier_res.get('exception') or verifier_res.get('infra_error')}"

        except Exception as e:
            logger.warning(f"Failed to read Harbor result.json: {e}")
            harbor_has_exception = True
            harbor_exception_msg = f"Failed to parse result.json: {e}"

    # 3. Cross-check and enforce pessimistic downgrade
    final_status = self_status

    # Priority 1: Check NO_RUNNABLE_ENTRY / instruction-only FIRST before Harbor trial exceptions
    is_no_entry = (
        failure_type == "NO_RUNNABLE_ENTRY"
        or execution_error_sublabel == "no_entry"
        or (not entry_point_reached and self_status == "NOT_INVOKED")
    )

    if is_no_entry:
        final_status = "NOT_INVOKED"
        failure_type = "NO_RUNNABLE_ENTRY"
        if not execution_error_sublabel:
            execution_error_sublabel = "no_entry"
    elif harbor_has_exception:
        # Determine if this is a genuine infrastructure failure
        exc_str = (harbor_exception_msg or "").lower()
        is_true_infra = any(kw in exc_str for kw in [
            "docker", "container", "image", "build", "timeout", "oom", "killed",
            "daemon", "connection refused", "failed to parse", "verifier crash", "infra_error"
        ])

        if self_status in ["INVOKED_SUCCEEDED", "INVOKED_FAILED"]:
            if is_true_infra:
                logger.warning(
                    f"[DISAGREEMENT] Self-reported status was '{self_status}' but Harbor result.json reported true infra exception: "
                    f"'{harbor_exception_msg}'. Downgrading to INFRA_FAILURE."
                )
                final_status = "INFRA_FAILURE"
                failure_type = "HarborTrialException"
                execution_error_sublabel = clean_evidence_string(harbor_exception_msg)
            else:
                # Skill executed and failed/succeeded normally; Harbor reporting non-zero exit code is NOT an infra failure!
                logger.info(
                    f"[PRESERVED] Preserving self-reported status '{self_status}' (exit code {exit_code}). "
                    f"Harbor non-zero exit '{harbor_exception_msg}' is not an infra crash."
                )
        elif self_status == "NOT_INVOKED":
            final_status = "INFRA_FAILURE"
            failure_type = "HarborEnvironmentFailure"

    # If exit code was 127 (missing command/dependency), distinguish no entry point vs missing tool
    if exit_code == 127:
        if is_no_entry:
            final_status = "NOT_INVOKED"
            failure_type = "NO_RUNNABLE_ENTRY"
        else:
            final_status = "INFRA_FAILURE"
            failure_type = "MissingDependency"

    return final_status, entry_point_reached, failure_type, execution_error_sublabel, exit_code
