from typing import TypedDict, Optional, List, Dict, Any, Literal

RunStatus = Literal["NOT_INVOKED", "INFRA_FAILURE", "INVOKED_FAILED", "INVOKED_SUCCEEDED"]
VerdictLabel = Literal[
    "Aligned", 
    "Undeclared_Behavior", 
    "Unimplemented_Intent", 
    "Semantically_Divergent", 
    "Blocked_Static_CRITICAL", 
    "INCONCLUSIVE_HARNESS", 
    "INCONCLUSIVE_INFRA", 
    "INCONCLUSIVE_LOW_COVERAGE", 
    "INCONCLUSIVE_CRASH",
    "INCONCLUSIVE_TIMEOUT",
    "INCONCLUSIVE_NO_ACTION"
]

class ContractExecutionRecord(TypedDict, total=False):
    contract_id: str
    run_status: RunStatus
    entry_point_reached: bool
    activation: Optional[bool]
    script_execution: Optional[bool]
    failure_type: Optional[str]
    execution_error_sublabel: Optional[str]
    exit_code: Optional[int]
    events: List[Dict[str, Any]]
    status: str
    error_message: Optional[str]

class PipelineState(TypedDict):
    skill_id: str
    skill_path: str
    domain: Optional[str]
    declaration_text: str                       # SKILL.md/README/YAML content only
    contracts: Optional[List[Dict[str, Any]]]    # Synthesized by A_syn
    test_cases: Optional[List[Dict[str, Any]]]   # Synthesized by A_gen
    traces: Optional[List[Dict[str, Any]]]       # Aggregated trace records from A_exec
    coverage_score: Optional[float]              # DTC metric from A_adj
    dtc: Optional[float]                         # Decision/contract test coverage
    csr_c: Optional[float]                       # Contract satisfaction rate
    refinement_attempts: int                    # Current feedback loop count
    max_refinement_attempts: int                # Maximum refinement budget (default: 3)
    prediction: Optional[Dict[str, Any]]         # Formal adjudication verdict from A_adj
    supervisor_directive: Optional[str]         # Directive from A_orch to A_gen
    supervisor_decision: Optional[str]          # "REFINE" | "CONCLUDE"
    agent_messages: Optional[List[Dict[str, Any]]] # Log of all agent actions and supervisor decisions
    force_refresh: Optional[bool]               # Bypass cache and re-synthesize contracts fresh
    status: str                                 # "in_progress" | "done" | "failed"
    # Harbor & run_status protocol fields (Phase 5)
    run_status: Optional[RunStatus]             # Aggregate/primary run status
    entry_point_reached: Optional[bool]         # Whether target entrypoint was reached
    activation: Optional[bool]                  # ACES check 1: SKILL.md read
    script_execution: Optional[bool]            # ACES check 2: bundled script invoked
    failure_type: Optional[str]                 # "NotImplementedError" | "AbstractMethodStub" | etc.
    execution_error_sublabel: Optional[str]     # Sub-label when INVOKED_FAILED is generic crash
    needs_rerun: Optional[bool]                 # True when INCONCLUSIVE_HARNESS / INCONCLUSIVE_INFRA
    harbor_task_dir: Optional[str]              # Path to generated harbor task
    harbor_trial_dir: Optional[str]             # Path to harbor trial artifacts
    contract_executions: Optional[List[ContractExecutionRecord]] # Per-contract records
    auto_installed_packages: Optional[List[str]] # Packages auto-installed during pre-flight
    gating_status: Optional[str]                # "INVOKED" | "INCONCLUSIVE_INFRA" | "INCONCLUSIVE_HARNESS" | "NOT_INVOKED" | "SKIPPED_LEVEL1_CRITICAL"
    fs_diff: Optional[str]                      # Filesystem diff content from test execution
    level1_report: Optional[Dict[str, Any]]     # Level-1 Static Security Scanner report
    backend: Optional[str]                      # "harbor_docker" | "local_fallback"
    valid_for_paper: Optional[bool]             # True only if executed in real Harbor/Docker
    level2_verdict: Optional[str]               # Level 2 formal verdict
