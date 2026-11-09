import os
import json
from typing import Dict, Any

from langgraph.graph import StateGraph, START, END
from src.state import PipelineState
from src.nodes import (
    supervisor_init_node,
    contract_synth_node,
    test_gen_node,
    sandbox_exec_node,
    adjudicate_node,
    supervisor_eval_node,
    finalize_node
)

MANIFEST_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "benchmark_manifest.json"))

def supervisor_router(state: PipelineState) -> str:
    """
    Supervisor routing conditional edge:
    Inspects supervisor_decision to choose 'refine' or 'conclude'.
    """
    decision = state.get("supervisor_decision", "CONCLUDE")
    if decision == "REFINE":
        return "refine"
    return "conclude"

def level1_router(state: PipelineState) -> str:
    """
    Level-1 Static Security routing:
    If flagged CRITICAL, bypass test generation and Harbor execution entirely.
    """
    if state.get("gating_status") == "SKIPPED_LEVEL1_CRITICAL":
        return "skip_to_finalize"
    return "proceed_to_test_gen"

def build_verification_graph() -> Any:
    """Constructs and compiles the multi-agent LangGraph StateGraph with Supervisor."""
    workflow = StateGraph(PipelineState)

    # 1. Add Nodes
    workflow.add_node("supervisor_init", supervisor_init_node)
    workflow.add_node("contract_synth", contract_synth_node)
    workflow.add_node("test_gen", test_gen_node)
    workflow.add_node("sandbox_exec", sandbox_exec_node)
    workflow.add_node("adjudicate", adjudicate_node)
    workflow.add_node("supervisor_eval", supervisor_eval_node)
    workflow.add_node("finalize", finalize_node)

    # 2. Add Edges with Level-1 Pre-Filter Gating
    workflow.add_edge(START, "supervisor_init")
    workflow.add_edge("supervisor_init", "contract_synth")
    workflow.add_conditional_edges(
        "contract_synth",
        level1_router,
        {
            "skip_to_finalize": "finalize",
            "proceed_to_test_gen": "test_gen"
        }
    )
    workflow.add_edge("test_gen", "sandbox_exec")
    workflow.add_edge("sandbox_exec", "adjudicate")
    workflow.add_edge("adjudicate", "supervisor_eval")

    # 3. Add Conditional Edge (Supervisor-directed feedback loop)
    workflow.add_conditional_edges(
        "supervisor_eval",
        supervisor_router,
        {
            "refine": "test_gen",
            "conclude": "finalize"
        }
    )
    workflow.add_edge("finalize", END)

    return workflow.compile()

# Precompiled graph instance
compiled_graph = build_verification_graph()

def run_skill(
    skill_id: str, 
    max_refinement_attempts: int = int(os.environ.get("MAX_REFINEMENT_ATTEMPTS", "3")),
    manifest_file: str = MANIFEST_PATH,
    force_refresh: bool = False
) -> Dict[str, Any]:
    """
    Entry point:
    - Loads skill_path and declaration_text from manifest given skill_id.
    - Initializes state, calls graph.invoke(state).
    - Returns the final state.
    """
    if not os.path.exists(manifest_file):
        raise FileNotFoundError(f"Manifest not found at: {manifest_file}")

    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Find skill entry
    skill_entry = next((s for s in manifest.get("skills", []) if s.get("skill_id") == skill_id), None)
    if not skill_entry:
        raise ValueError(f"Skill ID '{skill_id}' not found in manifest")

    skill_path = os.path.abspath(skill_entry.get("path"))
    skill_md_path = os.path.join(skill_path, "SKILL.md")
    
    declaration_text = ""
    if os.path.exists(skill_md_path):
        with open(skill_md_path, "r", encoding="utf-8", errors="ignore") as f:
            declaration_text = f.read()

    initial_state: PipelineState = {
        "skill_id": skill_id,
        "skill_path": skill_path,
        "domain": skill_entry.get("domain", "data_processing"),
        "declaration_text": declaration_text,
        "contracts": None,
        "test_cases": None,
        "traces": None,
        "coverage_score": None,
        "refinement_attempts": 0,
        "max_refinement_attempts": max_refinement_attempts,
        "prediction": None,
        "supervisor_directive": None,
        "supervisor_decision": None,
        "force_refresh": force_refresh,
        "status": "in_progress",
        "run_status": None,
        "entry_point_reached": False,
        "activation": None,
        "script_execution": None,
        "failure_type": None,
        "execution_error_sublabel": None,
        "needs_rerun": False,
        "harbor_task_dir": None,
        "harbor_trial_dir": None,
        "contract_executions": None,
        "auto_installed_packages": [],
        "gating_status": None,
        "level1_report": None,
        "agent_messages": [],
    }

    final_state = compiled_graph.invoke(initial_state)
    return final_state
