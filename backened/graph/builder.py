"""
LangGraph Builder - 图构建器
构建漏洞数据处理的状态图
"""
import logging
import inspect
from typing import Dict

from langgraph.graph import StateGraph, END
from graph.state import VulnProcessingState
from graph.nodes import (
    extract_node,
    clean_validate_node,
    store_node,
    mark_low_quality_node,
)
from graph.recovery_nodes import (
    decide_next_node,
    diagnose_failure_node,
    execute_action_node,
    guard_action_node,
    plan_recovery_node,
    verify_evidence_node,
)
from graph.hil_nodes import (
    apply_review_node,
    human_review_node,
    prepare_review_node,
    reject_review_node,
)

logger = logging.getLogger(__name__)


def _bind(function, app_config):
    """Bind application config without exposing LangGraph's reserved config parameter."""
    if inspect.iscoroutinefunction(function):
        async def async_node(state):
            return await function(state, app_config)
        return async_node

    def sync_node(state):
        return function(state, app_config)
    return sync_node


def route_after_extract(state: VulnProcessingState, config: Dict) -> str:
    if state.get('final_status') == 'skipped':
        return 'end'
    return 'clean'


def route_after_clean(state: VulnProcessingState, config: Dict) -> str:
    quality_threshold = config.get('agents', {}).get('cleaner_validator', {}).get('quality_threshold', 0.7)
    validation_passed = (state.get('validation_result') or {}).get('is_valid', True)
    if validation_passed and state.get('quality_score', 0.0) >= quality_threshold:
        return 'store'
    if not config.get('agentic', {}).get('recovery', {}).get('enabled', False):
        return 'low_quality'
    return 'diagnose_failure'


def route_after_diagnosis(state: VulnProcessingState, config: Dict) -> str:
    enabled = config.get('agentic', {}).get('recovery', {}).get('enabled', False)
    return 'plan_recovery' if enabled else 'low_quality'


def route_after_plan(state: VulnProcessingState, config: Dict) -> str:
    decision = (state.get('recovery_decision') or {}).get('decision')
    return 'guard_action' if decision == 'CALL_TOOL' else 'decide_next'


def route_after_guard(state: VulnProcessingState, config: Dict) -> str:
    return 'execute_action' if state.get('pending_action') else 'decide_next'


def route_after_decision(state: VulnProcessingState, config: Dict) -> str:
    decision = state.get('final_decision')
    if decision == 'PASS':
        return 'store'
    if decision == 'REPLAN':
        return 'plan_recovery'
    if decision == 'REVIEW':
        return 'prepare_review'
    return 'low_quality'


def route_after_prepare_review(state: VulnProcessingState, config: Dict) -> str:
    return 'end' if state.get('review_status') == 'dry_run' else 'human_review'


def route_after_human_review(state: VulnProcessingState, config: Dict) -> str:
    action = (state.get('review_response') or {}).get('action')
    if action == 'approve':
        return 'apply_review'
    if action == 'reject':
        return 'reject_review'
    raise ValueError(f"Unsupported review action: {action}")


def route_after_apply_review(state: VulnProcessingState, config: Dict) -> str:
    return 'store' if state.get('review_status') == 'approved' else 'end'


def check_quality(state: VulnProcessingState, config: Dict) -> str:
    """Backward-compatible combined quality route."""
    route = route_after_clean(state, config)
    return route if route != 'diagnose_failure' else route_after_diagnosis(state, config)


def build_vuln_processing_graph(config: Dict, checkpointer=None) -> StateGraph:
    """
    构建漏洞数据处理图

    图结构：
      START → extract → clean → store → END
                  ↑        └→ diagnose → legacy reflect / constrained recovery loop
                  └──────────────────────────────────────────────────────────────┘
    """
    logger.info("Building vulnerability processing graph...")

    workflow = StateGraph(VulnProcessingState)

    extract_with_config = _bind(extract_node, config)
    clean_with_config = _bind(clean_validate_node, config)
    store_with_config = _bind(store_node, config)
    low_quality_with_config = _bind(mark_low_quality_node, config)
    diagnose_with_config = _bind(diagnose_failure_node, config)
    plan_recovery_with_config = _bind(plan_recovery_node, config)
    guard_action_with_config = _bind(guard_action_node, config)
    execute_action_with_config = _bind(execute_action_node, config)
    verify_evidence_with_config = _bind(verify_evidence_node, config)
    decide_next_with_config = _bind(decide_next_node, config)
    prepare_review_with_config = _bind(prepare_review_node, config)
    human_review_with_config = _bind(human_review_node, config)
    apply_review_with_config = _bind(apply_review_node, config)
    reject_review_with_config = _bind(reject_review_node, config)
    route_after_clean_with_config = _bind(route_after_clean, config)
    route_after_diagnosis_with_config = _bind(route_after_diagnosis, config)
    route_after_extract_with_config = _bind(route_after_extract, config)
    route_after_plan_with_config = _bind(route_after_plan, config)
    route_after_guard_with_config = _bind(route_after_guard, config)
    route_after_decision_with_config = _bind(route_after_decision, config)
    route_after_prepare_review_with_config = _bind(route_after_prepare_review, config)
    route_after_human_review_with_config = _bind(route_after_human_review, config)
    route_after_apply_review_with_config = _bind(route_after_apply_review, config)

    workflow.add_node("extract",     extract_with_config)
    workflow.add_node("clean",       clean_with_config)
    workflow.add_node("store",       store_with_config)
    workflow.add_node("low_quality", low_quality_with_config)
    workflow.add_node("diagnose_failure", diagnose_with_config)
    workflow.add_node("plan_recovery", plan_recovery_with_config)
    workflow.add_node("guard_action", guard_action_with_config)
    workflow.add_node("execute_action", execute_action_with_config)
    workflow.add_node("verify_evidence", verify_evidence_with_config)
    workflow.add_node("decide_next", decide_next_with_config)
    workflow.add_node("prepare_review", prepare_review_with_config)
    workflow.add_node("human_review", human_review_with_config)
    workflow.add_node("apply_review", apply_review_with_config)
    workflow.add_node("reject_review", reject_review_with_config)

    workflow.set_entry_point("extract")
    workflow.add_conditional_edges(
        "extract",
        route_after_extract_with_config,
        {"clean": "clean", "end": END},
    )
    workflow.add_conditional_edges(
        "clean",
        route_after_clean_with_config,
        {
            "store": "store",
            "diagnose_failure": "diagnose_failure",
            "low_quality": "low_quality",
        },
    )
    workflow.add_conditional_edges(
        "diagnose_failure",
        route_after_diagnosis_with_config,
        {
            "plan_recovery": "plan_recovery",
            "low_quality": "low_quality",
        },
    )
    workflow.add_conditional_edges(
        "plan_recovery",
        route_after_plan_with_config,
        {"guard_action": "guard_action", "decide_next": "decide_next"},
    )
    workflow.add_conditional_edges(
        "guard_action",
        route_after_guard_with_config,
        {"execute_action": "execute_action", "decide_next": "decide_next"},
    )
    workflow.add_edge("execute_action", "verify_evidence")
    workflow.add_edge("verify_evidence", "decide_next")
    workflow.add_conditional_edges(
        "decide_next",
        route_after_decision_with_config,
        {
            "store": "store",
            "plan_recovery": "plan_recovery",
            "prepare_review": "prepare_review",
            "low_quality": "low_quality",
        },
    )
    workflow.add_conditional_edges(
        "prepare_review",
        route_after_prepare_review_with_config,
        {"human_review": "human_review", "end": END},
    )
    workflow.add_conditional_edges(
        "human_review",
        route_after_human_review_with_config,
        {"apply_review": "apply_review", "reject_review": "reject_review"},
    )
    workflow.add_conditional_edges(
        "apply_review",
        route_after_apply_review_with_config,
        {"store": "store", "end": END},
    )
    workflow.add_edge("reject_review", END)
    workflow.add_edge("store",       END)
    workflow.add_edge("low_quality", END)

    logger.info("Graph compiled successfully")
    return workflow.compile(checkpointer=checkpointer)
