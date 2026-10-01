"""
LangGraph Builder - 图构建器
构建漏洞数据处理的状态图
"""
import logging
from typing import Dict
from functools import partial

from langgraph.graph import StateGraph, END
from graph.state import VulnProcessingState
from graph.nodes import (
    extract_node,
    clean_validate_node,
    store_node,
    mark_low_quality_node,
    reflect_node,
)
from graph.recovery_nodes import (
    decide_next_node,
    diagnose_failure_node,
    execute_action_node,
    guard_action_node,
    plan_recovery_node,
    verify_evidence_node,
)

logger = logging.getLogger(__name__)


def route_after_extract(state: VulnProcessingState, config: Dict) -> str:
    if state.get('final_status') == 'skipped':
        return 'end'
    return 'clean'


def route_after_clean(state: VulnProcessingState, config: Dict) -> str:
    quality_threshold = config.get('agents', {}).get('cleaner_validator', {}).get('quality_threshold', 0.7)
    if state.get('quality_score', 0.0) >= quality_threshold:
        return 'store'
    if not config.get('agentic', {}).get('recovery', {}).get('enabled', False):
        return route_after_diagnosis(state, config)
    return 'diagnose_failure'


def route_after_diagnosis(state: VulnProcessingState, config: Dict) -> str:
    recovery_cfg = config.get('agentic', {}).get('recovery', {})
    if recovery_cfg.get('agent_loop_enabled', False):
        return 'plan_recovery'

    reflection_cfg = config.get('agentic', {}).get('reflection', {})
    if reflection_cfg.get('enabled', False):
        max_retries = reflection_cfg.get('max_retries', 2)
        if state.get('retry_count', 0) < max_retries:
            return 'reflect'
    return 'low_quality'


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
    return 'low_quality'


def check_quality(state: VulnProcessingState, config: Dict) -> str:
    """Backward-compatible combined quality route."""
    route = route_after_clean(state, config)
    return route if route != 'diagnose_failure' else route_after_diagnosis(state, config)


def build_vuln_processing_graph(config: Dict) -> StateGraph:
    """
    构建漏洞数据处理图

    图结构：
      START → extract → clean → store → END
                  ↑        └→ diagnose → legacy reflect / constrained recovery loop
                  └──────────────────────────────────────────────────────────────┘
    """
    logger.info("Building vulnerability processing graph...")

    workflow = StateGraph(VulnProcessingState)

    extract_with_config      = partial(extract_node,          config=config)
    clean_with_config        = partial(clean_validate_node,   config=config)
    store_with_config        = partial(store_node,            config=config)
    low_quality_with_config  = partial(mark_low_quality_node, config=config)
    reflect_with_config      = partial(reflect_node,          config=config)
    diagnose_with_config     = partial(diagnose_failure_node, config=config)
    plan_recovery_with_config = partial(plan_recovery_node, config=config)
    guard_action_with_config = partial(guard_action_node, config=config)
    execute_action_with_config = partial(execute_action_node, config=config)
    verify_evidence_with_config = partial(verify_evidence_node, config=config)
    decide_next_with_config = partial(decide_next_node, config=config)
    route_after_clean_with_config = partial(route_after_clean, config=config)
    route_after_diagnosis_with_config = partial(route_after_diagnosis, config=config)
    route_after_extract_with_config = partial(route_after_extract, config=config)
    route_after_plan_with_config = partial(route_after_plan, config=config)
    route_after_guard_with_config = partial(route_after_guard, config=config)
    route_after_decision_with_config = partial(route_after_decision, config=config)

    workflow.add_node("extract",     extract_with_config)
    workflow.add_node("clean",       clean_with_config)
    workflow.add_node("store",       store_with_config)
    workflow.add_node("low_quality", low_quality_with_config)
    workflow.add_node("reflect",     reflect_with_config)
    workflow.add_node("diagnose_failure", diagnose_with_config)
    workflow.add_node("plan_recovery", plan_recovery_with_config)
    workflow.add_node("guard_action", guard_action_with_config)
    workflow.add_node("execute_action", execute_action_with_config)
    workflow.add_node("verify_evidence", verify_evidence_with_config)
    workflow.add_node("decide_next", decide_next_with_config)

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
            "reflect": "reflect",
            "low_quality": "low_quality",
        },
    )
    workflow.add_conditional_edges(
        "diagnose_failure",
        route_after_diagnosis_with_config,
        {
            "plan_recovery": "plan_recovery",
            "reflect": "reflect",
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
            "low_quality": "low_quality",
        },
    )
    workflow.add_edge("reflect", "extract")   # 反思循环
    workflow.add_edge("store",       END)
    workflow.add_edge("low_quality", END)

    logger.info("Graph compiled successfully")
    return workflow.compile()
