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

logger = logging.getLogger(__name__)


def route_after_extract(state: VulnProcessingState, config: Dict) -> str:
    if state.get('final_status') == 'skipped':
        return 'end'
    return 'clean'


def check_quality(state: VulnProcessingState, config: Dict) -> str:
    """
    质量门批 — 三路路由

      store       : 质量达标，正常入库
      reflect     : 质量未达标 且 未达最大重试次数，升级策略后重试
      low_quality : 质量未达标 且 已用尽重试次数
    """
    quality_threshold = config.get('agents', {}).get('cleaner_validator', {}).get('quality_threshold', 0.7)
    quality_score = state.get('quality_score', 0.0)

    if quality_score >= quality_threshold:
        return 'store'

    reflection_cfg = config.get('agentic', {}).get('reflection', {})
    if reflection_cfg.get('enabled', False):
        max_retries = reflection_cfg.get('max_retries', 2)
        if state.get('retry_count', 0) < max_retries:
            logger.debug(f"Quality check → reflect (score={quality_score:.2f}, retry={state.get('retry_count', 0)})")
            return 'reflect'

    logger.debug(f"Quality check → low_quality (score={quality_score:.2f})")
    return 'low_quality'


def build_vuln_processing_graph(config: Dict) -> StateGraph:
    """
    构建漏洞数据处理图

    图结构：
      START → extract → clean → [quality_gate]
                  ↑                    ├→ store → END
                  ├──── reflect ◄───┤
                                       └→ low_quality → END
    """
    logger.info("Building vulnerability processing graph...")

    workflow = StateGraph(VulnProcessingState)

    extract_with_config      = partial(extract_node,          config=config)
    clean_with_config        = partial(clean_validate_node,   config=config)
    store_with_config        = partial(store_node,            config=config)
    low_quality_with_config  = partial(mark_low_quality_node, config=config)
    reflect_with_config      = partial(reflect_node,          config=config)
    check_quality_with_config = partial(check_quality,        config=config)
    route_after_extract_with_config = partial(route_after_extract, config=config)

    workflow.add_node("extract",     extract_with_config)
    workflow.add_node("clean",       clean_with_config)
    workflow.add_node("store",       store_with_config)
    workflow.add_node("low_quality", low_quality_with_config)
    workflow.add_node("reflect",     reflect_with_config)

    workflow.set_entry_point("extract")
    workflow.add_conditional_edges(
        "extract",
        route_after_extract_with_config,
        {"clean": "clean", "end": END},
    )
    workflow.add_conditional_edges(
        "clean",
        check_quality_with_config,
        {"store": "store", "reflect": "reflect", "low_quality": "low_quality"},
    )
    workflow.add_edge("reflect", "extract")   # 反思循环
    workflow.add_edge("store",       END)
    workflow.add_edge("low_quality", END)

    logger.info("Graph compiled successfully")
    return workflow.compile()
