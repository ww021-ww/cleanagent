"""
Planner Agent — 批次级任务规划
在批处理开始前预分析文件，按复杂度分配策略，输出优先级排序
"""
import logging
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

_SIZE_SMALL = 10 * 1024   # <10KB → 大概率结构简单
_SIZE_LARGE = 100 * 1024  # >100KB → 大概率复杂


class PlannerAgent:
    """
    任务规划智能体

    职责：
    1. 预分析文件列表，按复杂度分组（rule / hybrid / llm_full）
    2. 结合 AgentMemory 历史信息优化策略
    3. 生成处理优先级顺序（小/简单文件优先，快速积累成功记录）
    4. 估算 LLM 调用次数，帮助控制成本
    """

    def __init__(self, config: Dict, memory=None):
        self.config = config
        self.memory = memory

        planner_cfg = config.get("agentic", {}).get("planner", {})
        self.enabled: bool = planner_cfg.get("enabled", True)
        self.file_size_large: int = planner_cfg.get("file_size_threshold", _SIZE_LARGE)
        self.skip_known_ids: bool = planner_cfg.get("skip_known_ids", True)

        self._extractor = None

    # ──────────────────────────────────────────────
    #  公共接口
    # ──────────────────────────────────────────────

    def plan(self, files: List[Path]) -> Dict:
        """
        对文件列表制定处理计划

        Returns:
            {
              strategy_groups: {rule: [...], hybrid: [...], llm_full: [...]},
              skip_list: [...],
              priority_order: [...],   # 按策略难度+文件大小排序的绝对顺序
              file_strategies: {path_str: strategy},
              estimated_llm_calls: int,
            }
        """
        if not self.enabled:
            return self._passthrough_plan(files)

        logger.info(f"📋 PlannerAgent: 规划 {len(files)} 个文件...")

        extractor = self._get_extractor()
        strategy_groups: Dict[str, List[Path]] = defaultdict(list)
        skip_list: List[Path] = []
        file_strategies: Dict[str, str] = {}
        source_stats: Dict[str, int] = defaultdict(int)

        for f in files:
            file_path = str(f)
            file_size = f.stat().st_size if f.exists() else 0
            file_ext = f.suffix.lower()

            # 识别来源
            try:
                source = extractor.identify_source(file_path, "")
            except Exception:
                source = "UNKNOWN"
            source_lower = source.lower()
            source_stats[source_lower] += 1

            # Memory 批次内去重
            if self.memory and self.skip_known_ids:
                if self.memory.is_seen(f.stem, source):
                    skip_list.append(f)
                    continue

            strategy = self._decide_strategy(file_path, file_size, file_ext, source_lower)
            strategy_groups[strategy].append(f)
            file_strategies[file_path] = strategy

        # 优先级排序：rule 优先，组内小文件优先
        priority_order: List[Path] = []
        for s in ("rule", "hybrid", "llm_full"):
            group = sorted(
                strategy_groups.get(s, []),
                key=lambda p: p.stat().st_size if p.exists() else 0,
            )
            priority_order.extend(group)

        estimated_llm = (
            len(strategy_groups.get("hybrid", []))
            + len(strategy_groups.get("llm_full", [])) * 2
        )

        plan = {
            "strategy_groups": {k: [str(f) for f in v] for k, v in strategy_groups.items()},
            "skip_list": [str(f) for f in skip_list],
            "priority_order": [str(f) for f in priority_order],
            "file_strategies": file_strategies,
            "estimated_llm_calls": estimated_llm,
            "source_stats": dict(source_stats),
        }

        logger.info(
            f"📋 规划完成 — rule:{len(strategy_groups.get('rule', []))} "
            f"hybrid:{len(strategy_groups.get('hybrid', []))} "
            f"llm_full:{len(strategy_groups.get('llm_full', []))} "
            f"skip:{len(skip_list)} 预估LLM调用:{estimated_llm}"
        )
        return plan

    # ──────────────────────────────────────────────
    #  内部逻辑
    # ──────────────────────────────────────────────

    def _decide_strategy(self, file_path: str, file_size: int,
                         file_ext: str, source: str) -> str:
        """
        按以下优先级决定策略：
        1. Memory 历史失败率高 → 升级策略
        2. JSON 格式 → rule（已有专用 JSON 提取器）
        3. 已知来源 + 小文件 → rule
        4. 已知来源 + 大文件 → hybrid
        5. 未知来源 → llm_full
        """
        # Memory 失败率高 → 从 rule 升为 hybrid
        if self.memory and source != "unknown":
            recommended = self.memory.get_recommended_strategy(source)
            if recommended and recommended != "rule":
                return recommended

        if file_ext == ".json":
            return "rule"

        unknown_source = source in ("unknown", "")
        if unknown_source:
            return "llm_full"

        if file_size < self.file_size_large:
            return "rule"
        return "hybrid"

    def _passthrough_plan(self, files: List[Path]) -> Dict:
        """Planner 禁用时，所有文件按 rule 策略、原始顺序处理"""
        file_strategies = {str(f): "rule" for f in files}
        return {
            "strategy_groups": {"rule": [str(f) for f in files]},
            "skip_list": [],
            "priority_order": [str(f) for f in files],
            "file_strategies": file_strategies,
            "estimated_llm_calls": 0,
            "source_stats": {},
        }

    def _get_extractor(self):
        if self._extractor is None:
            from agent.extractor import ExtractorAgent
            self._extractor = ExtractorAgent(self.config, None)
        return self._extractor
