"""
Agent Memory — 双层记忆系统
ShortTermMemory（批次内实时决策）+ LongTermMemory（跨批次经验持久化）
"""
import json
import logging
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

_STRATEGY_ESCALATION = {'rule': 'hybrid', 'hybrid': 'llm_full'}


class ShortTermMemory:
    """批次级内存 — 实时去重、连续失败检测、本批次策略升级"""

    def __init__(self, failure_threshold: int = 3):
        self.failure_threshold = failure_threshold
        self.reset()

    def reset(self):
        self.batch_seen_ids: Dict[str, Set[str]] = defaultdict(set)
        self.consecutive_failures: Dict[str, int] = defaultdict(int)
        self.strategy_overrides: Dict[str, str] = {}
        self.batch_quality_scores: Dict[str, List[float]] = defaultdict(list)
        self.batch_stats: Dict[str, Dict] = defaultdict(
            lambda: {'success': 0, 'failed': 0, 'total': 0}
        )
        # 增量聚合策略统计（替代逐条 batch_log，大规模场景节省内存）
        self.strategy_stats: Dict[tuple, Dict] = defaultdict(
            lambda: {'used': 0, 'success': 0, 'total_quality': 0.0}
        )

    def is_seen_in_batch(self, vuln_id: str, source: str) -> bool:
        return vuln_id in self.batch_seen_ids[source.lower()]

    def mark_seen(self, vuln_id: str, source: str):
        self.batch_seen_ids[source.lower()].add(vuln_id)

    def record_success(self, source: str, quality_score: float = 0.0, strategy: str = 'rule'):
        src = source.lower()
        self.consecutive_failures[src] = 0
        self.batch_stats[src]['success'] += 1
        self.batch_stats[src]['total'] += 1
        if quality_score > 0:
            self.batch_quality_scores[src].append(quality_score)
        key = (src, strategy or 'rule')
        self.strategy_stats[key]['used'] += 1
        self.strategy_stats[key]['success'] += 1
        self.strategy_stats[key]['total_quality'] += quality_score

    def record_failure(self, source: str, strategy: str = 'rule'):
        src = source.lower()
        self.consecutive_failures[src] += 1
        self.batch_stats[src]['failed'] += 1
        self.batch_stats[src]['total'] += 1
        key = (src, self.strategy_overrides.get(src, strategy or 'rule'))
        self.strategy_stats[key]['used'] += 1

        if self.consecutive_failures[src] >= self.failure_threshold:
            current = self.strategy_overrides.get(src, 'rule')
            upgraded = _STRATEGY_ESCALATION.get(current, 'llm_full')
            if upgraded != current:
                self.strategy_overrides[src] = upgraded
                logger.warning(
                    f"🧠 短期记忆: {src} 连续失败 {self.consecutive_failures[src]} 次，"
                    f"策略升级 {current} → {upgraded}"
                )

    def get_recommended_strategy(self, source: str) -> Optional[str]:
        return self.strategy_overrides.get(source.lower())


class LongTermMemory:
    """跨批次持久化记忆 — ID 去重、来源画像、失败模式、策略效果"""

    def __init__(self, persist_file: str = ''):
        self.persist_file = persist_file
        self.known_ids: Dict[str, Set[str]] = defaultdict(set)
        self.source_profiles: Dict[str, Dict] = defaultdict(lambda: {
            'total_processed': 0, 'total_success': 0, 'total_failed': 0,
            'avg_quality': 0.0, 'quality_history': [], 'best_strategy': None,
        })
        self.failure_patterns: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self.strategy_effectiveness: Dict[str, Dict] = defaultdict(
            lambda: defaultdict(lambda: {'used': 0, 'success': 0, 'avg_quality': 0.0})
        )
        self.load()

    def is_known(self, vuln_id: str, source: str) -> bool:
        return vuln_id in self.known_ids[source.lower()]

    def get_known_count(self, source: str = None) -> int:
        if source:
            return len(self.known_ids[source.lower()])
        return sum(len(v) for v in self.known_ids.values())

    def get_source_default_strategy(self, source: str) -> Optional[str]:
        return self.source_profiles[source.lower()].get('best_strategy')

    def record_field_failures(self, source: str, missing_fields: List[str]):
        src = source.lower()
        for field in missing_fields:
            self.failure_patterns[src][field] += 1

    def get_common_missing_fields(self, source: str, top_n: int = 5) -> List[tuple]:
        patterns = self.failure_patterns.get(source.lower(), {})
        return sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:top_n]

    def absorb_short_term(self, short_term: ShortTermMemory):
        for src, ids in short_term.batch_seen_ids.items():
            self.known_ids[src].update(ids)

        for src, stats in short_term.batch_stats.items():
            profile = self.source_profiles[src]
            profile['total_processed'] += stats['total']
            profile['total_success'] += stats['success']
            profile['total_failed'] += stats['failed']
            batch_scores = short_term.batch_quality_scores.get(src, [])
            if batch_scores:
                history = profile['quality_history']
                history.extend(batch_scores)
                profile['quality_history'] = history[-200:]
                profile['avg_quality'] = sum(profile['quality_history']) / len(profile['quality_history'])

        for (src, strategy), stats in short_term.strategy_stats.items():
            se = self.strategy_effectiveness[src][strategy]
            old_used = se['used']
            se['used'] += stats['used']
            se['success'] += stats['success']
            if stats['used'] > 0 and stats['total_quality'] > 0:
                old_total = se['avg_quality'] * old_used
                se['avg_quality'] = (old_total + stats['total_quality']) / se['used']

        for src in short_term.batch_stats:
            self._update_best_strategy(src)

        total = sum(s['total'] for s in short_term.batch_stats.values())
        logger.info(f"🧠 长期记忆吸收: 本批次 {total} 条记录")

    def _update_best_strategy(self, source: str):
        strategies = self.strategy_effectiveness.get(source, {})
        best, best_score = None, -1.0
        for strategy, stats in strategies.items():
            if stats['used'] < 3:
                continue
            score = (stats['success'] / stats['used']) * 0.6 + stats['avg_quality'] * 0.4
            if score > best_score:
                best_score, best = score, strategy
        if best:
            self.source_profiles[source]['best_strategy'] = best

    def save(self):
        if not self.persist_file:
            return
        data = {
            'known_ids': {k: list(v) for k, v in self.known_ids.items()},
            'source_profiles': {k: dict(v) for k, v in self.source_profiles.items()},
            'failure_patterns': {k: dict(v) for k, v in self.failure_patterns.items()},
            'strategy_effectiveness': {
                src: {s: dict(d) for s, d in strategies.items()}
                for src, strategies in self.strategy_effectiveness.items()
            },
            'saved_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        Path(self.persist_file).parent.mkdir(parents=True, exist_ok=True)
        with open(self.persist_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        logger.info(f"🧠 长期记忆已保存: {self.get_known_count()} 个已知ID → {self.persist_file}")

    def load(self):
        if not self.persist_file or not Path(self.persist_file).exists():
            return
        try:
            with open(self.persist_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for src, ids in data.get('known_ids', {}).items():
                self.known_ids[src] = set(ids)
            for src, profile in data.get('source_profiles', {}).items():
                self.source_profiles[src].update(profile)
            for src, patterns in data.get('failure_patterns', {}).items():
                for field, count in patterns.items():
                    self.failure_patterns[src][field] = count
            for src, strategies in data.get('strategy_effectiveness', {}).items():
                for strategy, stats in strategies.items():
                    self.strategy_effectiveness[src][strategy].update(stats)
            logger.info(
                f"🧠 长期记忆已加载: {self.get_known_count()} 个已知ID"
                f" (上次保存: {data.get('saved_at', '未知')})"
            )
        except Exception as e:
            logger.warning(f"长期记忆加载失败: {e}")


class AgentMemory:
    """智能体双层记忆 — 统一入口，组合 ShortTermMemory + LongTermMemory"""

    def __init__(self, config: Dict = None):
        cfg = config or {}
        self.short_term = ShortTermMemory(failure_threshold=cfg.get('failure_threshold', 3))
        self.long_term = LongTermMemory(persist_file=cfg.get('persist_file', ''))
        logger.info(f"AgentMemory 初始化 (已知ID: {self.long_term.get_known_count()} 个)")

    # ── 去重 ──────────────────────────────────────────────────────────────────

    def is_seen(self, vuln_id: str, source: str) -> bool:
        return (self.short_term.is_seen_in_batch(vuln_id, source)
                or self.long_term.is_known(vuln_id, source))

    def mark_seen(self, vuln_id: str, source: str):
        self.short_term.mark_seen(vuln_id, source)

    # ── 成功/失败记录 ─────────────────────────────────────────────────────────

    def record_success(self, source: str, quality_score: float = 0.0, strategy: str = 'rule'):
        self.short_term.record_success(source, quality_score, strategy)

    def record_failure(self, source: str, strategy: str = 'rule'):
        self.short_term.record_failure(source, strategy)

    def record_field_failures(self, source: str, missing_fields: List[str]):
        self.long_term.record_field_failures(source, missing_fields)

    # ── 策略推荐 ──────────────────────────────────────────────────────────────

    def get_recommended_strategy(self, source: str) -> Optional[str]:
        return (self.short_term.get_recommended_strategy(source)
                or self.long_term.get_source_default_strategy(source))

    # ── 批次生命周期 ──────────────────────────────────────────────────────────

    def end_batch(self):
        logger.info("🧠 批次结束，开始记忆聚合...")
        self.long_term.absorb_short_term(self.short_term)
        self.long_term.save()
        self.short_term.reset()
        logger.info("🧠 记忆聚合完成，短期记忆已清空")

    # ── 查询接口 ──────────────────────────────────────────────────────────────

    def get_seen_count(self) -> int:
        """返回长期记忆中已知漏洞 ID 的总数"""
        return self.long_term.get_known_count()

    def get_source_profile(self, source: str) -> Dict:
        """返回指定来源的历史画像（处理量、成功率、常见缺失字段等）"""
        src = source.lower()
        profile = dict(self.long_term.source_profiles.get(src, {}))
        profile['common_missing_fields'] = self.long_term.get_common_missing_fields(src)
        profile['best_strategy'] = self.long_term.get_source_default_strategy(src)
        return profile

    def get_quality_summary(self) -> Dict:
        summary = {}
        for src, profile in self.long_term.source_profiles.items():
            if profile.get('quality_history'):
                scores = profile['quality_history']
                summary[src] = {
                    'avg': profile['avg_quality'],
                    'min': min(scores),
                    'max': max(scores),
                    'count': profile['total_processed'],
                }
        return summary

    def print_summary(self):
        print("\n" + "=" * 60)
        print("🧠 智能体记忆摘要")
        print("=" * 60)
        print(f"长期已知ID总数: {self.long_term.get_known_count()}")
        quality = self.get_quality_summary()
        for src, stats in quality.items():
            print(f"  [{src}] 平均质量: {stats['avg']:.2f} | 总量: {stats['count']}")
        print("=" * 60 + "\n")
