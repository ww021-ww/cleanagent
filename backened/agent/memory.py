"""Batch and cross-batch memory for deduplication and quality statistics."""
import json
import logging
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set

logger = logging.getLogger(__name__)


class ShortTermMemory:
    """Batch-local IDs, quality scores, and success/failure counters."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.batch_seen_ids: Dict[str, Set[str]] = defaultdict(set)
        self.batch_quality_scores: Dict[str, List[float]] = defaultdict(list)
        self.batch_stats: Dict[str, Dict] = defaultdict(
            lambda: {'success': 0, 'failed': 0, 'total': 0}
        )

    def is_seen_in_batch(self, vuln_id: str, source: str) -> bool:
        return vuln_id in self.batch_seen_ids[source.lower()]

    def mark_seen(self, vuln_id: str, source: str):
        self.batch_seen_ids[source.lower()].add(vuln_id)

    def record_success(self, source: str, quality_score: float = 0.0):
        src = source.lower()
        self.batch_stats[src]['success'] += 1
        self.batch_stats[src]['total'] += 1
        if quality_score > 0:
            self.batch_quality_scores[src].append(quality_score)

    def record_failure(self, source: str):
        src = source.lower()
        self.batch_stats[src]['failed'] += 1
        self.batch_stats[src]['total'] += 1


class LongTermMemory:
    """Persistent known IDs, source profiles, and field failure patterns."""

    def __init__(self, persist_file: str = ''):
        self.persist_file = persist_file
        self.known_ids: Dict[str, Set[str]] = defaultdict(set)
        self.source_profiles: Dict[str, Dict] = defaultdict(lambda: {
            'total_processed': 0,
            'total_success': 0,
            'total_failed': 0,
            'avg_quality': 0.0,
            'quality_history': [],
        })
        self.failure_patterns: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self.load()

    def is_known(self, vuln_id: str, source: str) -> bool:
        return vuln_id in self.known_ids[source.lower()]

    def get_known_count(self, source: str = None) -> int:
        if source:
            return len(self.known_ids[source.lower()])
        return sum(len(ids) for ids in self.known_ids.values())

    def record_field_failures(self, source: str, missing_fields: List[str]):
        src = source.lower()
        for field in missing_fields:
            self.failure_patterns[src][field] += 1

    def get_common_missing_fields(self, source: str, top_n: int = 5) -> List[tuple]:
        patterns = self.failure_patterns.get(source.lower(), {})
        return sorted(patterns.items(), key=lambda item: item[1], reverse=True)[:top_n]

    def absorb_short_term(self, short_term: ShortTermMemory):
        for src, ids in short_term.batch_seen_ids.items():
            self.known_ids[src].update(ids)

        for src, stats in short_term.batch_stats.items():
            profile = self.source_profiles[src]
            profile['total_processed'] += stats['total']
            profile['total_success'] += stats['success']
            profile['total_failed'] += stats['failed']
            scores = short_term.batch_quality_scores.get(src, [])
            if scores:
                profile['quality_history'].extend(scores)
                profile['quality_history'] = profile['quality_history'][-200:]
                profile['avg_quality'] = (
                    sum(profile['quality_history']) / len(profile['quality_history'])
                )

        total = sum(stats['total'] for stats in short_term.batch_stats.values())
        logger.info(f"🧠 长期记忆吸收: 本批次 {total} 条记录")

    def save(self):
        if not self.persist_file:
            return
        data = {
            'known_ids': {key: list(ids) for key, ids in self.known_ids.items()},
            'source_profiles': {key: dict(value) for key, value in self.source_profiles.items()},
            'failure_patterns': {key: dict(value) for key, value in self.failure_patterns.items()},
            'saved_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        }
        Path(self.persist_file).parent.mkdir(parents=True, exist_ok=True)
        with open(self.persist_file, 'w', encoding='utf-8') as file:
            json.dump(data, file, ensure_ascii=False, indent=2)
        logger.info(
            f"🧠 长期记忆已保存: {self.get_known_count()} 个已知ID → {self.persist_file}"
        )

    def load(self):
        if not self.persist_file or not Path(self.persist_file).exists():
            return
        try:
            with open(self.persist_file, 'r', encoding='utf-8') as file:
                data = json.load(file)
            for src, ids in data.get('known_ids', {}).items():
                self.known_ids[src] = set(ids)
            for src, profile in data.get('source_profiles', {}).items():
                self.source_profiles[src].update({
                    key: value for key, value in profile.items()
                    if key in self.source_profiles[src]
                })
            for src, patterns in data.get('failure_patterns', {}).items():
                for field, count in patterns.items():
                    self.failure_patterns[src][field] = count
            logger.info(
                f"🧠 长期记忆已加载: {self.get_known_count()} 个已知ID"
                f" (上次保存: {data.get('saved_at', '未知')})"
            )
        except Exception as exc:
            logger.warning(f"长期记忆加载失败: {exc}")


class AgentMemory:
    """Single entry point for batch and persistent memory."""

    def __init__(self, config: Dict = None):
        cfg = config or {}
        self.short_term = ShortTermMemory()
        self.long_term = LongTermMemory(cfg.get('persist_file', ''))
        logger.info(f"AgentMemory 初始化 (已知ID: {self.long_term.get_known_count()} 个)")

    def is_seen(self, vuln_id: str, source: str) -> bool:
        return (
            self.short_term.is_seen_in_batch(vuln_id, source)
            or self.long_term.is_known(vuln_id, source)
        )

    def mark_seen(self, vuln_id: str, source: str):
        self.short_term.mark_seen(vuln_id, source)

    def record_success(self, source: str, quality_score: float = 0.0):
        self.short_term.record_success(source, quality_score)

    def record_failure(self, source: str):
        self.short_term.record_failure(source)

    def record_field_failures(self, source: str, missing_fields: List[str]):
        self.long_term.record_field_failures(source, missing_fields)

    def end_batch(self):
        logger.info("🧠 批次结束，开始记忆聚合...")
        self.long_term.absorb_short_term(self.short_term)
        self.long_term.save()
        self.short_term.reset()
        logger.info("🧠 记忆聚合完成，短期记忆已清空")

    def get_seen_count(self) -> int:
        return self.long_term.get_known_count()

    def get_source_profile(self, source: str) -> Dict:
        src = source.lower()
        profile = dict(self.long_term.source_profiles.get(src, {}))
        profile['common_missing_fields'] = self.long_term.get_common_missing_fields(src)
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
        for src, stats in self.get_quality_summary().items():
            print(f"  [{src}] 平均质量: {stats['avg']:.2f} | 总量: {stats['count']}")
        print("=" * 60 + "\n")
