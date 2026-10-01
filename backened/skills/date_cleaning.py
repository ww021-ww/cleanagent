"""
日期格式归一化技能（通用）
将各种日期格式统一为 YYYY-MM-DD
"""
import re
from datetime import datetime
from typing import Dict, List

from agent.skills import CleaningSkill


class DateNormalizerSkill(CleaningSkill):
    name = "date_normalizer"
    description = "统一日期格式为 YYYY-MM-DD"
    source = ""     # 通用，适用所有来源
    priority = 5

    _DATE_FIELDS = ["published_date", "modified_date", "disclosure_date", "update_date"]
    _PATTERNS = [
        (r"\d{4}/\d{2}/\d{2}", "%Y/%m/%d"),
        (r"\d{4}\.\d{2}\.\d{2}", "%Y.%m.%d"),
        (r"\d{4}年\d{1,2}月\d{1,2}日", "%Y年%m月%d日"),
        (r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", "%Y-%m-%dT%H:%M:%S"),
    ]

    def clean(self, data: Dict) -> Dict:
        for field in self._DATE_FIELDS:
            value = data.get(field)
            if value and isinstance(value, str):
                normalized = self._normalize(value)
                if normalized:
                    data[field] = normalized
        return data

    def _normalize(self, date_str: str) -> str:
        for pattern, fmt in self._PATTERNS:
            if re.match(pattern, date_str.strip()):
                try:
                    return datetime.strptime(date_str.strip(), fmt).strftime("%Y-%m-%d")
                except ValueError:
                    pass
        return date_str
