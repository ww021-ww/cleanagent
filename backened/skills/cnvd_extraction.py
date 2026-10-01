"""
CNVD HTML 提取技能
示例：如何为特定来源编写 ExtractionSkill
"""
from typing import Dict, List

from agent.skills import ExtractionSkill


class CnvdHtmlExtractionSkill(ExtractionSkill):
    name = "cnvd_html_extractor"
    description = "CNVD HTML 页面漏洞提取"
    source = "cnvd"
    priority = 10

    def extract(self, content: str, file_path: str = "") -> List[Dict]:
        """
        直接复用 ExtractorAgent 中已有的 CNVD 提取器。
        此技能的存在主要是让 SkillRegistry 能感知 CNVD 有专用提取逻辑，
        实际提取委托给 agent.extractor.SourceExtractor。
        """
        from agent.extractor import ExtractorAgent
        # 此处不重复实现，只做路由标记
        return []
