"""
Tool Registry — 工具管理与智能调用
"""
import logging
from typing import Any, Callable, Dict, List, Optional

from tools.builtin import BUILTIN_TOOLS

logger = logging.getLogger(__name__)


class ToolAgent:
    """
    工具智能体

    职责：
    1. 注册和管理可用工具（内置 + 自定义）
    2. 根据缺失字段自动选择合适的工具（auto_fill）
    3. 记录调用统计
    """

    def __init__(self, config: Dict, llm_client=None):
        tool_cfg = config.get("agentic", {}).get("tools", {})
        self.enabled: bool = tool_cfg.get("enabled", False)
        self.nvd_api_key: str = tool_cfg.get("nvd_api_key", "")
        self.tavily_api_key: str = tool_cfg.get("tavily_api_key", "")
        self.max_calls_per_file: int = tool_cfg.get("max_calls_per_file", 3)

        self.llm_client = llm_client
        self.tools: Dict[str, Callable] = {}
        self.stats = {"calls": 0, "success": 0, "failed": 0}

        self._register_builtin_tools()

    # ──────────────────────────────────────────────
    #  注册管理
    # ──────────────────────────────────────────────

    def _register_builtin_tools(self):
        for func in BUILTIN_TOOLS:
            meta = getattr(func, "_tool_meta", {})
            if meta:
                self.tools[meta["name"]] = func
        logger.info(f"🔧 ToolAgent: 注册 {len(self.tools)} 个内置工具")

    def register(self, func: Callable):
        """注册自定义工具（需带 @tool 装饰器）"""
        meta = getattr(func, "_tool_meta", {})
        if meta:
            self.tools[meta["name"]] = func

    def get_descriptions(self) -> str:
        lines = []
        for func in self.tools.values():
            m = func._tool_meta
            lines.append(f"- {m['name']}: {m['description']} [成本:{m['cost']}]")
        return "\n".join(lines)

    # ──────────────────────────────────────────────
    #  智能补全（clean_validate_node 后调用）
    # ──────────────────────────────────────────────

    def auto_fill(self, data: Dict, missing_fields: List[str],
                  source: str, raw_content: str = "") -> Dict[str, Any]:
        """
        根据缺失字段自动选择工具补全

        决策顺序：
        1. 有 CVE ID → nvd_lookup 补全 description / cvss_score
        2. JVN 来源 + 日文描述 → translate_text 翻译
        3. 其余缺失且有内容 → tavily_search 搜索补全
        """
        if not self.enabled:
            return {}

        filled: Dict[str, Any] = {}
        calls = 0

        cve_id = data.get("cve_id", "")

        # 策略 1：有 CVE ID，通过 NVD 补全
        if cve_id and cve_id.startswith("CVE-"):
            needs_nvd = any(
                f in missing_fields for f in ["description", "cvss_score", "overview"]
            )
            if needs_nvd and calls < self.max_calls_per_file:
                nvd_data = self.tools["nvd_lookup"](cve_id, self.nvd_api_key)
                calls += 1
                self._tally(nvd_data)
                if nvd_data:
                    if "description" in missing_fields and nvd_data.get("description"):
                        filled["description"] = nvd_data["description"]
                    if "cvss_score" in missing_fields and nvd_data.get("cvss_score"):
                        filled["cvss_score"] = nvd_data["cvss_score"]

        # 策略 2：JVN 日文描述翻译
        if source.lower() == "jvn" and data.get("description"):
            desc = data["description"]
            has_japanese = any("\u3040" <= c <= "\u30FF" for c in desc)
            if has_japanese and calls < self.max_calls_per_file:
                result = self.tools["translate_text"](
                    desc, source_lang="日文", llm_client=self.llm_client
                )
                calls += 1
                self._tally(result)
                if result:
                    filled["description_zh"] = result

        # 策略 3：还有缺失字段，用 Tavily 搜索
        still_missing = [f for f in missing_fields if f not in filled]
        if still_missing and calls < self.max_calls_per_file:
            vuln_id = (
                cve_id
                or data.get("cnvd_id", "")
                or data.get("title", "")[:50]
            )
            if vuln_id:
                query = f"{vuln_id} vulnerability {' '.join(still_missing)}"
                search_results = self.tools["tavily_search"](query, max_results=3, api_key=self.tavily_api_key)
                calls += 1
                self._tally(search_results)
                if search_results:
                    # 将搜索摘要作为 extra_context 返回供 LLM 参考
                    snippets = [r.get("content", "") for r in search_results if r.get("content")]
                    if snippets:
                        filled["_search_context"] = "\n".join(snippets[:2])[:1000]

        if filled:
            logger.info(f"🔧 ToolAgent: 补全 {[k for k in filled if not k.startswith('_')]}")

        return filled

    def _tally(self, result):
        self.stats["calls"] += 1
        if result is not None:
            self.stats["success"] += 1
        else:
            self.stats["failed"] += 1
