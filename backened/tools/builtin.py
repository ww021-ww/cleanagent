"""
内置工具函数
每个工具用 @tool 装饰器标注 name / description / cost
"""
import os
import logging
import time
from functools import wraps
from typing import Any, Callable, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────
#  工具装饰器
# ──────────────────────────────────────────────

def tool(name: str, description: str, cost: str = "low"):
    """
    工具注册装饰器

    Args:
        name: 工具名称
        description: 工具描述（供 Agent 选择时参考）
        cost: 调用成本 ('low'/'medium'/'high')
    """
    def decorator(func: Callable) -> Callable:
        func._tool_meta = {"name": name, "description": description, "cost": cost}

        @wraps(func)
        def wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = func(*args, **kwargs)
                logger.info(f"🔧 工具 {name}: 成功 ({time.time() - start:.1f}s)")
                return result
            except Exception as e:
                logger.warning(f"🔧 工具 {name}: 失败 ({time.time() - start:.1f}s) - {e}")
                return None

        wrapper._tool_meta = func._tool_meta
        return wrapper

    return decorator


# ──────────────────────────────────────────────
#  内置工具实现
# ──────────────────────────────────────────────

@tool("nvd_lookup", "查询 NVD 数据库获取 CVE 详细信息（描述、CVSS 评分）", cost="medium")
def nvd_lookup(cve_id: str, api_key: str = "") -> Optional[Dict]:
    """调用 NVD 公开 REST API（免费，有 key 限速更高）"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    headers = {"apiKey": api_key} if api_key else {}
    resp = requests.get(url, headers=headers, timeout=15)
    resp.raise_for_status()
    vulns = resp.json().get("vulnerabilities", [])
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})
    en_desc = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), ""
    )
    cvss_v31 = cve.get("metrics", {}).get("cvssMetricV31", [])
    score = cvss_v31[0].get("cvssData", {}).get("baseScore") if cvss_v31 else None
    return {
        "cve_id": cve_id,
        "description": en_desc,
        "cvss_score": score,
        "published": cve.get("published", ""),
        "references": [r.get("url") for r in cve.get("references", [])],
    }


@tool("cve_verify", "验证 CVE ID 是否真实存在于 NVD 数据库", cost="low")
def cve_verify(cve_id: str) -> bool:
    """快速验证 CVE ID 有效性"""
    if not cve_id or not cve_id.startswith("CVE-"):
        return False
    return nvd_lookup(cve_id) is not None


@tool("tavily_search", "使用 Tavily 搜索漏洞相关资讯", cost="medium")
def tavily_search(query: str, max_results: int = 5, api_key: str = "") -> Optional[List[Dict]]:
    """调用 Tavily 搜索 API"""
    api_key = api_key or os.getenv("TAVILY_API_KEY", "")
    if not api_key:
        return None
    from tavily import TavilyClient
    client = TavilyClient(api_key=api_key)
    resp = client.search(query=query, max_results=max_results)
    return resp.get("results", [])


@tool("serpapi_search", "使用 SerpAPI 进行 Google 搜索（Tavily 备用）", cost="medium")
def serpapi_search(query: str, num: int = 5) -> Optional[List[Dict]]:
    """调用 SerpAPI Google 搜索"""
    api_key = os.getenv("SERPAPI_API_KEY", "").strip()
    if not api_key:
        return None
    from serpapi import GoogleSearch
    results = GoogleSearch({"q": query, "api_key": api_key, "num": num}).get_dict()
    return results.get("organic_results", [])


@tool("web_fetch", "抓取指定 URL 的网页内容", cost="medium")
def web_fetch(url: str, max_length: int = 5000) -> Optional[str]:
    """抓取网页内容（用于从 reference 链接获取补充信息）"""
    resp = requests.get(
        url, timeout=10,
        headers={"User-Agent": "Mozilla/5.0 VulnProcessor/1.0"},
    )
    resp.raise_for_status()
    return resp.text[:max_length]


@tool("translate_text", "使用 LLM 翻译文本（日文/英文→中文）", cost="high")
def translate_text(text: str, source_lang: str = "auto",
                   llm_client=None) -> Optional[str]:
    """调用 OpenAI 兼容 LLM 翻译"""
    if not llm_client or not text:
        return None
    model = os.getenv("DEFAULT_LLM_MODEL", "gpt-4o-mini")
    prompt = f"请将以下{source_lang}文本翻译为中文，只输出翻译结果：\n{text[:2000]}"
    resp = llm_client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1,
    )
    return resp.choices[0].message.content.strip()


# 提供给 ToolAgent 注册的工具列表
BUILTIN_TOOLS: List[Callable] = [
    nvd_lookup, cve_verify, tavily_search, serpapi_search, web_fetch, translate_text,
]
