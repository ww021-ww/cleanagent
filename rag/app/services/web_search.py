from tavily import TavilyClient

from app.config.settings import TAVILY_API_KEY
from app.utils.logger import logger

_client = TavilyClient(api_key=TAVILY_API_KEY) if TAVILY_API_KEY else None


def web_search(query: str, max_results: int = 3) -> list[dict]:
    """
    调用 Tavily 联网搜索，返回结构化结果列表。
    每条结果：{"title": str, "content": str, "url": str}
    未配置 API Key 或搜索失败时返回空列表。
    """
    if not _client:
        logger.warning("TAVILY_API_KEY 未配置，跳过联网搜索")
        return []
    try:
        resp = _client.search(query, max_results=max_results, search_depth="basic")
        results = []
        for item in resp.get("results", []):
            results.append({
                "title":   item.get("title", ""),
                "content": item.get("content", ""),
                "url":     item.get("url", ""),
            })
        logger.info(f"[web_search] 查询 '{query}'，返回 {len(results)} 条结果")
        return results
    except Exception as e:
        logger.error(f"[web_search] 搜索失败: {e}")
        return []
