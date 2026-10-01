import json
from openai import OpenAI

from app.config.settings import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, KNOWLEDGE_INDEX
from app.es.knowledge_index import (
    ensure_indices, add_knowledge, update_knowledge,
    delete_knowledge, list_knowledge, get_knowledge
)
from app.es.query_keyword import keyword_search
from app.es.query_vector import vector_search
from app.es.combine import merge_results, top_k_weighted
from app.utils.logger import logger
from app.services.web_search import web_search

_llm = OpenAI(api_key=LLM_API_KEY, base_url=LLM_BASE_URL)


# ---------- CRUD ----------

def create_knowledge_doc(title: str, content: str, source: str = "direct_input", filename: str = "") -> dict:
    ensure_indices()
    doc_id = add_knowledge(title, content, source, filename)
    logger.info(f"知识文档已创建: {doc_id} - {title}")
    return {"id": doc_id, "title": title}


def update_knowledge_doc(doc_id: str, title: str, content: str) -> dict:
    update_knowledge(doc_id, title, content)
    logger.info(f"知识文档已更新: {doc_id}")
    return {"id": doc_id, "title": title}


def delete_knowledge_doc(doc_id: str) -> dict:
    delete_knowledge(doc_id)
    logger.info(f"知识文档已删除: {doc_id}")
    return {"id": doc_id}


def list_knowledge_docs(page: int = 1, size: int = 10) -> dict:
    ensure_indices()
    return list_knowledge(page, size)


def get_knowledge_doc(doc_id: str) -> dict | None:
    return get_knowledge(doc_id)


# ---------- 检索 ----------

def search_knowledge(query: str, top_k: int = 5) -> list:
    """混合检索：关键词 + 向量，融合排序"""
    ensure_indices()
    kw_results = keyword_search(query, KNOWLEDGE_INDEX, top_k)
    vec_results = vector_search(query, KNOWLEDGE_INDEX, top_k)
    merged = merge_results(kw_results, vec_results)
    for doc_id, data in merged.items():
        s1 = data.get("score1", 0)
        s2 = data.get("score2", 0)
        logger.info(f"[score] {data.get('title','?')} | kw={s1:.3f} vec={s2:.3f} combined={s1*0.4+s2*0.6:.3f}")
    return top_k_weighted(merged, top_k)


# ---------- 流式问答 ----------

def stream_ask(query: str, top_k: int = 3):
    """
    检索相关文档后调用 LLM 流式回答，以 SSE 格式 yield 数据。
    前端通过 EventSource 或 fetch + ReadableStream 接收。
    """
    ensure_indices()

    results = search_knowledge(query, top_k)
    web_results = []

    if results:
        context_parts = []
        for i, doc in enumerate(results, 1):
            title = doc.get("title", "无标题")
            content = doc.get("content", "")
            context_parts.append(f"【文档{i}：{title}】\n{content}")
        context = "\n\n".join(context_parts)
        prompt = (
            f"你是一个知识库助手，请根据以下知识库内容回答用户问题。\n\n"
            f"知识库内容：\n{context}\n\n"
            f"用户问题：{query}\n\n"
            f"请根据知识库内容进行回答。如果知识库中没有相关信息，请如实告知。"
        )
    else:
        web_results = web_search(query, max_results=3)
        if web_results:
            context_parts = []
            for i, r in enumerate(web_results, 1):
                context_parts.append(f"【网络{i}：{r['title']}】\n{r['content']}")
            context = "\n\n".join(context_parts)
            prompt = (
                f"你是一个智能助手，本地知识库中无相关内容，以下是联网搜索结果，请根据它回答用户问题。\n\n"
                f"搜索结果：\n{context}\n\n"
                f"用户问题：{query}\n\n"
                f"请综合搜索结果回答，如无有用信息请如实告知。"
            )
        else:
            context = "知识库中暂无相关内容，联网搜索也未找到相关信息。"
            prompt = (
                f"用户问题：{query}\n\n"
                f"知识库和联网均无相关内容，请如实告知用户。"
            )

    def generate():
        try:
            # 先推送来源信息
            if results:
                sources = [
                    {"id": d["id"], "title": d.get("title", ""), "score": d.get("score", 0), "type": "kb"}
                    for d in results
                ]
            elif web_results:
                sources = [
                    {"id": str(i), "title": r["title"], "score": 0, "url": r["url"], "type": "web"}
                    for i, r in enumerate(web_results, 1)
                ]
            else:
                sources = []
            yield f"data: {json.dumps({'type': 'sources', 'data': sources}, ensure_ascii=False)}\n\n"

            # 知识库未命中时推送提示
            if not results and web_results:
                yield f"data: {json.dumps({'type': 'notice', 'data': '📭 本地知识库未检索到相关内容，已启用联网搜索'}, ensure_ascii=False)}\n\n"
            elif not results and not web_results:
                yield f"data: {json.dumps({'type': 'notice', 'data': '📭 本地知识库与联网均未找到相关内容'}, ensure_ascii=False)}\n\n"

            # 流式推送 LLM 回答
            stream = _llm.chat.completions.create(
                model=LLM_MODEL,
                messages=[{"role": "user", "content": prompt}],
                stream=True,
                temperature=0.1
            )
            for chunk in stream:
                delta = chunk.choices[0].delta
                if delta.content:
                    yield f"data: {json.dumps({'type': 'text', 'data': delta.content}, ensure_ascii=False)}\n\n"

            yield f"data: {json.dumps({'type': 'done'}, ensure_ascii=False)}\n\n"

        except Exception as e:
            logger.error(f"流式问答出错: {e}")
            yield f"data: {json.dumps({'type': 'error', 'data': str(e)}, ensure_ascii=False)}\n\n"

    return generate()
