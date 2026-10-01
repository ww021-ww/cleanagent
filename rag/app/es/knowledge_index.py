from datetime import datetime, timezone
import numpy as np

from app.es.client import es
from app.es.embeddings import generate_embeddings
from app.config.settings import KNOWLEDGE_INDEX, KNOWLEDGE_VEC_INDEX, VECTOR_DIMS
from app.utils.logger import logger


def ensure_indices():
    """若索引不存在则自动创建"""
    if not es.indices.exists(index=KNOWLEDGE_INDEX):
        es.indices.create(index=KNOWLEDGE_INDEX, body={
            "mappings": {
                "properties": {
                    "title":      {"type": "text", "analyzer": "standard"},
                    "content":    {"type": "text", "analyzer": "standard"},
                    "source":     {"type": "keyword"},
                    "filename":   {"type": "keyword"},
                    "created_at": {"type": "date"},
                    "updated_at": {"type": "date"}
                }
            }
        })
        logger.info(f"索引创建成功: {KNOWLEDGE_INDEX}")

    if not es.indices.exists(index=KNOWLEDGE_VEC_INDEX):
        es.indices.create(index=KNOWLEDGE_VEC_INDEX, body={
            "mappings": {
                "properties": {
                    "knowledge_vector": {
                        "type": "dense_vector",
                        "dims": VECTOR_DIMS,
                        "index": False
                    }
                }
            }
        })
        logger.info(f"索引创建成功: {KNOWLEDGE_VEC_INDEX}")


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def add_knowledge(title: str, content: str, source: str = "direct_input", filename: str = "") -> str:
    """新增知识文档，返回文档 ID"""
    now = _now_iso()
    result = es.index(index=KNOWLEDGE_INDEX, body={
        "title": title,
        "content": content,
        "source": source,
        "filename": filename,
        "created_at": now,
        "updated_at": now
    })
    doc_id = result["_id"]

    try:
        vec = generate_embeddings(title + " " + content)
        embedding = np.array(vec[0])
        es.index(index=KNOWLEDGE_VEC_INDEX, id=doc_id, body={
            "knowledge_vector": embedding.tolist()
        })
    except Exception as e:
        logger.error(f"向量写入失败 doc_id={doc_id}: {e}")

    return doc_id


def update_knowledge(doc_id: str, title: str, content: str):
    """更新知识文档及向量"""
    es.update(index=KNOWLEDGE_INDEX, id=doc_id, body={
        "doc": {"title": title, "content": content, "updated_at": _now_iso()}
    })
    try:
        vec = generate_embeddings(title + " " + content)
        embedding = np.array(vec[0])
        es.index(index=KNOWLEDGE_VEC_INDEX, id=doc_id, body={
            "knowledge_vector": embedding.tolist()
        })
    except Exception as e:
        logger.error(f"向量更新失败 doc_id={doc_id}: {e}")


def delete_knowledge(doc_id: str):
    """删除知识文档及对应向量"""
    es.delete(index=KNOWLEDGE_INDEX, id=doc_id, ignore=[404])
    es.delete(index=KNOWLEDGE_VEC_INDEX, id=doc_id, ignore=[404])


def list_knowledge(page: int = 1, size: int = 10) -> dict:
    """分页查询"""
    resp = es.search(index=KNOWLEDGE_INDEX, body={
        "query": {"match_all": {}},
        "sort": [{"created_at": {"order": "desc"}}],
        "from": (page - 1) * size,
        "size": size
    })
    total = resp["hits"]["total"]["value"]
    docs = []
    for hit in resp["hits"]["hits"]:
        src = hit["_source"]
        docs.append({
            "id": hit["_id"],
            "title": src.get("title", ""),
            "content": src.get("content", ""),
            "source": src.get("source", ""),
            "filename": src.get("filename", ""),
            "created_at": src.get("created_at", ""),
            "updated_at": src.get("updated_at", "")
        })
    return {"total": total, "page": page, "size": size, "docs": docs}


def get_knowledge(doc_id: str) -> dict | None:
    """按 ID 获取单条文档"""
    try:
        hit = es.get(index=KNOWLEDGE_INDEX, id=doc_id)
        return {"id": hit["_id"], **hit["_source"]}
    except Exception:
        return None
