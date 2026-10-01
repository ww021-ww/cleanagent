from app.es.client import es


def keyword_search(query_text: str, index: str, top_k: int = 10) -> list:
    """全文关键词检索，分数归一化到 [0,1]"""
    resp = es.search(index=index, body={
        "query": {
            "multi_match": {
                "query": query_text,
                "fields": ["title^2", "content"]
            }
        },
        "size": top_k
    })
    hits = resp["hits"]["hits"]
    if not hits:
        return []

    raw_scores = [h["_score"] for h in hits]
    min_s = min(raw_scores)
    max_s = max(raw_scores)
    score_range = max_s - min_s if max_s != min_s else 1.0

    results = []
    for hit in hits:
        norm = (hit["_score"] - min_s) / score_range if hit["_score"] != min_s else 1.0
        results.append({"_id": hit["_id"], **hit["_source"], "_score": norm})
    return results
