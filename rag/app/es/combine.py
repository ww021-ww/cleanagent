def merge_results(keyword_results: list, vector_results: list) -> dict:
    """合并关键词检索与向量检索结果，每条记录包含 score1(关键词) 和 score2(向量)"""
    merged = {}

    for hit in keyword_results:
        doc_id = hit["_id"]
        merged[doc_id] = {"score1": hit["_score"], "score2": 0.0}
        for k, v in hit.items():
            if k not in ("_id", "_score"):
                merged[doc_id][k] = v

    for hit in vector_results:
        doc_id = hit["_id"]
        if doc_id in merged:
            merged[doc_id]["score2"] = hit["_score"]
        else:
            merged[doc_id] = {"score1": 0.0, "score2": hit["_score"]}
            for k, v in hit.items():
                if k not in ("_id", "_score"):
                    merged[doc_id][k] = v

    return merged


MIN_SCORE = 0.70       # 融合分数低于此阈值视为不相关
MIN_KW_SCORE = 0.10   # 关键词分数低于此值视为无效匹配（仅靠停用词命中）
MIN_VEC_ONLY = 0.65   # 关键词无效时，向量分数须超过此值才算相关


def top_k_weighted(merged: dict, top_k: int = 5, w1: float = 0.4, w2: float = 0.6) -> list:
    """加权融合分数，返回 top_k 条结果（向量权重更高，语义优先）"""
    scored = {}
    for doc_id, data in merged.items():
        score1 = data["score1"]
        score2 = data["score2"]
        score = score1 * w1 + score2 * w2
        if score < MIN_SCORE:
            continue
        if score1 < MIN_KW_SCORE and score2 < MIN_VEC_ONLY:
            continue
        scored[doc_id] = {"score": round(score, 4)}
        for k, v in data.items():
            if k not in ("score1", "score2"):
                scored[doc_id][k] = v

    sorted_items = sorted(scored.items(), key=lambda x: x[1]["score"], reverse=True)
    return [{"id": doc_id, **data} for doc_id, data in sorted_items[:top_k]]
