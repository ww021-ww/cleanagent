import numpy as np
from elasticsearch.exceptions import NotFoundError

from app.es.client import es
from app.es.embeddings import generate_embeddings
from app.utils.logger import logger


def vector_search(query_text: str, index: str, top_k: int = 10) -> list:
    """语义向量检索，余弦相似度，分数映射到 [0,1]"""
    vec = generate_embeddings(query_text)
    query_vec = np.array(vec[0]).tolist()

    resp = es.search(index=f"{index}_vec", body={
        "size": top_k,
        "query": {
            "script_score": {
                "query": {"match_all": {}},
                "script": {
                    "source": "cosineSimilarity(params.query_vector, params.field_name) + 1.0",
                    "params": {
                        "query_vector": query_vec,
                        "field_name": f"{index}_vector"
                    }
                }
            }
        }
    })

    results = []
    for hit in resp["hits"]["hits"]:
        score = max(hit["_score"] - 1.0, 0.0)
        try:
            doc = es.get(index=index, id=hit["_id"])
            results.append({"_id": hit["_id"], **doc["_source"], "_score": score})
        except NotFoundError:
            logger.warning(f"向量命中但文档不存在: {hit['_id']}")
            continue
    return results
