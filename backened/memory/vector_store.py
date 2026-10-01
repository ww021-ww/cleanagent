import logging
import os
from typing import Dict, List

from rag.embeddings import OllamaEmbedding


logger = logging.getLogger(__name__)


class MemoryVectorStore:
    def __init__(self, collection_name: str = "conversation_memory", host: str = None, port: int = None):
        self.collection_name = collection_name
        self.host = host or os.getenv("MILVUS_HOST", "localhost")
        self.port = int(port or os.getenv("MILVUS_PORT", "19530"))
        self.enabled = False
        self._client = None
        self._embed = OllamaEmbedding()
        self._init_milvus()

    def _init_milvus(self):
        try:
            from pymilvus import MilvusClient, DataType
            self._client = MilvusClient(uri=f"http://{self.host}:{self.port}")
            self._ensure_collection(DataType)
            self.enabled = True
        except Exception as e:
            logger.warning(f"MemoryVectorStore 初始化失败，将禁用向量召回: {e}")
            self.enabled = False

    def _ensure_collection(self, DataType):
        if self._client.has_collection(self.collection_name):
            return
        schema = self._client.create_schema(auto_id=False, enable_dynamic_field=True)
        schema.add_field("memory_id", DataType.VARCHAR, is_primary=True, max_length=64)
        schema.add_field("vector", DataType.FLOAT_VECTOR, dim=self._embed.dim)
        schema.add_field("user_id", DataType.VARCHAR, max_length=64)
        schema.add_field("scope", DataType.VARCHAR, max_length=16)
        schema.add_field("memory_type", DataType.VARCHAR, max_length=32)
        schema.add_field("summary_text", DataType.VARCHAR, max_length=4096)
        index_params = self._client.prepare_index_params()
        index_params.add_index("vector", metric_type="IP", index_type="HNSW", params={"M": 16, "efConstruction": 200})
        self._client.create_collection(collection_name=self.collection_name, schema=schema, index_params=index_params)

    def upsert_memory(self, memory_id: str, user_id: str, scope: str, memory_type: str, retrieval_text: str, summary_text: str):
        if not self.enabled or not self._client or not retrieval_text.strip():
            return
        vector = self._embed.embed(retrieval_text[:4096])
        self._client.upsert(
            collection_name=self.collection_name,
            data=[{
                "memory_id": memory_id,
                "vector": vector,
                "user_id": user_id[:64],
                "scope": scope[:16],
                "memory_type": memory_type[:32],
                "summary_text": summary_text[:4096],
            }],
        )

    def search(self, query: str, user_id: str, top_k: int = 5) -> List[Dict]:
        if not self.enabled or not self._client or not query.strip():
            return []
        vector = self._embed.embed(query[:2000])
        try:
            results = self._client.search(
                collection_name=self.collection_name,
                data=[vector],
                limit=top_k,
                filter=f'user_id == "{user_id}"',
                output_fields=["scope", "memory_type", "summary_text"],
            )
        except Exception as e:
            logger.debug(f"长期记忆向量检索失败: {e}")
            return []
        hits = []
        for hit in results[0]:
            hits.append({
                "memory_id": hit["id"],
                "scope": hit["entity"].get("scope", ""),
                "memory_type": hit["entity"].get("memory_type", ""),
                "summary_text": hit["entity"].get("summary_text", ""),
                "distance": hit.get("distance"),
            })
        return hits
