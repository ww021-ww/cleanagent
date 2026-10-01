"""
RAG Retriever — 漏洞知识库检索器
基于 Milvus 向量数据库，为提取和清洗提供历史相似漏洞参考
"""
import os
import logging
from typing import Dict, List, Optional

from rag.embeddings import OllamaEmbedding

logger = logging.getLogger(__name__)

_MILVUS_HOST = os.getenv("MILVUS_HOST", "localhost")
_MILVUS_PORT = int(os.getenv("MILVUS_PORT", "19530"))
_COLLECTION = os.getenv("MILVUS_COLLECTION", "vuln_knowledge_v2")


class RAGRetriever:
    """
    漏洞知识库检索器

    职责：
    1. 将已处理的漏洞向量化存入 Milvus
    2. 根据当前漏洞内容检索相似历史漏洞
    3. 为 LLM 构建 few-shot 参考上下文
    """

    def __init__(self, config: Dict):
        rag_cfg = config.get("agentic", {}).get("rag", {})
        self.enabled: bool = rag_cfg.get("enabled", False)
        self.collection_name: str = rag_cfg.get("collection_name", _COLLECTION)
        self.top_k: int = rag_cfg.get("top_k", 5)
        self.host: str = rag_cfg.get("host", _MILVUS_HOST)
        self.port: int = int(rag_cfg.get("port", _MILVUS_PORT))

        self._client = None
        self._embed = OllamaEmbedding()

        if self.enabled:
            self._init_milvus()

    # ──────────────────────────────────────────────
    #  初始化
    # ──────────────────────────────────────────────

    def _init_milvus(self):
        try:
            from pymilvus import MilvusClient, DataType

            uri = f"http://{self.host}:{self.port}"
            self._client = MilvusClient(uri=uri)
            embed_dim = self._embed.detect_dim()
            logger.info(f"🔢 当前 embedding 维度: {embed_dim}")
            self._ensure_collection(DataType)
            count = self._client.query(
                collection_name=self.collection_name,
                filter="",
                output_fields=["count(*)"],
            )
            total = count[0].get("count(*)", 0) if count else 0
            logger.info(f"🔍 RAG 初始化完成: {total} 条向量 @ {uri}")
        except ImportError:
            logger.warning("pymilvus 未安装，RAG 功能禁用")
            self.enabled = False
        except Exception as e:
            logger.warning(f"RAG 初始化失败，功能禁用: {e}")
            self.enabled = False

    def _ensure_collection(self, DataType):
        """确保 Collection 存在且维度匹配，不存在则创建。"""
        expected_dim = self._embed.dim
        if self._client.has_collection(self.collection_name):
            actual_dim = self._get_collection_vector_dim(self.collection_name)
            if actual_dim and actual_dim != expected_dim:
                raise ValueError(
                    f"Milvus collection '{self.collection_name}' 向量维度不匹配："
                    f"当前 collection={actual_dim}，embedding={expected_dim}。"
                    f"请切换新的 collection_name 或重建该 collection。"
                )
            return

        schema = self._client.create_schema(auto_id=False, enable_dynamic_field=True)
        schema.add_field("id", DataType.VARCHAR, is_primary=True, max_length=128)
        schema.add_field("vector", DataType.FLOAT_VECTOR, dim=expected_dim)
        schema.add_field("source", DataType.VARCHAR, max_length=32)
        schema.add_field("vuln_id", DataType.VARCHAR, max_length=64)
        schema.add_field("document", DataType.VARCHAR, max_length=65535)

        index_params = self._client.prepare_index_params()
        index_params.add_index("vector", metric_type="IP", index_type="HNSW",
                               params={"M": 16, "efConstruction": 200})

        self._client.create_collection(
            collection_name=self.collection_name,
            schema=schema,
            index_params=index_params,
        )
        logger.info(f"✅ Milvus Collection '{self.collection_name}' 创建完成")

    def _get_collection_vector_dim(self, collection_name: str) -> int:
        try:
            desc = self._client.describe_collection(collection_name)
        except Exception:
            return 0
        for field in desc.get("fields", []):
            if field.get("name") != "vector":
                continue
            params = field.get("params", {}) or {}
            dim = params.get("dim")
            if dim is None:
                dim = field.get("dim")
            try:
                return int(dim or 0)
            except Exception:
                return 0
        return 0

    # ──────────────────────────────────────────────
    #  写入（store_node 成功后调用）
    # ──────────────────────────────────────────────

    def index_vulnerability(self, vuln_data: Dict, source: str):
        """
        将一条已处理的漏洞写入 Milvus

        向量内容 = title + description + overview + source + severity
        """
        if not self.enabled or not self._client:
            raise RuntimeError("RAG indexing is disabled or Milvus is unavailable")

        vuln_id = (
            vuln_data.get("vuln_id")
            or vuln_data.get("cnvd_id")
            or vuln_data.get("cve_id", "")
        )
        if not vuln_id:
            raise ValueError("Vulnerability ID is required for RAG indexing")

        content = list(filter(None, [
            vuln_data.get("title", ""),
            vuln_data.get("description", ""),
            vuln_data.get("overview", ""),
        ]))
        if not content:
            raise ValueError(f"No indexable content for vulnerability {vuln_id}")
        doc = "\n".join(content + [
            f"来源: {source}",
            f"严重程度: {vuln_data.get('severity', '')}",
        ])

        vector = self._embed.embed(doc)
        if len(vector) != self._embed.dim:
            raise ValueError(
                f"Embedding dimension mismatch for {vuln_id}: "
                f"expected={self._embed.dim}, actual={len(vector)}"
            )
        record_id = f"{source}_{vuln_id}"[:128]

        self._client.upsert(
            collection_name=self.collection_name,
            data=[{
                "id": record_id,
                "vector": vector,
                "source": source[:32],
                "vuln_id": str(vuln_id)[:64],
                "document": doc[:65535],
            }],
        )

    # ──────────────────────────────────────────────
    #  检索（extract_node 调用）
    # ──────────────────────────────────────────────

    def retrieve_similar(self, query_text: str, source: str = "",
                         top_k: int = None) -> List[Dict]:
        """
        检索相似漏洞

        Args:
            query_text: 当前漏洞的原始文本片段
            source: 可选，限定同来源检索
            top_k: 返回条数

        Returns:
            [{id, document, source, vuln_id, distance}, ...]
        """
        if not self.enabled or not self._client:
            return []

        k = top_k or self.top_k
        vector = self._embed.embed(query_text[:2000])
        if len(vector) != self._embed.dim:
            logger.warning(f"RAG 检索跳过：向量维度异常，expected={self._embed.dim}, actual={len(vector)}")
            return []

        filter_expr = f'source == "{source}"' if source else ""

        try:
            results = self._client.search(
                collection_name=self.collection_name,
                data=[vector],
                limit=k,
                filter=filter_expr,
                output_fields=["source", "vuln_id", "document"],
            )
            similar = []
            for hit in results[0]:
                similar.append({
                    "id": hit["id"],
                    "document": hit["entity"].get("document", ""),
                    "source": hit["entity"].get("source", ""),
                    "vuln_id": hit["entity"].get("vuln_id", ""),
                    "distance": hit.get("distance"),
                })
            return similar
        except Exception as e:
            logger.debug(f"RAG 检索失败: {e}")
            return []

    def build_rag_context(self, similar_vulns: List[Dict]) -> str:
        """将检索结果转为 LLM few-shot 上下文文本"""
        if not similar_vulns:
            return ""
        parts = ["以下是历史相似漏洞的处理结果，供参考：\n"]
        for i, v in enumerate(similar_vulns[:3], 1):
            parts.append(
                f"参考{i} [{v.get('source', '')}] {v.get('vuln_id', '')}:\n"
                f"{v.get('document', '')[:500]}\n"
            )
        return "\n".join(parts)
