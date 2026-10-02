"""
OpenAI-Compatible Embedding — 调用兼容 OpenAI 的 embeddings 接口生成向量
"""
import os
import logging
from typing import List, Optional

import requests

logger = logging.getLogger(__name__)

class OllamaEmbedding:
    """
    基于 OpenAI 兼容接口的文本向量化工具

    直接调用 POST /v1/embeddings，无需 openai 库。
    """

    def __init__(self, base_url: str = None, model: str = None, dim: Optional[int] = None):
        self.url = (
            base_url
            or os.getenv("EMBED_API_BASE", "https://api.openai.com/v1")
        ).rstrip("/")
        if not self.url.endswith("/embeddings"):
            self.url = self.url + "/embeddings"
        self.model = model or os.getenv("EMBED_MODEL", "text-embedding-3-small")
        self.api_key = os.getenv("EMBED_API_KEY", "")
        self._dim: int = int(dim or os.getenv("EMBED_DIM", "0") or 0)

    def _fallback_dim(self) -> int:
        return self._dim or 768

    def _zero_vector(self) -> List[float]:
        return [0.0] * self._fallback_dim()

    def embed(self, text: str) -> List[float]:
        """
        将单条文本向量化

        Returns:
            embedding float 列表；失败时返回当前已知维度的零向量
        """
        if not text or not text.strip():
            return self._zero_vector()
        if not self.api_key:
            raise RuntimeError("EMBED_API_KEY is not configured")
        try:
            resp = requests.post(
                self.url,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"model": self.model, "input": text[:4096]},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            vector = data["data"][0]["embedding"]
            if isinstance(vector, list) and vector:
                self._dim = len(vector)
            return vector
        except Exception as e:
            raise RuntimeError(f"Embedding request failed: {e}") from e

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        """批量向量化（逐条调用兼容接口）"""
        return [self.embed(t) for t in texts]

    @property
    def dim(self) -> int:
        return self._fallback_dim()

    def detect_dim(self) -> int:
        if self._dim > 0:
            return self._dim
        probe = self.embed("dimension probe")
        if probe:
            self._dim = len(probe)
        return self._fallback_dim()
