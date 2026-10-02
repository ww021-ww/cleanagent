import pytest
import requests
import openai

import check_env
from rag.embeddings import OllamaEmbedding


class _Response:
    def raise_for_status(self):
        return None

    def json(self):
        return {"data": [{"embedding": [0.1, 0.2, 0.3, 0.4]}]}


def test_embedding_request_uses_dedicated_provider_config(monkeypatch):
    monkeypatch.setenv("OPENAI_API_BASE", "https://api.deepseek.com")
    monkeypatch.setenv("OPENAI_API_KEY", "chat-secret")
    monkeypatch.setenv("EMBED_API_BASE", "https://api.siliconflow.cn/v1")
    monkeypatch.setenv("EMBED_API_KEY", "embed-secret")
    monkeypatch.setenv("EMBED_MODEL", "Qwen/Qwen3-VL-Embedding-8B")
    monkeypatch.setenv("EMBED_DIM", "4096")
    request = {}

    def fake_post(url, *, headers, json, timeout):
        request.update(url=url, headers=headers, json=json, timeout=timeout)
        return _Response()

    monkeypatch.setattr(requests, "post", fake_post)

    vector = OllamaEmbedding().embed("verified vulnerability")

    assert vector == [0.1, 0.2, 0.3, 0.4]
    assert request == {
        "url": "https://api.siliconflow.cn/v1/embeddings",
        "headers": {"Authorization": "Bearer embed-secret"},
        "json": {
            "model": "Qwen/Qwen3-VL-Embedding-8B",
            "input": "verified vulnerability",
        },
        "timeout": 30,
    }


def test_embedding_failure_raises_instead_of_returning_zero_vector(monkeypatch):
    monkeypatch.setenv("EMBED_API_BASE", "https://embedding.invalid/v1")
    monkeypatch.setenv("EMBED_API_KEY", "embed-secret")
    monkeypatch.setenv("EMBED_MODEL", "embedding-model")
    monkeypatch.setenv("EMBED_DIM", "4096")

    def fail(*args, **kwargs):
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(requests, "post", fail)

    with pytest.raises(RuntimeError, match="Embedding request failed"):
        OllamaEmbedding().embed("verified vulnerability")


def test_environment_check_uses_embedding_provider_config(monkeypatch):
    monkeypatch.setenv("OPENAI_API_BASE", "https://api.deepseek.com")
    monkeypatch.setenv("OPENAI_API_KEY", "chat-secret")
    monkeypatch.setenv("EMBED_API_BASE", "https://api.siliconflow.cn/v1")
    monkeypatch.setenv("EMBED_API_KEY", "embed-secret")
    monkeypatch.setenv("EMBED_MODEL", "Qwen/Qwen3-VL-Embedding-8B")
    captured = {}

    class Embeddings:
        def create(self, *, model, input):
            captured.update(model=model, input=input)
            return type("Response", (), {"data": [type("Item", (), {"embedding": [0.1]})()]})()

    def client(**kwargs):
        captured.update(kwargs)
        return type("Client", (), {"embeddings": Embeddings()})()

    monkeypatch.setattr(openai, "OpenAI", client)
    check_env.results.clear()

    check_env.check_openai_compatible_embed()

    assert captured == {
        "api_key": "embed-secret",
        "timeout": 8,
        "base_url": "https://api.siliconflow.cn/v1",
        "model": "Qwen/Qwen3-VL-Embedding-8B",
        "input": "test",
    }
