from openai import OpenAI
from app.config.settings import EMB_API_KEY, EMB_BASE_URL, EMB_MODEL

_client = OpenAI(api_key=EMB_API_KEY, base_url=EMB_BASE_URL, timeout=30.0)


def generate_embeddings(texts):
    """生成嵌入向量，返回 list[list[float]]"""
    if isinstance(texts, str):
        texts = [texts]
    response = _client.embeddings.create(model=EMB_MODEL, input=texts)
    return [item.embedding for item in response.data]
