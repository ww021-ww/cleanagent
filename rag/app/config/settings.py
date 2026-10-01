import os
from dotenv import load_dotenv

load_dotenv()

# Elasticsearch
ES_HOST = os.getenv("ES_HOST", "http://localhost:9201")

# 向量嵌入模型（需支持 OpenAI 兼容接口）
EMB_MODEL   = os.getenv("EMB_MODEL",   "BAAI/bge-m3")
EMB_API_KEY = os.getenv("EMB_API_KEY", "")
EMB_BASE_URL = os.getenv("EMB_BASE_URL", "https://api.siliconflow.cn/v1")

# 大语言模型（需支持 OpenAI 兼容接口）
LLM_MODEL   = os.getenv("LLM_MODEL",   "deepseek-ai/DeepSeek-V3")
LLM_API_KEY = os.getenv("LLM_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.siliconflow.cn/v1")

# 联网搜索兜底（Tavily）
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "")

# ES 索引名
KNOWLEDGE_INDEX = "knowledge"
KNOWLEDGE_VEC_INDEX = "knowledge_vec"

# BGE-M3 向量维度
VECTOR_DIMS = 1024
