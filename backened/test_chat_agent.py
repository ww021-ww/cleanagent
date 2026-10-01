"""
独立测试脚本：不启动 FastAPI，直接验证 ChatAgent 意图分类和 RAG 检索
用法: python test_chat_agent.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

# 加载环境变量（手动解析 .env 文件）
def _load_env(path):
    if not os.path.exists(path):
        return False
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())
    return True

for env_file in ["config/database.env", ".env", "../.env"]:
    if _load_env(env_file):
        print(f"[ENV] 已加载 {env_file}")
        break

TEST_QUERIES = [
    ("rag_search",  "Apache远程代码执行漏洞有哪些"),
    ("rag_search",  "缓冲区溢出相关漏洞"),
    ("sql_query",   "CVE-2021-44228 的详情"),
    ("stats",       "数据库里总共有多少漏洞"),
]


async def run_tests():
    # 直接从文件加载 ChatAgent（绕过 agent/__init__.py 的重型依赖）
    import importlib.util, yaml
    spec = importlib.util.spec_from_file_location("agent_chat", "agent/chat.py")
    chat_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(chat_mod)
    ChatAgent = chat_mod.ChatAgent

    with open("config/agent_config.yaml", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    rag = None
    try:
        from rag.retriever import RAGRetriever
        cfg["agentic"]["rag"]["enabled"] = True
        rag = RAGRetriever(cfg)
        print(f"[INIT] RAGRetriever OK, enabled={rag.enabled}, collection={rag.collection_name}")
    except Exception as e:
        print(f"[INIT] RAGRetriever 初始化失败: {e}")

    agent = ChatAgent(cfg, rag=rag)
    print(f"[INIT] ChatAgent OK, LLM={'ok' if agent._llm else 'None'}\n")

    passed = 0
    for expected_type, query in TEST_QUERIES:
        print(f"{'='*55}")
        print(f"Query : {query}")
        print(f"期望  : {expected_type}")

        # 只测意图分类
        intent = await asyncio.to_thread(agent._classify_intent, query)
        actual_type = intent.get("type")
        ok = "✅" if actual_type == expected_type else "❌"
        print(f"实际  : {actual_type}  {ok}  params={intent.get('params')}")

        # 若是 rag_search，跑一次真实检索
        if actual_type == "rag_search":
            results = await asyncio.to_thread(agent._exec_rag, intent)
            count = results.get("count", 0)
            print(f"RAG结果: {count} 条")
            for i, r in enumerate(results.get("results", [])[:2], 1):
                doc = r.get("document", "")[:80].replace("\n", " ")
                print(f"  [{i}] {r.get('vuln_id','')} | {doc}...")

        if actual_type == expected_type:
            passed += 1
        print()

    print(f"{'='*55}")
    print(f"通过: {passed}/{len(TEST_QUERIES)}")


if __name__ == "__main__":
    asyncio.run(run_tests())
