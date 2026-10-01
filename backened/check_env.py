"""
CleanAgent 环境可用性诊断脚本
运行方式：  python check_env.py
无需项目其他模块，独立可执行。
"""
import os
import sys
import time
from pathlib import Path

# ── 颜色输出（Windows 兼容）──────────────────────────────────────────────────
try:
    from colorama import init as _colorama_init, Fore, Style
    _colorama_init(autoreset=True)
    OK  = Fore.GREEN  + "✅" + Style.RESET_ALL
    ERR = Fore.RED    + "❌" + Style.RESET_ALL
    WARN= Fore.YELLOW + "⚠️ " + Style.RESET_ALL
except ImportError:
    OK, ERR, WARN = "[OK]", "[ERR]", "[WARN]"

# ── 加载 .env ─────────────────────────────────────────────────────────────────
def _load_env():
    base = Path(__file__).parent / "config"
    for name in ("database.env", ".env"):
        p = base / name
        if p.exists():
            try:
                from dotenv import load_dotenv
                load_dotenv(p, override=False)
                return str(p)
            except ImportError:
                # 手动解析
                with open(p, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, _, v = line.partition("=")
                            os.environ.setdefault(k.strip(), v.strip())
                return str(p)
    return None

# ── 结果收集 ──────────────────────────────────────────────────────────────────
results = []   # (label, status, detail)
missing_pkgs  = []
missing_keys  = []
need_services = []

def _record(label, status, detail=""):
    results.append((label, status, detail))
    icon = OK if status == "ok" else (ERR if status == "err" else WARN)
    print(f"  {icon}  {label:<22} {detail}")

# ─────────────────────────────────────────────────────────────────────────────
# 1. 环境变量文件
# ─────────────────────────────────────────────────────────────────────────────
def check_env_file():
    path = _load_env()
    if path:
        count = sum(1 for k in os.environ if not k.startswith("_"))
        _record("环境变量文件", "ok", f"{path} 已加载")
    else:
        _record("环境变量文件", "warn", "未找到 config/database.env 或 config/.env，将使用系统环境变量")

# ─────────────────────────────────────────────────────────────────────────────
# 2. MySQL
# ─────────────────────────────────────────────────────────────────────────────
def check_mysql():
    db_uri = os.getenv("DB_URI", "")
    if not db_uri:
        _record("MySQL", "warn", "DB_URI 未设置")
        missing_keys.append("DB_URI")
        return
    # 安全显示（隐藏密码）
    try:
        from urllib.parse import urlparse
        u = urlparse(db_uri.replace("+pymysql", ""))
        safe = f"{u.hostname}/{u.path.lstrip('/')}"
    except Exception:
        safe = "***"

    try:
        import sqlalchemy
    except ImportError:
        missing_pkgs.append("sqlalchemy pymysql")
        _record("MySQL", "err", "缺少 sqlalchemy，运行: pip install sqlalchemy pymysql")
        return

    try:
        import sqlalchemy as sa
        engine = sa.create_engine(db_uri, connect_args={"connect_timeout": 5})
        with engine.connect() as conn:
            tables = sa.inspect(engine).get_table_names()
        _record("MySQL", "ok", f"连接成功 | 主机: {safe} | 表数量: {len(tables)}")
    except Exception as e:
        _record("MySQL", "err", f"连接失败 ({safe}): {e}")

# ─────────────────────────────────────────────────────────────────────────────
# 3. LLM API（OpenAI 兼容，非 Ollama 的主力模型）
# ─────────────────────────────────────────────────────────────────────────────
def check_llm_api():
    api_key  = os.getenv("OPENAI_API_KEY", "")
    api_base = os.getenv("OPENAI_API_BASE", "")
    model    = os.getenv("DEFAULT_LLM_MODEL", "tq-gpt-Qwen3-30B-Instruct")

    if not api_key:
        _record("LLM API", "warn", "OPENAI_API_KEY 未设置，跳过")
        missing_keys.append("OPENAI_API_KEY")
        return

    try:
        import openai
    except ImportError:
        missing_pkgs.append("openai")
        _record("LLM API", "err", "缺少 openai，运行: pip install openai")
        return

    try:
        kwargs = {"api_key": api_key, "timeout": 8}
        if api_base:
            kwargs["base_url"] = api_base
        client = openai.OpenAI(**kwargs)
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "回复'你好'两个字"}],
            max_tokens=10,
        )
        answer = resp.choices[0].message.content.strip()
        _record("LLM API", "ok", f"模型: {model} | 回复: {answer[:30]}")
    except Exception as e:
        _record("LLM API", "err", f"调用失败: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# 4. OpenAI 兼容 LLM
# ─────────────────────────────────────────────────────────────────────────────
def check_openai_compatible_llm():
    base  = os.getenv("OPENAI_API_BASE", "")
    model = os.getenv("DEFAULT_LLM_MODEL", "gpt-4o-mini")
    api_key = os.getenv("OPENAI_API_KEY", "")

    if not api_key:
        _record("兼容 LLM", "warn", "OPENAI_API_KEY 未设置，跳过")
        return

    try:
        import openai
    except ImportError:
        missing_pkgs.append("openai")
        _record("兼容 LLM", "err", "缺少 openai，运行: pip install openai")
        return

    try:
        kwargs = {"api_key": api_key, "timeout": 8}
        if base:
            kwargs["base_url"] = base
        client = openai.OpenAI(**kwargs)
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "say hi"}],
            max_tokens=10,
        )
        answer = resp.choices[0].message.content.strip()
        _record("兼容 LLM", "ok", f"模型: {model} | 回复: {answer[:30]}")
    except Exception as e:
        _record("兼容 LLM", "err", f"调用失败 ({base or '默认地址'}): {e}")

# ─────────────────────────────────────────────────────────────────────────────
# 5. OpenAI 兼容 Embedding
# ─────────────────────────────────────────────────────────────────────────────
def check_openai_compatible_embed():
    base  = os.getenv("OPENAI_API_BASE", "")
    model = os.getenv("EMBED_MODEL", "text-embedding-3-small")
    api_key = os.getenv("OPENAI_API_KEY", "")

    if not api_key:
        _record("兼容 Embedding", "warn", "OPENAI_API_KEY 未设置，跳过")
        return

    try:
        import openai
    except ImportError:
        _record("兼容 Embedding", "err", "缺少 openai")
        return

    try:
        kwargs = {"api_key": api_key, "timeout": 8}
        if base:
            kwargs["base_url"] = base
        client = openai.OpenAI(**kwargs)
        resp = client.embeddings.create(model=model, input="test")
        dim = len(resp.data[0].embedding)
        _record("兼容 Embedding", "ok", f"模型: {model} | 向量维度: {dim}")
    except Exception as e:
        _record("兼容 Embedding", "err", f"失败 ({base or '默认地址'}): {e}")

# ─────────────────────────────────────────────────────────────────────────────
# 6. Milvus 向量数据库
# ─────────────────────────────────────────────────────────────────────────────
def check_milvus():
    host = os.getenv("MILVUS_HOST", "localhost")
    port = int(os.getenv("MILVUS_PORT", "19530"))

    try:
        from pymilvus import MilvusClient
    except ImportError:
        missing_pkgs.append("pymilvus>=2.3.0")
        _record("Milvus", "err", "缺少 pymilvus，运行: pip install pymilvus")
        return

    try:
        client = MilvusClient(uri=f"http://{host}:{port}", timeout=5)
        cols = client.list_collections()
        _record("Milvus", "ok", f"{host}:{port} 连接成功 | Collections: {cols or '（空）'}")
    except Exception as e:
        need_services.append(
            "Milvus（运行: docker-compose -f mysql/milvus-standalone-docker-compose.yml up -d）"
        )
        _record("Milvus", "err", f"连接失败 ({host}:{port}): {e}")

# ─────────────────────────────────────────────────────────────────────────────
# 7. Tavily 搜索 API
# ─────────────────────────────────────────────────────────────────────────────
def check_tavily():
    api_key = os.getenv("TAVILY_API_KEY", "")
    if not api_key:
        _record("Tavily", "warn", "TAVILY_API_KEY 未设置（tools.auto_fill 搜索功能将不可用）")
        missing_keys.append("TAVILY_API_KEY")
        return

    try:
        from tavily import TavilyClient
    except ImportError:
        missing_pkgs.append("tavily-python>=0.3.0")
        _record("Tavily", "err", "缺少 tavily-python，运行: pip install tavily-python")
        return

    try:
        client = TavilyClient(api_key=api_key)
        result = client.search("CVE-2024-0001", max_results=1)
        _record("Tavily", "ok", f"搜索成功，返回 {len(result.get('results', []))} 条结果")
    except Exception as e:
        _record("Tavily", "err", f"调用失败: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# 8. SerpAPI
# ─────────────────────────────────────────────────────────────────────────────
def check_serpapi():
    api_key = os.getenv("SERPAPI_API_KEY", "")
    if not api_key:
        _record("SerpAPI", "warn", "SERPAPI_API_KEY 未设置（Google 搜索工具将不可用）")
        missing_keys.append("SERPAPI_API_KEY")
        return

    try:
        from serpapi import GoogleSearch
    except ImportError:
        try:
            from serpapi.google_search import GoogleSearch
        except ImportError:
            missing_pkgs.append("google-search-results>=2.4.2")
            _record("SerpAPI", "err", "缺少 google-search-results，运行: pip install google-search-results")
            return

    try:
        search = GoogleSearch({"q": "CVE-2024-0001", "api_key": api_key, "num": 1})
        res = search.get_dict()
        hits = len(res.get("organic_results", []))
        _record("SerpAPI", "ok", f"搜索成功，返回 {hits} 条结果")
    except Exception as e:
        _record("SerpAPI", "err", f"调用失败: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# 9. NVD API（美国国家漏洞数据库）
# ─────────────────────────────────────────────────────────────────────────────
def check_nvd():
    import urllib.request, json as _json
    nvd_key = os.getenv("NVD_API_KEY", "")
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"
    headers = {"User-Agent": "CleanAgent-Checker/1.0"}
    if nvd_key:
        headers["apiKey"] = nvd_key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=8) as r:
            data = _json.loads(r.read())
        total = data.get("totalResults", 0)
        key_info = f"（已配置 API Key，速率更高）" if nvd_key else "（无 Key，每 30 秒 5 次）"
        _record("NVD API", "ok", f"公开接口可达，CVE-2021-44228 存在 {key_info}")
    except Exception as e:
        _record("NVD API", "err", f"网络不可达: {e}")

# ─────────────────────────────────────────────────────────────────────────────
# 10. FastAPI 后端
# ─────────────────────────────────────────────────────────────────────────────
def check_fastapi():
    import urllib.request, json as _json
    url = "http://127.0.0.1:8000/api/v1/health"
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            data = _json.loads(r.read())
        _record("FastAPI 后端", "ok", f"http://127.0.0.1:8000 在线 | code={data.get('code')}")
    except Exception:
        _record("FastAPI 后端", "warn", "未运行（uvicorn api.app:app --port 8000 --reload）")

# ─────────────────────────────────────────────────────────────────────────────
# 主程序
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("\n" + "=" * 60)
    print("  CleanAgent 环境诊断报告")
    print("=" * 60)

    checks = [
        ("1.  环境变量文件",    check_env_file),
        ("2.  MySQL",          check_mysql),
        ("3.  LLM API",        check_llm_api),
        ("4.  兼容 LLM",       check_openai_compatible_llm),
        ("5.  兼容 Embedding", check_openai_compatible_embed),
        ("6.  Milvus",         check_milvus),
        ("7.  Tavily",         check_tavily),
        ("8.  SerpAPI",        check_serpapi),
        ("9.  NVD API",        check_nvd),
        ("10. FastAPI 后端",   check_fastapi),
    ]

    for label, fn in checks:
        print(f"\n─── {label} ───")
        try:
            fn()
        except Exception as e:
            _record(label, "err", f"未预期错误: {e}")

    # ── 汇总 ──────────────────────────────────────────────────────────────────
    ok_count   = sum(1 for _, s, _ in results if s == "ok")
    err_count  = sum(1 for _, s, _ in results if s == "err")
    warn_count = sum(1 for _, s, _ in results if s == "warn")

    print("\n" + "=" * 60)
    print(f"  汇总: {ok_count} ✅   {err_count} ❌   {warn_count} ⚠️ ")
    print("=" * 60)

    if missing_pkgs:
        print("\n📦 缺少的 Python 包（运行以下命令安装）：")
        unique = list(dict.fromkeys(missing_pkgs))
        print(f"   pip install {' '.join(unique)}")

    if missing_keys:
        print("\n🔑 未设置的 API Key / 环境变量：")
        for k in missing_keys:
            print(f"   {k}=你的key   （写入 config/database.env）")

    if need_services:
        print("\n🐳 需要先启动的外部服务：")
        for s in need_services:
            print(f"   {s}")

    print()


if __name__ == "__main__":
    main()
