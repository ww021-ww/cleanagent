import time
import logging
import os
import uuid

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from api.routers.health import router as health_router
from api.routers.vulns import router as vulns_router
from api.routers.stats import router as stats_router
from config import load_yaml_config

logger = logging.getLogger(__name__)

app = FastAPI(title="CleanAgent Vulnerability Search API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health_router)
app.include_router(vulns_router)
app.include_router(stats_router)

# ──────────────────────────────────────────────
#  ChatAgent 初始化（延迟加载，避免循环依赖）
# ──────────────────────────────────────────────

_chat_agent = None
_chat_agent_signature = None


def _build_chat_agent_signature(config: dict) -> tuple:
    return (
        config.get('db_uri') or os.getenv('DB_URI', ''),
        os.getenv('OPENAI_API_BASE', ''),
        os.getenv('OPENAI_API_KEY', ''),
        os.getenv('DEFAULT_LLM_MODEL', ''),
        os.getenv('EMBED_MODEL', ''),
        os.getenv('EMBED_DIM', ''),
        os.getenv('TAVILY_API_KEY', ''),
        str(config.get('agentic', {}).get('rag', {}).get('enabled', False)),
        config.get('agentic', {}).get('rag', {}).get('collection_name', ''),
    )


def _get_chat_agent():
    global _chat_agent, _chat_agent_signature
    config = load_yaml_config()
    signature = _build_chat_agent_signature(config)
    if _chat_agent is not None and _chat_agent_signature == signature:
        return _chat_agent
    try:
        from agent.chat import ChatAgent
        from agent.memory import AgentMemory
        from database import DatabaseManager
        from config.field_config_loader import FieldConfigLoader
        from memory import ConversationMemoryService
        from tools import ToolAgent
        from openai import OpenAI

        db_uri = config.get('db_uri') or os.getenv('DB_URI', '')
        cfg_path = os.path.join(os.path.dirname(__file__), '..', 'config', 'field_mappings.yaml')
        db_manager = DatabaseManager(db_uri, FieldConfigLoader(cfg_path)) if db_uri else None
        memory_cfg = config.get('agentic', {}).get('memory', {})
        memory = AgentMemory(memory_cfg) if memory_cfg.get('enabled', False) else None
        conversation_memory = ConversationMemoryService(db_uri=db_uri) if db_uri else None
        tool_agent = None
        tool_cfg = config.get('agentic', {}).get('tools', {})
        if tool_cfg.get('enabled', False):
            llm_client = None
            try:
                api_base = os.getenv('OPENAI_API_BASE', '').strip() or None
                api_key = os.getenv('OPENAI_API_KEY', '').strip()
                if api_key:
                    kwargs = {'api_key': api_key, 'timeout': 20}
                    if api_base:
                        kwargs['base_url'] = api_base
                    llm_client = OpenAI(**kwargs)
            except Exception:
                llm_client = None
            tool_agent = ToolAgent(config, llm_client)

        # 初始化 RAGRetriever
        rag = None
        try:
            from rag.retriever import RAGRetriever
            rag_cfg = config.get('agentic', {}).get('rag', {})
            if rag_cfg.get('enabled', False):
                rag = RAGRetriever(config)
        except Exception as e:
            logger.warning(f"RAGRetriever 初始化失败: {e}")

        _chat_agent = ChatAgent(
            config,
            db_manager=db_manager,
            rag=rag,
            memory=memory,
            conversation_memory=conversation_memory,
            tool_agent=tool_agent,
        )
        _chat_agent_signature = signature
        logger.info("ChatAgent 初始化成功")
    except Exception as e:
        _chat_agent = None
        _chat_agent_signature = None
        logger.warning(f"ChatAgent 初始化失败: {e}")
    return _chat_agent


# ──────────────────────────────────────────────
#  REST 对话接口
# ──────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None
    user_id: str | None = None


class CreateSessionRequest(BaseModel):
    user_id: str | None = None
    title: str | None = None


class RenameSessionRequest(BaseModel):
    user_id: str | None = None
    title: str


@app.post("/api/chat")
async def chat_endpoint(request: ChatRequest):
    """
    自然语言对话接口

    POST /api/chat
    Body: {"message": "最近有哪些高危漏洞？"}
    """
    agent = _get_chat_agent()
    if not agent:
        return {"answer": "ChatAgent 未初始化，请检查配置。", "timestamp": time.time()}
    try:
        session_id = request.session_id or str(uuid.uuid4())
        answer = await agent.chat(
            request.message,
            session_id=session_id,
            user_id=request.user_id or "default",
        )
        return {"answer": answer, "timestamp": time.time(), "session_id": session_id}
    except Exception as e:
        logger.error(f"REST Chat 处理失败: {e}", exc_info=True)
        return {"answer": f"⚠️ 后端处理出错：{type(e).__name__}: {e}", "timestamp": time.time()}


@app.get("/api/chat/sessions")
def list_chat_sessions(user_id: str = "default"):
    agent = _get_chat_agent()
    conversation_memory = getattr(agent, "conversation_memory", None) if agent else None
    if not conversation_memory:
        return {"sessions": []}
    return {"sessions": conversation_memory.list_sessions(user_id=user_id)}


@app.post("/api/chat/sessions")
def create_chat_session(request: CreateSessionRequest):
    agent = _get_chat_agent()
    conversation_memory = getattr(agent, "conversation_memory", None) if agent else None
    if not conversation_memory:
        session_id = str(uuid.uuid4())
        return {
            "session": {
                "session_id": session_id,
                "user_id": request.user_id or "default",
                "project_id": "cleanagent",
                "title": request.title or "新对话",
                "summary": "",
                "last_user_message": "",
                "last_assistant_message": "",
            }
        }
    session = conversation_memory.create_session(user_id=request.user_id or "default", title=request.title or "")
    return {"session": session}


@app.get("/api/chat/sessions/{session_id}")
def get_chat_session(session_id: str, user_id: str = "default"):
    agent = _get_chat_agent()
    conversation_memory = getattr(agent, "conversation_memory", None) if agent else None
    if not conversation_memory:
        return {"session": None, "messages": []}
    return conversation_memory.get_session_detail(session_id=session_id, user_id=user_id)


@app.patch("/api/chat/sessions/{session_id}")
def rename_chat_session(session_id: str, request: RenameSessionRequest):
    agent = _get_chat_agent()
    conversation_memory = getattr(agent, "conversation_memory", None) if agent else None
    if not conversation_memory:
        return {"session": None}
    session = conversation_memory.rename_session(session_id=session_id, user_id=request.user_id or "default", title=request.title)
    return {"session": session}


@app.delete("/api/chat/sessions/{session_id}")
def delete_chat_session(session_id: str, user_id: str = "default"):
    agent = _get_chat_agent()
    conversation_memory = getattr(agent, "conversation_memory", None) if agent else None
    if not conversation_memory:
        return {"ok": False}
    return {"ok": conversation_memory.delete_session(session_id=session_id, user_id=user_id)}


# ──────────────────────────────────────────────
#  WebSocket 实时对话接口
# ──────────────────────────────────────────────

@app.websocket("/ws/chat")
async def chat_websocket(websocket: WebSocket):
    """WebSocket 实时对话（每轮消息独立处理）"""
    await websocket.accept()
    agent = _get_chat_agent()
    session_id = websocket.query_params.get("session_id") or str(uuid.uuid4())
    user_id = websocket.query_params.get("user_id") or "default"
    try:
        while True:
            message = await websocket.receive_text()
            if not message.strip():
                continue
            try:
                if agent:
                    answer = await agent.chat(message, session_id=session_id, user_id=user_id)
                else:
                    answer = "ChatAgent 未初始化，请检查配置。"
            except Exception as e:
                logger.error(f"ChatAgent 处理消息失败: {e}", exc_info=True)
                answer = f"⚠️ 后端处理出错：{type(e).__name__}: {e}"
            await websocket.send_text(answer)
    except WebSocketDisconnect:
        logger.info("WebSocket 客户端断开连接")


@app.get("/")
def root():
    return {"name": "cleanagent-api", "version": "1.0.0"}


@app.get("/api/chat/status")
def chat_status():
    """调试接口：查看 ChatAgent 和 RAG 初始化状态"""
    agent = _get_chat_agent()
    if not agent:
        return {"status": "ChatAgent 未初始化"}
    rag = agent.rag
    stats_snapshot = {}
    try:
        if hasattr(agent, "_exec_stats"):
            stats_snapshot = agent._exec_stats()
    except Exception as e:
        stats_snapshot = {"error": str(e)}
    return {
        "chat_agent": "ok",
        "llm": str(agent._llm) if agent._llm else "None",
        "db": str(agent.db) if agent.db else "None",
        "rag_enabled": rag.enabled if rag else False,
        "rag_collection": rag.collection_name if rag else None,
        "rag_embed_dim": rag._embed.dim if (rag and getattr(rag, '_embed', None)) else None,
        "rag_client": str(rag._client) if (rag and rag._client) else "None",
        "stats_snapshot": stats_snapshot,
    }
