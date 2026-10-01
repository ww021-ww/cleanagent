"""
Chat Agent — 自然语言对话智能体
意图识别 → SQL / RAG / Memory 三路路由 → LLM 生成自然语言回答
"""
import asyncio
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from api.mappings.source_field_map import SOURCE_TABLE_MAP

logger = logging.getLogger(__name__)


class ChatAgent:
    """
    对话智能体

    能力：
    1. 意图识别（LLM 判断用户想查什么，带规则兜底）
    2. 多工具路由（SQL / RAG / Memory / Stats）
    3. 结果整合，生成中文自然语言回答
    """

    def __init__(self, config: Dict, db_manager=None, rag=None, memory=None, conversation_memory=None, tool_agent=None):
        self.config = config
        self.db = db_manager
        self.rag = rag
        self.memory = memory
        self.conversation_memory = conversation_memory
        self.tool_agent = tool_agent or config.get("_tool_agent")

        llm_cfg = config.get("llm_config", {})
        chat_cfg = config.get("agentic", {}).get("chat", {})
        self.model: str = os.getenv("DEFAULT_LLM_MODEL") or chat_cfg.get("model") or llm_cfg.get("model", "gpt-4o-mini")
        self.temperature: float = float(os.getenv("LLM_TEMPERATURE", llm_cfg.get("temperature", 0)))
        self.max_results: int = chat_cfg.get("max_results", 10)
        self.enable_external_fallback: bool = bool(chat_cfg.get("enable_external_fallback", True))
        self.prefer_nvd_for_cve: bool = bool(chat_cfg.get("prefer_nvd_for_cve", True))
        self.enable_tavily_fallback: bool = bool(chat_cfg.get("enable_tavily_fallback", True))
        self.max_external_results: int = int(chat_cfg.get("max_external_results", 3) or 3)
        self.show_external_sources: bool = bool(chat_cfg.get("show_external_sources", True))
        budget_cfg = chat_cfg.get("context_budget", {}) or {}
        self.context_section_budgets = {
            "memory": int(budget_cfg.get("memory", chat_cfg.get("memory_context_budget", 1400)) or 1400),
            "task": int(budget_cfg.get("task", chat_cfg.get("task_context_budget", 500)) or 500),
            "conversation": int(budget_cfg.get("conversation", chat_cfg.get("conversation_context_budget", 1800)) or 1800),
            "knowledge": int(budget_cfg.get("knowledge", chat_cfg.get("knowledge_context_budget", 1600)) or 1600),
            "result": int(budget_cfg.get("result", chat_cfg.get("result_context_budget", 3200)) or 3200),
        }
        self.enable_context_logging: bool = bool(budget_cfg.get("log", True))

        self._llm = None
        self._init_llm()

    # ──────────────────────────────────────────────
    #  初始化
    # ──────────────────────────────────────────────

    def _init_llm(self):
        try:
            from openai import OpenAI
            base_url = os.getenv("OPENAI_API_BASE", "").strip() or None
            api_key = os.getenv("OPENAI_API_KEY", "").strip()
            if not api_key:
                logger.warning("ChatAgent LLM 初始化失败: OPENAI_API_KEY 未配置")
                return
            kwargs = {"api_key": api_key, "timeout": 20}
            if base_url:
                kwargs["base_url"] = base_url
            self._llm = OpenAI(**kwargs)
        except Exception as e:
            logger.warning(f"ChatAgent LLM 初始化失败: {e}")

    # ──────────────────────────────────────────────
    #  公共接口
    # ──────────────────────────────────────────────

    async def chat(self, user_message: str, session_id: str = "default", user_id: str = "default",
                   project_id: str = "cleanagent") -> str:
        """
        处理用户对话

        流程: 意图识别 → 路由到对应工具 → 执行查询 → 生成回答
        """
        working_message = user_message
        prompt_memory_context = ""
        prompt_memory_payload = {}
        session_state = None
        resolved_target_type = "none"
        raw_result_index = -1
        if self.conversation_memory:
            memory_turn = self.conversation_memory.begin_turn(
                user_message,
                session_id=session_id,
                user_id=user_id,
                project_id=project_id,
            )
            explicit_memory = memory_turn.get("explicit_memory")
            if explicit_memory:
                answer = f"好的，我记住了：{explicit_memory.get('summary_text', user_message)}"
                self.conversation_memory.persist_turn(
                    session_id=session_id,
                    user_id=user_id,
                    project_id=project_id,
                    user_message=user_message,
                    assistant_message=answer,
                    intent_type="memory_preference",
                    summary=answer,
                )
                return answer
            if memory_turn.get("requires_clarification"):
                answer = self.conversation_memory.format_correction_reply(session_id)
                self.conversation_memory.persist_turn(
                    session_id=session_id,
                    user_id=user_id,
                    project_id=project_id,
                    user_message=user_message,
                    assistant_message=answer,
                    intent_type="clarification",
                    summary=answer,
                )
                return answer
            working_message = memory_turn.get("message", user_message)
            prompt_memory_context = memory_turn.get("prompt_memory_context", "")
            prompt_memory_payload = memory_turn.get("prompt_memory_payload", {}) or {}
            session_state = memory_turn.get("state")
            resolved_target_type = memory_turn.get("resolved_target_type", "none")
            raw_result_index = memory_turn.get("resolved_result_index", -1)

        intent = await asyncio.to_thread(
            self._classify_intent,
            working_message,
            session_state,
            resolved_target_type,
        )
        logger.info(f"💬 ChatAgent: 意图={intent.get('type')}, 参数={intent.get('params')}")

        # rag_search 兜底：若 query 为空，用原始消息
        if intent.get("type") == "rag_search":
            intent.setdefault("params", {})
            if not intent["params"].get("query"):
                intent["params"]["query"] = working_message

        if intent["type"] == "sql_query":
            results = await asyncio.to_thread(self._exec_sql, intent)
        elif intent["type"] == "rag_search":
            results = await asyncio.to_thread(self._exec_rag, intent)
        elif intent["type"] == "memory_query":
            results = self._exec_memory(intent)
        elif intent["type"] == "stats":
            results = self._exec_stats(intent)
        elif intent["type"] in {"smalltalk", "capability_query"}:
            results = self._build_conversational_results(intent, working_message, session_state)
        elif intent["type"] in {"followup_summary", "result_explanation", "answer_refinement"}:
            results = self._build_followup_results(intent, working_message, session_state, raw_result_index)
        else:
            results = {"message": "我可以帮你查询漏洞数据、系统状态和处理统计。"}

        results = self._finalize_results_for_answer(working_message, intent, results)
        results = await asyncio.to_thread(self._apply_external_fallback, working_message, intent, results)
        answer_mode = self._determine_answer_mode(working_message, intent, results)
        answer_context = self._build_answer_context(
            question=working_message,
            intent=intent,
            results=results,
            session_state=session_state,
            memory_context=prompt_memory_context,
            memory_payload=prompt_memory_payload,
            answer_mode=answer_mode,
        )
        answer = await asyncio.to_thread(self._generate_answer, working_message, intent, results, answer_context, answer_mode)
        if self.conversation_memory:
            self.conversation_memory.finalize_turn(
                session_id=session_id,
                message=working_message,
                intent=intent,
                results=results,
                answer=answer,
                answer_mode=answer_mode,
            )
        return answer

    # ──────────────────────────────────────────────
    #  意图识别
    # ──────────────────────────────────────────────

    def _classify_intent(self, message: str, session_state: Optional[Any] = None, resolved_target_type: str = "none") -> Dict:
        """LLM 意图识别，失败自动降级到规则"""
        rule_intent = self._rule_intent(message, session_state=session_state, resolved_target_type=resolved_target_type)
        if rule_intent.get("type") in {"sql_query", "memory_query", "stats", "smalltalk", "capability_query", "followup_summary", "result_explanation", "answer_refinement"}:
            return rule_intent
        if not self._llm:
            return rule_intent

        system_prompt = (
            "你是意图识别器。根据用户问题返回 JSON。\n"
            "可用类型：sql_query（精确查询）、rag_search（语义搜索）、"
            "memory_query（系统记忆）、stats（处理统计）、smalltalk（日常对话）、"
            "capability_query（能力/身份说明）、followup_summary（总结上一轮结果）、"
            "result_explanation（解释上一轮结果）、answer_refinement（换一种表达已有结果）\n"
            "示例：\n"
            '- "CNVD-2024-12345 详情" → {"type":"sql_query","params":{"vuln_id":"CNVD-2024-12345"}}\n'
            '- "Apache 相关漏洞" → {"type":"rag_search","params":{"query":"Apache"}}\n'
            '- "CERT 来源质量" → {"type":"memory_query","params":{"source":"cert"}}\n'
            '- "一共处理了多少" → {"type":"stats","params":{}}\n'
            '- "你能做什么" → {"type":"capability_query","params":{}}\n'
            '- "帮我把这个搜索结果总结一下" → {"type":"followup_summary","params":{}}\n'
            '- "你刚才说的第一个漏洞是什么意思" → {"type":"result_explanation","params":{"index":0}}\n'
            '- "换一种更容易理解的说法" → {"type":"answer_refinement","params":{"style":"simpler"}}'
        )
        try:
            resp = self._llm.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": message},
                ],
                temperature=self.temperature,
                max_tokens=200,
            )
            raw = resp.choices[0].message.content.strip()
            logger.debug(f"[INTENT LLM] raw={raw!r}")
            parsed = self._parse_json_safe(raw)
            if parsed:
                return self._validate_intent(parsed, message)
            return rule_intent
        except Exception as e:
            logger.debug(f"意图识别 LLM 调用失败: {e}")
            return rule_intent

    def _validate_intent(self, intent: Dict, message: str) -> Dict:
        """校验 LLM 意图，防止幻觉 ID 导致误分类"""
        t = intent.get("type", "")
        params = intent.get("params", {})
        if t == "sql_query":
            # 只有用户消息里真实出现了漏洞 ID 才走 sql_query
            id_in_message = re.search(r"(CVE-\d{4}-\d+|CNVD-\d{4}-\d+|JVNVU?#?\d+)", message, re.I)
            if not id_in_message and not any(params.get(key) for key in ["keyword", "source", "severity", "recent"]):
                logger.debug("[INTENT VALIDATE] 消息中无真实漏洞 ID，降级为 rag_search")
                return {"type": "rag_search", "params": {"query": message}}
        if t in {"sql_query", "rag_search", "memory_query", "stats"}:
            normalized_source = self._normalize_source_name(str(params.get("source", "")))
            if normalized_source:
                params["source"] = normalized_source
            elif "source" in params:
                params.pop("source", None)
            if t == "stats":
                params["include_latest"] = bool(params.get("include_latest") or params.get("latest"))
            intent["params"] = params
        if t == "rag_search" and not params.get("query"):
            intent["params"] = {"query": message}
        if t == "answer_refinement" and not params.get("style"):
            params["style"] = self._guess_refinement_style(message)
            intent["params"] = params
        return intent

    def _parse_json_safe(self, text: str) -> Optional[Dict]:
        """先直接解析，失败则从文本中提取 JSON 块（llama3.2 兜底）"""
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        m = re.search(r"\{.*?\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
        return None

    def _rule_intent(self, message: str, session_state: Optional[Any] = None, resolved_target_type: str = "none") -> Dict:
        """基于规则的意图兜底"""
        source = self._extract_source_name(message)
        if self._looks_like_capability_query(message):
            return {"type": "capability_query", "params": {}}
        if self._looks_like_smalltalk_query(message):
            return {"type": "smalltalk", "params": {}}
        if resolved_target_type != "none":
            if self._looks_like_followup_summary(message, session_state, resolved_target_type):
                return {"type": "followup_summary", "params": {}}
            if self._looks_like_result_explanation(message, session_state, resolved_target_type):
                index = self._extract_result_index(message)
                params = {"index": index} if index >= 0 else {}
                return {"type": "result_explanation", "params": params}
        id_match = re.search(r"(CVE-\d{4}-\d+|CNVD-\d{4}-\d+|JVNVU?#?\d+)", message, re.I)
        if id_match:
            return {"type": "sql_query", "params": {"vuln_id": id_match.group(1)}}
        if self._looks_like_answer_refinement(message, session_state):
            return {"type": "answer_refinement", "params": {"style": self._guess_refinement_style(message)}}
        if self._looks_like_followup_summary(message, session_state, resolved_target_type):
            return {"type": "followup_summary", "params": {}}
        if self._looks_like_result_explanation(message, session_state, resolved_target_type):
            index = self._extract_result_index(message)
            params = {"index": index} if index >= 0 else {}
            return {"type": "result_explanation", "params": params}
        if any(w in message for w in ["质量", "画像", "策略", "失败率", "来源"]):
            params = {"source": source} if source else {}
            return {"type": "memory_query", "params": params}
        if self._looks_like_stats_query(message):
            params = {"source": source} if source else {}
            if any(w in message for w in ["最近", "最新"]):
                params["include_latest"] = True
            return {"type": "stats", "params": params}
        if self._looks_like_list_query(message):
            params = {"limit": self.max_results, "recent": any(w in message for w in ["最近", "最新"])}
            if source:
                params["source"] = source
            if any(w in message for w in ["高危", "严重", "critical", "high"]):
                params["severity"] = "high"
            return {"type": "sql_query", "params": params}
        if self._looks_like_keyword_search(message):
            params = {"keyword": self._extract_keyword_query(message), "limit": self.max_results}
            if source:
                params["source"] = source
            return {"type": "sql_query", "params": params}
        return {"type": "rag_search", "params": {"query": message}}

    def _normalize_source_name(self, source: str) -> str:
        normalized = re.sub(r"[^a-z]", "", (source or "").lower())
        aliases = {
            "cve": "cve",
            "nvd": "nvd",
            "cnvd": "cnvd",
            "cisa": "cisa",
            "cert": "cert",
            "jvn": "jvn",
        }
        return aliases.get(normalized, "")

    def _extract_source_name(self, message: str) -> str:
        normalized = re.sub(r"\s+", "", (message or "").lower())
        for source in SOURCE_TABLE_MAP.keys():
            if source in normalized:
                return source
        return ""

    def _looks_like_stats_query(self, message: str) -> bool:
        return any(w in message for w in ["多少", "统计", "总数", "成功率", "批次", "几条", "几条记录", "多少条", "多少个漏洞"])

    def _handle_smalltalk(self, message: str) -> Optional[str]:
        if self._llm:
            return None
        normalized = re.sub(r"\s+", "", message).lower()
        greetings = {
            "你好", "您好", "hi", "hello", "hey", "嗨", "哈喽", "在吗", "在嘛", "你好吗"
        }
        if normalized in greetings:
            return "你好，我可以帮你查询漏洞详情、统计数据，或按关键词检索漏洞。你可以试试：`CVE-2024-12345 详情`、`最近有哪些高危漏洞`、`统计总数`。"
        return None

    def _looks_like_capability_query(self, message: str) -> bool:
        normalized = re.sub(r"\s+", "", (message or "").lower())
        return any(token in normalized for token in [
            "你能做什么", "你可以做什么", "你会什么", "你的能力", "你是谁", "你是干嘛的", "你用的什么模型", "你用什么模型",
        ])

    def _looks_like_smalltalk_query(self, message: str) -> bool:
        normalized = re.sub(r"\s+", "", (message or "").lower())
        greetings = {"你好", "您好", "hi", "hello", "hey", "嗨", "哈喽", "在吗", "在嘛", "你好吗"}
        return normalized in greetings

    def _looks_like_followup_summary(self, message: str, session_state: Optional[Any], resolved_target_type: str = "none") -> bool:
        if not session_state:
            return False
        if not any(token in message for token in ["总结", "概括", "归纳", "梳理", "汇总"]):
            return False
        if resolved_target_type == "result_set":
            return True
        return bool(getattr(session_state, "last_result_payload", {})) and any(token in message for token in ["结果", "搜索结果", "上面", "刚才", "刚刚"])

    def _looks_like_result_explanation(self, message: str, session_state: Optional[Any], resolved_target_type: str = "none") -> bool:
        if not session_state:
            return False
        if not any(token in message for token in ["什么意思", "是什么意思", "怎么理解", "解释", "展开讲", "详细说说", "具体说说"]):
            return False
        if resolved_target_type in {"vuln", "result_set"}:
            return True
        return bool(getattr(session_state, "last_result_payload", {})) or bool(getattr(session_state, "last_result_preview", []))

    def _looks_like_answer_refinement(self, message: str, session_state: Optional[Any]) -> bool:
        if not session_state or not getattr(session_state, "last_answer_text", ""):
            return False
        return any(token in message for token in ["换一种", "换个说法", "简单一点", "简单点", "通俗一点", "更容易理解", "详细一点", "详细点", "先给结论", "简短一点", "重说一遍"])

    def _guess_refinement_style(self, message: str) -> str:
        if any(token in message for token in ["简单", "通俗", "容易理解"]):
            return "simpler"
        if any(token in message for token in ["详细", "展开"]):
            return "detailed"
        if any(token in message for token in ["先给结论", "直接说结论"]):
            return "conclusion_first"
        if "简短" in message:
            return "concise"
        return "simpler"

    def _extract_result_index(self, message: str) -> int:
        if any(token in message for token in ["第三个", "第3个", "第三条", "第3条"]):
            return 2
        if any(token in message for token in ["第二个", "第2个", "第二条", "第2条"]):
            return 1
        if any(token in message for token in ["第一个", "第1个", "第一条", "第1条"]):
            return 0
        return -1

    def _build_conversational_results(self, intent: Dict, message: str, session_state: Optional[Any]) -> Dict:
        intent_type = intent.get("type", "smalltalk")
        fallback_text = self._handle_smalltalk(message)
        return {
            "type": "conversation",
            "count": 1,
            "message": fallback_text or "",
            "conversation_context": {
                "kind": intent_type,
                "question": message,
                "last_answer_text": getattr(session_state, "last_answer_text", "") if session_state else "",
                "conversation_summary": getattr(session_state, "conversation_summary", "") if session_state else "",
            },
        }

    def _build_followup_results(self, intent: Dict, message: str, session_state: Optional[Any], resolved_result_index: int = -1) -> Dict:
        if not session_state:
            return {
                "type": "conversation",
                "count": 0,
                "message": "我这边还没有可承接的上一轮结果。你可以先让我查一个漏洞，或者把你想让我总结的内容再发给我。",
            }
        last_result_payload = getattr(session_state, "last_result_payload", {}) or {}
        last_result_preview = getattr(session_state, "last_result_preview", []) or []
        last_answer_text = getattr(session_state, "last_answer_text", "") or ""
        if not last_result_payload and not last_answer_text:
            return {
                "type": "conversation",
                "count": 0,
                "message": "我目前还没有可直接承接的上一轮结果。你可以先让我查一个漏洞，或者把刚才那段内容再发给我。",
            }
        target_index = resolved_result_index if resolved_result_index >= 0 else self._extract_result_index(message)
        result_items = list(last_result_payload.get("results", []) or [])
        target_item = None
        if 0 <= target_index < len(result_items):
            target_item = result_items[target_index]
        elif result_items and intent.get("type") == "result_explanation":
            target_index = 0
            target_item = result_items[0]
        return {
            "type": "conversation",
            "count": 1,
            "message": "",
            "conversation_context": {
                "kind": intent.get("type", "followup_summary"),
                "question": message,
                "style": intent.get("params", {}).get("style", ""),
                "target_index": target_index,
                "target_item": target_item,
                "last_result_preview": last_result_preview,
                "last_result_payload": last_result_payload,
                "last_answer_text": last_answer_text,
                "last_answer_mode": getattr(session_state, "last_answer_mode", "") or "",
                "last_external_sources": getattr(session_state, "last_external_sources", []) or [],
            },
        }

    # ──────────────────────────────────────────────
    #  路由执行
    # ──────────────────────────────────────────────

    def _exec_sql(self, intent: Dict) -> Dict:
        if not self.db:
            return {"error": "数据库未连接"}
        params = intent.get("params", {})
        vuln_id = params.get("vuln_id", "")
        keyword = params.get("keyword", "")
        source = params.get("source", "")
        severity = params.get("severity", "")
        recent = bool(params.get("recent", False))
        limit = int(params.get("limit", self.max_results) or self.max_results)
        try:
            if vuln_id and hasattr(self.db, "query_by_id"):
                results = self.db.query_by_id(vuln_id)
            elif vuln_id:
                results = self._fallback_query_by_id(vuln_id)
            elif keyword or severity or recent:
                results = self._fallback_search_records(
                    keyword=keyword,
                    source=source,
                    severity=severity,
                    recent=recent,
                    limit=limit,
                )
            elif keyword:
                results = self._fallback_search_by_keyword(keyword, limit=self.max_results)
            elif source and hasattr(self.db, "query_by_source"):
                results = self.db.query_by_source(source, limit=self.max_results)
            elif source:
                results = self._fallback_query_by_source(source, limit=self.max_results)
            else:
                results = []
            return {"type": "sql", "results": results, "count": len(results)}
        except Exception as e:
            return {"error": str(e)}

    def _fallback_query_by_id(self, vuln_id: str) -> List[Dict]:
        if not hasattr(self.db, "Session") or not hasattr(self.db, "config_loader"):
            return []
        session = self.db.Session()
        try:
            results = []
            for source, model_class in getattr(self.db, "models", {}).items():
                src_cfg = self.db.config_loader.get_source_config(source)
                id_field = src_cfg.get("id_field")
                if not id_field or not hasattr(model_class, id_field):
                    continue
                rows = session.query(model_class).filter(getattr(model_class, id_field) == vuln_id).limit(self.max_results).all()
                for row in rows:
                    item = self._serialize_model_instance(row)
                    item.setdefault("source", source)
                    results.append(item)
            return results
        finally:
            session.close()

    def _fallback_search_by_keyword(self, keyword: str, limit: int = 10) -> List[Dict]:
        return self._fallback_search_records(keyword=keyword, limit=limit)

    def _fallback_search_records(self, keyword: str = "", source: str = "", severity: str = "", recent: bool = False,
                                 limit: int = 10) -> List[Dict]:
        if not hasattr(self.db, "Session"):
            return []
        query = keyword.strip()
        source = self._normalize_source_name(source)
        session = self.db.Session()
        try:
            results: List[Dict] = []
            per_source_limit = max(limit, 5)
            target_sources = [source] if source else list(SOURCE_TABLE_MAP.keys())
            for source_name in target_sources:
                mapping = SOURCE_TABLE_MAP.get(source_name)
                if not mapping:
                    continue
                params: Dict[str, object] = {"limit": per_source_limit}
                sql = (
                    f"SELECT '{source_name}' AS source, "
                    f"CAST({mapping['id']} AS CHAR) AS vuln_id, "
                    f"{self._sql_select_expr(mapping['title'], 'title')}, "
                    f"{self._sql_select_expr(mapping['description'], 'description')}, "
                    f"{self._sql_select_expr(mapping['severity'], 'severity')}, "
                    f"{self._sql_select_expr(mapping['published'], 'published_date')}, "
                    f"{self._sql_select_expr(mapping['updated'], 'last_updated')}, "
                    f"{self._sql_select_expr(mapping['cve_id'], 'cve_id')}, "
                    f"{self._sql_select_expr(mapping['vendor'], 'vendor')} "
                    f"FROM {mapping['table']} WHERE is_deleted = 0"
                )

                if query:
                    sql += (
                        f" AND (CAST({mapping['id']} AS CHAR) LIKE :q"
                        f" OR CAST({mapping['title']} AS CHAR) LIKE :q"
                        f" OR CAST({mapping['description']} AS CHAR) LIKE :q"
                        f" OR CAST({mapping['cve_id']} AS CHAR) LIKE :q)"
                    )
                    params["q"] = f"%{query}%"

                if severity and mapping["severity"] != "NULL":
                    if severity == "high":
                        sql += (
                            f" AND {mapping['severity']} IS NOT NULL"
                            f" AND (LOWER({mapping['severity']}) LIKE '%critical%'"
                            f" OR LOWER({mapping['severity']}) LIKE '%high%'"
                            f" OR {mapping['severity']} LIKE '%严重%'"
                            f" OR {mapping['severity']} LIKE '%高%')"
                        )
                    else:
                        sql += f" AND CAST({mapping['severity']} AS CHAR) = :severity"
                        params["severity"] = severity

                order_field = mapping["updated"] if recent else mapping["published"]
                sql += f" ORDER BY {order_field} DESC LIMIT :limit"

                rows = session.execute(text(sql), params).mappings().all()
                for row in rows:
                    results.append(dict(row))

            deduped: List[Dict] = []
            seen = set()
            for item in results:
                key = (item.get("source", ""), item.get("vuln_id", ""))
                if key in seen:
                    continue
                seen.add(key)
                deduped.append(item)

            deduped.sort(
                key=lambda x: x.get("last_updated") or x.get("published_date") or "",
                reverse=True,
            )
            return deduped[:limit]
        finally:
            session.close()

    def _sql_select_expr(self, field: str, alias: str) -> str:
        if field == 'NULL':
            return f"NULL AS {alias}"
        return f"CAST({field} AS CHAR) AS {alias}"

    def _fallback_query_by_source(self, source: str, limit: int = 10) -> List[Dict]:
        if not hasattr(self.db, "Session"):
            return []
        model_class = getattr(self.db, "models", {}).get(source.lower())
        if not model_class:
            return []
        session = self.db.Session()
        try:
            rows = session.query(model_class).limit(limit).all()
            results = []
            for row in rows:
                item = self._serialize_model_instance(row)
                item.setdefault("source", source.lower())
                results.append(item)
            return results
        finally:
            session.close()

    def _serialize_model_instance(self, row) -> Dict:
        data = {}
        table = getattr(row, "__table__", None)
        if table is None:
            return data
        for column in table.columns:
            value = getattr(row, column.name, None)
            if value is not None:
                data[column.name] = str(value)
        return data

    def _exec_rag(self, intent: Dict) -> Dict:
        if not self.rag or not self.rag.enabled:
            logger.warning("RAG 未启用或未初始化，自动降级到数据库关键词检索")
            keyword = intent.get("params", {}).get("query", "")
            return {"type": "sql", "results": self._fallback_search_by_keyword(keyword, limit=self.max_results), "count": 0}
        params = intent.get("params", {})
        query = params.get("query", "")
        source = params.get("source", "")
        smalltalk_answer = self._handle_smalltalk(query)
        if smalltalk_answer:
            return {"type": "smalltalk", "message": smalltalk_answer, "count": 0}
        logger.debug(f"[RAG DEBUG] query='{query}' source='{source}' top_k={self.max_results}")
        try:
            results = self.rag.retrieve_similar(query, source=source, top_k=self.max_results)
        except Exception as e:
            logger.warning(f"RAG 检索失败，自动降级到数据库关键词检索: {e}")
            fallback_results = self._fallback_search_by_keyword(query, limit=self.max_results)
            return {"type": "sql", "results": fallback_results, "count": len(fallback_results)}
        logger.debug(f"[RAG DEBUG] 结果数量={len(results)}")
        if not results:
            fallback_results = self._fallback_search_by_keyword(query, limit=self.max_results)
            if fallback_results:
                return {"type": "sql", "results": fallback_results, "count": len(fallback_results)}
        return {"type": "rag", "results": results, "count": len(results)}

    def _exec_memory(self, intent: Dict) -> Dict:
        if not self.memory:
            return {"error": "记忆系统未启用"}
        source = intent.get("params", {}).get("source", "")
        if source and hasattr(self.memory, "get_source_profile"):
            return {
                "type": "memory",
                "profile": self.memory.get_source_profile(source),
                "missing_fields": self.memory.get_common_missing_fields(source),
            }
        summary = self.memory.get_quality_summary() if hasattr(self.memory, "get_quality_summary") else {}
        return {"type": "memory", "summary": summary}

    def _exec_stats(self, intent: Optional[Dict] = None) -> Dict:
        params = intent.get("params", {}) if isinstance(intent, dict) else {}
        source = self._normalize_source_name(str(params.get("source", "")))
        include_latest = bool(params.get("include_latest") or params.get("latest"))
        stats = {}
        if self.db and hasattr(self.db, "Session"):
            session = self.db.Session()
            try:
                by_source = {}
                total = 0
                updated_today = 0
                high_risk_total = 0
                latest_candidates: List[Dict] = []
                target_sources = [source] if source else list(SOURCE_TABLE_MAP.keys())
                for source_name in target_sources:
                    mapping = SOURCE_TABLE_MAP.get(source_name)
                    if not mapping:
                        continue
                    count_sql = f"SELECT COUNT(1) AS cnt FROM {mapping['table']} WHERE is_deleted = 0"
                    cnt = session.execute(text(count_sql)).scalar() or 0
                    cnt = int(cnt)
                    by_source[source_name] = cnt
                    total += cnt

                    updated_sql = (
                        f"SELECT COUNT(1) AS cnt FROM {mapping['table']} "
                        f"WHERE is_deleted = 0 AND {mapping['updated']} IS NOT NULL "
                        f"AND DATE({mapping['updated']}) = CURDATE()"
                    )
                    updated_today += int(session.execute(text(updated_sql)).scalar() or 0)

                    if mapping["severity"] != "NULL":
                        risk_sql = (
                            f"SELECT COUNT(1) AS cnt FROM {mapping['table']} "
                            f"WHERE is_deleted = 0 AND {mapping['severity']} IS NOT NULL "
                            f"AND (LOWER({mapping['severity']}) LIKE '%critical%' "
                            f"OR LOWER({mapping['severity']}) LIKE '%high%' "
                            f"OR {mapping['severity']} LIKE '%严重%' "
                            f"OR {mapping['severity']} LIKE '%高%')"
                        )
                        high_risk_total += int(session.execute(text(risk_sql)).scalar() or 0)

                    if include_latest:
                        latest_sql = (
                            f"SELECT '{source_name}' AS source, "
                            f"CAST({mapping['id']} AS CHAR) AS vuln_id, "
                            f"{self._sql_select_expr(mapping['title'], 'title')}, "
                            f"{self._sql_select_expr(mapping['description'], 'description')}, "
                            f"{self._sql_select_expr(mapping['severity'], 'severity')}, "
                            f"{self._sql_select_expr(mapping['published'], 'published_date')}, "
                            f"{self._sql_select_expr(mapping['updated'], 'last_updated')}, "
                            f"{self._sql_select_expr(mapping['cve_id'], 'cve_id')}, "
                            f"{self._sql_select_expr(mapping['vendor'], 'vendor')} "
                            f"FROM {mapping['table']} WHERE is_deleted = 0 "
                            f"ORDER BY {mapping['updated']} DESC, {mapping['published']} DESC LIMIT 1"
                        )
                        latest_row = session.execute(text(latest_sql)).mappings().first()
                        if latest_row:
                            latest_candidates.append(dict(latest_row))

                stats["total"] = total
                stats["by_source"] = by_source
                stats["updated_today"] = updated_today
                stats["high_risk_total"] = high_risk_total
                if source:
                    stats["source"] = source
                if latest_candidates:
                    latest_candidates.sort(
                        key=lambda x: x.get("last_updated") or x.get("published_date") or "",
                        reverse=True,
                    )
                    stats["latest_record"] = latest_candidates[0]
            except Exception as e:
                logger.warning(f"数据库统计查询失败: {e}")
                stats["db_error"] = str(e)
            finally:
                session.close()
        if self.memory:
            if hasattr(self.memory, "get_seen_count"):
                stats["known_ids"] = self.memory.get_seen_count()
            if hasattr(self.memory, "get_quality_summary"):
                stats["quality_summary"] = self.memory.get_quality_summary()
        return {"type": "stats", "data": stats}

    # ──────────────────────────────────────────────
    #  回答生成
    # ──────────────────────────────────────────────

    def _build_answer_context(self, question: str, intent: Dict, results: Dict, session_state: Optional[Any],
                              memory_context: str = "", memory_payload: Optional[Dict] = None,
                              answer_mode: str = "") -> Dict:
        sections = []
        memory_text = self._build_memory_context_text(memory_payload, memory_context)
        if memory_text:
            sections.append({
                "name": "memory",
                "title": "会话记忆与历史上下文",
                "content": memory_text,
            })
        task_text = self._build_task_state_context(session_state, intent, results)
        if task_text:
            sections.append({
                "name": "task",
                "title": "当前任务状态",
                "content": task_text,
            })
        conversation_text = self._build_conversation_context(results)
        if conversation_text:
            sections.append({
                "name": "conversation",
                "title": "当前对话任务上下文",
                "content": conversation_text,
            })
        knowledge_text = self._build_knowledge_context(results)
        if knowledge_text:
            sections.append({
                "name": "knowledge",
                "title": "外部知识与补充来源",
                "content": knowledge_text,
            })
        rendered_context = self._render_context_sections(sections)
        result_text = self._build_result_context(results, answer_mode)
        if self.enable_context_logging:
            section_lengths = {item.get("name", "unknown"): len(item.get("content", "")) for item in sections}
            logger.info(
                "🧠 ChatAgent context mode=%s sections=%s result_chars=%s question_chars=%s",
                answer_mode or self._determine_answer_mode(question, intent, results),
                section_lengths,
                len(result_text),
                len(question or ""),
            )
        return {
            "sections": sections,
            "rendered_context": rendered_context or "无",
            "result_context": result_text or "无",
        }

    def _build_memory_context_text(self, memory_payload: Optional[Dict], memory_context: str = "") -> str:
        if isinstance(memory_payload, dict) and memory_payload.get("sections"):
            parts = []
            for item in memory_payload.get("sections", []):
                title = str(item.get("title", "")).strip()
                content = str(item.get("content", "")).strip()
                if not content:
                    continue
                if title:
                    parts.append(f"{title}：")
                parts.append(content)
            return self._clip_text("\n".join(parts), self.context_section_budgets["memory"])
        return self._clip_text(memory_context, self.context_section_budgets["memory"])

    def _build_task_state_context(self, session_state: Optional[Any], intent: Dict, results: Dict) -> str:
        lines = []
        if session_state:
            if getattr(session_state, "current_task", ""):
                lines.append(f"当前任务：{getattr(session_state, 'current_task', '')}")
            if getattr(session_state, "task_stage", ""):
                lines.append(f"当前阶段：{getattr(session_state, 'task_stage', '')}")
            if getattr(session_state, "active_vuln_id", ""):
                lines.append(f"当前讨论对象：{getattr(session_state, 'active_vuln_id', '')}")
            if getattr(session_state, "active_filters", None):
                lines.append(f"当前筛选条件：{json.dumps(getattr(session_state, 'active_filters', {}), ensure_ascii=False)}")
            completed_steps = list(getattr(session_state, "completed_steps", []) or [])
            if completed_steps:
                lines.append(f"已完成步骤：{'；'.join(completed_steps[-2:])}")
            open_questions = list(getattr(session_state, "open_questions", []) or [])
            if open_questions:
                lines.append(f"待确认问题：{'；'.join(open_questions[:2])}")
            next_actions = list(getattr(session_state, "next_actions", []) or [])
            if next_actions:
                lines.append(f"建议下一步：{'；'.join(next_actions[:2])}")
            if getattr(session_state, "last_intent", ""):
                lines.append(f"上一轮意图：{getattr(session_state, 'last_intent', '')}")
            if getattr(session_state, "last_answer_mode", ""):
                lines.append(f"上一轮回答模式：{getattr(session_state, 'last_answer_mode', '')}")
        if isinstance(intent, dict) and intent.get("type"):
            lines.append(f"本轮任务类型：{intent.get('type')}")
        if isinstance(results, dict) and results.get("external_sources"):
            lines.append(f"本轮外部来源：{', '.join(results.get('external_sources', []))}")
        return self._clip_text("\n".join(lines), self.context_section_budgets["task"])

    def _build_conversation_context(self, results: Dict) -> str:
        if not isinstance(results, dict) or not results.get("conversation_context"):
            return ""
        return self._serialize_context_value(results.get("conversation_context", {}), self.context_section_budgets["conversation"])

    def _build_knowledge_context(self, results: Dict) -> str:
        if not isinstance(results, dict):
            return ""
        knowledge_payload = {}
        if results.get("external_source") or results.get("external_sources"):
            knowledge_payload = {
                "external_source": results.get("external_source", ""),
                "external_sources": results.get("external_sources", []),
                "local_message": results.get("local_message", ""),
                "results": list(results.get("results", []) or [])[:2],
            }
        elif results.get("type") == "rag":
            knowledge_payload = {
                "type": results.get("type", "rag"),
                "count": results.get("count", 0),
                "results": list(results.get("results", []) or [])[:3],
            }
        if not knowledge_payload:
            return ""
        return self._serialize_context_value(knowledge_payload, self.context_section_budgets["knowledge"])

    def _build_result_context(self, results: Dict, answer_mode: str = "") -> str:
        if not isinstance(results, dict):
            return ""
        payload = {
            "type": results.get("type", ""),
            "count": results.get("count", 0),
            "message": results.get("message", ""),
            "external_source": results.get("external_source", ""),
            "external_sources": list(results.get("external_sources", []) or []),
        }
        if results.get("data") is not None:
            payload["data"] = results.get("data")
        result_limit = 3 if answer_mode == "strict_raw" else 5
        if results.get("results"):
            payload["results"] = list(results.get("results", []) or [])[:result_limit]
        if results.get("conversation_context"):
            payload["conversation_context"] = results.get("conversation_context")
        return self._serialize_context_value(payload, self.context_section_budgets["result"])

    def _render_context_sections(self, sections: List[Dict]) -> str:
        parts = []
        for item in sections:
            title = str(item.get("title", "")).strip()
            content = str(item.get("content", "")).strip()
            if not content:
                continue
            if title:
                parts.append(f"{title}：\n{content}")
            else:
                parts.append(content)
        return "\n\n".join(parts)

    def _resolve_prompt_context_texts(self, context_payload: Any, results: Dict, memory_limit: int, result_limit: int):
        if isinstance(context_payload, dict):
            memory_text = self._clip_text(context_payload.get("rendered_context", ""), memory_limit) or "无"
            result_text = self._clip_text(context_payload.get("result_context", ""), result_limit) or "无"
            return memory_text, result_text
        memory_text = self._clip_text(str(context_payload or ""), memory_limit) or "无"
        result_text = self._serialize_context_value(results.get("conversation_context", {}) if isinstance(results, dict) else {}, result_limit) or "无"
        return memory_text, result_text

    def _serialize_context_value(self, value: Any, limit: int) -> str:
        if value in (None, "", [], {}):
            return ""
        if isinstance(value, str):
            return self._clip_text(value, limit)
        try:
            rendered = json.dumps(value, ensure_ascii=False, indent=2)
        except TypeError:
            rendered = str(value)
        return self._clip_text(rendered, limit)

    @staticmethod
    def _clip_text(text: str, limit: int) -> str:
        value = str(text or "").strip()
        if not value or limit <= 0 or len(value) <= limit:
            return value
        if limit <= 12:
            return value[:limit]
        return value[: limit - 8].rstrip() + "...[截断]"

    def _generate_answer(self, question: str, intent: Dict, results: Dict, context_payload: Optional[Dict] = None,
                         answer_mode: str = "") -> str:
        answer_mode = answer_mode or self._determine_answer_mode(question, intent, results)
        if isinstance(results, dict) and results.get("message") and results.get("count", 0) == 0:
            return results["message"]
        if isinstance(results, dict) and results.get("error"):
            return f"查询执行失败：{results.get('error')}"
        if isinstance(results, dict) and results.get("type") == "stats":
            return self._render_stats_answer(results)
        if answer_mode == "strict_raw" and isinstance(results, dict) and results.get("results"):
            return self._render_raw_result_answer(results)
        if not self._llm:
            if answer_mode in {"smalltalk", "followup_summary", "result_explanation", "answer_refinement"}:
                return self._render_conversation_fallback(question, intent, results)
            if isinstance(results, dict) and results.get("external_source") and results.get("results"):
                return self._render_external_fallback_answer(results)
            if isinstance(results, dict) and results.get("type") == "sql" and results.get("results"):
                return self._render_structured_sql_answer(results)
            return json.dumps(results, ensure_ascii=False, indent=2)

        rendered_context, result_context = self._resolve_prompt_context_texts(
            context_payload,
            results,
            memory_limit=self.context_section_budgets["memory"],
            result_limit=self.context_section_budgets["result"],
        )

        if answer_mode == "strict_raw":
            prompt = (
                "你是数据库结果转述助手。必须严格遵守以下规则：\n"
                "1. 只能依据提供的查询结果逐项转述，严禁补充外部知识、严禁猜测、严禁改写为数据库中不存在的结论。\n"
                "2. 优先保留原始字段和值；如果用户要原始信息，就直接按字段输出。\n"
                "3. 不要补充 CVSS、利用方式、修复建议、影响范围等未在结果中出现的内容。\n"
                "4. 如果某个字段为空或未提供，只能说“数据库结果未提供该字段”。\n"
                "5. 如果当前结果来自外部来源，也必须明确标注来源，不要说成数据库原文。\n"
                "6. 使用简体中文回答，但不要做扩展分析。\n\n"
                f"用户问题: {question}\n"
                f"上下文装配:\n{rendered_context}\n"
                f"查询类型: {intent.get('type')}\n"
                f"结果来源: {results.get('external_source', '本地数据库')}\n"
                f"查询结果:\n{result_context}\n"
            )
            system_message = "你必须始终使用简体中文回答，并且只能依据提供的数据作答。"
        elif answer_mode == "smalltalk":
            prompt = self._build_smalltalk_prompt(question, results, context_payload)
            system_message = "你是一个自然、克制、友好的漏洞助手。可以像助手一样对话，但不能编造技术事实。"
        elif answer_mode == "followup_summary":
            prompt = self._build_followup_summary_prompt(question, results, context_payload)
            system_message = "你是一个会承接上下文的漏洞助手。请基于上一轮结果做总结，不要重新检索，不要编造新事实。"
        elif answer_mode == "result_explanation":
            prompt = self._build_result_explanation_prompt(question, results, context_payload)
            system_message = "你是一个擅长解释漏洞结果的助手。请用更易懂的话解释已有结果，但不要超出给定事实。"
        elif answer_mode == "answer_refinement":
            prompt = self._build_answer_refinement_prompt(question, results, context_payload)
            system_message = "你是一个会重写和重述答案的漏洞助手。请在不改变事实的前提下，用用户要求的方式重写已有答案。"
        else:
            prompt = (
                "你是一个自然、专业、会承接上下文的漏洞助手。请按以下方式回答：\n"
                "1. 先接住用户的问题，再回答，不要像系统报错。\n"
                "2. 优先先给一句简短结论，再补关键细节。\n"
                "3. 如果用户是在让你总结、解释、梳理重点，可以自然归纳，但归纳内容必须能在提供的结果中找到依据。\n"
                "4. 如果结果为空或相关性不足，要自然说明现状，并给出 2 到 3 个可操作的下一步建议。\n"
                "5. 不要把不相关结果强行解释成用户要找的内容。\n"
                "6. 会话记忆上下文只能用于理解当前讨论对象和用户偏好，不能当作新的漏洞事实来源。\n"
                "7. 除非结果本身已经给出，否则不要补充 CVSS、影响版本、修复方式等事实。\n"
                "8. 如果结果来自外部来源，要明确告诉用户这是在本地数据库未命中后补查到的外部信息，并标注来源。\n"
                "9. 如果用户明确要求原始字段、原文、数据库内容，则不应总结，应改为严格转述字段。\n\n"
                f"用户问题: {question}\n"
                f"上下文装配:\n{rendered_context}\n"
                f"查询类型: {intent.get('type')}\n"
                f"结果来源: {results.get('external_source', '本地数据库')}\n"
                f"查询结果:\n{result_context}\n"
            )
            system_message = "你必须始终使用简体中文回答，并且只能依据提供的数据作答。"
        try:
            resp = self._llm.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": prompt},
                ],
                temperature=min(self.temperature, 0.1) if answer_mode == "strict_raw" else max(self.temperature, 0.4),
                max_tokens=1024,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            logger.debug(f"回答生成失败: {e}")
            if isinstance(results, dict) and results.get("external_source") and results.get("results"):
                return self._render_external_fallback_answer(results)
            if isinstance(results, dict) and results.get("type") == "sql" and results.get("results"):
                if answer_mode == "strict_raw":
                    return self._render_raw_result_answer(results)
                return self._render_structured_sql_answer(results)
            if answer_mode in {"smalltalk", "followup_summary", "result_explanation", "answer_refinement"}:
                return self._render_conversation_fallback(question, intent, results)
            return json.dumps(results, ensure_ascii=False, indent=2)

    def _determine_answer_mode(self, question: str, intent: Dict, results: Dict) -> str:
        intent_type = intent.get("type", "") if isinstance(intent, dict) else ""
        if self._wants_raw_database_answer(question) and isinstance(results, dict) and results.get("results"):
            return "strict_raw"
        if intent_type in {"smalltalk", "capability_query"}:
            return "smalltalk"
        if intent_type == "followup_summary":
            return "followup_summary"
        if intent_type == "result_explanation":
            return "result_explanation"
        if intent_type == "answer_refinement":
            return "answer_refinement"
        return "analysis"

    def _build_smalltalk_prompt(self, question: str, results: Dict, context_payload: Optional[Dict] = None) -> str:
        rendered_context, result_context = self._resolve_prompt_context_texts(
            context_payload,
            results,
            memory_limit=min(1000, self.context_section_budgets["memory"]),
            result_limit=min(1800, self.context_section_budgets["conversation"]),
        )
        return (
            "请像一个自然的助手一样回答用户，不要像 FAQ 模板，也不要像数据库接口。\n"
            "你可以简短地说明自己的能力范围，但不要编造模型细节或系统架构细节。\n"
            "如果用户的问题其实需要查询数据，可以自然引导他继续提问。\n\n"
            f"用户问题: {question}\n"
            f"上下文装配:\n{rendered_context}\n"
            f"对话上下文:\n{result_context}\n"
        )

    def _build_followup_summary_prompt(self, question: str, results: Dict, context_payload: Optional[Dict] = None) -> str:
        rendered_context, result_context = self._resolve_prompt_context_texts(
            context_payload,
            results,
            memory_limit=min(1000, self.context_section_budgets["memory"]),
            result_limit=min(2600, self.context_section_budgets["result"]),
        )
        return (
            "用户正在让你总结上一轮结果。请基于已有结果做压缩总结，不要重新检索。\n"
            "先给一句总括，再给 2 到 4 个重点。可以自然表达，但不能新增事实。\n\n"
            f"用户问题: {question}\n"
            f"上下文装配:\n{rendered_context}\n"
            f"上一轮结果上下文:\n{result_context}\n"
        )

    def _build_result_explanation_prompt(self, question: str, results: Dict, context_payload: Optional[Dict] = None) -> str:
        rendered_context, result_context = self._resolve_prompt_context_texts(
            context_payload,
            results,
            memory_limit=min(1000, self.context_section_budgets["memory"]),
            result_limit=min(2600, self.context_section_budgets["result"]),
        )
        return (
            "用户正在追问上一轮某条结果的含义。请用更易懂的话解释已有结果。\n"
            "可以更口语化，但不要超出给定结果本身，不要补充未提供的漏洞事实。\n\n"
            f"用户问题: {question}\n"
            f"上下文装配:\n{rendered_context}\n"
            f"上一轮结果上下文:\n{result_context}\n"
        )

    def _build_answer_refinement_prompt(self, question: str, results: Dict, context_payload: Optional[Dict] = None) -> str:
        rendered_context, result_context = self._resolve_prompt_context_texts(
            context_payload,
            results,
            memory_limit=min(1000, self.context_section_budgets["memory"]),
            result_limit=min(2600, self.context_section_budgets["result"]),
        )
        return (
            "用户不是要你重新查询，而是要你把上一轮回答换一种表达方式。\n"
            "请保留事实不变，只调整表达风格，例如更简单、更详细、先给结论或更简短。\n\n"
            f"用户问题: {question}\n"
            f"上下文装配:\n{rendered_context}\n"
            f"上一轮结果上下文:\n{result_context}\n"
        )

    def _render_conversation_fallback(self, question: str, intent: Dict, results: Dict) -> str:
        intent_type = intent.get("type", "") if isinstance(intent, dict) else ""
        ctx = results.get("conversation_context", {}) if isinstance(results, dict) else {}
        if intent_type in {"smalltalk", "capability_query"}:
            return results.get("message") or "你好，我可以帮你查询漏洞、总结结果、解释某条漏洞记录，也可以根据你的问法换一种更容易理解的说法。"
        if intent_type == "followup_summary":
            previews = ctx.get("last_result_preview", []) or []
            if not previews:
                return results.get("message") or "我这边暂时没有可总结的上一轮结果。"
            lines = ["我帮你把刚才的结果压缩总结一下：", ""]
            for item in previews[:3]:
                lines.append(f"- [{item.get('source') or '-'}] {item.get('vuln_id') or '-'} {item.get('title') or ''}".rstrip())
            return "\n".join(lines)
        if intent_type == "result_explanation":
            item = ctx.get("target_item") or {}
            if item:
                return f"简单说，这条结果主要是在说：{item.get('title') or item.get('description') or item.get('content') or '当前记录给出的信息有限'}"
            return results.get("message") or "我目前还没有定位到你想让我解释的那条结果。"
        if intent_type == "answer_refinement":
            last_answer = ctx.get("last_answer_text", "")
            if last_answer:
                return f"我换一种更直白的说法：\n\n{last_answer}"
            return results.get("message") or "我这边暂时没有上一轮回答可供重写。"
        return results.get("message", "") or question

    def _render_stats_answer(self, results: Dict) -> str:
        data = results.get("data", {}) if isinstance(results, dict) else {}
        total = int(data.get("total", 0) or 0)
        by_source = data.get("by_source", {}) or {}
        updated_today = int(data.get("updated_today", 0) or 0)
        high_risk_total = int(data.get("high_risk_total", 0) or 0)
        source = str(data.get("source", "") or "")
        latest_record = data.get("latest_record") or {}
        known_ids = data.get("known_ids")
        db_error = data.get("db_error")

        if db_error:
            return f"我查询数据库总量时出错了：{db_error}"

        if source:
            lines = [f"当前 {source.upper()} 数据库中共有 {total} 条未删除的漏洞记录。"]
        else:
            lines = [f"当前数据库中共有 {total} 条未删除的漏洞记录。"]

        if by_source and not source:
            lines.append("")
            lines.append("按来源统计：")
            for source, count in sorted(by_source.items()):
                lines.append(f"- {source.upper()}: {int(count or 0)}")

        if latest_record:
            latest_id = latest_record.get("vuln_id") or latest_record.get("cve_id") or "-"
            latest_title = latest_record.get("title") or latest_record.get("description") or "-"
            latest_time = latest_record.get("last_updated") or latest_record.get("published_date") or "-"
            lines.append("")
            lines.append("最新一条记录：")
            lines.append(f"- 来源: {(latest_record.get('source') or source or '-').upper()}")
            lines.append(f"- 漏洞编号: {latest_id}")
            lines.append(f"- 标题: {latest_title}")
            lines.append(f"- 时间: {latest_time}")

        lines.append("")
        lines.append(f"今日更新: {updated_today}")
        lines.append(f"高危/严重数量: {high_risk_total}")

        if known_ids is not None:
            lines.append(f"记忆中的已知ID数: {int(known_ids or 0)}")

        return "\n".join(lines)

    def _render_structured_sql_answer(self, results: Dict) -> str:
        message = results.get("message", "")
        items = results.get("results", [])[:5]
        if not items:
            return message or "未检索到相关结果。"
        intro = message or f"我先帮你整理了 {len(items)} 条比较相关的漏洞结果，先给你看前几条："
        lines = [intro, ""]
        for idx, item in enumerate(items, 1):
            vuln_id = item.get("vuln_id") or item.get("cve_id") or "-"
            title = item.get("title") or "-"
            source = item.get("source") or "-"
            vendor = item.get("vendor") or "-"
            updated = item.get("last_updated") or item.get("published_date") or "-"
            lines.append(f"{idx}. [{source}] {vuln_id}")
            lines.append(f"   标题：{title}")
            lines.append(f"   厂商/产品：{vendor}")
            lines.append(f"   时间：{updated}")
        lines.append("")
        lines.append("如果你愿意，我可以继续帮你展开其中某一条的详情，或者按厂商、产品、时间范围继续缩小结果。")
        return "\n".join(lines)

    def _wants_raw_database_answer(self, question: str) -> bool:
        normalized = re.sub(r"\s+", "", (question or "")).lower()
        if not normalized:
            return False
        triggers = [
            "原始信息", "原始数据", "原文", "原始内容", "原始字段", "数据库内容", "数据库原文",
            "原始记录", "原始结果", "原始返回", "原样返回", "按字段", "逐字段", "字段值",
            "不要总结", "不要概括", "不要润色", "严格按数据库", "严格按照数据库", "只看数据库",
            "只返回数据库", "直接给我原文", "给我原始信息", "给我数据库内容",
        ]
        return any(token in normalized for token in triggers)

    def _render_raw_result_answer(self, results: Dict) -> str:
        message = results.get("message", "")
        items = results.get("results", [])[:3]
        if not items:
            return message or "未检索到相关结果。"
        lines = [message or f"以下为数据库中的原始结果，共 {len(items)} 条：", ""]
        for idx, item in enumerate(items, 1):
            lines.append(f"第 {idx} 条记录：")
            for key, value in item.items():
                if value is None or value == "":
                    continue
                if isinstance(value, (dict, list)):
                    rendered = json.dumps(value, ensure_ascii=False)
                else:
                    rendered = str(value)
                lines.append(f"- {key}: {rendered}")
            lines.append("")
        return "\n".join(lines).strip()

    def _render_external_fallback_answer(self, results: Dict) -> str:
        items = results.get("results", [])[:self.max_external_results]
        if not items:
            return results.get("message", "未检索到相关结果。")
        lines = [results.get("message", "我补查到了外部来源信息。")]
        if results.get("local_message"):
            lines.append(f"本地检索情况：{results.get('local_message')}")
        lines.append("")
        for idx, item in enumerate(items, 1):
            source = str(item.get("source", "external")).upper()
            lines.append(f"{idx}. [{source}] {item.get('title') or item.get('cve_id') or '-'}")
            if item.get("description"):
                lines.append(f"   描述：{item.get('description')}")
            if item.get("cvss_score") not in (None, ""):
                lines.append(f"   CVSS：{item.get('cvss_score')}")
            if item.get("published"):
                lines.append(f"   发布时间：{item.get('published')}")
            if item.get("content"):
                lines.append(f"   摘要：{item.get('content')}")
            if item.get("url"):
                lines.append(f"   链接：{item.get('url')}")
            if item.get("references"):
                refs = item.get("references")[:3] if isinstance(item.get("references"), list) else [item.get("references")]
                for ref in refs:
                    lines.append(f"   参考：{ref}")
        if self.show_external_sources and results.get("external_sources"):
            lines.append("")
            lines.append(f"来源：{', '.join(results.get('external_sources', []))}")
        return "\n".join(lines)

    def _looks_like_keyword_search(self, message: str) -> bool:
        normalized = (message or "").strip()
        if not normalized:
            return False
        if len(normalized) <= 2:
            return False
        if self._looks_like_list_query(normalized):
            return False
        if any(token in normalized for token in ["CVE-", "CNVD-", "JVN", "Apache", "OpenSSH", "Windows", "Linux", "厂商", "产品"]):
            return True
        if re.search(r"[A-Za-z][A-Za-z0-9._-]{2,}", normalized):
            return True
        return False

    def _looks_like_list_query(self, message: str) -> bool:
        normalized = (message or "").strip()
        if not normalized:
            return False
        return (
            ("漏洞" in normalized and any(token in normalized for token in ["最近", "最新", "高危", "严重", "有哪些", "哪些"]))
            or any(token in normalized for token in ["最近有哪些高危漏洞", "最新漏洞", "高危漏洞"])
        )

    def _extract_keyword_query(self, message: str) -> str:
        query = (message or "").strip()
        query = re.sub(r"(请问|帮我|查询|检索|搜索|一下|一下子|看看|相关漏洞|有哪些|哪些|最近|最新|数据库|漏洞库|有多少个漏洞|有多少漏洞|多少个漏洞|哪个漏洞是最新的|哪一个漏洞是最新的)", " ", query)
        query = re.sub(r"\s+", " ", query).strip()
        return query or (message or "").strip()

    def _extract_question_keywords(self, question: str) -> List[str]:
        lowered = (question or "").lower()
        id_keywords = [m.lower() for m in re.findall(r"(CVE-\d{4}-\d+|CNVD-\d{4}-\d+|JVNVU?#?\d+)", question or "", re.I)]
        english_keywords: List[str] = []
        stop_words = {
            "vulnerability", "vulnerabilities", "remote", "code", "execution",
            "related", "about", "detail", "details", "what", "which",
            "database", "latest", "count", "records",
        }
        for token in re.findall(r"[A-Za-z][A-Za-z0-9._-]{2,}", question or ""):
            token = token.lower()
            if token not in stop_words:
                english_keywords.append(token)
        ordered: List[str] = []
        for keyword in id_keywords + english_keywords:
            if keyword and keyword in lowered and keyword not in ordered:
                ordered.append(keyword)
        return ordered

    def _filter_rag_results(self, question: str, rag_results: List[Dict]) -> List[Dict]:
        keywords = self._extract_question_keywords(question)
        if not keywords:
            return rag_results[:self.max_results]
        filtered: List[Dict] = []
        for item in rag_results:
            haystack = " ".join([
                str(item.get("vuln_id", "")),
                str(item.get("cve_id", "")),
                str(item.get("title", "")),
                str(item.get("description", "")),
                str(item.get("document", "")),
                str(item.get("source", "")),
            ]).lower()
            if any(keyword in haystack for keyword in keywords):
                filtered.append(item)
        return (filtered or rag_results)[:self.max_results]

    def _finalize_results_for_answer(self, question: str, intent: Dict, results: Dict) -> Dict:
        intent_type = intent.get("type") if isinstance(intent, dict) else ""
        params = intent.get("params", {}) if isinstance(intent, dict) else {}
        if intent_type in {"smalltalk", "capability_query", "followup_summary", "result_explanation", "answer_refinement", "stats"}:
            return results
        if isinstance(results, dict) and results.get("error"):
            return {"message": f"查询执行失败：{results.get('error')}"}
        if intent_type == "sql_query":
            sql_results = results.get("results", []) if isinstance(results, dict) else []
            if not sql_results:
                if params.get("vuln_id"):
                    return {
                        "type": "sql",
                        "results": [],
                        "count": 0,
                        "message": "我暂时没有查到这个漏洞编号对应的数据。你可以先确认编号是否输入正确，或者换成产品名、厂商名再让我帮你检索。",
                    }
                if params.get("severity") or params.get("recent"):
                    if params.get("severity") == "high" and params.get("recent"):
                        fallback_results = self._fallback_search_records(
                            source=params.get("source", ""),
                            limit=min(self.max_results, 10),
                            recent=True,
                        )
                        if fallback_results:
                            return {
                                "type": "sql",
                                "results": fallback_results,
                                "count": len(fallback_results),
                                "message": "我先按“最近高危漏洞”帮你筛了一遍，当前没有直接命中的高危记录。先给你看最近更新的漏洞数据，方便你继续缩小范围。",
                            }
                    return {
                        "type": "sql",
                        "results": [],
                        "count": 0,
                        "message": "我这次没有筛到符合条件的漏洞记录。你可以换一种问法试试，比如加上产品名、厂商名，或者放宽严重等级和时间范围。",
                    }
                return {
                    "type": "sql",
                    "results": [],
                    "count": 0,
                    "message": "我暂时没找到直接相关的漏洞记录。你可以告诉我更具体的产品名、厂商名、漏洞编号，或者让我按关键词继续帮你缩小范围。",
                }
            return results
        if intent_type != "rag_search":
            return results
        rag_results = results.get("results", []) if isinstance(results, dict) else []
        if not rag_results:
            return {
                "type": "rag",
                "results": [],
                "count": 0,
                "message": "我暂时没有检索到足够相关的语义结果。你可以补充产品名、组件名、漏洞编号，或者换成更具体的场景描述。",
            }
        filtered = self._filter_rag_results(question, rag_results)
        normalized = dict(results)
        normalized["results"] = filtered
        normalized["count"] = len(filtered)
        return normalized

    def _apply_external_fallback(self, question: str, intent: Dict, results: Dict) -> Dict:
        if not isinstance(results, dict):
            return results
        if not self.enable_external_fallback:
            return results
        if results.get("results"):
            return results
        intent_type = intent.get("type", "") if isinstance(intent, dict) else ""
        if intent_type not in {"sql_query", "rag_search"}:
            return results
        if not self.tool_agent or not getattr(self.tool_agent, "enabled", False):
            return results

        params = intent.get("params", {}) if isinstance(intent, dict) else {}
        external_results: List[Dict] = []
        external_sources: List[str] = []

        vuln_id = str(params.get("vuln_id", "") or "")
        if vuln_id.upper().startswith("CVE-") and self.prefer_nvd_for_cve and "nvd_lookup" in self.tool_agent.tools:
            nvd_data = self.tool_agent.tools["nvd_lookup"](vuln_id, self.tool_agent.nvd_api_key)
            if nvd_data:
                external_results.append({
                    "source": "nvd",
                    "cve_id": nvd_data.get("cve_id", vuln_id),
                    "title": nvd_data.get("cve_id", vuln_id),
                    "description": nvd_data.get("description", ""),
                    "cvss_score": nvd_data.get("cvss_score"),
                    "published": nvd_data.get("published", ""),
                    "references": nvd_data.get("references", []),
                })
                external_sources.append("NVD")

        if not external_results and self.enable_tavily_fallback and "tavily_search" in self.tool_agent.tools:
            query = vuln_id or params.get("query") or params.get("keyword") or question
            tavily_results = self.tool_agent.tools["tavily_search"](
                query,
                max_results=self.max_external_results,
                api_key=self.tool_agent.tavily_api_key,
            )
            if tavily_results:
                for item in tavily_results[:self.max_external_results]:
                    external_results.append({
                        "source": "tavily",
                        "title": item.get("title", ""),
                        "description": item.get("content", ""),
                        "content": item.get("content", ""),
                        "url": item.get("url", ""),
                    })
                external_sources.append("Tavily")

        if not external_results:
            return results

        local_message = results.get("message", "")
        return {
            "type": results.get("type", intent_type or "external"),
            "results": external_results,
            "count": len(external_results),
            "message": "本地数据库未直接命中，我补查到了一些外部来源信息供你参考。",
            "local_message": local_message,
            "external_source": external_sources[0] if external_sources else "external",
            "external_sources": external_sources,
        }
