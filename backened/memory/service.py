import hashlib
import json
import logging
import re
from typing import Dict, List, Optional

from memory.history_store import ConversationHistoryStore
from memory.resolver import ReferenceResolver
from memory.session import SessionMemoryStore, SessionState
from memory.store import LongTermMemoryStore


logger = logging.getLogger(__name__)


class ConversationMemoryService:
    def __init__(self, db_uri: str = "", session_ttl_seconds: int = 3600, vector_enabled: bool = True):
        self.sessions = SessionMemoryStore(ttl_seconds=session_ttl_seconds)
        self.resolver = ReferenceResolver()
        self.long_term = LongTermMemoryStore(db_uri=db_uri, vector_enabled=vector_enabled) if db_uri else None
        self.history = ConversationHistoryStore(db_uri=db_uri) if db_uri else None
        self.max_message_window = 20
        self.recent_message_tail = 8
        self.max_compressed_chars = 1500
        self.hydration_message_limit = 60
        self.prompt_section_limits = {
            "compressed_summary": 600,
            "active_context": 320,
            "task_scratchpad": 520,
            "result_preview": 500,
            "recent_messages": 900,
            "conversation_summary": 280,
            "long_term_memories": 420,
        }

    def begin_turn(self, message: str, session_id: str, user_id: str = "default", project_id: str = "cleanagent") -> Dict:
        if self.history:
            self.history.ensure_session(session_id=session_id, user_id=user_id, project_id=project_id)
        state = self.sessions.get_or_create(session_id=session_id, user_id=user_id, project_id=project_id)
        self._hydrate_session_state(state)
        explicit_memory = self._extract_explicit_memory(state, message)
        if explicit_memory:
            self.sessions.update(state)
            return {
                "message": message,
                "state": state,
                "resolved_vuln_id": state.active_vuln_id,
                "requires_clarification": False,
                "explicit_memory": explicit_memory,
                "retrieved_memories": [],
                "prompt_memory_payload": {"sections": [], "meta": {"section_count": 0, "total_chars": 0, "memory_hits": 0}},
                "prompt_memory_context": "",
            }
        resolved = self.resolver.resolve_message(message, state)
        if resolved.get("requires_reset"):
            state.clear_active_context()
            self.sessions.update(state)
        retrieved_memories = self._retrieve_memories(resolved.get("message", message), user_id, project_id)
        prompt_memory_payload = self._build_prompt_memory_payload(state, retrieved_memories)
        prompt_memory_context = self._render_prompt_memory_payload(prompt_memory_payload)
        logger.debug(
            "Memory context built: sections=%s total_chars=%s memory_hits=%s",
            prompt_memory_payload.get("meta", {}).get("section_count", 0),
            prompt_memory_payload.get("meta", {}).get("total_chars", 0),
            prompt_memory_payload.get("meta", {}).get("memory_hits", 0),
        )
        return {
            "message": resolved.get("message", message),
            "state": state,
            "resolved_vuln_id": resolved.get("resolved_vuln_id", ""),
            "resolved_target_type": resolved.get("resolved_target_type", "none"),
            "resolved_result_index": resolved.get("resolved_result_index", -1),
            "requires_clarification": resolved.get("requires_clarification", False),
            "explicit_memory": None,
            "retrieved_memories": retrieved_memories,
            "prompt_memory_payload": prompt_memory_payload,
            "prompt_memory_context": prompt_memory_context,
        }

    def finalize_turn(self, session_id: str, message: str, intent: Dict, results: Dict, answer: str, answer_mode: str = ""):
        state = self.sessions.get(session_id)
        if not state:
            return
        intent_type = intent.get("type", "") if isinstance(intent, dict) else ""
        conversational_intents = {"smalltalk", "capability_query", "followup_summary", "result_explanation", "answer_refinement"}
        params = intent.get("params", {}) if isinstance(intent, dict) else {}
        vuln_id = params.get("vuln_id", "")
        if vuln_id:
            state.active_vuln_id = vuln_id
        result_ids = self._extract_result_ids(results)
        if intent_type not in conversational_intents and isinstance(results, dict):
            state.last_result_ids = result_ids
            state.last_result_preview = self._build_result_preview(results)
            state.last_result_payload = self._build_result_payload(results)
            state.last_result_type = str(results.get("type", ""))
            state.last_external_sources = list(results.get("external_sources", []) or [])
            if len(result_ids) == 1 and not state.active_vuln_id:
                state.active_vuln_id = result_ids[0]
        if vuln_id or result_ids:
            active_vuln_id = vuln_id or (result_ids[0] if result_ids else "")
            if active_vuln_id:
                state.active_entities = {"vuln_id": active_vuln_id}
        if params:
            state.active_filters = {k: v for k, v in params.items() if k in {"severity", "recent", "source", "keyword"} and v}
        state.last_intent = intent_type
        self._append_messages_window(state, message, answer)
        self._compress_messages_window(state)
        state.last_answer_text = answer or ""
        state.last_answer_mode = answer_mode or ""
        self._update_task_state(state, message, intent, results, answer)
        state.conversation_summary = self._build_summary(message, state, answer)
        self.sessions.update(state)
        if self.history:
            self.history.append_turn(
                session_id=session_id,
                user_id=state.user_id,
                project_id=state.project_id,
                user_message=message,
                assistant_message=answer,
                intent_type=state.last_intent,
                summary=state.conversation_summary,
            )

    def format_correction_reply(self, session_id: str) -> str:
        state = self.sessions.get(session_id)
        if state:
            state.clear_active_context()
            self.sessions.update(state)
        return "明白了，我先不再沿用刚才的漏洞对象。你可以直接告诉我漏洞编号，或者让我按关键词重新检索。"

    def _retrieve_memories(self, message: str, user_id: str, project_id: str) -> List[Dict]:
        if not self.long_term:
            return []
        memories = self.long_term.search_memories(message, user_id=user_id, project_id=project_id, top_k=5)
        return [item for item in memories if item.get("memory_type") != "preference"]

    def create_session(self, user_id: str = "default", project_id: str = "cleanagent", title: str = "") -> Dict:
        if self.history:
            return self.history.create_session(user_id=user_id, project_id=project_id, title=title)
        return {
            "session_id": "",
            "user_id": user_id,
            "project_id": project_id,
            "title": title or "新对话",
            "summary": "",
            "last_user_message": "",
            "last_assistant_message": "",
        }

    def list_sessions(self, user_id: str = "default", project_id: str = "cleanagent") -> List[Dict]:
        if not self.history:
            return []
        return self.history.list_sessions(user_id=user_id, project_id=project_id)

    def get_session_detail(self, session_id: str, user_id: str = "default") -> Dict:
        session_info = self.history.get_session(session_id, user_id=user_id) if self.history else None
        messages = self.history.list_messages(session_id, user_id=user_id) if self.history else []
        return {
            "session": session_info,
            "messages": messages,
        }

    def rename_session(self, session_id: str, user_id: str, title: str) -> Optional[Dict]:
        if not self.history:
            return None
        return self.history.rename_session(session_id=session_id, user_id=user_id, title=title)

    def delete_session(self, session_id: str, user_id: str) -> bool:
        self.sessions.delete(session_id)
        if not self.history:
            return False
        return self.history.delete_session(session_id=session_id, user_id=user_id)

    def persist_turn(self, session_id: str, user_id: str, project_id: str, user_message: str,
                     assistant_message: str, intent_type: str = "", summary: str = ""):
        if not self.history:
            return
        self.history.append_turn(
            session_id=session_id,
            user_id=user_id,
            project_id=project_id,
            user_message=user_message,
            assistant_message=assistant_message,
            intent_type=intent_type,
            summary=summary,
        )

    def _build_prompt_memory_payload(self, state: SessionState, memories: List[Dict]) -> Dict:
        sections: List[Dict] = []

        compressed_context = self._clip_text(
            state.compressed_context,
            self.prompt_section_limits["compressed_summary"],
        )
        if compressed_context:
            sections.append({
                "name": "compressed_summary",
                "title": "较早对话压缩摘要",
                "content": compressed_context,
            })

        active_lines = []
        if state.active_vuln_id:
            active_lines.append(f"当前会话正在讨论的漏洞编号：{state.active_vuln_id}")
        if state.last_result_ids:
            active_lines.append(f"上一轮结果编号：{', '.join(state.last_result_ids[:5])}")
        if state.active_filters:
            active_lines.append(f"当前筛选条件：{json.dumps(state.active_filters, ensure_ascii=False)}")
        active_context = self._clip_text(
            "\n".join(active_lines),
            self.prompt_section_limits["active_context"],
        )
        if active_context:
            sections.append({
                "name": "active_context",
                "title": "当前讨论焦点",
                "content": active_context,
            })

        preference_text = self._clip_text(
            self._render_session_preferences(state),
            self.prompt_section_limits["active_context"],
        )
        if preference_text:
            sections.append({
                "name": "session_preferences",
                "title": "当前窗口偏好",
                "content": preference_text,
            })

        task_scratchpad = self._clip_text(
            self._render_task_scratchpad(state),
            self.prompt_section_limits["task_scratchpad"],
        )
        if task_scratchpad:
            sections.append({
                "name": "task_scratchpad",
                "title": "任务状态笔记",
                "content": task_scratchpad,
            })

        result_preview_lines = []
        for item in state.last_result_preview[:3]:
            result_preview_lines.append(
                f"- [{item.get('source') or '-'}] "
                f"{item.get('vuln_id') or '-'} {item.get('title') or ''}".rstrip()
            )
        result_preview = self._clip_text(
            "\n".join(result_preview_lines),
            self.prompt_section_limits["result_preview"],
        )
        if result_preview:
            sections.append({
                "name": "result_preview",
                "title": "上一轮结果预览",
                "content": result_preview,
            })

        recent_message_lines = []
        for item in state.messages_window[-6:]:
            role = "用户" if item.get("role") == "user" else "助手"
            content = str(item.get("content", "")).strip()
            if not content:
                continue
            recent_message_lines.append(f"- {role}：{content[:160]}")
        recent_messages = self._clip_text(
            "\n".join(recent_message_lines),
            self.prompt_section_limits["recent_messages"],
        )
        if recent_messages:
            sections.append({
                "name": "recent_messages",
                "title": "最近对话窗口",
                "content": recent_messages,
            })

        conversation_summary = self._clip_text(
            state.conversation_summary,
            self.prompt_section_limits["conversation_summary"],
        )
        if conversation_summary:
            sections.append({
                "name": "conversation_summary",
                "title": "会话摘要",
                "content": conversation_summary,
            })

        memory_lines = []
        for item in memories[:3]:
            memory_lines.append(f"- [{item.get('scope')}] {item.get('summary_text')}")
        long_term_memories = self._clip_text(
            "\n".join(memory_lines),
            self.prompt_section_limits["long_term_memories"],
        )
        if long_term_memories:
            sections.append({
                "name": "long_term_memories",
                "title": "长期记忆",
                "content": long_term_memories,
            })

        total_chars = sum(len(item.get("content", "")) for item in sections)
        return {
            "sections": sections,
            "meta": {
                "section_count": len(sections),
                "total_chars": total_chars,
                "memory_hits": len(memories or []),
            },
        }

    def _render_prompt_memory_payload(self, payload: Dict) -> str:
        sections = payload.get("sections", []) if isinstance(payload, dict) else []
        parts = []
        for item in sections:
            title = str(item.get("title", "")).strip()
            content = str(item.get("content", "")).strip()
            if not content:
                continue
            if title:
                parts.append(f"{title}：")
            parts.append(content)
        return "\n".join(parts)

    def _format_prompt_memory_context(self, state: SessionState, memories: List[Dict]) -> str:
        payload = self._build_prompt_memory_payload(state, memories)
        return self._render_prompt_memory_payload(payload)

    @staticmethod
    def _clip_text(text: str, limit: int) -> str:
        value = str(text or "").strip()
        if not value or limit <= 0 or len(value) <= limit:
            return value
        if limit <= 12:
            return value[:limit]
        return value[: limit - 8].rstrip() + "...[截断]"

    def _extract_result_ids(self, results: Dict) -> List[str]:
        if not isinstance(results, dict):
            return []
        ids = []
        for item in results.get("results", []) or []:
            vuln_id = item.get("vuln_id") or item.get("cve_id") or item.get("id")
            if vuln_id:
                ids.append(str(vuln_id))
        seen = []
        for item in ids:
            if item not in seen:
                seen.append(item)
        return seen[:10]

    def _build_result_preview(self, results: Dict) -> List[Dict]:
        previews = []
        if not isinstance(results, dict):
            return previews
        for item in (results.get("results", []) or [])[:5]:
            previews.append({
                "vuln_id": item.get("vuln_id") or item.get("cve_id") or item.get("id") or "",
                "title": item.get("title") or "",
                "source": item.get("source") or "",
            })
        return previews

    def _build_result_payload(self, results: Dict) -> Dict:
        if not isinstance(results, dict):
            return {}
        payload = {
            "type": results.get("type", ""),
            "message": results.get("message", ""),
            "count": results.get("count", 0),
            "external_source": results.get("external_source", ""),
            "external_sources": list(results.get("external_sources", []) or []),
            "results": [],
        }
        for item in (results.get("results", []) or [])[:5]:
            if isinstance(item, dict):
                payload["results"].append(dict(item))
        return payload

    def _build_summary(self, message: str, state: SessionState, answer: str) -> str:
        base = []
        if state.active_vuln_id:
            base.append(f"当前讨论对象为 {state.active_vuln_id}")
        if state.current_task:
            base.append(f"当前任务：{state.current_task}")
        if state.task_stage:
            base.append(f"当前阶段：{state.task_stage}")
        if state.last_intent:
            base.append(f"最近一次意图为 {state.last_intent}")
        if state.active_filters:
            base.append(f"当前筛选条件：{json.dumps(state.active_filters, ensure_ascii=False)}")
        if state.next_actions:
            base.append(f"下一步：{'；'.join(state.next_actions[:2])}")
        if state.messages_window:
            base.append(f"最近消息窗口：{len(state.messages_window)} 条")
        if message:
            base.append(f"最近问题：{message[:80]}")
        if answer:
            base.append(f"最近回答摘要：{answer[:120]}")
        return "；".join(base)

    def _append_messages_window(self, state: SessionState, user_message: str, assistant_message: str):
        if user_message:
            state.messages_window.append({"role": "user", "content": user_message[:2000]})
        if assistant_message:
            state.messages_window.append({"role": "assistant", "content": assistant_message[:2000]})

    def _compress_messages_window(self, state: SessionState):
        if len(state.messages_window) <= self.max_message_window:
            return
        keep_count = max(4, min(self.recent_message_tail, self.max_message_window))
        older_messages = state.messages_window[:-keep_count]
        recent_messages = state.messages_window[-keep_count:]
        summary = self._summarize_messages(older_messages)
        state.compressed_context = self._merge_compressed_context(state.compressed_context, summary)
        state.messages_window = recent_messages

    def _summarize_messages(self, messages: List[Dict]) -> str:
        if not messages:
            return ""
        lines: List[str] = []
        for item in messages:
            content = re.sub(r"\s+", " ", str(item.get("content", "")).strip())
            if not content:
                continue
            role = "用户" if item.get("role") == "user" else "助手"
            lines.append(f"{role}：{content[:120]}")
        if not lines:
            return ""
        if len(lines) > 6:
            lines = lines[:3] + ["..."] + lines[-3:]
        return "\n".join(lines)

    def _merge_compressed_context(self, existing: str, incoming: str) -> str:
        chunks = [item.strip() for item in [existing, incoming] if item and item.strip()]
        if not chunks:
            return ""
        merged = "\n".join(chunks)
        if len(merged) <= self.max_compressed_chars:
            return merged
        return merged[-self.max_compressed_chars:]

    def _hydrate_session_state(self, state: SessionState):
        if state.conversation_summary or state.last_result_ids or state.active_vuln_id or not self.history:
            return
        detail = self.history.hydrate_state(
            state.session_id,
            user_id=state.user_id,
            limit=self.hydration_message_limit,
        )
        session_info = detail.get("session") or {}
        messages = detail.get("messages") or []
        if session_info.get("summary"):
            state.conversation_summary = session_info.get("summary", "")
        if session_info.get("last_assistant_message"):
            state.last_answer_text = session_info.get("last_assistant_message", "")
        if session_info.get("last_user_message"):
            state.active_filters = state.active_filters or {}
        normalized_messages = [
            {"role": item.get("role", ""), "content": item.get("content", "")}
            for item in messages if item.get("role") in {"user", "assistant"}
        ]
        if normalized_messages:
            state.messages_window = normalized_messages[-self.max_message_window:]
            older_messages = normalized_messages[:-self.max_message_window]
            if older_messages:
                state.compressed_context = self._summarize_messages(older_messages)
        last_intent = ""
        for item in reversed(messages):
            if item.get("intent_type"):
                last_intent = item.get("intent_type", "")
                break
        if last_intent:
            state.last_intent = last_intent
        for item in reversed(messages):
            if item.get("role") != "assistant":
                continue
            preview_items = self._extract_message_vuln_ids(item.get("content", ""))
            ids = self._extract_result_ids({"results": preview_items})
            if ids:
                state.last_result_ids = ids
                state.last_result_preview = preview_items[:5]
                state.last_result_payload = {
                    "type": "history_hydrated",
                    "message": session_info.get("summary", "") or item.get("content", "")[:300],
                    "count": len(preview_items),
                    "external_source": "",
                    "external_sources": [],
                    "results": preview_items[:5],
                }
                state.last_result_type = "history_hydrated"
                if not state.active_vuln_id:
                    state.active_vuln_id = ids[0]
                break
        self._restore_session_preferences(state, messages)
        self._restore_task_state(state, session_info, messages)
        self.sessions.update(state)

    def _render_session_preferences(self, state: SessionState) -> str:
        lines = list(state.session_preference_summaries[:3])
        return "\n".join(lines)

    def _render_task_scratchpad(self, state: SessionState) -> str:
        lines: List[str] = []
        if state.current_task:
            lines.append(f"当前任务：{state.current_task}")
        if state.task_stage:
            lines.append(f"当前阶段：{state.task_stage}")
        if state.completed_steps:
            lines.append("已完成步骤：")
            for item in state.completed_steps[:3]:
                lines.append(f"- {item}")
        if state.open_questions:
            lines.append("待确认问题：")
            for item in state.open_questions[:3]:
                lines.append(f"- {item}")
        if state.next_actions:
            lines.append("建议下一步：")
            for item in state.next_actions[:3]:
                lines.append(f"- {item}")
        return "\n".join(lines)

    def _update_task_state(self, state: SessionState, message: str, intent: Dict, results: Dict, answer: str):
        intent_type = intent.get("type", "") if isinstance(intent, dict) else ""
        params = intent.get("params", {}) if isinstance(intent, dict) else {}
        state.task_stage = self._infer_task_stage(intent_type, results)
        state.current_task = self._infer_current_task(state, message, intent_type, params)

        if intent_type in {"sql_query", "rag_search", "memory_query", "stats"}:
            step_text = self._build_completed_step(intent_type, state, results)
            if step_text:
                self._append_unique_item(state.completed_steps, step_text)

        if intent_type == "followup_summary":
            self._append_unique_item(state.completed_steps, "已对上一轮结果做压缩总结")
        elif intent_type == "result_explanation":
            self._append_unique_item(state.completed_steps, "已对上一轮结果做进一步解释")
        elif intent_type == "answer_refinement":
            self._append_unique_item(state.completed_steps, "已按用户要求重写上一轮回答")

        state.open_questions = []
        followup_question = self._infer_open_question(message, answer)
        if followup_question:
            self._append_unique_item(state.open_questions, followup_question, limit=3)

        state.next_actions = self._infer_next_actions(state, intent_type, results)

    def _restore_task_state(self, state: SessionState, session_info: Dict, messages: List[Dict]):
        if state.current_task or state.task_stage:
            return
        summary = str((session_info or {}).get("summary", "") or "").strip()
        if state.active_vuln_id:
            state.current_task = f"围绕 {state.active_vuln_id} 继续查询、解释或总结"
        elif summary:
            state.current_task = summary[:80]
        if state.last_intent:
            state.task_stage = self._infer_task_stage(state.last_intent, state.last_result_payload)
        if not state.completed_steps and state.last_intent:
            restored_step = self._build_completed_step(state.last_intent, state, state.last_result_payload)
            if restored_step:
                self._append_unique_item(state.completed_steps, restored_step)
        if not state.next_actions:
            state.next_actions = self._infer_next_actions(state, state.last_intent, state.last_result_payload)

    def _restore_session_preferences(self, state: SessionState, messages: List[Dict]):
        if state.session_preferences:
            return
        for item in messages:
            if item.get("role") != "user":
                continue
            self._extract_explicit_memory(state, item.get("content", ""), persist_only=True)

    def _infer_current_task(self, state: SessionState, message: str, intent_type: str, params: Dict) -> str:
        vuln_id = params.get("vuln_id") or state.active_vuln_id
        if vuln_id:
            return f"围绕 {vuln_id} 继续查询、解释或总结"
        if intent_type == "stats":
            return "查看漏洞库统计与整体处理状态"
        if intent_type == "memory_query":
            source = params.get("source") or "系统记忆"
            return f"分析 {source} 相关记忆与质量画像"
        if intent_type == "rag_search":
            query = params.get("query") or message
            return f"按主题检索相关漏洞知识：{str(query)[:50]}"
        if intent_type == "sql_query":
            keyword = params.get("keyword") or message
            return f"在本地漏洞库中定位相关结果：{str(keyword)[:50]}"
        if intent_type in {"followup_summary", "result_explanation", "answer_refinement"} and state.current_task:
            return state.current_task
        return str(message or state.current_task or "")[:80]

    @staticmethod
    def _infer_task_stage(intent_type: str, results: Dict) -> str:
        if intent_type in {"sql_query", "rag_search"}:
            count = int((results or {}).get("count", 0) or 0) if isinstance(results, dict) else 0
            return "已完成结果检索" if count > 0 else "检索未命中，等待下一步"
        if intent_type == "memory_query":
            return "已完成记忆分析"
        if intent_type == "stats":
            return "已完成统计查看"
        if intent_type == "followup_summary":
            return "已完成结果总结"
        if intent_type == "result_explanation":
            return "已完成结果解释"
        if intent_type == "answer_refinement":
            return "已完成回答改写"
        if intent_type in {"smalltalk", "capability_query"}:
            return "对话承接中"
        return "处理中"

    def _build_completed_step(self, intent_type: str, state: SessionState, results: Dict) -> str:
        if intent_type == "sql_query":
            target = state.active_vuln_id or (state.last_result_ids[0] if state.last_result_ids else "相关漏洞")
            return f"已查询本地漏洞结果：{target}"
        if intent_type == "rag_search":
            count = int((results or {}).get("count", 0) or 0) if isinstance(results, dict) else 0
            return f"已完成语义检索，获得 {count} 条候选结果"
        if intent_type == "memory_query":
            return "已查看系统记忆或来源画像"
        if intent_type == "stats":
            return "已查看漏洞库统计信息"
        return ""

    @staticmethod
    def _infer_open_question(message: str, answer: str) -> str:
        normalized = str(message or "").strip()
        if any(token in normalized for token in ["怎么", "如何", "为什么", "哪个", "哪条", "是否"]):
            return normalized[:80]
        if any(token in str(answer or "") for token in ["可以继续", "如果你愿意", "你可以再", "下一步"]):
            return "用户可能会继续追问更细的漏洞详情、总结或修复建议"
        return ""

    def _infer_next_actions(self, state: SessionState, intent_type: str, results: Dict) -> List[str]:
        actions: List[str] = []
        result_count = int((results or {}).get("count", 0) or 0) if isinstance(results, dict) else 0
        if state.last_result_preview:
            actions.append("继续展开某一条结果的详情或解释")
        if result_count > 1:
            actions.append("按来源、严重等级或关键词继续缩小结果范围")
        if state.active_vuln_id:
            actions.append(f"围绕 {state.active_vuln_id} 继续查看影响范围、描述或修复信息")
        if intent_type in {"followup_summary", "result_explanation", "answer_refinement"}:
            actions.append("继续承接上一轮结果做总结、解释或换一种表达")
        if not actions and intent_type in {"smalltalk", "capability_query"}:
            actions.append("引导用户提出具体漏洞编号、关键词或统计需求")
        if not actions:
            actions.append("继续补充更明确的筛选条件或查询目标")
        deduped: List[str] = []
        for item in actions:
            if item not in deduped:
                deduped.append(item)
        return deduped[:3]

    @staticmethod
    def _append_unique_item(target: List[str], value: str, limit: int = 5):
        item = str(value or "").strip()
        if not item:
            return
        if item in target:
            target.remove(item)
        target.append(item)
        if len(target) > limit:
            del target[:-limit]

    @staticmethod
    def _extract_message_vuln_ids(content: str) -> List[Dict]:
        ids = re.findall(r"(CVE-\d{4}-\d+|CNVD-\d{4}-\d+|JVNVU?#?\d+)", content or "", re.I)
        return [{"vuln_id": item} for item in ids]

    def _extract_explicit_memory(self, state: SessionState, message: str, persist_only: bool = False) -> Optional[Dict]:
        normalized = message.strip()
        if not normalized:
            return None
        if not any(token in normalized for token in ["记住", "以后默认", "今后都按", "以后回答"]):
            return None
        memory_key = self._derive_memory_key(normalized)
        memory_value = {"text": normalized}
        summary_text = f"用户偏好：{normalized}"
        state.session_preferences[memory_key] = memory_value
        self._append_unique_item(state.session_preference_summaries, summary_text, limit=5)
        if persist_only:
            return None
        return {"memory_id": f"session:{state.session_id}:{memory_key}", "summary_text": summary_text}

    @staticmethod
    def _derive_memory_key(message: str) -> str:
        if "先给结论" in message:
            return "response_style"
        if "修复建议" in message:
            return "include_remediation"
        if any(token in message for token in ["CISA", "CVE", "NVD"]):
            return "preferred_sources"
        digest = hashlib.md5(message.encode("utf-8")).hexdigest()[:12]
        return f"preference_{digest}"
