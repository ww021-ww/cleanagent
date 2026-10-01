import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SessionState:
    session_id: str
    user_id: str = "default"
    project_id: str = "cleanagent"
    active_vuln_id: str = ""
    active_entities: Dict[str, Any] = field(default_factory=dict)
    active_filters: Dict[str, Any] = field(default_factory=dict)
    session_preferences: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    session_preference_summaries: List[str] = field(default_factory=list)
    current_task: str = ""
    task_stage: str = ""
    completed_steps: List[str] = field(default_factory=list)
    open_questions: List[str] = field(default_factory=list)
    next_actions: List[str] = field(default_factory=list)
    last_intent: str = ""
    last_result_ids: List[str] = field(default_factory=list)
    last_result_preview: List[Dict[str, Any]] = field(default_factory=list)
    last_result_payload: Dict[str, Any] = field(default_factory=dict)
    last_result_type: str = ""
    last_external_sources: List[str] = field(default_factory=list)
    messages_window: List[Dict[str, Any]] = field(default_factory=list)
    compressed_context: str = ""
    last_answer_text: str = ""
    last_answer_mode: str = ""
    conversation_summary: str = ""
    updated_at: float = field(default_factory=time.time)

    def touch(self):
        self.updated_at = time.time()

    def clear_active_context(self):
        self.active_vuln_id = ""
        self.active_entities = {}
        self.active_filters = {}
        self.touch()


class SessionMemoryStore:
    def __init__(self, ttl_seconds: int = 3600, max_sessions: int = 200):
        self.ttl_seconds = ttl_seconds
        self.max_sessions = max_sessions
        self._sessions: Dict[str, SessionState] = {}

    def get_or_create(self, session_id: str, user_id: str = "default", project_id: str = "cleanagent") -> SessionState:
        self._cleanup_expired()
        state = self._sessions.get(session_id)
        if state is None:
            if len(self._sessions) >= self.max_sessions:
                self._evict_oldest()
            state = SessionState(session_id=session_id, user_id=user_id, project_id=project_id)
            self._sessions[session_id] = state
        else:
            state.user_id = user_id or state.user_id
            state.project_id = project_id or state.project_id
            state.touch()
        return state

    def get(self, session_id: str) -> Optional[SessionState]:
        self._cleanup_expired()
        state = self._sessions.get(session_id)
        if state:
            state.touch()
        return state

    def update(self, state: SessionState):
        state.touch()
        self._sessions[state.session_id] = state
        self._cleanup_expired()

    def delete(self, session_id: str):
        self._sessions.pop(session_id, None)

    def _cleanup_expired(self):
        now = time.time()
        expired = [sid for sid, state in self._sessions.items() if now - state.updated_at > self.ttl_seconds]
        for sid in expired:
            self._sessions.pop(sid, None)

    def _evict_oldest(self):
        if not self._sessions:
            return
        oldest_session_id = min(self._sessions.items(), key=lambda item: item[1].updated_at)[0]
        self._sessions.pop(oldest_session_id, None)
