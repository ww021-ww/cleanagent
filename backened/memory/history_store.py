import json
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from memory.models import Base, ChatMessage, ChatSession


class ConversationHistoryStore:
    def __init__(self, db_uri: str):
        connect_args = {}
        if db_uri and db_uri.startswith("mysql"):
            connect_args = {"connect_timeout": 5, "read_timeout": 10, "write_timeout": 10}
        self.engine = create_engine(db_uri, echo=False, pool_pre_ping=True, connect_args=connect_args) if db_uri else None
        self.Session = sessionmaker(bind=self.engine) if self.engine else None
        if self.engine:
            Base.metadata.create_all(self.engine)

    def create_session(self, user_id: str = "default", project_id: str = "cleanagent", title: str = "") -> Dict:
        if not self.Session:
            session_id = str(uuid.uuid4())
            return {
                "session_id": session_id,
                "user_id": user_id,
                "project_id": project_id,
                "title": title or "新对话",
                "summary": "",
                "last_user_message": "",
                "last_assistant_message": "",
                "created_at": datetime.utcnow().isoformat(),
                "updated_at": datetime.utcnow().isoformat(),
            }
        db = self.Session()
        try:
            row = ChatSession(
                session_id=str(uuid.uuid4()),
                user_id=user_id,
                project_id=project_id,
                title=(title or "新对话")[:200],
                is_active=True,
            )
            db.add(row)
            db.commit()
            return self._serialize_session(row)
        finally:
            db.close()

    def ensure_session(self, session_id: str, user_id: str = "default", project_id: str = "cleanagent", title: str = "") -> Dict:
        if not self.Session:
            return {
                "session_id": session_id,
                "user_id": user_id,
                "project_id": project_id,
                "title": title or "新对话",
                "summary": "",
                "last_user_message": "",
                "last_assistant_message": "",
            }
        db = self.Session()
        try:
            row = db.query(ChatSession).filter(ChatSession.session_id == session_id, ChatSession.user_id == user_id).one_or_none()
            if row is None:
                row = ChatSession(
                    session_id=session_id,
                    user_id=user_id,
                    project_id=project_id,
                    title=(title or "新对话")[:200],
                    is_active=True,
                )
                db.add(row)
                db.commit()
            elif not row.is_active:
                row.is_active = True
                row.updated_at = datetime.utcnow()
                db.commit()
            return self._serialize_session(row)
        finally:
            db.close()

    def get_session(self, session_id: str, user_id: str = "default") -> Optional[Dict]:
        if not self.Session:
            return None
        db = self.Session()
        try:
            row = db.query(ChatSession).filter(
                ChatSession.session_id == session_id,
                ChatSession.user_id == user_id,
                ChatSession.is_active.is_(True),
            ).one_or_none()
            return self._serialize_session(row) if row else None
        finally:
            db.close()

    def list_sessions(self, user_id: str = "default", project_id: str = "cleanagent", limit: int = 50) -> List[Dict]:
        if not self.Session:
            return []
        db = self.Session()
        try:
            rows = db.query(ChatSession).filter(
                ChatSession.user_id == user_id,
                ChatSession.project_id == project_id,
                ChatSession.is_active.is_(True),
            ).order_by(ChatSession.updated_at.desc()).limit(limit).all()
            return [self._serialize_session(row) for row in rows]
        finally:
            db.close()

    def list_messages(self, session_id: str, user_id: str = "default", limit: int = 200) -> List[Dict]:
        if not self.Session:
            return []
        db = self.Session()
        try:
            rows = db.query(ChatMessage).filter(
                ChatMessage.session_id == session_id,
                ChatMessage.user_id == user_id,
            ).order_by(ChatMessage.created_at.asc()).limit(limit).all()
            return [self._serialize_message(row) for row in rows]
        finally:
            db.close()

    def append_turn(self, session_id: str, user_id: str, project_id: str, user_message: str, assistant_message: str,
                    intent_type: str = "", summary: str = "") -> None:
        if not self.Session:
            return
        db = self.Session()
        try:
            row = db.query(ChatSession).filter(ChatSession.session_id == session_id, ChatSession.user_id == user_id).one_or_none()
            if row is None:
                row = ChatSession(
                    session_id=session_id,
                    user_id=user_id,
                    project_id=project_id,
                    title=self._derive_title(user_message),
                    is_active=True,
                )
                db.add(row)
                db.flush()
            if not row.title or row.title == "新对话":
                row.title = self._derive_title(user_message)
            row.summary = (summary or row.summary or "")[:1000]
            row.last_user_message = user_message[:1000]
            row.last_assistant_message = assistant_message[:2000]
            row.updated_at = datetime.utcnow()
            db.add(ChatMessage(
                session_id=session_id,
                user_id=user_id,
                role="user",
                content=user_message,
                intent_type=intent_type[:32],
                metadata_json="",
            ))
            db.add(ChatMessage(
                session_id=session_id,
                user_id=user_id,
                role="assistant",
                content=assistant_message,
                intent_type=intent_type[:32],
                metadata_json="",
            ))
            db.commit()
        finally:
            db.close()

    def rename_session(self, session_id: str, user_id: str, title: str) -> Optional[Dict]:
        if not self.Session:
            return None
        db = self.Session()
        try:
            row = db.query(ChatSession).filter(ChatSession.session_id == session_id, ChatSession.user_id == user_id).one_or_none()
            if row is None:
                return None
            row.title = (title or "新对话")[:200]
            row.updated_at = datetime.utcnow()
            db.commit()
            return self._serialize_session(row)
        finally:
            db.close()

    def delete_session(self, session_id: str, user_id: str) -> bool:
        if not self.Session:
            return False
        db = self.Session()
        try:
            row = db.query(ChatSession).filter(ChatSession.session_id == session_id, ChatSession.user_id == user_id).one_or_none()
            if row is None:
                return False
            row.is_active = False
            row.updated_at = datetime.utcnow()
            db.commit()
            return True
        finally:
            db.close()

    def hydrate_state(self, session_id: str, user_id: str = "default", limit: int = 20) -> Dict:
        session_info = self.get_session(session_id, user_id=user_id) or {}
        messages = self.list_messages(session_id, user_id=user_id, limit=limit)
        return {
            "session": session_info,
            "messages": messages,
        }

    @staticmethod
    def _derive_title(message: str) -> str:
        title = (message or "新对话").strip().replace("\n", " ")
        if len(title) > 18:
            title = title[:18].rstrip() + "..."
        return title or "新对话"

    @staticmethod
    def _serialize_session(row: ChatSession) -> Dict:
        return {
            "session_id": row.session_id,
            "user_id": row.user_id,
            "project_id": row.project_id,
            "title": row.title,
            "summary": row.summary or "",
            "last_user_message": row.last_user_message or "",
            "last_assistant_message": row.last_assistant_message or "",
            "created_at": row.created_at.isoformat() if row.created_at else "",
            "updated_at": row.updated_at.isoformat() if row.updated_at else "",
        }

    @staticmethod
    def _serialize_message(row: ChatMessage) -> Dict:
        return {
            "id": row.id,
            "session_id": row.session_id,
            "user_id": row.user_id,
            "role": row.role,
            "content": row.content,
            "intent_type": row.intent_type,
            "metadata": json.loads(row.metadata_json) if row.metadata_json else {},
            "created_at": row.created_at.isoformat() if row.created_at else "",
        }
