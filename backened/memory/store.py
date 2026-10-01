import json
import logging
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from sqlalchemy import create_engine
from sqlalchemy import or_
from sqlalchemy.orm import sessionmaker

from memory.models import Base, MemoryWriteLog, ProjectMemorySource, UserLongTermMemory
from memory.vector_store import MemoryVectorStore


logger = logging.getLogger(__name__)


class LongTermMemoryStore:
    def __init__(self, db_uri: str, vector_enabled: bool = True):
        self.db_uri = db_uri
        connect_args = {}
        if db_uri and db_uri.startswith("mysql"):
            connect_args = {"connect_timeout": 5, "read_timeout": 10, "write_timeout": 10}
        self.engine = create_engine(db_uri, echo=False, pool_pre_ping=True, connect_args=connect_args) if db_uri else None
        self.Session = sessionmaker(bind=self.engine) if self.engine else None
        if self.engine:
            Base.metadata.create_all(self.engine)
        self.vector_store = MemoryVectorStore() if vector_enabled else None

    def upsert_memory(self, user_id: str, project_id: str, scope: str, memory_type: str, memory_key: str,
                      memory_value: Dict, summary_text: str, retrieval_text: str, confidence: float = 0.9,
                      source: str = "explicit") -> Optional[str]:
        if not self.Session:
            return None
        stored_project_id = "__global__" if scope == "user" else project_id
        payload = json.dumps(memory_value, ensure_ascii=False)
        session = self.Session()
        try:
            row = session.query(UserLongTermMemory).filter(
                UserLongTermMemory.user_id == user_id,
                UserLongTermMemory.project_id == stored_project_id,
                UserLongTermMemory.scope == scope,
                UserLongTermMemory.memory_key == memory_key,
            ).one_or_none()
            action = "update"
            if row is None:
                row = UserLongTermMemory(
                    memory_id=str(uuid.uuid4()),
                    user_id=user_id,
                    project_id=stored_project_id,
                    scope=scope,
                    memory_type=memory_type,
                    memory_key=memory_key,
                    memory_value=payload,
                    summary_text=summary_text,
                    retrieval_text=retrieval_text,
                    confidence=confidence,
                    source=source,
                    is_active=True,
                )
                session.add(row)
                action = "create"
            else:
                row.memory_type = memory_type
                row.memory_value = payload
                row.summary_text = summary_text
                row.retrieval_text = retrieval_text
                row.confidence = confidence
                row.source = source
                row.is_active = True
                row.updated_at = datetime.utcnow()
                row.last_used_at = datetime.utcnow()
            session.add(MemoryWriteLog(memory_id=row.memory_id, user_id=user_id, action=action, detail_text=summary_text))
            session.commit()
            if self.vector_store:
                self.vector_store.upsert_memory(row.memory_id, user_id, scope, memory_type, retrieval_text, summary_text)
            return row.memory_id
        except Exception as e:
            session.rollback()
            logger.warning(f"长期记忆写入失败: {e}")
            return None
        finally:
            session.close()

    def search_memories(self, query: str, user_id: str, project_id: str, scopes: Optional[List[str]] = None, top_k: int = 5) -> List[Dict]:
        if not self.Session:
            return []
        scopes = scopes or ["local", "project", "user"]
        vector_hits = self.vector_store.search(query, user_id, top_k=top_k * 2) if self.vector_store else []
        hit_ids = [item["memory_id"] for item in vector_hits]
        session = self.Session()
        try:
            query_builder = session.query(UserLongTermMemory).filter(
                UserLongTermMemory.user_id == user_id,
                UserLongTermMemory.is_active.is_(True),
                UserLongTermMemory.scope.in_(scopes),
                or_(
                    UserLongTermMemory.project_id == project_id,
                    UserLongTermMemory.project_id == "__global__",
                ),
            )
            if hit_ids:
                rows = query_builder.filter(UserLongTermMemory.memory_id.in_(hit_ids)).all()
            else:
                rows = query_builder.order_by(UserLongTermMemory.last_used_at.desc()).limit(top_k).all()
            score_map = {item["memory_id"]: item.get("distance") or 0 for item in vector_hits}
            results = []
            for row in rows:
                results.append({
                    "memory_id": row.memory_id,
                    "scope": row.scope,
                    "memory_type": row.memory_type,
                    "memory_key": row.memory_key,
                    "memory_value": json.loads(row.memory_value),
                    "summary_text": row.summary_text,
                    "confidence": row.confidence,
                    "score": score_map.get(row.memory_id, 0),
                })
            results.sort(key=lambda item: (self._scope_priority(item["scope"]), item["score"], item["confidence"]), reverse=True)
            return results[:top_k]
        finally:
            session.close()

    def deactivate_memory(self, memory_id: str):
        if not self.Session:
            return
        session = self.Session()
        try:
            row = session.query(UserLongTermMemory).filter(UserLongTermMemory.memory_id == memory_id).one_or_none()
            if row:
                row.is_active = False
                row.updated_at = datetime.utcnow()
                session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    def register_project_source(self, project_id: str, source_type: str, source_path: str, source_summary: str):
        if not self.Session:
            return
        session = self.Session()
        try:
            row = session.query(ProjectMemorySource).filter(
                ProjectMemorySource.project_id == project_id,
                ProjectMemorySource.source_type == source_type,
                ProjectMemorySource.source_path == source_path,
            ).one_or_none()
            if row is None:
                row = ProjectMemorySource(
                    project_id=project_id,
                    source_type=source_type,
                    source_path=source_path,
                    source_summary=source_summary,
                    is_active=True,
                )
                session.add(row)
            else:
                row.source_summary = source_summary
                row.is_active = True
                row.updated_at = datetime.utcnow()
            session.commit()
        except Exception as e:
            session.rollback()
            logger.debug(f"项目记忆来源登记失败: {e}")
        finally:
            session.close()

    @staticmethod
    def _scope_priority(scope: str) -> int:
        return {"local": 3, "project": 2, "user": 1}.get(scope, 0)
