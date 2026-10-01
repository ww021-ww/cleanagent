from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, UniqueConstraint
try:
    from sqlalchemy.orm import declarative_base
except ImportError:
    from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class UserLongTermMemory(Base):
    __tablename__ = "user_long_term_memory"
    __table_args__ = (
        UniqueConstraint("user_id", "project_id", "scope", "memory_key", name="uq_user_project_scope_key"),
        {"extend_existing": True},
    )

    id = Column(Integer, primary_key=True, autoincrement=True)
    memory_id = Column(String(64), nullable=False, unique=True, index=True)
    user_id = Column(String(64), nullable=False, index=True)
    project_id = Column(String(128), nullable=False, index=True)
    scope = Column(String(16), nullable=False, index=True)
    memory_type = Column(String(32), nullable=False, index=True)
    memory_key = Column(String(128), nullable=False, index=True)
    memory_value = Column(Text, nullable=False)
    summary_text = Column(Text, nullable=False)
    retrieval_text = Column(Text, nullable=False)
    confidence = Column(Float, nullable=False, default=0.9)
    source = Column(String(32), nullable=False, default="explicit")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_used_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class MemoryWriteLog(Base):
    __tablename__ = "memory_write_log"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    memory_id = Column(String(64), nullable=False, index=True)
    user_id = Column(String(64), nullable=False, index=True)
    action = Column(String(32), nullable=False)
    detail_text = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class ProjectMemorySource(Base):
    __tablename__ = "project_memory_source"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(String(128), nullable=False, index=True)
    source_type = Column(String(32), nullable=False)
    source_path = Column(String(512), nullable=False)
    source_summary = Column(Text, nullable=False)
    is_active = Column(Boolean, nullable=False, default=True)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class ChatSession(Base):
    __tablename__ = "chat_session"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), nullable=False, unique=True, index=True)
    user_id = Column(String(64), nullable=False, index=True)
    project_id = Column(String(128), nullable=False, index=True)
    title = Column(String(200), nullable=False, default="新对话")
    summary = Column(Text, nullable=False, default="")
    last_user_message = Column(Text, nullable=False, default="")
    last_assistant_message = Column(Text, nullable=False, default="")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class ChatMessage(Base):
    __tablename__ = "chat_message"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(64), nullable=False, index=True)
    user_id = Column(String(64), nullable=False, index=True)
    role = Column(String(16), nullable=False)
    content = Column(Text, nullable=False)
    intent_type = Column(String(32), nullable=False, default="")
    metadata_json = Column(Text, nullable=False, default="")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
