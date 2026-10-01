from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import get_db_uri
from fastapi import HTTPException, Request


engine = None
SessionLocal = None
_cached_db_uri = None


def _create_session_factory():
    global engine, SessionLocal, _cached_db_uri
    db_uri = get_db_uri()
    if not db_uri:
        raise RuntimeError('DB_URI 未配置')
    if SessionLocal is not None and _cached_db_uri == db_uri:
        return SessionLocal
    connect_args = {}
    if db_uri.startswith('mysql'):
        connect_args = {
            'connect_timeout': 5,
            'read_timeout': 10,
            'write_timeout': 10,
        }
    engine = create_engine(db_uri, echo=False, pool_pre_ping=True, connect_args=connect_args)
    SessionLocal = sessionmaker(bind=engine)
    _cached_db_uri = db_uri
    return SessionLocal


def get_db_session():
    session_factory = _create_session_factory()
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


def get_processing_runtime(request: Request):
    runtime = getattr(request.app.state, "processing_runtime", None)
    if runtime is None:
        raise HTTPException(status_code=503, detail="Processing runtime unavailable")
    return runtime
