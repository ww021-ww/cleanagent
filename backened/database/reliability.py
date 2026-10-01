"""Durable review queue and vector-index outbox storage."""

import json
from datetime import datetime, timedelta

from sqlalchemy import (
    JSON,
    BigInteger,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
    or_,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import declarative_base


ReliabilityBase = declarative_base()
_ID_TYPE = BigInteger().with_variant(Integer, "sqlite")
_ERROR_LIMIT = 2000


class ReviewTask(ReliabilityBase):
    __tablename__ = "review_tasks"

    id = Column(_ID_TYPE, primary_key=True, autoincrement=True)
    task_id = Column(String(128), nullable=False, unique=True, index=True)
    status = Column(String(32), nullable=False, default="pending", index=True)
    source = Column(String(32), nullable=False)
    vuln_id = Column(String(128))
    file_path = Column(String(1024), nullable=False)
    reason_code = Column(String(128), nullable=False)
    candidate_data = Column(JSON, nullable=False, default=dict)
    proposed_patches = Column(JSON, nullable=False, default=list)
    subtable_data = Column(JSON, nullable=False, default=list)
    corrected_data = Column(JSON, nullable=False, default=dict)
    reviewer = Column(String(255))
    note = Column(Text)
    last_error = Column(Text)
    locked_at = Column(DateTime)
    reviewed_at = Column(DateTime)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


class VectorIndexOutbox(ReliabilityBase):
    __tablename__ = "vector_index_outbox"
    __table_args__ = (
        UniqueConstraint("source", "vuln_id", name="uq_vector_index_source_vuln"),
    )

    id = Column(_ID_TYPE, primary_key=True, autoincrement=True)
    source = Column(String(32), nullable=False)
    vuln_id = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False, default="pending", index=True)
    attempt_count = Column(Integer, nullable=False, default=0)
    next_retry_at = Column(DateTime)
    locked_at = Column(DateTime)
    last_error = Column(Text)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )


def _snapshot(value):
    """Return data safe for a SQL JSON column without retaining caller mutations."""
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def _as_dict(row):
    if row is None:
        return None
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}


class ReliabilityStore:
    def __init__(self, session_factory):
        self.Session = session_factory

    def create_tables(self, engine) -> None:
        ReliabilityBase.metadata.create_all(engine)

    def enqueue_review(
        self,
        *,
        task_id,
        source,
        vuln_id,
        file_path,
        reason_code,
        candidate_data,
        proposed_patches,
        subtable_data,
    ):
        values = {
            "source": source,
            "vuln_id": vuln_id,
            "file_path": file_path,
            "reason_code": reason_code,
            "candidate_data": _snapshot(candidate_data),
            "proposed_patches": _snapshot(proposed_patches),
            "subtable_data": _snapshot(subtable_data),
        }
        with self.Session() as session:
            row = session.query(ReviewTask).filter_by(task_id=task_id).first()
            if row is None:
                row = ReviewTask(task_id=task_id, **values)
                session.add(row)
            elif row.status == "pending":
                for key, value in values.items():
                    setattr(row, key, value)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                row = session.query(ReviewTask).filter_by(task_id=task_id).one()
            session.refresh(row)
            return _as_dict(row)

    def list_reviews(self, *, status=None, page=1, page_size=20):
        page = max(1, page)
        page_size = max(1, min(page_size, 100))
        with self.Session() as session:
            query = session.query(ReviewTask)
            if status:
                query = query.filter(ReviewTask.status == status)
            total = query.count()
            rows = (
                query.order_by(ReviewTask.created_at.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return {"items": [_as_dict(row) for row in rows], "total": total}

    def get_review(self, task_id):
        with self.Session() as session:
            return _as_dict(session.query(ReviewTask).filter_by(task_id=task_id).first())

    def claim_review(
        self,
        *,
        task_id,
        reviewer,
        note,
        corrected_data,
        lease_seconds,
    ):
        now = datetime.utcnow()
        expired = now - timedelta(seconds=lease_seconds)
        with self.Session() as session:
            changed = (
                session.query(ReviewTask)
                .filter(ReviewTask.task_id == task_id)
                .filter(
                    or_(
                        ReviewTask.status == "pending",
                        (ReviewTask.status == "processing")
                        & (ReviewTask.locked_at < expired),
                    )
                )
                .update(
                    {
                        ReviewTask.status: "processing",
                        ReviewTask.reviewer: reviewer,
                        ReviewTask.note: note,
                        ReviewTask.corrected_data: _snapshot(corrected_data),
                        ReviewTask.locked_at: now,
                        ReviewTask.last_error: None,
                    },
                    synchronize_session=False,
                )
            )
            session.commit()
            if changed != 1:
                return None
            return _as_dict(session.query(ReviewTask).filter_by(task_id=task_id).one())

    def release_review(self, task_id, error) -> None:
        with self.Session() as session:
            session.query(ReviewTask).filter_by(
                task_id=task_id,
                status="processing",
            ).update(
                {
                    ReviewTask.status: "pending",
                    ReviewTask.locked_at: None,
                    ReviewTask.last_error: str(error)[:_ERROR_LIMIT],
                },
                synchronize_session=False,
            )
            session.commit()

    def mark_review_rejected(self, task_id, reviewer, note) -> bool:
        with self.Session() as session:
            changed = session.query(ReviewTask).filter_by(
                task_id=task_id,
                status="processing",
            ).update(
                {
                    ReviewTask.status: "rejected",
                    ReviewTask.reviewer: reviewer,
                    ReviewTask.note: note,
                    ReviewTask.reviewed_at: datetime.utcnow(),
                    ReviewTask.locked_at: None,
                },
                synchronize_session=False,
            )
            session.commit()
            return changed == 1

    def claim_vector_jobs(self, *, limit, lease_seconds):
        now = datetime.utcnow()
        expired = now - timedelta(seconds=lease_seconds)
        claimed = []
        with self.Session() as session:
            ids = [
                row.id
                for row in (
                    session.query(VectorIndexOutbox)
                    .filter(
                        or_(
                            (VectorIndexOutbox.status == "pending")
                            & or_(
                                VectorIndexOutbox.next_retry_at.is_(None),
                                VectorIndexOutbox.next_retry_at <= now,
                            ),
                            (VectorIndexOutbox.status == "processing")
                            & (VectorIndexOutbox.locked_at < expired),
                        )
                    )
                    .order_by(VectorIndexOutbox.id)
                    .limit(limit)
                    .all()
                )
            ]
            for job_id in ids:
                changed = (
                    session.query(VectorIndexOutbox)
                    .filter(VectorIndexOutbox.id == job_id)
                    .filter(
                        or_(
                            (VectorIndexOutbox.status == "pending")
                            & or_(
                                VectorIndexOutbox.next_retry_at.is_(None),
                                VectorIndexOutbox.next_retry_at <= now,
                            ),
                            (VectorIndexOutbox.status == "processing")
                            & (VectorIndexOutbox.locked_at < expired),
                        )
                    )
                    .update(
                        {
                            VectorIndexOutbox.status: "processing",
                            VectorIndexOutbox.locked_at: now,
                        },
                        synchronize_session=False,
                    )
                )
                if changed == 1:
                    claimed.append(job_id)
            session.commit()
            rows = (
                session.query(VectorIndexOutbox)
                .filter(VectorIndexOutbox.id.in_(claimed))
                .all()
                if claimed
                else []
            )
            return [_as_dict(row) for row in rows]

    def mark_vector_success(self, job_id) -> None:
        with self.Session() as session:
            session.query(VectorIndexOutbox).filter_by(id=job_id).update(
                {
                    VectorIndexOutbox.status: "succeeded",
                    VectorIndexOutbox.locked_at: None,
                    VectorIndexOutbox.last_error: None,
                },
                synchronize_session=False,
            )
            session.commit()

    def mark_vector_failure(
        self,
        *,
        job_id,
        error,
        max_attempts,
        retry_base_seconds,
        retry_max_seconds,
    ) -> None:
        with self.Session() as session:
            row = session.query(VectorIndexOutbox).filter_by(id=job_id).one()
            row.attempt_count += 1
            row.last_error = str(error)[:_ERROR_LIMIT]
            row.locked_at = None
            if row.attempt_count >= max_attempts:
                row.status = "failed"
                row.next_retry_at = None
            else:
                delay = min(
                    retry_base_seconds * (2 ** (row.attempt_count - 1)),
                    retry_max_seconds,
                )
                row.status = "pending"
                row.next_retry_at = datetime.utcnow() + timedelta(seconds=delay)
            session.commit()
