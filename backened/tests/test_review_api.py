from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from api.deps import get_processing_runtime
from api.routers.reviews import router
from api.runtime import ProcessingRuntime
from database.reliability import ReliabilityStore, ReviewTask


class FakeConfigLoader:
    def get_source_config(self, source):
        return {
            "id_field": "cve_id",
            "fields": [
                {"name": "cve_id", "required": True},
                {"name": "description", "required": True},
            ],
        }


class FakeCleaner:
    cleaner = SimpleNamespace(clean=lambda data: dict(data))

    def validate(self, data, source):
        errors = [] if data.get("description") else ["Missing required field: description"]
        return {"is_valid": not errors, "errors": errors, "warnings": []}


class FakeController:
    def __init__(self, session_factory):
        self.Session = session_factory
        self.fail_resume = False

    async def resume_review(self, task_id, review_input):
        if self.fail_resume:
            raise RuntimeError("checkpoint not found")
        status = "approved" if review_input["action"] == "approve" else "rejected"
        with self.Session() as session:
            row = session.query(ReviewTask).filter_by(task_id=task_id).one()
            row.status = status
            session.commit()
        return {"task_id": task_id, "final_status": status}


@pytest.fixture
def review_api(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'reviews.db'}")
    Session = sessionmaker(bind=engine)
    store = ReliabilityStore(Session)
    store.create_tables(engine)
    db = SimpleNamespace(reliability=store, config_loader=FakeConfigLoader())
    runtime = ProcessingRuntime(
        controller=FakeController(Session),
        db_manager=db,
        cleaner=FakeCleaner(),
    )
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_processing_runtime] = lambda: runtime
    monkeypatch.setenv("HIL_REVIEW_TOKEN", "review-secret")
    with TestClient(app) as client:
        yield client, runtime
    engine.dispose()


def _enqueue(runtime, task_id="review-1", candidate=None):
    return runtime.db_manager.reliability.enqueue_review(
        task_id=task_id,
        source="CVE",
        vuln_id="CVE-2026-3001",
        file_path="sample.json",
        reason_code="missing_evidence",
        candidate_data=candidate
        or {"cve_id": "CVE-2026-3001", "description": None},
        proposed_patches=[],
        subtable_data=[],
    )


def _auth():
    return {"Authorization": "Bearer review-secret"}


def test_list_and_detail_reviews_do_not_expose_raw_content(review_api):
    client, runtime = review_api
    _enqueue(
        runtime,
        candidate={
            "cve_id": "CVE-2026-3001",
            "description": None,
            "raw_content": "SECRET",
        },
    )

    listed = client.get("/api/v1/reviews").json()
    detail = client.get("/api/v1/reviews/review-1").json()

    assert "raw_content" not in listed["items"][0]["candidate_data"]
    assert "raw_content" not in detail["candidate_data"]
    assert "SECRET" not in str(listed) + str(detail)


def test_review_write_requires_configured_bearer_token(review_api):
    client, runtime = review_api
    _enqueue(runtime)

    missing = client.post("/api/v1/reviews/review-1/reject", json={"reviewer": "a"})
    wrong = client.post(
        "/api/v1/reviews/review-1/reject",
        headers={"Authorization": "Bearer wrong"},
        json={"reviewer": "a"},
    )

    assert missing.status_code == 401
    assert wrong.status_code == 401


def test_approve_rejects_protected_id_change_with_422(review_api):
    client, runtime = review_api
    _enqueue(runtime)

    response = client.post(
        "/api/v1/reviews/review-1/approve",
        headers=_auth(),
        json={
            "reviewer": "alice",
            "corrected_fields": {"cve_id": "CVE-2026-9999", "description": "ok"},
        },
    )

    assert response.status_code == 422
    assert runtime.db_manager.reliability.get_review("review-1")["status"] == "pending"


def test_approve_rejects_unknown_field_with_422(review_api):
    client, runtime = review_api
    _enqueue(runtime)

    response = client.post(
        "/api/v1/reviews/review-1/approve",
        headers=_auth(),
        json={"reviewer": "alice", "corrected_fields": {"made_up": "value"}},
    )

    assert response.status_code == 422
    assert runtime.db_manager.reliability.get_review("review-1")["status"] == "pending"


def test_duplicate_or_concurrent_approve_returns_409(review_api):
    client, runtime = review_api
    _enqueue(runtime)
    runtime.db_manager.reliability.claim_review(
        task_id="review-1",
        reviewer="first",
        note="",
        corrected_data={"description": "ok"},
        lease_seconds=60,
    )

    response = client.post(
        "/api/v1/reviews/review-1/approve",
        headers=_auth(),
        json={"reviewer": "second", "corrected_fields": {"description": "ok"}},
    )

    assert response.status_code == 409


def test_invalid_correction_returns_422_and_releases_claim(review_api):
    client, runtime = review_api
    _enqueue(runtime)

    response = client.post(
        "/api/v1/reviews/review-1/approve",
        headers=_auth(),
        json={"reviewer": "alice", "corrected_fields": {"description": ""}},
    )

    assert response.status_code == 422
    assert runtime.db_manager.reliability.get_review("review-1")["status"] == "pending"


def test_missing_checkpoint_returns_conflict_and_releases_claim(review_api):
    client, runtime = review_api
    _enqueue(runtime)
    runtime.controller.fail_resume = True

    response = client.post(
        "/api/v1/reviews/review-1/approve",
        headers=_auth(),
        json={"reviewer": "alice", "corrected_fields": {"description": "verified"}},
    )

    assert response.status_code == 409
    assert runtime.db_manager.reliability.get_review("review-1")["status"] == "pending"


def test_approve_resumes_graph_and_returns_final_status(review_api):
    client, runtime = review_api
    _enqueue(runtime)

    response = client.post(
        "/api/v1/reviews/review-1/approve",
        headers=_auth(),
        json={"reviewer": "alice", "corrected_fields": {"description": "verified"}},
    )

    assert response.status_code == 200
    assert response.json()["final_status"] == "approved"
    assert runtime.db_manager.reliability.get_review("review-1")["status"] == "approved"


def test_reject_resumes_graph_without_storing(review_api):
    client, runtime = review_api
    _enqueue(runtime)

    response = client.post(
        "/api/v1/reviews/review-1/reject",
        headers=_auth(),
        json={"reviewer": "bob", "note": "not enough evidence"},
    )

    assert response.status_code == 200
    assert response.json()["final_status"] == "rejected"
    assert runtime.db_manager.reliability.get_review("review-1")["status"] == "rejected"
