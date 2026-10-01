from datetime import datetime, timedelta
from pathlib import Path

import pytest

from config.field_config_loader import FieldConfigLoader
from database.manager import DatabaseManager
from database.reliability import ReviewTask, VectorIndexOutbox


@pytest.fixture
def manager(tmp_path):
    config_path = Path(__file__).parents[1] / "config" / "field_mappings.yaml"
    db = DatabaseManager(
        f"sqlite:///{tmp_path / 'reliability.db'}",
        FieldConfigLoader(str(config_path)),
    )
    yield db
    db.close()


def _review_payload(task_id="review-1"):
    return {
        "task_id": task_id,
        "source": "CVE",
        "vuln_id": "CVE-2026-1001",
        "file_path": "sample.json",
        "reason_code": "missing_required_evidence",
        "candidate_data": {"cveMetadata_cveId": "CVE-2026-1001"},
        "proposed_patches": [],
        "subtable_data": [],
    }


def test_enqueue_review_is_idempotent_by_task_id(manager):
    first = manager.reliability.enqueue_review(**_review_payload())
    second = manager.reliability.enqueue_review(**_review_payload())

    assert first["id"] == second["id"]
    with manager.Session() as session:
        assert session.query(ReviewTask).count() == 1


def test_claim_review_rejects_active_processing_task(manager):
    manager.reliability.enqueue_review(**_review_payload())
    claimed = manager.reliability.claim_review(
        task_id="review-1",
        reviewer="alice",
        note="checking",
        corrected_data={},
        lease_seconds=60,
    )

    duplicate = manager.reliability.claim_review(
        task_id="review-1",
        reviewer="bob",
        note="duplicate",
        corrected_data={},
        lease_seconds=60,
    )

    assert claimed["status"] == "processing"
    assert duplicate is None


def test_claim_review_reclaims_expired_processing_task(manager):
    manager.reliability.enqueue_review(**_review_payload())
    manager.reliability.claim_review(
        task_id="review-1",
        reviewer="alice",
        note="checking",
        corrected_data={},
        lease_seconds=60,
    )
    with manager.Session() as session:
        row = session.query(ReviewTask).filter_by(task_id="review-1").one()
        row.locked_at = datetime.utcnow() - timedelta(seconds=61)
        session.commit()

    reclaimed = manager.reliability.claim_review(
        task_id="review-1",
        reviewer="bob",
        note="recovered",
        corrected_data={"containers_cna_title": "fixed"},
        lease_seconds=60,
    )

    assert reclaimed["status"] == "processing"
    assert reclaimed["reviewer"] == "bob"


def test_upsert_with_outbox_commits_main_subtable_and_unique_job(manager):
    stored = manager.upsert_with_outbox(
        {"cveMetadata_cveId": "CVE-2026-1002"},
        "CVE",
        [{"cve_id": "CVE-2026-1002", "containers_cna_metrics_cvssV3_1_baseScore": 8.1}],
    )

    assert stored is True
    assert manager.get_record("CVE", "CVE-2026-1002")["cveMetadata_cveId"] == "CVE-2026-1002"
    with manager.Session() as session:
        assert session.query(manager.subtable_models["cve"]).count() == 1
        assert session.query(VectorIndexOutbox).count() == 1


def test_upsert_with_outbox_rolls_back_everything_on_outbox_failure(manager, monkeypatch):
    def fail_outbox(*_args, **_kwargs):
        raise RuntimeError("outbox unavailable")

    monkeypatch.setattr(manager, "_enqueue_outbox_in_session", fail_outbox)

    stored = manager.upsert_with_outbox(
        {"cveMetadata_cveId": "CVE-2026-1003"},
        "CVE",
        [{"cve_id": "CVE-2026-1003"}],
    )

    assert stored is False
    assert manager.get_record("CVE", "CVE-2026-1003") is None
    with manager.Session() as session:
        assert session.query(manager.subtable_models["cve"]).count() == 0
        assert session.query(VectorIndexOutbox).count() == 0


def test_review_approval_rolls_back_with_failed_store_transaction(manager, monkeypatch):
    manager.reliability.enqueue_review(**_review_payload())
    manager.reliability.claim_review(
        task_id="review-1",
        reviewer="alice",
        note="approved",
        corrected_data={},
        lease_seconds=60,
    )

    def fail_outbox(*_args, **_kwargs):
        raise RuntimeError("outbox unavailable")

    monkeypatch.setattr(manager, "_enqueue_outbox_in_session", fail_outbox)
    stored = manager.upsert_with_outbox(
        {"cveMetadata_cveId": "CVE-2026-1001"},
        "CVE",
        review_task_id="review-1",
    )

    assert stored is False
    assert manager.reliability.get_review("review-1")["status"] == "processing"
    assert manager.get_record("CVE", "CVE-2026-1001") is None


def test_new_upsert_resets_existing_outbox_job_to_pending(manager):
    payload = {"cveMetadata_cveId": "CVE-2026-1004"}
    assert manager.upsert_with_outbox(payload, "CVE") is True
    with manager.Session() as session:
        job = session.query(VectorIndexOutbox).one()
        job.status = "succeeded"
        job.attempt_count = 3
        session.commit()

    assert manager.upsert_with_outbox(payload, "CVE") is True

    with manager.Session() as session:
        jobs = session.query(VectorIndexOutbox).all()
        assert len(jobs) == 1
        assert jobs[0].status == "pending"
        assert jobs[0].attempt_count == 0
