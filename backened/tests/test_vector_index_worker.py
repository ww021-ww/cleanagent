import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from config.field_config_loader import FieldConfigLoader
from database.manager import DatabaseManager
from database.reliability import VectorIndexOutbox
from graph.nodes import store_node
from graph.state import create_initial_state
from rag.retriever import RAGRetriever
from workers.vector_index_worker import VectorIndexWorker


class FakeRAG:
    def __init__(self, error=None):
        self.error = error
        self.calls = []

    def index_vulnerability(self, data, source):
        self.calls.append((dict(data), source))
        if self.error:
            raise self.error


@pytest.fixture
def manager(tmp_path):
    config_path = Path(__file__).parents[1] / "config" / "field_mappings.yaml"
    db = DatabaseManager(
        f"sqlite:///{tmp_path / 'worker.db'}",
        FieldConfigLoader(str(config_path)),
    )
    yield db
    db.close()


def _config(max_attempts=3):
    return {
        "agentic": {
            "vector_outbox": {
                "batch_size": 10,
                "poll_seconds": 0.01,
                "lease_seconds": 60,
                "max_attempts": max_attempts,
                "retry_base_seconds": 2,
                "retry_max_seconds": 30,
            }
        }
    }


def _insert(manager, vuln_id="CVE-2026-4001"):
    assert manager.upsert_with_outbox(
        {
            "cveMetadata_cveId": vuln_id,
            "containers_cna_title": "Buffer overflow",
            "containers_cna_descriptions_value": "Verified vulnerability description",
        },
        "CVE",
    )


def test_worker_indexes_latest_mysql_record_and_marks_success(manager):
    _insert(manager)
    rag = FakeRAG()

    result = VectorIndexWorker(manager, rag, _config()).run_once()

    assert result == {"claimed": 1, "succeeded": 1, "failed": 0}
    assert rag.calls[0][0]["vuln_id"] == "CVE-2026-4001"
    assert rag.calls[0][0]["description"] == "Verified vulnerability description"
    with manager.Session() as session:
        assert session.query(VectorIndexOutbox).one().status == "succeeded"


def test_worker_records_failure_and_exponential_retry(manager):
    _insert(manager)
    rag = FakeRAG(RuntimeError("milvus unavailable"))

    result = VectorIndexWorker(manager, rag, _config()).run_once()

    with manager.Session() as session:
        row = session.query(VectorIndexOutbox).one()
        delay = (row.next_retry_at - datetime.utcnow()).total_seconds()
        assert row.status == "pending"
        assert row.attempt_count == 1
        assert 0 < delay <= 2
        assert "milvus unavailable" in row.last_error
    assert result == {"claimed": 1, "succeeded": 0, "failed": 1}


def test_worker_stops_retrying_at_max_attempts(manager):
    _insert(manager)
    rag = FakeRAG(RuntimeError("still unavailable"))
    worker = VectorIndexWorker(manager, rag, _config(max_attempts=2))
    worker.run_once()
    with manager.Session() as session:
        row = session.query(VectorIndexOutbox).one()
        row.next_retry_at = datetime.utcnow() - timedelta(seconds=1)
        session.commit()

    worker.run_once()
    third = worker.run_once()

    with manager.Session() as session:
        row = session.query(VectorIndexOutbox).one()
        assert row.status == "failed"
        assert row.attempt_count == 2
    assert len(rag.calls) == 2
    assert third["claimed"] == 0


def test_worker_reclaims_expired_processing_job(manager):
    _insert(manager)
    with manager.Session() as session:
        row = session.query(VectorIndexOutbox).one()
        row.status = "processing"
        row.locked_at = datetime.utcnow() - timedelta(seconds=61)
        session.commit()

    result = VectorIndexWorker(manager, FakeRAG(), _config()).run_once()

    assert result["succeeded"] == 1
    with manager.Session() as session:
        assert session.query(VectorIndexOutbox).one().status == "succeeded"


def test_store_node_does_not_call_milvus_inline():
    class FakeDB:
        config_loader = SimpleNamespace(
            get_source_config=lambda source: {"id_field": "cve_id"}
        )

        def upsert_with_outbox(self, data, source, subtable_records=None, review_task_id=None):
            return True

    rag = FakeRAG(AssertionError("Milvus must be handled by the worker"))
    state = create_initial_state("task-store", "sample.json")
    state.update(
        source="CVE",
        cleaned_data={"cve_id": "CVE-2026-4002", "description": "valid"},
        quality_score=0.9,
    )
    config = {
        "_storage": SimpleNamespace(db=FakeDB()),
        "_rag": rag,
        "_memory": None,
        "agents": {"storage": {"skip_html_if_json_processed": False}},
        "agentic": {"smart_merge": {"enabled": False}},
    }

    result = asyncio.run(store_node(state, config))

    assert result["final_status"] == "success"
    assert result["storage_status"] == "success_pending_index"
    assert rag.calls == []


def test_index_vulnerability_raises_when_rag_is_disabled():
    rag = object.__new__(RAGRetriever)
    rag.enabled = False
    rag._client = None

    with pytest.raises(RuntimeError, match="disabled"):
        rag.index_vulnerability({"vuln_id": "CVE-2026-4003", "description": "x"}, "cve")
