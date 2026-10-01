from types import SimpleNamespace

import pytest
from langgraph.checkpoint.memory import InMemorySaver

import graph.builder as builder
from graph.checkpoint import open_checkpointer
from graph.controller import LangGraphController
from graph.state import create_initial_state


class FakeConfigLoader:
    def get_source_config(self, source):
        return {
            "id_field": "cve_id",
            "fields": [
                {"name": "cve_id", "required": True},
                {"name": "description", "required": True},
            ],
        }


class FakeReliability:
    def __init__(self):
        self.rows = {}

    def enqueue_review(self, **payload):
        self.rows.setdefault(payload["task_id"], {**payload, "status": "pending"})
        return self.rows[payload["task_id"]]

    def claim(self, task_id):
        self.rows[task_id]["status"] = "processing"

    def mark_review_rejected(self, task_id, reviewer, note):
        if self.rows[task_id]["status"] != "processing":
            return False
        self.rows[task_id].update(status="rejected", reviewer=reviewer, note=note)
        return True


class FakeDB:
    def __init__(self):
        self.config_loader = FakeConfigLoader()
        self.reliability = FakeReliability()
        self.stored = []

    def upsert(self, *_args, **_kwargs):
        raise AssertionError("review storage must use the atomic outbox boundary")

    def upsert_with_outbox(
        self, data, source, subtable_records=None, review_task_id=None
    ):
        if review_task_id:
            row = self.reliability.rows[review_task_id]
            assert row["status"] == "processing"
            row["status"] = "approved"
        self.stored.append(
            {
                "data": dict(data),
                "source": source,
                "subtable_records": list(subtable_records or []),
                "review_task_id": review_task_id,
            }
        )
        return True


class FakeCleaner:
    config_loader = FakeConfigLoader()
    cleaner = SimpleNamespace(clean=lambda data: dict(data))

    def validate(self, data, source):
        errors = [] if data.get("description") else ["Missing required field: description"]
        return {"is_valid": not errors, "errors": errors, "warnings": []}

    def calculate_quality_score(self, data, validation, confidence):
        return 0.9 if validation["is_valid"] else 0.1


def _config(db, *, dry_run=False):
    return {
        "processing": {"dry_run": dry_run},
        "agents": {
            "cleaner_validator": {"quality_threshold": 0.5},
            "storage": {"skip_html_if_json_processed": False},
        },
        "agentic": {
            "recovery": {"enabled": True},
            "smart_merge": {"enabled": False},
        },
        "_storage": SimpleNamespace(db=db),
        "_cleaner": FakeCleaner(),
        "_memory": None,
        "_rag": None,
    }


def _patch_review_pipeline(monkeypatch):
    async def extract(state, config):
        return {
            **state,
            "source": "CVE",
            "raw_content": "SECRET_RAW_CONTENT",
            "extracted_data": {"cve_id": "CVE-2026-2001"},
            "extraction_confidence": 0.8,
        }

    async def clean(state, config):
        return {
            **state,
            "cleaned_data": {"cve_id": "CVE-2026-2001", "description": None},
            "cleaned_subtable_data": [],
            "validation_result": {
                "is_valid": False,
                "errors": ["Missing required field: description"],
                "warnings": [],
            },
            "quality_score": 0.1,
        }

    def diagnose(state, config):
        return {**state, "failure_profile": {"failure_type": "missing_evidence"}}

    async def plan(state, config):
        return {
            **state,
            "recovery_decision": {
                "decision": "REVIEW",
                "reason_code": "missing_authoritative_evidence",
            },
        }

    def decide(state, config):
        return {**state, "final_decision": "REVIEW"}

    monkeypatch.setattr(builder, "extract_node", extract)
    monkeypatch.setattr(builder, "clean_validate_node", clean)
    monkeypatch.setattr(builder, "diagnose_failure_node", diagnose)
    monkeypatch.setattr(builder, "plan_recovery_node", plan)
    monkeypatch.setattr(builder, "decide_next_node", decide)


async def _start_review(monkeypatch, db, task_id, checkpointer):
    _patch_review_pipeline(monkeypatch)
    graph = builder.build_vuln_processing_graph(_config(db), checkpointer=checkpointer)
    run_config = {"configurable": {"thread_id": task_id}}
    result = await graph.ainvoke(create_initial_state(task_id, "sample.json"), run_config)
    return graph, run_config, result


@pytest.mark.asyncio
async def test_review_decision_interrupts_without_storing_raw_content(monkeypatch):
    db = FakeDB()
    graph, run_config, result = await _start_review(
        monkeypatch, db, "task-interrupt", InMemorySaver()
    )

    assert "__interrupt__" in result
    assert db.stored == []
    assert "raw_content" not in db.reliability.rows["task-interrupt"]["candidate_data"]
    assert (await graph.aget_state(run_config)).values["raw_content"] is None


@pytest.mark.asyncio
async def test_approved_review_resumes_same_thread_and_stores(monkeypatch):
    db = FakeDB()
    graph, _, _ = await _start_review(
        monkeypatch, db, "task-approve", InMemorySaver()
    )
    db.reliability.claim("task-approve")
    controller = object.__new__(LangGraphController)
    controller.graph = graph

    result = await controller.resume_review(
        "task-approve",
        {
            "action": "approve",
            "reviewer": "alice",
            "note": "evidence checked",
            "corrected_fields": {"description": "verified description"},
        },
    )

    assert result["final_status"] == "success"
    assert db.stored[0]["review_task_id"] == "task-approve"
    assert db.stored[0]["data"]["description"] == "verified description"
    assert db.reliability.rows["task-approve"]["status"] == "approved"


@pytest.mark.asyncio
async def test_rejected_review_resumes_and_ends_without_storage(monkeypatch):
    db = FakeDB()
    graph, _, _ = await _start_review(
        monkeypatch, db, "task-reject", InMemorySaver()
    )
    db.reliability.claim("task-reject")
    controller = object.__new__(LangGraphController)
    controller.graph = graph

    result = await controller.resume_review(
        "task-reject",
        {"action": "reject", "reviewer": "bob", "note": "insufficient evidence"},
    )

    assert result["final_status"] == "rejected"
    assert db.stored == []
    assert db.reliability.rows["task-reject"]["status"] == "rejected"


@pytest.mark.asyncio
async def test_checkpoint_reopens_and_resumes_by_thread_id(monkeypatch, tmp_path):
    db = FakeDB()
    checkpoint_path = str(tmp_path / "checkpoints.sqlite")
    _patch_review_pipeline(monkeypatch)
    run_config = {"configurable": {"thread_id": "task-restart"}}

    async with open_checkpointer(checkpoint_path) as saver:
        graph = builder.build_vuln_processing_graph(_config(db), checkpointer=saver)
        result = await graph.ainvoke(
            create_initial_state("task-restart", "sample.json"), run_config
        )
        assert "__interrupt__" in result

    db.reliability.claim("task-restart")
    async with open_checkpointer(checkpoint_path) as saver:
        graph = builder.build_vuln_processing_graph(_config(db), checkpointer=saver)
        controller = object.__new__(LangGraphController)
        controller.graph = graph
        result = await controller.resume_review(
            "task-restart",
            {
                "action": "approve",
                "reviewer": "alice",
                "corrected_fields": {"description": "verified after restart"},
            },
        )

    assert result["final_status"] == "success"
    assert db.stored[0]["data"]["description"] == "verified after restart"


@pytest.mark.asyncio
async def test_dry_run_records_review_without_persistent_interrupt(monkeypatch):
    db = FakeDB()
    _patch_review_pipeline(monkeypatch)
    graph = builder.build_vuln_processing_graph(_config(db, dry_run=True))

    result = await graph.ainvoke(
        create_initial_state("task-dry", "sample.json"),
        {"configurable": {"thread_id": "task-dry"}},
    )

    assert "__interrupt__" not in result
    assert result["final_status"] == "review_pending"
    assert db.reliability.rows == {}
    assert db.stored == []
