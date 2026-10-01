import asyncio

from graph.builder import (
    build_vuln_processing_graph,
    route_after_clean,
    route_after_diagnosis,
)
from graph.nodes import mark_low_quality_node, store_node
from graph.recovery_nodes import diagnose_failure_node
from graph.state import create_initial_state


def base_config():
    return {
        "agents": {"cleaner_validator": {"quality_threshold": 0.5}},
        "agentic": {
            "recovery": {"enabled": True},
        },
    }


def test_quality_routes_normal_records_to_store_and_anomalies_to_diagnosis():
    assert route_after_clean(
        {"quality_score": 0.5, "validation_result": {"is_valid": True}},
        base_config(),
    ) == "store"
    assert (
        route_after_clean({"quality_score": 0.49}, base_config())
        == "diagnose_failure"
    )


def test_validation_error_cannot_be_hidden_by_a_high_quality_score():
    state = {"quality_score": 0.9, "validation_result": {"is_valid": False}}

    assert route_after_clean(state, base_config()) == "diagnose_failure"


def test_diagnosed_anomaly_enters_constrained_recovery():
    assert route_after_diagnosis({}, base_config()) == "plan_recovery"


def test_disabled_recovery_routes_to_low_quality():
    config = base_config()
    config["agentic"]["recovery"]["enabled"] = False

    assert route_after_clean({"quality_score": 0.2}, config) == "low_quality"


def test_initial_state_contains_recovery_defaults():
    state = create_initial_state("task-1", "sample.json")

    assert state["failure_profile"] is None
    assert state["trace_events"] == []


def test_diagnosis_node_records_profile_without_raw_content_in_trace():
    state = create_initial_state("task-1", "sample.json")
    state.update(
        {
            "source": "CVE",
            "raw_content": "SECRET_RAW_CONTENT",
            "cleaned_data": {"cve_id": "CVE-2026-1234"},
            "validation_result": {
                "errors": ["Missing required field: description"],
                "warnings": [],
                "is_valid": False,
            },
            "quality_score": 0.3,
        }
    )

    result = diagnose_failure_node(state, {})

    assert result["failure_profile"]["failure_type"] == "missing_required_fields"
    assert result["trace_events"][-1]["node"] == "diagnose_failure"
    assert result["trace_events"][-1]["reason_code"] == "missing_required_fields"
    assert "SECRET_RAW_CONTENT" not in str(result["trace_events"])


def test_low_quality_appends_bounded_decision_trace():
    state = create_initial_state("task-1", "sample.json")
    state.update({"source": "CVE", "quality_score": 0.2})
    aborted = mark_low_quality_node(state, {})

    assert aborted["trace_events"][-1]["decision"] == "ABORT"


class FakeConfigLoader:
    def get_source_config(self, source):
        return {"id_field": "cve_id"}


class FakeDB:
    config_loader = FakeConfigLoader()

    def upsert_with_outbox(self, data, source, subtable_records=None, review_task_id=None):
        return True


class FakeStorage:
    db = FakeDB()


def test_successful_store_appends_pass_trace():
    state = create_initial_state("task-1", "sample.json")
    state.update(
        {
            "source": "CVE",
            "cleaned_data": {"cve_id": "CVE-2026-1234"},
            "quality_score": 0.8,
        }
    )
    config = {
        "_storage": FakeStorage(),
        "agents": {"storage": {"skip_html_if_json_processed": False}},
        "agentic": {},
    }

    result = asyncio.run(store_node(state, config))

    assert result["final_status"] == "success"
    assert result["trace_events"][-1]["decision"] == "PASS"
    assert result["trace_events"][-1]["reason_code"] == "storage_success"


def test_compiled_graph_contains_diagnosis_node():
    graph = build_vuln_processing_graph(base_config())

    assert "diagnose_failure" in graph.get_graph().nodes
