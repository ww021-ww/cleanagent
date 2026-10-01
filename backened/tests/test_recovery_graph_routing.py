import asyncio

from graph.builder import (
    build_vuln_processing_graph,
    route_after_clean,
    route_after_diagnosis,
)
from graph.nodes import mark_low_quality_node, reflect_node, store_node
from graph.recovery_nodes import diagnose_failure_node
from graph.state import create_initial_state


def base_config(max_retries=2):
    return {
        "agents": {"cleaner_validator": {"quality_threshold": 0.5}},
        "agentic": {
            "recovery": {"enabled": True},
            "reflection": {"enabled": True, "max_retries": max_retries}
        },
    }


def test_quality_routes_normal_records_to_store_and_anomalies_to_diagnosis():
    assert route_after_clean({"quality_score": 0.5}, base_config()) == "store"
    assert (
        route_after_clean({"quality_score": 0.49}, base_config())
        == "diagnose_failure"
    )


def test_diagnosed_anomaly_respects_existing_retry_budget():
    assert route_after_diagnosis({"retry_count": 0}, base_config()) == "reflect"
    assert route_after_diagnosis({"retry_count": 2}, base_config()) == "low_quality"


def test_disabled_recovery_keeps_legacy_quality_routing():
    config = base_config()
    config["agentic"]["recovery"]["enabled"] = False

    assert route_after_clean({"quality_score": 0.2, "retry_count": 0}, config) == "reflect"


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


def test_reflect_and_low_quality_append_bounded_decision_trace():
    state = create_initial_state("task-1", "sample.json")
    state.update({"source": "CVE", "quality_score": 0.2, "extraction_strategy": "rule"})

    reflected = reflect_node(state, base_config())
    aborted = mark_low_quality_node(state, {})

    assert reflected["trace_events"][-1]["decision"] == "REPLAN"
    assert aborted["trace_events"][-1]["decision"] == "ABORT"


class FakeConfigLoader:
    def get_source_config(self, source):
        return {"id_field": "cve_id"}


class FakeDB:
    config_loader = FakeConfigLoader()

    def upsert(self, data, source):
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
