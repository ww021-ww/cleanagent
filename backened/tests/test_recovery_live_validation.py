import asyncio
from pathlib import Path
from unittest.mock import patch

import main
from graph.controller import LangGraphController
from graph.nodes import extract_node, store_node
from graph.state import create_initial_state
from recovery_ab import build_variant_config, compare_results, summarize_results


class SourceExtractor:
    def extract(self, content, file_path):
        return [{"cve_id": "CVE-2026-1234", "description": content}]

    def calculate_confidence(self, data):
        return 0.8

class ExtractorConfig:
    def has_subtable(self, source):
        return False


class FakeExtractor:
    config_loader = ExtractorConfig()
    extractors = {"cve": SourceExtractor()}

    def identify_source(self, file_path, content):
        return "CVE"


class StorageProbe:
    db_reads = 0

    @property
    def db(self):
        self.db_reads += 1
        raise AssertionError("dry-run must not inspect the database")


class SuccessfulGraph:
    async def ainvoke(self, state, config=None):
        return {**state, "final_status": "success"}


def test_cli_exposes_dry_run_without_a_second_recovery_switch():
    default = main.parse_cli_args(["--file", "sample.json"])
    enabled = main.parse_cli_args(["--file", "sample.json", "--dry-run"])

    assert default.dry_run is False
    assert not hasattr(default, "agent_recovery")
    assert enabled.dry_run is True


def test_runtime_options_only_override_explicit_flags():
    config = {
        "processing": {"dry_run": False},
        "agentic": {"recovery": {"enabled": True}},
    }

    unchanged = main.apply_runtime_options(config, False)
    enabled = main.apply_runtime_options(config, True)

    assert unchanged["processing"]["dry_run"] is False
    assert unchanged["agentic"]["recovery"]["enabled"] is True
    assert enabled["processing"]["dry_run"] is True
    assert enabled["agentic"]["rag"]["enabled"] is False


def test_dry_run_extract_skips_database_deduplication():
    sample = Path(__file__).parent / "fixtures" / "recovery_cases.json"
    storage = StorageProbe()
    state = create_initial_state("task-1", str(sample))

    result = asyncio.run(
        extract_node(
            state,
            {
                "processing": {"dry_run": True},
                "_extractor": FakeExtractor(),
                "_storage": storage,
            },
        )
    )

    assert storage.db_reads == 0
    assert result["extracted_data"]["cve_id"] == "CVE-2026-1234"


def test_dry_run_store_returns_candidate_without_database_or_rag_writes():
    state = create_initial_state("task-1", "sample.json")
    state.update(
        source="CVE",
        cleaned_data={"cve_id": "CVE-2026-1234", "description": "safe"},
        quality_score=0.9,
    )

    result = asyncio.run(store_node(state, {"processing": {"dry_run": True}}))

    assert result["stored"] is False
    assert result["storage_status"] == "dry_run"
    assert result["final_status"] == "success"
    assert result["trace_events"][-1]["reason_code"] == "dry_run"


def test_controller_does_not_initialize_milvus_rag_in_dry_run():
    initialized = []

    def record_optional(cls, *args, label="", **kwargs):
        initialized.append(label)
        return None

    config = {
        "processing": {"dry_run": True},
        "agents": {"cleaner_validator": {"quality_threshold": 0.5}},
        "agentic": {
            "rag": {"enabled": True},
            "memory": {"enabled": False},
            "tools": {"enabled": False},
            "skills": {"enabled": False},
            "chat": {"enabled": False},
            "recovery": {"enabled": False},
        },
    }

    with patch("graph.controller._init_optional", side_effect=record_optional):
        LangGraphController(config)

    assert "RAGRetriever" not in initialized


def test_standalone_file_processing_counts_the_file_in_stats():
    controller = LangGraphController.__new__(LangGraphController)
    controller.graph = SuccessfulGraph()
    controller.stats = {
        "total": 0,
        "success": 0,
        "failed": 0,
        "low_quality": 0,
        "skipped": 0,
        "start_time": None,
        "end_time": None,
    }

    asyncio.run(controller.process_file("sample.json"))

    assert controller.get_stats()["total"] == 1
    assert controller.get_stats()["success_rate"] == 1.0


def test_ab_configs_are_isolated_and_force_side_effect_free_runs():
    base = {
        "processing": {"dry_run": False},
        "agentic": {
            "recovery": {"enabled": True},
            "memory": {"enabled": True},
        },
    }

    legacy = build_variant_config(base, recovery_enabled=False)
    agent = build_variant_config(base, recovery_enabled=True)

    assert base["processing"]["dry_run"] is False
    assert legacy["processing"]["dry_run"] is True
    assert agent["processing"]["dry_run"] is True
    assert legacy["agentic"]["recovery"]["enabled"] is False
    assert agent["agentic"]["recovery"]["enabled"] is True
    assert legacy["agentic"]["memory"]["enabled"] is False
    assert agent["agentic"]["memory"]["enabled"] is False
    assert legacy["agentic"]["rag"]["enabled"] is False
    assert agent["agentic"]["rag"]["enabled"] is False


def test_ab_report_exposes_quality_cost_and_unverified_recovery_proxy():
    legacy_results = [
        {
            "final_status": "success",
            "quality_score": 0.8,
            "trace_events": [{"node": "diagnose_failure"}],
            "verification": None,
            "llm_call_count": 0,
            "tool_call_count": 0,
            "step_count": 0,
        },
        {
            "final_status": "low_quality",
            "quality_score": 0.3,
            "trace_events": [{"node": "diagnose_failure"}],
            "llm_call_count": 0,
            "tool_call_count": 0,
            "step_count": 0,
        },
    ]
    agent_results = [
        {
            "final_status": "success",
            "quality_score": 0.9,
            "trace_events": [{"node": "diagnose_failure"}],
            "verification": {"status": "accepted"},
            "llm_call_count": 1,
            "tool_call_count": 1,
            "step_count": 1,
        },
        {
            "final_status": "low_quality",
            "quality_score": 0.4,
            "trace_events": [{"node": "diagnose_failure"}],
            "verification": {"status": "rejected"},
            "llm_call_count": 2,
            "tool_call_count": 1,
            "step_count": 2,
        },
    ]

    legacy = summarize_results(legacy_results, elapsed_seconds=2.0)
    agent = summarize_results(agent_results, elapsed_seconds=3.0)
    report = compare_results(legacy, agent)

    assert legacy == {
        "files": 2,
        "anomalies": 2,
        "successes": 1,
        "success_rate": 0.5,
        "low_quality": 1,
        "recovered": 1,
        "recovery_rate": 0.5,
        "unverified_recoveries": 1,
        "average_quality": 0.55,
        "llm_calls": 0,
        "tool_calls": 0,
        "average_steps": 0.0,
        "elapsed_seconds": 2.0,
    }
    assert agent["unverified_recoveries"] == 0
    assert agent["llm_calls"] == 3
    assert agent["tool_calls"] == 2
    assert report["delta"] == {
        "successes": 0,
        "success_rate": 0.0,
        "recovered": 0,
        "recovery_rate": 0.0,
        "unverified_recoveries": -1,
        "average_quality": 0.1,
        "llm_calls": 3,
        "tool_calls": 2,
        "elapsed_seconds": 1.0,
    }
