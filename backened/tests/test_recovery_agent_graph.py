import asyncio
import time

from agent.recovery.guard import RecoveryActionGuard
from agent.recovery.models import (
    AuthorizedAction,
    RecoveryBudget,
    RecoveryDecision,
    ToolResult,
    VerificationResult,
)
from agent.recovery.tool_registry import RecoveryToolRegistry
from agent.recovery.verifier import EvidenceVerifier
from graph.builder import (
    build_vuln_processing_graph,
    route_after_clean,
    route_after_decision,
    route_after_diagnosis,
)
from graph.nodes import clean_validate_node
from graph.recovery_nodes import (
    decide_next_node,
    execute_action_node,
    guard_action_node,
    plan_recovery_node,
    verify_evidence_node,
)
from graph.state import create_initial_state


class FakePlanner:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def plan(self, context):
        self.calls += 1
        return self.result


class FakeFieldConfig:
    def get_id_field(self, source):
        return "cve_id"


class FakeCleaner:
    config_loader = FakeFieldConfig()

    def validate(self, data, source):
        errors = [] if data.get("description") else ["Missing required field: description"]
        return {"errors": errors, "warnings": [], "is_valid": not errors}

    def calculate_quality_score(self, data, validation, confidence):
        return 0.9 if validation["is_valid"] else 0.2


def config(planner=None, registry=None, budget=None, verifier=None):
    budget = budget or RecoveryBudget()
    registry = registry or RecoveryToolRegistry()
    return {
        "agents": {"cleaner_validator": {"quality_threshold": 0.5}},
        "agentic": {
            "recovery": {
                "enabled": True,
                "agent_loop_enabled": True,
                "tool_timeout_seconds": 0.2,
            },
            "reflection": {"enabled": True, "max_retries": 2},
        },
        "_recovery_budget": budget,
        "_recovery_registry": registry,
        "_recovery_guard": RecoveryActionGuard(budget),
        "_recovery_verifier": verifier or EvidenceVerifier(FakeFieldConfig()),
        "_recovery_planner": planner,
        "_cleaner": FakeCleaner(),
    }


def recovery_state():
    state = create_initial_state("task-1", "sample.json")
    state.update(
        source="CVE",
        raw_content="Description: validated buffer overflow description",
        cleaned_data={"cve_id": "CVE-2026-1234", "description": None},
        validation_result={
            "errors": ["Missing required field: description"],
            "warnings": [],
            "is_valid": False,
        },
        quality_score=0.2,
        extraction_confidence=0.8,
        failure_profile={
            "failure_type": "missing_required_fields",
            "missing_fields": ["description"],
            "quality_score": 0.2,
            "source": "CVE",
        },
        deadline_at=time.time() + 10,
    )
    return state


def test_normal_record_and_disabled_loop_never_enter_agent_planner():
    planner = FakePlanner(None)
    cfg = config(planner=planner)

    assert route_after_clean({"quality_score": 0.8}, cfg) == "store"
    cfg["agentic"]["recovery"]["agent_loop_enabled"] = False
    assert route_after_diagnosis({"retry_count": 0}, cfg) == "reflect"
    assert planner.calls == 0


def test_raw_text_evidence_routes_to_review_without_changing_description():
    planner = FakePlanner(
        RecoveryDecision(
            decision="CALL_TOOL",
            reason_code="recover_description",
            target_fields=["description"],
            tool_name="search_raw_text",
            tool_args={"field_hint": "description", "keywords": ["validated"]},
            expected_evidence="current file text",
        )
    )
    cfg = config(planner=planner)
    state = recovery_state()

    state = asyncio.run(plan_recovery_node(state, cfg))
    state = guard_action_node(state, cfg)
    state = asyncio.run(execute_action_node(state, cfg))
    state = verify_evidence_node(state, cfg)
    state = decide_next_node(state, cfg)

    assert planner.calls == 1
    assert state["cleaned_data"]["description"] is None
    assert state["verification"]["status"] == "review"
    assert state["final_decision"] == "REVIEW"
    assert route_after_decision(state, cfg) == "prepare_review"


class SlowRegistry(RecoveryToolRegistry):
    def invoke(self, name, args, context):
        time.sleep(0.05)
        return ToolResult(success=True, tool_name=name, data={})


class SlowPlanner:
    def plan(self, context):
        time.sleep(0.2)
        return RecoveryDecision(decision="ABORT", reason_code="too_late")


def test_planner_is_bounded_by_recovery_deadline():
    cfg = config(planner=SlowPlanner())
    state = recovery_state()
    state["deadline_at"] = time.time() + 0.1

    state = asyncio.run(plan_recovery_node(state, cfg))

    assert state["recovery_decision"]["decision"] == "STOP"
    assert state["recovery_decision"]["reason_code"] == "planner_timeout"
    assert decide_next_node(state, cfg)["final_decision"] == "ABORT"


def test_last_allowed_planner_call_can_still_execute_its_action():
    planner = FakePlanner(
        RecoveryDecision(
            decision="CALL_TOOL",
            reason_code="recover_description",
            target_fields=["description"],
            tool_name="search_raw_text",
            tool_args={"field_hint": "description", "keywords": []},
            expected_evidence="current file text",
        )
    )
    cfg = config(
        planner=planner,
        budget=RecoveryBudget(max_steps=3, max_tool_calls=5, max_llm_calls=3),
    )
    state = recovery_state()
    state.update(step_count=2, llm_call_count=2)

    state = asyncio.run(plan_recovery_node(state, cfg))
    state = guard_action_node(state, cfg)

    assert state["step_count"] == 3
    assert state["llm_call_count"] == 3
    assert state["pending_action"]["tool_name"] == "search_raw_text"


def test_tool_timeout_is_observed_then_replanned_within_budget():
    cfg = config(registry=SlowRegistry())
    cfg["agentic"]["recovery"]["tool_timeout_seconds"] = 0.01
    state = recovery_state()
    state.update(
        pending_action=AuthorizedAction(
            tool_name="search_raw_text",
            tool_args={"field_hint": "description", "keywords": []},
            target_fields=["description"],
        ).model_dump(),
        step_count=1,
        llm_call_count=1,
    )

    state = asyncio.run(execute_action_node(state, cfg))
    state = decide_next_node(state, cfg)

    assert state["observations"][-1]["success"] is False
    assert state["observations"][-1]["error"] == "tool_timeout"
    assert state["tool_call_count"] == 1
    assert state["final_decision"] == "REPLAN"


class RejectingVerifier:
    def verify(self, candidate, action, result, source):
        return VerificationResult(
            status="rejected",
            reason_code="authoritative_source_required",
            rejected_fields=action.target_fields,
        )


def test_rejected_authoritative_patch_is_not_merged_and_budget_aborts():
    cfg = config(verifier=RejectingVerifier())
    state = recovery_state()
    state.update(
        cleaned_data={"cve_id": "CVE-2026-1234", "cvss_score": 7.0},
        pending_action=AuthorizedAction(
            tool_name="search_raw_text",
            tool_args={"field_hint": "cvss_score", "keywords": []},
            target_fields=["cvss_score"],
        ).model_dump(),
        observations=[
            ToolResult(
                success=True,
                tool_name="search_raw_text",
                data={"cvss_score": 9.8},
                evidence="9.8",
                source_name="current_file",
                evidence_location="chars:2-5",
            ).model_dump()
        ],
        step_count=3,
    )

    state = verify_evidence_node(state, cfg)
    state = decide_next_node(state, cfg)

    assert state["cleaned_data"]["cvss_score"] == 7.0
    assert state["final_decision"] == "ABORT"
    assert route_after_decision(state, cfg) == "low_quality"


class FakeDataCleaner:
    def clean(self, data):
        return dict(data)


class LegacyCleaner(FakeCleaner):
    cleaner = FakeDataCleaner()

    def __init__(self):
        self.recovery_calls = 0

    def recover_fields(self, data, validation, source, raw_content):
        self.recovery_calls += 1
        return {**data, "description": "unverified"}, ["description"]


class LegacyToolAgent:
    def __init__(self):
        self.calls = 0

    def auto_fill(self, *args):
        self.calls += 1
        return {"description": "unverified"}


def test_agent_loop_skips_legacy_unverified_field_recovery():
    cleaner = LegacyCleaner()
    tools = LegacyToolAgent()
    cfg = config()
    cfg.update(_cleaner=cleaner, _tool_agent=tools)
    cfg["agentic"]["field_recovery"] = {"enabled": True}
    state = create_initial_state("task-1", "sample.json")
    state.update(
        source="CVE",
        raw_content="raw",
        extracted_data={"cve_id": "CVE-2026-1234"},
        extraction_strategy="hybrid",
        extraction_confidence=0.8,
    )

    result = asyncio.run(clean_validate_node(state, cfg))

    assert cleaner.recovery_calls == 0
    assert tools.calls == 0
    assert not result["cleaned_data"].get("description")


def test_legacy_hybrid_recovery_counts_its_llm_call():
    cleaner = LegacyCleaner()
    cfg = config()
    cfg.update(_cleaner=cleaner, _tool_agent=None)
    cfg["agentic"]["recovery"]["agent_loop_enabled"] = False
    cfg["agentic"]["field_recovery"] = {"enabled": True}
    state = create_initial_state("task-1", "sample.json")
    state.update(
        source="CVE",
        raw_content="raw",
        extracted_data={"cve_id": "CVE-2026-1234"},
        extraction_strategy="hybrid",
        extraction_confidence=0.8,
    )

    result = asyncio.run(clean_validate_node(state, cfg))

    assert result["llm_call_count"] == 1


def test_compiled_graph_contains_bounded_recovery_loop_nodes():
    nodes = build_vuln_processing_graph(config()).get_graph().nodes

    assert {
        "plan_recovery",
        "guard_action",
        "execute_action",
        "verify_evidence",
        "decide_next",
    }.issubset(nodes)
