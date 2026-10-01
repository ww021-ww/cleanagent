import time

import pytest
from pydantic import ValidationError

from agent.recovery.models import (
    ActionRejection,
    AuthorizedAction,
    RecoveryBudget,
    RecoveryDecision,
    ToolResult,
    ToolSpec,
    VerificationResult,
)
from graph.state import create_initial_state


def test_recovery_contracts_are_strict_and_preserve_structured_actions():
    decision = RecoveryDecision(
        decision="CALL_TOOL",
        reason_code="missing_description",
        target_fields=["description"],
        tool_name="search_raw_text",
        tool_args={"field_hint": "description", "keywords": ["summary"]},
        expected_evidence="current_file_text",
    )
    spec = ToolSpec(
        name="search_raw_text",
        description="Search current input only",
        args_schema={"type": "object"},
        allowed_fields=["description"],
        external=False,
    )
    action = AuthorizedAction(
        tool_name="search_raw_text",
        tool_args=decision.tool_args,
        target_fields=decision.target_fields,
    )
    rejection = ActionRejection(reason_code="unknown_tool", details="not allowed")

    assert decision.tool_name == spec.name == action.tool_name
    assert rejection.reason_code == "unknown_tool"

    with pytest.raises(ValidationError):
        RecoveryDecision(**{**decision.model_dump(), "unexpected": True})


def test_tool_and_verification_results_reject_invalid_ranges():
    result = ToolResult(
        success=True,
        tool_name="search_raw_text",
        data={"description": "validated"},
        evidence="validated",
        source_name="current_file",
        evidence_location="chars:0-9",
        latency_ms=2.5,
    )
    verification = VerificationResult(
        status="accepted",
        reason_code="evidence_supported",
        accepted_patches=[],
        rejected_fields=[],
    )

    assert result.error is None
    assert verification.status == "accepted"

    with pytest.raises(ValidationError):
        ToolResult(**{**result.model_dump(), "latency_ms": -1})

    with pytest.raises(ValidationError):
        RecoveryBudget(max_steps=0)


def test_recovery_budget_defaults_and_stops_at_each_limit():
    budget = RecoveryBudget()
    deadline = time.time() + 10

    assert budget.model_dump() == {
        "max_steps": 3,
        "max_tool_calls": 5,
        "max_llm_calls": 2,
        "deadline_seconds": 30.0,
    }
    assert not budget.is_exhausted(2, 4, 1, deadline, now=deadline - 1)
    assert budget.is_exhausted(3, 0, 0, deadline, now=deadline - 1)
    assert budget.is_exhausted(0, 5, 0, deadline, now=deadline - 1)
    assert budget.is_exhausted(0, 0, 2, deadline, now=deadline - 1)
    assert budget.is_exhausted(0, 0, 0, deadline, now=deadline)


def test_initial_state_contains_empty_recovery_loop_state():
    state = create_initial_state("task-1", "sample.json")

    assert state["recovery_decision"] is None
    assert state["pending_action"] is None
    assert state["observations"] == []
    assert state["proposed_patches"] == []
    assert state["verification"] is None
    assert state["final_decision"] is None
    assert state["step_count"] == 0
    assert state["tool_call_count"] == 0
    assert state["llm_call_count"] == 0
    assert state["deadline_at"] == 0.0
