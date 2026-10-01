"""Deterministic diagnosis and the bounded recovery Agent loop."""
import asyncio
import time
from typing import Any, Dict, List, Optional

from agent.recovery.diagnosis import diagnose_failure
from agent.recovery.models import (
    ActionRejection,
    AuthorizedAction,
    RecoveryBudget,
    RecoveryDecision,
    ToolResult,
    TraceEvent,
    VerificationResult,
)
from graph.state import VulnProcessingState


def append_trace_event(
    state: VulnProcessingState,
    node: str,
    reason_code: str,
    decision: Optional[str] = None,
    duration_ms: float = 0.0,
    tool: Optional[str] = None,
    params_summary: Optional[str] = None,
    error: Optional[str] = None,
) -> List[Dict]:
    event = TraceEvent(
        task_id=state.get("task_id", ""),
        node=node,
        reason_code=reason_code,
        timestamp=time.time(),
        duration_ms=duration_ms,
        tool=tool,
        params_summary=(params_summary or "")[:512] or None,
        source=state.get("source"),
        error=(error or "")[:512] or None,
        decision=decision,
    )
    return [*state.get("trace_events", []), event.model_dump()]


def diagnose_failure_node(
    state: VulnProcessingState, config: Dict
) -> VulnProcessingState:
    started = time.perf_counter()
    profile = diagnose_failure(
        state.get("cleaned_data") or state.get("extracted_data") or {},
        state.get("validation_result") or {},
        state.get("quality_score", 0.0),
        state.get("source"),
    )
    deadline_at = state.get("deadline_at", 0.0)
    if _agent_loop_enabled(config) and deadline_at <= 0:
        deadline_at = time.time() + _budget(config).deadline_seconds
    return {
        **state,
        "failure_profile": profile.model_dump(),
        "deadline_at": deadline_at,
        "trace_events": append_trace_event(
            state,
            "diagnose_failure",
            profile.failure_type,
            duration_ms=(time.perf_counter() - started) * 1000,
        ),
    }


def _agent_loop_enabled(config: Dict) -> bool:
    return bool(
        config.get("agentic", {}).get("recovery", {}).get("agent_loop_enabled", False)
    )


def _budget(config: Dict) -> RecoveryBudget:
    injected = config.get("_recovery_budget")
    if injected:
        return injected
    recovery = config.get("agentic", {}).get("recovery", {})
    return RecoveryBudget(
        max_steps=recovery.get("max_steps", 3),
        max_tool_calls=recovery.get("max_tool_calls", 5),
        max_llm_calls=recovery.get("max_llm_calls", 2),
        deadline_seconds=recovery.get("deadline_seconds", 30),
    )


async def plan_recovery_node(
    state: VulnProcessingState, config: Dict
) -> VulnProcessingState:
    budget = _budget(config)
    if budget.is_exhausted(
        state.get("step_count", 0),
        state.get("tool_call_count", 0),
        state.get("llm_call_count", 0),
        state.get("deadline_at", 0.0),
    ):
        decision = RecoveryDecision(decision="ABORT", reason_code="budget_exhausted")
        llm_calls = state.get("llm_call_count", 0)
        steps = state.get("step_count", 0)
    else:
        planner = config.get("_recovery_planner")
        if planner:
            context = {
                "failure_profile": state.get("failure_profile") or {},
                "observations": state.get("observations", []),
                "remaining_budget": {
                    "steps": budget.max_steps - state.get("step_count", 0),
                    "tools": budget.max_tool_calls - state.get("tool_call_count", 0),
                    "llm": budget.max_llm_calls - state.get("llm_call_count", 0),
                },
            }
            decision = await asyncio.to_thread(planner.plan, context)
            llm_calls = state.get("llm_call_count", 0) + 1
            steps = state.get("step_count", 0) + 1
        else:
            decision = RecoveryDecision(
                decision="STOP", reason_code="planner_unavailable"
            )
            llm_calls = state.get("llm_call_count", 0)
            steps = state.get("step_count", 0)
    return {
        **state,
        "recovery_decision": decision.model_dump(),
        "pending_action": None,
        "action_rejection": None,
        "verification": None,
        "llm_call_count": llm_calls,
        "step_count": steps,
        "trace_events": append_trace_event(
            state,
            "plan_recovery",
            decision.reason_code,
            tool=decision.tool_name,
            params_summary=",".join(decision.target_fields),
        ),
    }


def guard_action_node(
    state: VulnProcessingState, config: Dict
) -> VulnProcessingState:
    try:
        decision = RecoveryDecision.model_validate(state.get("recovery_decision"))
        guard = config.get("_recovery_guard")
        registry = config.get("_recovery_registry")
        if not guard or not registry:
            result: Any = ActionRejection(reason_code="guard_unavailable")
        else:
            result = guard.authorize(decision, state, registry)
    except Exception as exc:
        result = ActionRejection(reason_code="invalid_decision", details=str(exc))
    authorized = isinstance(result, AuthorizedAction)
    reason = "action_authorized" if authorized else result.reason_code
    return {
        **state,
        "pending_action": result.model_dump() if authorized else None,
        "action_rejection": None if authorized else result.model_dump(),
        "trace_events": append_trace_event(
            state,
            "guard_action",
            reason,
            tool=result.tool_name if authorized else None,
        ),
    }


async def execute_action_node(
    state: VulnProcessingState, config: Dict
) -> VulnProcessingState:
    action = AuthorizedAction.model_validate(state.get("pending_action"))
    registry = config.get("_recovery_registry")
    timeout = config.get("agentic", {}).get("recovery", {}).get(
        "tool_timeout_seconds", 8
    )
    context = {
        "raw_content": state.get("raw_content") or "",
        "file_path": state.get("file_path"),
        "source": state.get("source"),
        "candidate": state.get("cleaned_data") or {},
    }
    try:
        if not registry:
            raise RuntimeError("registry_unavailable")
        result = await asyncio.wait_for(
            asyncio.to_thread(
                registry.invoke, action.tool_name, action.tool_args, context
            ),
            timeout=float(timeout),
        )
    except asyncio.TimeoutError:
        result = ToolResult(
            success=False, tool_name=action.tool_name, error="tool_timeout"
        )
    except Exception as exc:
        result = ToolResult(
            success=False, tool_name=action.tool_name, error=str(exc)[:512]
        )
    return {
        **state,
        "observations": [*state.get("observations", []), result.model_dump()],
        "tool_call_count": state.get("tool_call_count", 0) + 1,
        "trace_events": append_trace_event(
            state,
            "execute_action",
            "tool_success" if result.success else "tool_failed",
            tool=action.tool_name,
            duration_ms=result.latency_ms,
            error=result.error,
        ),
    }


def verify_evidence_node(
    state: VulnProcessingState, config: Dict
) -> VulnProcessingState:
    action = AuthorizedAction.model_validate(state.get("pending_action"))
    result = ToolResult.model_validate(state.get("observations", [])[-1])
    verifier = config.get("_recovery_verifier")
    verification = (
        verifier.verify(
            state.get("cleaned_data") or {}, action, result, state.get("source") or ""
        )
        if verifier
        else VerificationResult(
            status="rejected",
            reason_code="verifier_unavailable",
            rejected_fields=action.target_fields,
        )
    )
    cleaned = dict(state.get("cleaned_data") or {})
    validation = state.get("validation_result") or {}
    quality = state.get("quality_score", 0.0)
    if verification.status == "accepted":
        for field_patch in verification.accepted_patches:
            if field_patch.verification_status == "accepted":
                cleaned[field_patch.field] = field_patch.proposed_value
        cleaner = config.get("_cleaner")
        if cleaner:
            validation = cleaner.validate(cleaned, state.get("source") or "")
            quality = cleaner.calculate_quality_score(
                cleaned, validation, state.get("extraction_confidence", 0.0)
            )
    return {
        **state,
        "cleaned_data": cleaned,
        "validation_result": validation,
        "quality_score": quality,
        "verification": verification.model_dump(),
        "proposed_patches": [
            *state.get("proposed_patches", []),
            *[patch.model_dump() for patch in verification.accepted_patches],
        ],
        "trace_events": append_trace_event(
            state,
            "verify_evidence",
            verification.reason_code,
            decision=verification.status.upper(),
        ),
    }


def decide_next_node(
    state: VulnProcessingState, config: Dict
) -> VulnProcessingState:
    decision = state.get("recovery_decision") or {}
    verification = state.get("verification") or {}
    rejection = state.get("action_rejection") or {}
    observations = state.get("observations") or []
    budget = _budget(config)
    exhausted = budget.is_exhausted(
        state.get("step_count", 0),
        state.get("tool_call_count", 0),
        state.get("llm_call_count", 0),
        state.get("deadline_at", 0.0),
    )
    reason = "recovery_exhausted"
    if decision.get("decision") == "REVIEW":
        final = "REVIEW"
        reason = decision.get("reason_code", "review_requested")
    elif decision.get("decision") == "ABORT":
        final = "ABORT"
        reason = decision.get("reason_code", "planner_abort")
    elif decision.get("decision") == "STOP":
        reason = decision.get("reason_code", "planner_stop")
        final = "ABORT" if reason == "planner_unavailable" or exhausted else "REPLAN"
    elif rejection:
        reason = rejection.get("reason_code", "action_rejected")
        final = "ABORT" if exhausted else "REPLAN"
    elif verification.get("status") == "accepted":
        threshold = config.get("agents", {}).get("cleaner_validator", {}).get(
            "quality_threshold", 0.7
        )
        valid = (state.get("validation_result") or {}).get("is_valid", False)
        final = "PASS" if valid and state.get("quality_score", 0.0) >= threshold else (
            "ABORT" if exhausted else "REPLAN"
        )
        reason = "quality_gate_passed" if final == "PASS" else "quality_still_low"
    elif verification.get("status") == "review":
        final = "REVIEW"
        reason = verification.get("reason_code", "verification_review")
    else:
        if observations and not observations[-1].get("success", False):
            reason = observations[-1].get("error") or "tool_failed"
        elif verification:
            reason = verification.get("reason_code", "verification_rejected")
        final = "ABORT" if exhausted else "REPLAN"
    return {
        **state,
        "final_decision": final,
        "trace_events": append_trace_event(
            state, "decide_next", reason, decision=final
        ),
    }
