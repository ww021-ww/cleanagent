"""Deterministic recovery diagnosis and bounded trace events."""
import time
from typing import Dict, List, Optional

from agent.recovery.diagnosis import diagnose_failure
from agent.recovery.models import TraceEvent
from graph.state import VulnProcessingState


def append_trace_event(
    state: VulnProcessingState,
    node: str,
    reason_code: str,
    decision: Optional[str] = None,
    duration_ms: float = 0.0,
) -> List[Dict]:
    event = TraceEvent(
        task_id=state.get("task_id", ""),
        node=node,
        reason_code=reason_code,
        timestamp=time.time(),
        duration_ms=duration_ms,
        source=state.get("source"),
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
    return {
        **state,
        "failure_profile": profile.model_dump(),
        "trace_events": append_trace_event(
            state,
            "diagnose_failure",
            profile.failure_type,
            duration_ms=(time.perf_counter() - started) * 1000,
        ),
    }
