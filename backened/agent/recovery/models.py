"""Strict data contracts shared by recovery nodes."""

import time
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Reject fields that are not part of the recovery contract."""

    model_config = ConfigDict(extra="forbid")


class FieldIssue(StrictModel):
    field: str
    code: str
    severity: Literal["error", "warning"]
    message: str
    evidence_required: bool = False


class Evidence(StrictModel):
    source_name: str
    content: str
    source_url: Optional[str] = None
    location: Optional[str] = None


class EvidenceGap(StrictModel):
    field: str
    reason: str


class FieldPatch(StrictModel):
    field: str
    old_value: Any
    proposed_value: Any
    method: str
    source_name: str
    source_url: Optional[str] = None
    evidence: str
    evidence_location: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0)
    verification_status: Literal["pending", "accepted", "rejected", "review"]


class FailureProfile(StrictModel):
    failure_type: Literal[
        "missing_required_fields",
        "schema_mismatch",
        "source_unknown",
        "field_conflict",
        "evidence_missing",
        "external_dependency_failure",
    ]
    missing_fields: List[str] = Field(default_factory=list)
    conflicting_fields: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    attempted_actions: List[str] = Field(default_factory=list)
    field_issues: List[FieldIssue] = Field(default_factory=list)
    quality_score: float = Field(ge=0.0, le=1.0)
    source: Optional[str] = None


class TraceEvent(StrictModel):
    task_id: str
    node: str
    reason_code: str
    timestamp: float
    duration_ms: float = Field(ge=0.0)
    tool: Optional[str] = None
    params_summary: Optional[str] = None
    source: Optional[str] = None
    token_usage: int = Field(default=0, ge=0)
    error: Optional[str] = None
    decision: Optional[str] = None


class RecoveryDecision(StrictModel):
    decision: Literal["CALL_TOOL", "STOP", "REVIEW", "ABORT"]
    reason_code: str
    target_fields: List[str] = Field(default_factory=list)
    tool_name: Optional[str] = None
    tool_args: Dict[str, Any] = Field(default_factory=dict)
    expected_evidence: str = ""


class ToolSpec(StrictModel):
    name: str
    description: str
    args_schema: Dict[str, Any]
    allowed_fields: List[str] = Field(default_factory=list)
    external: bool = False


class ToolResult(StrictModel):
    success: bool
    tool_name: str
    data: Dict[str, Any] = Field(default_factory=dict)
    evidence: Optional[str] = None
    source_name: Optional[str] = None
    source_url: Optional[str] = None
    evidence_location: Optional[str] = None
    latency_ms: float = Field(default=0.0, ge=0.0)
    error: Optional[str] = None


class AuthorizedAction(StrictModel):
    tool_name: str
    tool_args: Dict[str, Any]
    target_fields: List[str]


class ActionRejection(StrictModel):
    reason_code: str
    details: str = ""


class VerificationResult(StrictModel):
    status: Literal["accepted", "rejected", "review"]
    reason_code: str
    accepted_patches: List[FieldPatch] = Field(default_factory=list)
    rejected_fields: List[str] = Field(default_factory=list)


class RecoveryBudget(StrictModel):
    max_steps: int = Field(default=3, gt=0)
    max_tool_calls: int = Field(default=5, gt=0)
    max_llm_calls: int = Field(default=2, gt=0)
    deadline_seconds: float = Field(default=30.0, gt=0.0)

    def is_exhausted(
        self,
        step_count: int,
        tool_call_count: int,
        llm_call_count: int,
        deadline_at: float,
        now: Optional[float] = None,
    ) -> bool:
        current_time = time.time() if now is None else now
        return (
            step_count >= self.max_steps
            or tool_call_count >= self.max_tool_calls
            or llm_call_count >= self.max_llm_calls
            or (deadline_at > 0 and current_time >= deadline_at)
        )
