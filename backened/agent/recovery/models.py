"""Strict data contracts shared by recovery nodes."""

from typing import Any, List, Literal, Optional

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
