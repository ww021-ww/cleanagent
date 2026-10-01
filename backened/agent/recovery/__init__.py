"""Constrained recovery primitives for failed vulnerability records."""

from .diagnosis import diagnose_failure
from .models import (
    ActionRejection,
    AuthorizedAction,
    Evidence,
    EvidenceGap,
    FailureProfile,
    FieldIssue,
    FieldPatch,
    RecoveryBudget,
    RecoveryDecision,
    ToolResult,
    ToolSpec,
    TraceEvent,
    VerificationResult,
)
from .tool_registry import RecoveryToolRegistry

__all__ = [
    "diagnose_failure",
    "ActionRejection",
    "AuthorizedAction",
    "Evidence",
    "EvidenceGap",
    "FailureProfile",
    "FieldIssue",
    "FieldPatch",
    "RecoveryBudget",
    "RecoveryDecision",
    "RecoveryToolRegistry",
    "ToolResult",
    "ToolSpec",
    "TraceEvent",
    "VerificationResult",
]
