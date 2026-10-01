"""Constrained recovery primitives for failed vulnerability records."""

from .diagnosis import diagnose_failure
from .models import (
    Evidence,
    EvidenceGap,
    FailureProfile,
    FieldIssue,
    FieldPatch,
    TraceEvent,
)

__all__ = [
    "diagnose_failure",
    "Evidence",
    "EvidenceGap",
    "FailureProfile",
    "FieldIssue",
    "FieldPatch",
    "TraceEvent",
]
