"""Deterministic failure diagnosis; no LLM, tools, or persistence."""

from typing import Any, Dict, Iterable, List, Optional

from pydantic import ValidationError

from .models import FailureProfile, FieldIssue


KNOWN_SOURCES = {"CVE", "NVD", "CNVD", "CISA", "CERT", "JVN"}


def _unique(values: Iterable[str]) -> List[str]:
    return list(dict.fromkeys(value for value in values if value))


def _read_field_issues(validation: Dict[str, Any]) -> List[FieldIssue]:
    issues: List[FieldIssue] = []
    for raw in validation.get("field_issues", []) or []:
        try:
            issues.append(FieldIssue.model_validate(raw))
        except (ValidationError, TypeError):
            continue

    existing = {(issue.field, issue.code) for issue in issues}
    for message in validation.get("errors", []) or []:
        prefix = "Missing required field: "
        if message.startswith(prefix):
            field = message[len(prefix):].strip()
            if (field, "missing_required") not in existing:
                issues.append(
                    FieldIssue(
                        field=field,
                        code="missing_required",
                        severity="error",
                        message=message,
                        evidence_required=True,
                    )
                )

    for message in validation.get("warnings", []) or []:
        prefix = "Type mismatch for "
        if message.startswith(prefix):
            field = message[len(prefix):].split(":", 1)[0].strip()
            if (field, "type_mismatch") not in existing:
                issues.append(
                    FieldIssue(
                        field=field,
                        code="type_mismatch",
                        severity="warning",
                        message=message,
                    )
                )
    return issues


def _read_evidence_gaps(validation: Dict[str, Any]) -> List[str]:
    gaps: List[str] = []
    for raw in validation.get("evidence_gaps", []) or []:
        if isinstance(raw, str):
            gaps.append(raw)
        elif isinstance(raw, dict):
            gaps.append(str(raw.get("field", "")))
    return _unique(gaps)


def diagnose_failure(
    candidate: Dict[str, Any],
    validation: Dict[str, Any],
    quality_score: float,
    source: Optional[str],
) -> FailureProfile:
    """Convert validation output into an auditable failure profile."""

    issues = _read_field_issues(validation or {})
    missing_fields = _unique(
        issue.field for issue in issues if issue.code == "missing_required"
    )
    conflicting_fields = _unique(
        list(validation.get("conflicting_fields", []) or [])
        + [issue.field for issue in issues if issue.code == "field_conflict"]
    )
    evidence_gaps = _read_evidence_gaps(validation or {})
    evidence_gaps = _unique(
        evidence_gaps
        + [issue.field for issue in issues if issue.evidence_required]
        + (["candidate"] if not candidate else [])
    )

    normalized_source = source.upper() if source else None
    if normalized_source not in KNOWN_SOURCES:
        failure_type = "source_unknown"
    elif conflicting_fields:
        failure_type = "field_conflict"
    elif missing_fields:
        failure_type = "missing_required_fields"
    elif any(
        issue.code in {"type_mismatch", "max_length_exceeded", "schema_mismatch"}
        for issue in issues
    ):
        failure_type = "schema_mismatch"
    elif any(issue.code == "external_dependency_failure" for issue in issues):
        failure_type = "external_dependency_failure"
    else:
        failure_type = "evidence_missing"

    return FailureProfile(
        failure_type=failure_type,
        missing_fields=missing_fields,
        conflicting_fields=conflicting_fields,
        evidence_gaps=evidence_gaps,
        field_issues=issues,
        quality_score=quality_score,
        source=normalized_source,
    )
