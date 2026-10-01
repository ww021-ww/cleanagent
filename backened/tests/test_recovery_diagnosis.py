from copy import deepcopy

import pytest
from pydantic import ValidationError

from agent.recovery.diagnosis import diagnose_failure
from agent.recovery.models import Evidence, FieldPatch


def test_missing_required_fields_are_diagnosed_without_mutating_candidate():
    candidate = {"cve_id": "CVE-2026-1234", "description": None}
    original = deepcopy(candidate)
    validation = {
        "errors": ["Missing required field: description"],
        "warnings": [],
        "is_valid": False,
    }

    profile = diagnose_failure(candidate, validation, 0.35, "CVE")

    assert profile.failure_type == "missing_required_fields"
    assert profile.missing_fields == ["description"]
    assert profile.evidence_gaps == ["description"]
    assert profile.quality_score == 0.35
    assert candidate == original


def test_unknown_source_has_priority_over_field_errors():
    validation = {
        "errors": ["Missing required field: description"],
        "warnings": [],
        "is_valid": False,
    }

    profile = diagnose_failure({}, validation, 0.0, "unknown-feed")

    assert profile.failure_type == "source_unknown"
    assert profile.missing_fields == ["description"]


def test_enriched_type_issue_is_diagnosed_as_schema_mismatch():
    validation = {
        "errors": [],
        "warnings": ["Type mismatch for cvss_score: expected float"],
        "is_valid": True,
        "field_issues": [
            {
                "field": "cvss_score",
                "code": "type_mismatch",
                "severity": "warning",
                "message": "expected float",
                "evidence_required": False,
            }
        ],
        "evidence_gaps": [],
    }

    profile = diagnose_failure({"cvss_score": "high"}, validation, 0.4, "NVD")

    assert profile.failure_type == "schema_mismatch"
    assert [issue.field for issue in profile.field_issues] == ["cvss_score"]


def test_empty_candidate_without_validation_details_is_evidence_missing():
    profile = diagnose_failure(
        {}, {"errors": [], "warnings": [], "is_valid": False}, 0.0, "CERT"
    )

    assert profile.failure_type == "evidence_missing"
    assert profile.evidence_gaps == ["candidate"]


def test_field_patch_rejects_out_of_range_confidence_and_unknown_fields():
    valid = {
        "field": "description",
        "old_value": None,
        "proposed_value": "validated text",
        "method": "raw_text",
        "source_name": "current_file",
        "source_url": None,
        "evidence": "validated text",
        "evidence_location": "line:12",
        "confidence": 0.9,
        "verification_status": "pending",
    }

    with pytest.raises(ValidationError):
        FieldPatch(**{**valid, "confidence": 1.1})

    with pytest.raises(ValidationError):
        FieldPatch(**{**valid, "unexpected": "value"})


def test_evidence_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        Evidence(
            source_name="current_file",
            content="proof",
            location="line:1",
            unexpected="value",
        )
