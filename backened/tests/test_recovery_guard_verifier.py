import time
from copy import deepcopy

from agent.recovery.guard import RecoveryActionGuard
from agent.recovery.models import (
    ActionRejection,
    AuthorizedAction,
    RecoveryBudget,
    RecoveryDecision,
    ToolResult,
)
from agent.recovery.tool_registry import RecoveryToolRegistry
from agent.recovery.verifier import EvidenceVerifier


def decision(tool_name, target_fields, tool_args):
    return RecoveryDecision(
        decision="CALL_TOOL",
        reason_code="recover_missing_field",
        target_fields=target_fields,
        tool_name=tool_name,
        tool_args=tool_args,
        expected_evidence="field value and source location",
    )


def state(**overrides):
    value = {
        "cleaned_data": {"cve_id": "CVE-2026-1234"},
        "step_count": 0,
        "tool_call_count": 0,
        "llm_call_count": 0,
        "deadline_at": time.time() + 10,
    }
    value.update(overrides)
    return value


def test_guard_authorizes_only_schema_valid_allowed_action():
    registry = RecoveryToolRegistry()
    guard = RecoveryActionGuard(RecoveryBudget())
    planned = decision(
        "search_raw_text",
        ["description"],
        {"field_hint": "description", "keywords": ["summary"]},
    )

    result = guard.authorize(planned, state(), registry)

    assert result == AuthorizedAction(
        tool_name="search_raw_text",
        tool_args={"field_hint": "description", "keywords": ["summary"]},
        target_fields=["description"],
    )

    source_field = decision(
        "search_raw_text",
        ["descriptions_value"],
        {"field_hint": "descriptions_value", "keywords": ["description"]},
    )
    source_result = guard.authorize(
        source_field, state(source="NVD"), registry
    )
    assert isinstance(source_result, AuthorizedAction)


def test_guard_rejects_unknown_tool_bad_args_exhausted_budget_and_field_escape():
    registry = RecoveryToolRegistry()
    guard = RecoveryActionGuard(RecoveryBudget())
    unknown = guard.authorize(decision("shell", [], {}), state(), registry)
    bad_args = guard.authorize(
        decision(
            "search_raw_text",
            ["description"],
            {"field_hint": "description", "keywords": [], "command": "whoami"},
        ),
        state(),
        registry,
    )
    exhausted = guard.authorize(
        decision(
            "search_raw_text",
            ["description"],
            {"field_hint": "description", "keywords": []},
        ),
        state(step_count=3),
        registry,
    )
    escaped = guard.authorize(
        decision(
            "search_raw_text",
            ["cve_id"],
            {"field_hint": "cve_id", "keywords": []},
        ),
        state(),
        registry,
    )

    assert isinstance(unknown, ActionRejection)
    assert unknown.reason_code == "unknown_tool"
    assert bad_args.reason_code == "invalid_tool_args"
    assert exhausted.reason_code == "budget_exhausted"
    assert escaped.reason_code == "field_not_allowed"


def test_guard_rejects_forged_nvd_id_and_invented_normalization_value():
    registry = RecoveryToolRegistry()
    guard = RecoveryActionGuard(RecoveryBudget())
    forged = guard.authorize(
        decision(
            "nvd_lookup",
            ["description"],
            {"cve_id": "CVE-2026-9999", "target_fields": ["description"]},
        ),
        state(),
        registry,
    )
    invented = guard.authorize(
        decision(
            "normalize_field",
            ["cve_id"],
            {"field": "cve_id", "value": "CVE-2026-9999"},
        ),
        state(),
        registry,
    )

    assert forged.reason_code == "identifier_mismatch"
    assert invented.reason_code == "value_not_from_candidate"


class FakeFieldConfig:
    def get_id_field(self, source):
        return "cve_id"


def test_verifier_routes_raw_text_patch_to_review_without_mutating_candidate():
    verifier = EvidenceVerifier(FakeFieldConfig())
    candidate = {"cve_id": "CVE-2026-1234", "description": None}
    original = deepcopy(candidate)
    action = AuthorizedAction(
        tool_name="search_raw_text",
        tool_args={"field_hint": "description", "keywords": []},
        target_fields=["description"],
    )
    result = ToolResult(
        success=True,
        tool_name="search_raw_text",
        data={"description": "Validated description"},
        evidence="Validated description",
        source_name="current_file",
        evidence_location="chars:10-31",
    )

    verification = verifier.verify(candidate, action, result, "CVE")

    assert verification.status == "review"
    assert verification.accepted_patches[0].field == "description"
    assert verification.accepted_patches[0].proposed_value == "Validated description"
    assert verification.accepted_patches[0].verification_status == "review"
    assert candidate == original


def test_verifier_rejects_missing_evidence_and_untrusted_a_field_patch():
    verifier = EvidenceVerifier(FakeFieldConfig())
    candidate = {"cve_id": "CVE-2026-1234"}
    description_action = AuthorizedAction(
        tool_name="search_raw_text",
        tool_args={"field_hint": "description", "keywords": []},
        target_fields=["description"],
    )
    a_field_action = AuthorizedAction(
        tool_name="search_raw_text",
        tool_args={"field_hint": "cvss_score", "keywords": []},
        target_fields=["cvss_score"],
    )

    no_evidence = verifier.verify(
        candidate,
        description_action,
        ToolResult(
            success=True,
            tool_name="search_raw_text",
            data={"description": "guess"},
            source_name="current_file",
        ),
        "CVE",
    )
    untrusted = verifier.verify(
        candidate,
        a_field_action,
        ToolResult(
            success=True,
            tool_name="search_raw_text",
            data={"cvss_score": 9.8},
            evidence="9.8",
            source_name="current_file",
            evidence_location="chars:5-8",
        ),
        "CVE",
    )

    assert no_evidence.status == "rejected"
    assert no_evidence.reason_code == "evidence_missing"
    assert untrusted.status == "rejected"
    assert untrusted.reason_code == "authoritative_source_required"


def test_verifier_accepts_official_a_field_but_reviews_authority_conflict():
    verifier = EvidenceVerifier(FakeFieldConfig())
    action = AuthorizedAction(
        tool_name="nvd_lookup",
        tool_args={"cve_id": "CVE-2026-1234", "target_fields": ["cvss_score"]},
        target_fields=["cvss_score"],
    )
    official = ToolResult(
        success=True,
        tool_name="nvd_lookup",
        data={"cvss_score": 8.1},
        evidence='{"cvss_score": 8.1}',
        source_name="NVD",
        source_url="https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
        evidence_location="NVD API 2.0",
    )

    accepted = verifier.verify(
        {"cve_id": "CVE-2026-1234"}, action, official, "CVE"
    )
    conflict = verifier.verify(
        {"cve_id": "CVE-2026-1234", "cvss_score": 7.0},
        action,
        official,
        "CVE",
    )

    assert accepted.status == "accepted"
    assert accepted.accepted_patches[0].confidence == 1.0
    assert conflict.status == "review"
    assert conflict.accepted_patches[0].verification_status == "review"
