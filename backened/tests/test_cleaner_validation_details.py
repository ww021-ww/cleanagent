from agent.cleaner_validator import CleanerValidatorAgent


class FakeConfigLoader:
    def get_source_config(self, source):
        assert source == "CVE"
        return {
            "fields": [
                {"name": "description", "type": "text"},
                {"name": "cvss_score", "type": "float"},
                {"name": "title", "type": "string", "max_length": 5},
            ]
        }

    def get_required_fields(self, source):
        assert source == "CVE"
        return ["description"]


def make_validator():
    validator = object.__new__(CleanerValidatorAgent)
    validator.config_loader = FakeConfigLoader()
    return validator


def test_validate_preserves_legacy_result_and_adds_field_details():
    result = make_validator().validate(
        {"description": "", "cvss_score": "high", "title": "too long"},
        "CVE",
    )

    assert result["errors"] == ["Missing required field: description"]
    assert result["warnings"] == [
        "Type mismatch for cvss_score: expected float",
        "Field title exceeds max length 5",
    ]
    assert result["is_valid"] is False
    assert result["field_issues"] == [
        {
            "field": "description",
            "code": "missing_required",
            "severity": "error",
            "message": "Missing required field: description",
            "evidence_required": True,
        },
        {
            "field": "cvss_score",
            "code": "type_mismatch",
            "severity": "warning",
            "message": "Type mismatch for cvss_score: expected float",
            "evidence_required": False,
        },
        {
            "field": "title",
            "code": "max_length_exceeded",
            "severity": "warning",
            "message": "Field title exceeds max length 5",
            "evidence_required": False,
        },
    ]
    assert result["evidence_gaps"] == [
        {"field": "description", "reason": "required_field_missing"}
    ]


def test_validate_returns_empty_detail_lists_for_valid_data():
    result = make_validator().validate(
        {"description": "ok", "cvss_score": 7.5, "title": "short"},
        "CVE",
    )

    assert result == {
        "errors": [],
        "warnings": [],
        "is_valid": True,
        "field_issues": [],
        "evidence_gaps": [],
    }
