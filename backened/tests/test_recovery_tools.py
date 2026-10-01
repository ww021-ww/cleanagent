import json

from agent.recovery.tool_registry import RecoveryToolRegistry


def test_search_raw_text_returns_bounded_current_file_evidence():
    registry = RecoveryToolRegistry(max_result_chars=80)
    result = registry.invoke(
        "search_raw_text",
        {"field_hint": "description", "keywords": ["buffer overflow"]},
        {"raw_content": "Description: " + "buffer overflow " * 20},
    )

    assert result.success is True
    assert "buffer overflow" in result.data["description"]
    assert len(result.evidence) <= 80
    assert result.source_name == "current_file"
    assert result.evidence_location.startswith("chars:")


def test_parse_json_path_uses_data_navigation_not_code_execution():
    registry = RecoveryToolRegistry()
    context = {
        "raw_content": json.dumps({"containers": {"cna": {"title": "Issue"}}})
    }

    result = registry.invoke(
        "parse_json_path",
        {"path": "containers.cna.title", "target_field": "title"},
        context,
    )
    rejected = registry.invoke(
        "parse_json_path",
        {"path": "containers['cna']", "target_field": "title"},
        context,
    )

    assert result.success is True
    assert result.data == {"title": "Issue"}
    assert result.evidence_location == "json:containers.cna.title"
    assert rejected.success is False
    assert "path" in rejected.error.lower()


def test_normalize_field_only_normalizes_supported_precise_formats():
    registry = RecoveryToolRegistry()

    cve = registry.invoke(
        "normalize_field",
        {"field": "cve_id", "value": " cve-2026-1234 "},
        {},
    )
    date = registry.invoke(
        "normalize_field",
        {"field": "published_date", "value": "2026/01/02"},
        {},
    )
    score = registry.invoke(
        "normalize_field",
        {"field": "cvss_score", "value": "9.8"},
        {},
    )
    invalid = registry.invoke(
        "normalize_field",
        {"field": "cve_id", "value": "CVE-INVENTED"},
        {},
    )

    assert cve.data == {"cve_id": "CVE-2026-1234"}
    assert date.data == {"published_date": "2026-01-02"}
    assert score.data == {"cvss_score": 9.8}
    assert invalid.success is False


def test_nvd_lookup_uses_injected_official_client_and_filters_fields():
    def fake_nvd(cve_id, api_key=""):
        assert cve_id == "CVE-2026-1234"
        return {
            "cve_id": cve_id,
            "description": "Official description",
            "cvss_score": 8.1,
            "references": ["https://vendor.example/advisory"],
        }

    registry = RecoveryToolRegistry(nvd_lookup_fn=fake_nvd)
    result = registry.invoke(
        "nvd_lookup",
        {"cve_id": "CVE-2026-1234", "target_fields": ["description"]},
        {},
    )

    assert result.success is True
    assert result.data == {"description": "Official description"}
    assert result.source_name == "NVD"
    assert result.source_url.endswith("CVE-2026-1234")

    aliased = registry.invoke(
        "nvd_lookup",
        {
            "cve_id": "CVE-2026-1234",
            "target_fields": ["descriptions_value"],
        },
        {"source": "NVD"},
    )
    assert aliased.data == {"descriptions_value": "Official description"}


def test_registry_bounds_string_data_before_it_enters_graph_state():
    registry = RecoveryToolRegistry(
        nvd_lookup_fn=lambda cve_id, api_key="": {"description": "x" * 200},
        max_result_chars=32,
    )

    result = registry.invoke(
        "nvd_lookup",
        {"cve_id": "CVE-2026-1234", "target_fields": ["description"]},
        {},
    )

    assert result.success is True
    assert result.data == {"description": "x" * 32}


def test_registry_rejects_unknown_tools_extra_args_and_tool_failures():
    def failing_nvd(cve_id, api_key=""):
        raise TimeoutError("upstream timeout")

    registry = RecoveryToolRegistry(nvd_lookup_fn=failing_nvd)
    unknown = registry.invoke("shell", {}, {})
    extra = registry.invoke(
        "search_raw_text",
        {"field_hint": "description", "keywords": [], "command": "whoami"},
        {"raw_content": "description"},
    )
    failed = registry.invoke(
        "nvd_lookup",
        {"cve_id": "CVE-2026-1234", "target_fields": ["description"]},
        {},
    )

    assert unknown.success is extra.success is failed.success is False
    assert unknown.error == "unknown_tool"
    assert "command" in extra.error
    assert "upstream timeout" in failed.error


def test_descriptions_expose_only_the_four_phase_two_tools():
    specs = RecoveryToolRegistry().describe_allowed({})

    assert [spec.name for spec in specs] == [
        "search_raw_text",
        "parse_json_path",
        "normalize_field",
        "nvd_lookup",
    ]
