from pathlib import Path

import yaml

from agent.cleaner_validator import CleanerValidatorAgent


class CveConfigLoader:
    def get_source_config(self, source):
        assert source == "CVE"
        return {
            "fields": [
                {"name": "cveMetadata_cveId", "type": "string"},
                {"name": "containers_cna_descriptions_value", "type": "text"},
                {"name": "containers_cna_affected_product", "type": "text"},
                {"name": "containers_cna_solutions_value", "type": "text"},
            ]
        }

    def get_required_fields(self, source):
        assert source == "CVE"
        return ["cveMetadata_cveId"]


def make_validator():
    validator = object.__new__(CleanerValidatorAgent)
    validator.config_loader = CveConfigLoader()
    validator.config = {
        "agentic": {
            "quality_gate": {
                "enabled": True,
                "profiles": {
                    "cve": {
                        "required_any": {
                            "description": ["containers_cna_descriptions_value"]
                        },
                        "important_any": {
                            "affected": ["containers_cna_affected_product"],
                            "remediation": ["containers_cna_solutions_value"],
                        },
                    }
                },
            }
        }
    }
    return validator


def test_id_only_record_fails_quality_gate_and_scores_below_threshold():
    validator = make_validator()
    data = {"cveMetadata_cveId": "CVE-2022-1556"}

    validation = validator.validate(data, "CVE")
    score = validator.calculate_quality_score(data, validation, confidence=0.7)

    assert validation["is_valid"] is False
    assert "Missing required field: containers_cna_descriptions_value" in validation["errors"]
    assert validation["quality_filled"] == 1
    assert validation["quality_total"] == 4
    assert score < 0.5


def test_description_passes_hard_gate_while_important_fields_only_reduce_score():
    validator = make_validator()
    data = {
        "cveMetadata_cveId": "CVE-2022-1556",
        "containers_cna_descriptions_value": "Validated vulnerability description",
    }

    validation = validator.validate(data, "CVE")
    score = validator.calculate_quality_score(data, validation, confidence=0.8)

    assert validation["is_valid"] is True
    assert validation["errors"] == []
    assert validation["warnings"] == [
        "Missing important quality field: affected",
        "Missing important quality field: remediation",
    ]
    assert validation["quality_filled"] == 2
    assert validation["quality_total"] == 4
    assert score >= 0.5


def test_all_quality_profile_fields_exist_in_source_schemas():
    config_dir = Path(__file__).parents[1] / "config"
    app_config = yaml.safe_load(
        (config_dir / "agent_config.yaml").read_text(encoding="utf-8")
    )
    mappings = yaml.safe_load(
        (config_dir / "field_mappings.yaml").read_text(encoding="utf-8")
    )
    profiles = app_config["agentic"]["quality_gate"]["profiles"]

    assert set(profiles) == set(mappings)
    for source, profile in profiles.items():
        schema_fields = {field["name"] for field in mappings[source]["fields"]}
        configured_fields = {
            field
            for section in ("required_any", "important_any")
            for fields in profile[section].values()
            for field in fields
        }
        assert configured_fields <= schema_fields
