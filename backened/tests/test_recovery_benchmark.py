import asyncio
import json
from pathlib import Path

import pytest

import recovery_benchmark
from config import FieldConfigLoader, load_yaml_config
from recovery_ab import build_variant_config, compare_results
from recovery_benchmark import (
    case_is_auto_recoverable,
    create_anomaly_file,
    discover_samples,
    require_llm_config,
    score_result,
    summarize_scores,
)


def test_specialized_json_extractors_expose_benchmark_evidence_paths():
    fields = FieldConfigLoader(
        str(Path(__file__).parents[1] / "config" / "field_mappings.yaml")
    )

    assert recovery_benchmark._json_path(fields, "NVD", "descriptions_value") == (
        "descriptions[0].value"
    )
    assert recovery_benchmark._json_path(fields, "CISA", "shortDescription") == (
        "vulnerabilities[0].shortDescription"
    )
    assert recovery_benchmark._json_path(fields, "CERT", "overview") == "overview"


def test_required_any_group_uses_one_canonical_benchmark_field():
    config = {
        "agentic": {
            "quality_gate": {
                "profiles": {
                    "cert": {
                        "required_any": {
                            "description": ["overview", "clean_desc"],
                        }
                    }
                }
            }
        }
    }

    assert recovery_benchmark._description_fields(
        config, "CERT", {"overview": "full", "clean_desc": "derived"}
    ) == ["overview"]


def test_benchmark_rejects_missing_llm_credentials():
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        require_llm_config({"api_key": "", "model": "deepseek-v4-pro"})


def test_layout_drift_keeps_exact_evidence_at_recovery_json_path(tmp_path):
    original = tmp_path / "CVE-2026-1234.json"
    original.write_text(
        json.dumps({"cve": {"description": " exact  verified text "}, "id": "CVE-2026-1234"}),
        encoding="utf-8",
    )
    mutated = create_anomaly_file(
        original,
        tmp_path / "cases",
        "CVE",
        "layout_drift",
        target_field="description",
        source_json_path="cve.description",
    )
    payload = json.loads(mutated.read_text(encoding="utf-8"))

    assert "description" not in payload["cve"]
    assert payload["recovery_evidence"]["description"] == " exact  verified text "


def test_layout_drift_uses_stable_description_evidence_key(tmp_path):
    original = tmp_path / "CVE-2026-1234.json"
    original.write_text(
        json.dumps({"containers": {"cna": {"descriptions": [{"value": "verified"}]}}}),
        encoding="utf-8",
    )

    mutated = create_anomaly_file(
        original,
        tmp_path / "cases",
        "CVE",
        "layout_drift",
        target_field="containers_cna_descriptions_value",
        source_json_path="containers.cna.descriptions[0].value",
    )

    payload = json.loads(mutated.read_text(encoding="utf-8"))
    assert payload["recovery_evidence"] == {"description": "verified"}


def test_layout_drift_can_preserve_the_canonical_extracted_value(tmp_path):
    original = tmp_path / "cert.json"
    original.write_text(
        json.dumps({"overview": "### Overview\nsummary\n### Impact\ndetails"}),
        encoding="utf-8",
    )

    mutated = create_anomaly_file(
        original,
        tmp_path / "cases",
        "CERT",
        "layout_drift",
        target_field="overview",
        source_json_path="overview",
        evidence_value="summary",
    )

    payload = json.loads(mutated.read_text(encoding="utf-8"))
    assert payload["recovery_evidence"] == {"description": "summary"}


def test_html_missing_evidence_preserves_jvn_identifier(tmp_path):
    original = tmp_path / "sample.html"
    original.write_text("<html>full advisory</html>", encoding="utf-8")

    mutated = create_anomaly_file(
        original,
        tmp_path / "cases",
        "JVN",
        "missing_evidence",
        target_field="description",
        identifier="CPNI-072928",
    )

    assert 'class="h1ver2">CPNI-072928<' in mutated.read_text(encoding="utf-8")


def test_missing_evidence_contains_no_recoverable_description(tmp_path):
    original = tmp_path / "CVE-2026-1234.json"
    original.write_text(
        json.dumps({"cve": {"description": "secret evidence"}, "id": "CVE-2026-1234"}),
        encoding="utf-8",
    )
    mutated = create_anomaly_file(
        original,
        tmp_path / "cases",
        "CVE",
        "missing_evidence",
        target_field="description",
        source_json_path="cve.description",
    )

    assert "secret evidence" not in mutated.read_text(encoding="utf-8")


def test_cisa_missing_evidence_is_blocked_by_rule_baseline(tmp_path):
    original = tmp_path / "cisa" / "kev.json"
    original.parent.mkdir()
    original.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-1234",
                        "vendorProject": "Vendor",
                        "product": "Product",
                        "shortDescription": "verified description",
                        "requiredAction": "apply update",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    mutated = create_anomaly_file(
        original,
        tmp_path / "cases",
        "CISA",
        "missing_evidence",
        target_field="shortDescription",
        source_json_path="vulnerabilities[0].shortDescription",
        identifier="CVE-2026-1234",
    )

    config = load_yaml_config(str(Path(__file__).parents[1] / "config" / "agent_config.yaml"))
    results, _ = asyncio.run(
        recovery_benchmark._process(
            [mutated], recovery_benchmark._benchmark_config(config, False), workers=1
        )
    )

    assert results[0]["final_status"] != "success"


def test_score_separates_recoverable_accuracy_from_safe_block_rate():
    truth = {"cve_id": "CVE-2026-1234", "description": "verified"}
    recovered = score_result(
        {
            "final_status": "success",
            "final_decision": "PASS",
            "cleaned_data": {"cve_id": "CVE-2026-1234", "description": "verified"},
        },
        truth,
        id_field="cve_id",
        damaged_fields=["description"],
        mutation="layout_drift",
        auto_recoverable=True,
    )
    safely_blocked = score_result(
        {
            "final_status": "review_pending",
            "final_decision": "REVIEW",
            "cleaned_data": {"cve_id": "CVE-2026-1234", "description": None},
        },
        truth,
        id_field="cve_id",
        damaged_fields=["description"],
        mutation="missing_evidence",
        auto_recoverable=True,
    )

    summary = summarize_scores([recovered, safely_blocked], elapsed_seconds=1.25)

    assert summary["recoverable_field_accuracy"] == 1.0
    assert summary["safe_block_rate"] == 1.0
    assert summary["false_modification_rate"] == 0.0
    assert summary["protected_id_preservation_rate"] == 1.0
    assert recovered["outcome"] == "success"
    assert safely_blocked["outcome"] == "review_pending"


def test_html_only_source_is_reported_as_not_auto_recoverable():
    assert case_is_auto_recoverable("CNVD", "sample.html") is False
    assert case_is_auto_recoverable("JVN", "sample.htm") is False
    assert case_is_auto_recoverable("CVE", "sample.json") is True


def test_benchmark_variants_are_rule_baseline_and_recovery_agent():
    config = {
        "agentic": {
            "recovery": {"enabled": True},
        }
    }

    baseline = build_variant_config(config, False)
    agent = build_variant_config(config, True)
    report = compare_results({"safe_block_rate": 0.5}, {"safe_block_rate": 1.0})

    assert baseline["agentic"]["recovery"]["enabled"] is False
    assert agent["agentic"]["recovery"]["enabled"] is True
    assert set(report) == {"baseline", "agent", "delta"}


def test_sample_discovery_uses_one_real_file_per_source(tmp_path):
    for relative in (
        "json/cves/CVE-2026-0001.json",
        "json/nvd/CVE-2026-0002.json",
        "json/cisa/kev.json",
        "json/cert/VU-1.json",
        "html/cnvd/CNVD-2026-1.html",
        "html/jvn/JVN-2026-1.html",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("sample", encoding="utf-8")

    samples = discover_samples(tmp_path)

    assert set(samples) == {"CVE", "NVD", "CISA", "CERT", "CNVD", "JVN"}


def test_variant_processing_respects_worker_limit(monkeypatch, tmp_path):
    class ProbeController:
        active = 0
        maximum = 0

        async def process_file(self, path):
            self.active += 1
            self.maximum = max(self.maximum, self.active)
            await asyncio.sleep(0.01)
            self.active -= 1
            return {"file_path": path}

    probe = ProbeController()
    monkeypatch.setattr(recovery_benchmark, "LangGraphController", lambda config: probe)

    paths = [tmp_path / f"{index}.json" for index in range(5)]
    results, _ = asyncio.run(recovery_benchmark._process(paths, {}, workers=2))

    assert len(results) == 5
    assert probe.maximum == 2
