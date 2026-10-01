import asyncio

import pytest
import recovery_benchmark

from recovery_benchmark import (
    create_anomaly_file,
    discover_samples,
    require_llm_config,
    score_result,
    summarize_scores,
)


def test_benchmark_rejects_missing_llm_credentials():
    with pytest.raises(ValueError, match="OPENAI_API_KEY"):
        require_llm_config({"api_key": "", "model": "deepseek-v4-pro"})


def test_benchmark_scores_recovery_without_rewarding_id_changes(tmp_path):
    truth = {
        "cve_id": "CVE-2026-1234",
        "descriptions_value": "verified description",
    }
    result = {
        "final_status": "success",
        "cleaned_data": {
            "cve_id": "CVE-2026-9999",
            "descriptions_value": "verified description",
        },
        "trace_events": [{"node": "diagnose_failure"}],
        "llm_call_count": 1,
        "tool_call_count": 1,
    }

    score = score_result(
        result, truth, id_field="cve_id", damaged_fields=["descriptions_value"]
    )
    summary = summarize_scores([score], elapsed_seconds=1.25)

    assert summary["anomaly_detection_rate"] == 1.0
    assert summary["field_recovery_accuracy"] == 1.0
    assert summary["false_modification_rate"] == 1.0
    assert summary["protected_field_loss_rate"] == 0.0
    assert summary["llm_calls"] == 1
    assert summary["tool_calls"] == 1


def test_missing_protected_field_is_loss_not_false_modification():
    score = score_result(
        {"final_status": "low_quality", "cleaned_data": {}},
        {"cve_id": "CVE-2026-1234", "description": "truth"},
        id_field="cve_id",
        damaged_fields=["description"],
    )
    summary = summarize_scores([score], elapsed_seconds=0)

    assert summary["false_modification_rate"] == 0.0
    assert summary["protected_field_loss_rate"] == 1.0


def test_anomaly_files_preserve_source_path_and_identifier(tmp_path):
    original = tmp_path / "input" / "nvd" / "CVE-2026-1234.json"
    original.parent.mkdir(parents=True)
    original.write_text('{"id": "CVE-2026-1234", "descriptions": []}', encoding="utf-8")

    id_only = create_anomaly_file(
        original, tmp_path / "cases", "NVD", "CVE-2026-1234", "id_only"
    )
    empty_body = create_anomaly_file(
        original, tmp_path / "cases", "NVD", "CVE-2026-1234", "empty_body"
    )

    assert "nvd" in {part.lower() for part in id_only.parts}
    assert id_only.read_text(encoding="utf-8") == "CVE-2026-1234"
    assert "CVE-2026-1234" in empty_body.read_text(encoding="utf-8")


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
    assert all(path.is_file() for path in samples.values())


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
