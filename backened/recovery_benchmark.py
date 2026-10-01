"""Dry-run benchmark separating evidence recovery from safe blocking."""

import argparse
import asyncio
import json
import re
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

from config import FieldConfigLoader, get_env_loader, load_yaml_config
from graph.controller import LangGraphController
from recovery_ab import build_variant_config, compare_results


SOURCE_DIRS = {
    "CVE": ("json/cves", "json/cve", "html/cve"),
    "NVD": ("json/nvd", "html/nvd"),
    "CNVD": ("json/cnvd", "html/cnvd"),
    "CISA": ("json/cisa", "html/cisa"),
    "CERT": ("json/cert", "html/cert"),
    "JVN": ("json/jvn", "html/jvn"),
}
MUTATIONS = ("layout_drift", "missing_evidence")


def require_llm_config(llm_config: Dict) -> None:
    if not llm_config.get("api_key"):
        raise ValueError("OPENAI_API_KEY is required for the Agent benchmark")


def discover_samples(data_root: Path) -> Dict[str, Path]:
    samples = {}
    for source, directories in SOURCE_DIRS.items():
        for relative in directories:
            directory = data_root / relative
            files = (
                sorted(
                    path
                    for path in directory.rglob("*")
                    if path.is_file()
                    and path.suffix.lower() in {".json", ".html", ".htm"}
                )
                if directory.exists()
                else []
            )
            if files:
                samples[source] = files[0]
                break
    return samples


def case_is_auto_recoverable(source: str, path) -> bool:
    return Path(path).suffix.lower() == ".json"


def _path_tokens(json_path: str):
    return [
        int(index) if index else key
        for key, index in re.findall(r"([^.\[\]]+)|\[(\d+)\]", json_path)
    ]


def _pop_json_path(payload, json_path: str):
    tokens = _path_tokens(json_path)
    current = payload
    for token in tokens[:-1]:
        current = current[token]
    final = tokens[-1]
    if isinstance(final, int):
        value = current[final]
        current.pop(final)
        return value
    return current.pop(final)


def create_anomaly_file(
    original: Path,
    output_root: Path,
    source: str,
    mutation: str,
    *,
    target_field: str,
    source_json_path: str | None = None,
    identifier: str | None = None,
) -> Path:
    target = output_root / source.lower() / mutation / original.name
    target.parent.mkdir(parents=True, exist_ok=True)
    if original.suffix.lower() != ".json":
        if mutation != "missing_evidence":
            raise ValueError("HTML samples are not auto-recoverable")
        target.write_text(f"<html><body>{identifier or ''}</body></html>", encoding="utf-8")
        return target
    if not source_json_path:
        raise ValueError("source_json_path is required for JSON mutations")

    payload = json.loads(original.read_text(encoding="utf-8"))
    evidence = _pop_json_path(payload, source_json_path)
    if mutation == "layout_drift":
        payload.setdefault("recovery_evidence", {})[target_field] = evidence
    elif mutation != "missing_evidence":
        raise ValueError(f"Unsupported mutation: {mutation}")
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return target


def _same(left: Any, right: Any) -> bool:
    if isinstance(left, str) and isinstance(right, str):
        return " ".join(left.split()) == " ".join(right.split())
    return left == right


def score_result(
    result: Dict,
    truth: Dict,
    id_field: str,
    damaged_fields: Iterable[str],
    *,
    mutation: str,
    auto_recoverable: bool,
) -> Dict:
    candidate = result.get("cleaned_data") or {}
    expected = [field for field in damaged_fields if truth.get(field) not in (None, "")]
    recoverable = mutation == "layout_drift" and auto_recoverable
    safe_case = mutation == "missing_evidence" or not auto_recoverable
    blocked = (
        result.get("final_status") != "success"
        or result.get("final_decision") in {"REVIEW", "ABORT"}
    )
    false_modification = any(
        candidate.get(field) not in (None, "")
        and not _same(candidate.get(field), truth[field])
        for field in expected
    )
    protected = truth.get(id_field) not in (None, "")
    return {
        "recoverable_fields": len(expected) if recoverable else 0,
        "correctly_recovered_fields": (
            sum(_same(candidate.get(field), truth[field]) for field in expected)
            if recoverable
            else 0
        ),
        "safe_cases": int(safe_case),
        "safely_blocked": int(safe_case and blocked),
        "false_modifications": int(false_modification),
        "protected_ids": int(protected),
        "protected_ids_preserved": int(
            protected and _same(candidate.get(id_field), truth[id_field])
        ),
        "llm_calls": int(result.get("llm_call_count", 0)),
        "tool_calls": int(result.get("tool_call_count", 0)),
    }


def summarize_scores(scores: List[Dict], elapsed_seconds: float) -> Dict:
    recoverable = sum(score["recoverable_fields"] for score in scores)
    safe_cases = sum(score["safe_cases"] for score in scores)
    protected = sum(score["protected_ids"] for score in scores)
    cases = len(scores)
    return {
        "cases": cases,
        "recoverable_field_accuracy": round(
            sum(score["correctly_recovered_fields"] for score in scores) / recoverable,
            4,
        ) if recoverable else 0.0,
        "safe_block_rate": round(
            sum(score["safely_blocked"] for score in scores) / safe_cases, 4
        ) if safe_cases else 0.0,
        "false_modification_rate": round(
            sum(score["false_modifications"] for score in scores) / cases, 4
        ) if cases else 0.0,
        "protected_id_preservation_rate": round(
            sum(score["protected_ids_preserved"] for score in scores) / protected,
            4,
        ) if protected else 0.0,
        "llm_calls": sum(score["llm_calls"] for score in scores),
        "tool_calls": sum(score["tool_calls"] for score in scores),
        "elapsed_seconds": round(elapsed_seconds, 3),
    }


def write_report(report: Dict, output: Path) -> None:
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def _benchmark_config(config: Dict, agent_loop_enabled: bool) -> Dict:
    runtime = build_variant_config(config, agent_loop_enabled)
    for module in ("planner", "chat", "skills", "tools"):
        runtime.setdefault("agentic", {}).setdefault(module, {})["enabled"] = False
    return runtime


async def _process(paths: List[Path], config: Dict, workers: int = 3):
    controller = LangGraphController(config)
    semaphore = asyncio.Semaphore(workers)

    async def process(path: Path) -> Dict:
        async with semaphore:
            return await controller.process_file(str(path))

    started = time.perf_counter()
    results = await asyncio.gather(*(process(path) for path in paths))
    return results, time.perf_counter() - started


def _description_fields(config: Dict, source: str, truth: Dict) -> List[str]:
    profile = (
        config.get("agentic", {})
        .get("quality_gate", {})
        .get("profiles", {})
        .get(source.lower(), {})
    )
    aliases = profile.get("required_any", {}).get("description", [])
    return [field for field in aliases if truth.get(field) not in (None, "")]


def _json_path(field_config, source: str, target_field: str):
    for field in field_config.get_source_config(source).get("fields", []):
        if field.get("name") != target_field:
            continue
        for rule in field.get("extraction_rules", []):
            if rule.get("json_path"):
                return rule["json_path"]
    return None


async def run_benchmark(
    data_root: Path,
    config: Dict,
    cases_per_source: int = 2,
    workers: int = 3,
) -> Dict:
    samples = discover_samples(data_root)
    missing = sorted(set(SOURCE_DIRS) - set(samples))
    if missing:
        raise ValueError(f"Missing source samples: {', '.join(missing)}")

    originals = list(samples.values())
    baseline_results, _ = await _process(
        originals, _benchmark_config(config, False), workers
    )
    field_config = FieldConfigLoader(
        str(Path(__file__).parent / "config" / "field_mappings.yaml")
    )

    with tempfile.TemporaryDirectory(prefix="recovery-benchmark-") as temporary:
        paths, cases = [], []
        for (source, original), truth_result in zip(samples.items(), baseline_results):
            truth = truth_result.get("cleaned_data") or {}
            id_field = field_config.get_id_field(source)
            damaged_fields = _description_fields(config, source, truth)
            if not truth.get(id_field) or not damaged_fields:
                raise ValueError(f"Baseline lacks benchmark fields for {source}: {original}")
            auto_recoverable = case_is_auto_recoverable(source, original)
            mutations = MUTATIONS[:cases_per_source] if auto_recoverable else ("missing_evidence",)
            target_field = damaged_fields[0]
            source_path = _json_path(field_config, source, target_field)
            if auto_recoverable and not source_path:
                raise ValueError(f"No JSON evidence path for {source}.{target_field}")
            for mutation in mutations:
                paths.append(
                    create_anomaly_file(
                        original,
                        Path(temporary),
                        source,
                        mutation,
                        target_field=target_field,
                        source_json_path=source_path,
                        identifier=str(truth[id_field]),
                    )
                )
                cases.append(
                    {
                        "source": source,
                        "mutation": mutation,
                        "truth": truth,
                        "id_field": id_field,
                        "damaged_fields": damaged_fields,
                        "auto_recoverable": auto_recoverable,
                    }
                )

        baseline_results, baseline_elapsed = await _process(
            paths, _benchmark_config(config, False), workers
        )
        agent_results, agent_elapsed = await _process(
            paths, _benchmark_config(config, True), workers
        )

    baseline_scores, agent_scores, details = [], [], []
    for case, baseline_result, agent_result in zip(cases, baseline_results, agent_results):
        args = (case["truth"], case["id_field"], case["damaged_fields"])
        kwargs = {
            "mutation": case["mutation"],
            "auto_recoverable": case["auto_recoverable"],
        }
        baseline_score = score_result(baseline_result, *args, **kwargs)
        agent_score = score_result(agent_result, *args, **kwargs)
        baseline_scores.append(baseline_score)
        agent_scores.append(agent_score)
        details.append(
            {
                "source": case["source"],
                "mutation": case["mutation"],
                "auto_recoverable": case["auto_recoverable"],
                "baseline": baseline_score,
                "agent": agent_score,
            }
        )

    comparison = compare_results(
        summarize_scores(baseline_scores, baseline_elapsed),
        summarize_scores(agent_scores, agent_elapsed),
    )
    return {
        "sources": sorted(samples),
        "cases": len(cases),
        "dry_run": True,
        **comparison,
        "details": details,
    }


def main() -> None:
    script_dir = Path(__file__).parent
    parser = argparse.ArgumentParser(
        description="使用真实样本对比规则基线与证据约束 Recovery Agent"
    )
    parser.add_argument("--data-root", type=Path, default=script_dir)
    parser.add_argument(
        "--config", type=Path, default=script_dir / "config" / "agent_config.yaml"
    )
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--cases-per-source", type=int, choices=(1, 2), default=2)
    parser.add_argument("--workers", type=int, choices=range(1, 7), default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    loader = get_env_loader(str(args.env_file) if args.env_file else None)
    require_llm_config(loader.get_llm_config())
    report = asyncio.run(
        run_benchmark(
            args.data_root,
            load_yaml_config(str(args.config)),
            args.cases_per_source,
            args.workers,
        )
    )
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        write_report(report, args.output)
    print(text)


if __name__ == "__main__":
    main()
