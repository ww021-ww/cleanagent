"""Dry-run benchmark for controlled vulnerability-record anomalies."""

import argparse
import asyncio
import json
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List

from config import FieldConfigLoader, get_env_loader, load_yaml_config
from graph.controller import LangGraphController
from recovery_ab import build_variant_config


SOURCE_DIRS = {
    "CVE": ("json/cves", "json/cve", "html/cve"),
    "NVD": ("json/nvd", "html/nvd"),
    "CNVD": ("json/cnvd", "html/cnvd"),
    "CISA": ("json/cisa", "html/cisa"),
    "CERT": ("json/cert", "html/cert"),
    "JVN": ("json/jvn", "html/jvn"),
}
MUTATIONS = ("id_only", "empty_body")


def require_llm_config(llm_config: Dict) -> None:
    if not llm_config.get("api_key"):
        raise ValueError("OPENAI_API_KEY is required for the Agent benchmark")


def discover_samples(data_root: Path) -> Dict[str, Path]:
    samples = {}
    for source, directories in SOURCE_DIRS.items():
        for relative in directories:
            directory = data_root / relative
            files = sorted(
                path for path in directory.rglob("*")
                if path.is_file() and path.suffix.lower() in {".json", ".html", ".htm"}
            ) if directory.exists() else []
            if files:
                samples[source] = files[0]
                break
    return samples


def create_anomaly_file(
    original: Path,
    output_root: Path,
    source: str,
    identifier: str,
    mutation: str,
) -> Path:
    target = output_root / source.lower() / mutation / original.name
    target.parent.mkdir(parents=True, exist_ok=True)
    if mutation == "id_only":
        content = identifier
    elif mutation == "empty_body":
        content = f"<html><body>{identifier}</body></html>"
    else:
        raise ValueError(f"Unsupported mutation: {mutation}")
    target.write_text(content, encoding="utf-8")
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
) -> Dict:
    candidate = result.get("cleaned_data") or {}
    expected = [field for field in damaged_fields if truth.get(field) not in (None, "")]
    recovered = sum(_same(candidate.get(field), truth[field]) for field in expected)
    protected = int(truth.get(id_field) not in (None, ""))
    actual_id = candidate.get(id_field)
    false_modifications = int(
        protected
        and actual_id not in (None, "")
        and not _same(actual_id, truth[id_field])
    )
    protected_field_losses = int(protected and actual_id in (None, ""))
    detected = any(
        event.get("node") == "diagnose_failure"
        for event in result.get("trace_events", [])
    )
    final_decision = result.get("final_decision")
    review_or_abort = (
        result.get("final_status") != "success"
        or final_decision in {"REVIEW", "ABORT"}
    )
    return {
        "detected": int(detected),
        "expected_fields": len(expected),
        "recovered_fields": recovered,
        "protected_fields": protected,
        "false_modifications": false_modifications,
        "protected_field_losses": protected_field_losses,
        "review_or_abort": int(review_or_abort),
        "llm_calls": int(result.get("llm_call_count", 0)),
        "tool_calls": int(result.get("tool_call_count", 0)),
    }


def summarize_scores(scores: List[Dict], elapsed_seconds: float) -> Dict:
    cases = len(scores)
    expected = sum(score["expected_fields"] for score in scores)
    protected = sum(score["protected_fields"] for score in scores)
    return {
        "cases": cases,
        "anomaly_detection_rate": round(
            sum(score["detected"] for score in scores) / cases, 4
        ) if cases else 0.0,
        "field_recovery_accuracy": round(
            sum(score["recovered_fields"] for score in scores) / expected, 4
        ) if expected else 0.0,
        "false_modification_rate": round(
            sum(score["false_modifications"] for score in scores) / protected, 4
        ) if protected else 0.0,
        "protected_field_loss_rate": round(
            sum(score["protected_field_losses"] for score in scores) / protected, 4
        ) if protected else 0.0,
        "review_or_abort_rate": round(
            sum(score["review_or_abort"] for score in scores) / cases, 4
        ) if cases else 0.0,
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


async def _process(
    paths: List[Path], config: Dict, workers: int = 3
) -> tuple[List[Dict], float]:
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

    baseline_config = _benchmark_config(config, False)
    baseline_config["agentic"]["recovery"]["enabled"] = False
    baseline_config.setdefault("agentic", {}).setdefault("reflection", {})[
        "enabled"
    ] = False
    originals = list(samples.values())
    baseline_results, _ = await _process(originals, baseline_config, workers)
    field_config = FieldConfigLoader(
        str(Path(__file__).parent / "config" / "field_mappings.yaml")
    )

    with tempfile.TemporaryDirectory(prefix="recovery-benchmark-") as temporary:
        case_paths = []
        cases = []
        for (source, original), truth_result in zip(samples.items(), baseline_results):
            truth = truth_result.get("cleaned_data") or {}
            id_field = field_config.get_id_field(source)
            identifier = truth.get(id_field)
            damaged_fields = _description_fields(config, source, truth)
            if not identifier or not damaged_fields:
                raise ValueError(
                    f"Baseline lacks benchmark fields for {source}: {original}"
                )
            for mutation in MUTATIONS[:cases_per_source]:
                path = create_anomaly_file(
                    original, Path(temporary), source, str(identifier), mutation
                )
                case_paths.append(path)
                cases.append({
                    "source": source,
                    "original": str(original),
                    "mutation": mutation,
                    "truth": truth,
                    "id_field": id_field,
                    "damaged_fields": damaged_fields,
                })

        legacy_results, legacy_elapsed = await _process(
            case_paths, _benchmark_config(config, False), workers
        )
        agent_results, agent_elapsed = await _process(
            case_paths, _benchmark_config(config, True), workers
        )

    legacy_scores = []
    agent_scores = []
    details = []
    for case, legacy_result, agent_result in zip(
        cases, legacy_results, agent_results
    ):
        args = (
            case["truth"], case["id_field"], case["damaged_fields"]
        )
        legacy_score = score_result(legacy_result, *args)
        agent_score = score_result(agent_result, *args)
        legacy_scores.append(legacy_score)
        agent_scores.append(agent_score)
        details.append({
            "source": case["source"],
            "mutation": case["mutation"],
            "legacy": legacy_score,
            "agent": agent_score,
        })

    legacy = summarize_scores(legacy_scores, legacy_elapsed)
    agent = summarize_scores(agent_scores, agent_elapsed)
    return {
        "sources": sorted(samples),
        "cases": len(cases),
        "dry_run": True,
        "legacy": legacy,
        "agent": agent,
        "delta": {
            metric: round(agent[metric] - legacy[metric], 4)
            for metric in (
                "anomaly_detection_rate",
                "field_recovery_accuracy",
                "false_modification_rate",
                "protected_field_loss_rate",
                "review_or_abort_rate",
                "llm_calls",
                "tool_calls",
                "elapsed_seconds",
            )
        },
        "details": details,
    }


def main() -> None:
    script_dir = Path(__file__).parent
    parser = argparse.ArgumentParser(
        description="使用真实样本生成受控异常并对比旧流程与 Recovery Agent"
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
