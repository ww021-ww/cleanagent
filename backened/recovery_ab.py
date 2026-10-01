"""Side-effect-free A/B runner for rule-only and Recovery Agent paths."""

import argparse
import asyncio
import copy
import json
import time
from pathlib import Path
from typing import Dict, Iterable, List

from config import load_yaml_config
from graph.controller import LangGraphController


def build_variant_config(config: Dict, recovery_enabled: bool) -> Dict:
    variant = copy.deepcopy(config)
    variant.setdefault("processing", {})["dry_run"] = True
    agentic = variant.setdefault("agentic", {})
    agentic.setdefault("recovery", {})["enabled"] = recovery_enabled
    agentic.setdefault("memory", {})["enabled"] = False
    agentic.setdefault("rag", {})["enabled"] = False
    return variant


def summarize_results(results: List[Dict], elapsed_seconds: float) -> Dict:
    files = len(results)
    anomalies = sum(
        any(event.get("node") == "diagnose_failure" for event in result.get("trace_events", []))
        for result in results
    )
    successes = sum(result.get("final_status") == "success" for result in results)
    recovered = sum(
        result.get("final_status") == "success"
        and any(event.get("node") == "diagnose_failure" for event in result.get("trace_events", []))
        for result in results
    )
    unverified = sum(
        result.get("final_status") == "success"
        and any(event.get("node") == "diagnose_failure" for event in result.get("trace_events", []))
        and (result.get("verification") or {}).get("status") != "accepted"
        for result in results
    )
    total_quality = sum(float(result.get("quality_score", 0.0)) for result in results)
    return {
        "files": files,
        "anomalies": anomalies,
        "successes": successes,
        "success_rate": round(successes / files, 4) if files else 0.0,
        "low_quality": sum(result.get("final_status") == "low_quality" for result in results),
        "recovered": recovered,
        "recovery_rate": round(recovered / anomalies, 4) if anomalies else 0.0,
        "unverified_recoveries": unverified,
        "average_quality": round(total_quality / files, 4) if files else 0.0,
        "llm_calls": sum(result.get("llm_call_count", 0) for result in results),
        "tool_calls": sum(result.get("tool_call_count", 0) for result in results),
        "average_steps": round(
            sum(result.get("step_count", 0) for result in results) / files, 4
        ) if files else 0.0,
        "elapsed_seconds": round(elapsed_seconds, 3),
    }


def compare_results(baseline: Dict, agent: Dict) -> Dict:
    metrics = [
        key for key in (
            "successes", "success_rate", "recovered", "recovery_rate",
            "unverified_recoveries", "average_quality", "recoverable_field_accuracy",
            "safe_block_rate", "false_modification_rate",
            "protected_id_preservation_rate", "llm_calls", "tool_calls",
            "elapsed_seconds",
        )
        if key in baseline and key in agent
    ]
    return {
        "baseline": baseline,
        "agent": agent,
        "delta": {
            key: round(agent[key] - baseline[key], 4)
            for key in metrics
        },
    }


async def _run_variant(paths: Iterable[Path], config: Dict) -> Dict:
    controller = LangGraphController(config)
    started = time.perf_counter()
    results = [await controller.process_file(str(path)) for path in paths]
    return summarize_results(results, time.perf_counter() - started)


async def run_ab(paths: Iterable[Path], config: Dict) -> Dict:
    files = list(paths)
    baseline = await _run_variant(files, build_variant_config(config, False))
    agent = await _run_variant(files, build_variant_config(config, True))
    return compare_results(baseline, agent)


def _files(file_path: str, directory: str, pattern: str) -> List[Path]:
    if file_path:
        return [Path(file_path)]
    return sorted(path for path in Path(directory).rglob(pattern) if path.is_file())


def main() -> None:
    parser = argparse.ArgumentParser(description="对比规则基线与受约束 Recovery Agent")
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--file")
    inputs.add_argument("--directory")
    parser.add_argument("--pattern", default="*.json")
    parser.add_argument("--config", default=str(Path(__file__).parent / "config" / "agent_config.yaml"))
    parser.add_argument("--output")
    args = parser.parse_args()

    paths = _files(args.file, args.directory, args.pattern)
    if not paths:
        parser.error("没有找到待评测文件")
    report = asyncio.run(run_ab(paths, load_yaml_config(args.config)))
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
