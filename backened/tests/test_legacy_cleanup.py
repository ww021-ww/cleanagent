import asyncio
from pathlib import Path

from agent.extractor import SourceExtractor
from agent.memory import AgentMemory
from graph.builder import build_vuln_processing_graph
from graph.controller import LangGraphController


def test_production_graph_has_no_reflect_node():
    graph = build_vuln_processing_graph(
        {
            "agents": {"cleaner_validator": {"quality_threshold": 0.5}},
            "agentic": {"recovery": {"enabled": True}},
        }
    )

    assert "reflect" not in graph.get_graph().nodes


def test_source_extractor_html_path_never_calls_llm_fallback():
    class ForbiddenLLM:
        calls = 0

        def invoke(self, prompt):
            self.calls += 1
            raise AssertionError("deterministic extraction must not call the LLM")

    llm = ForbiddenLLM()
    extractor = SourceExtractor(
        "NVD",
        {
            "fields": [
                {
                    "name": "cve_id",
                    "required": True,
                    "extraction_rules": [{"regex": r"CVE-\d{4}-\d+"}],
                }
            ]
        },
        llm,
    )

    result = extractor.extract_from_html("<html><body>no vulnerability id</body></html>")

    assert result == {}
    assert llm.calls == 0


def test_directory_processing_keeps_deterministic_small_file_order(tmp_path):
    large = tmp_path / "a-large.json"
    small = tmp_path / "z-small.json"
    large.write_text("x" * 100, encoding="utf-8")
    small.write_text("x", encoding="utf-8")
    order = []

    controller = LangGraphController.__new__(LangGraphController)
    controller.storage_agent = None
    controller.extractor_agent = None
    controller.memory = None
    controller.planner = None
    controller.stats = {
        "total": 0,
        "success": 0,
        "failed": 0,
        "low_quality": 0,
        "skipped": 0,
        "review_pending": 0,
        "start_time": None,
        "end_time": None,
    }

    async def process_file(path):
        order.append(Path(path).name)
        return {"final_status": "success"}

    controller.process_file = process_file
    asyncio.run(
        controller.process_directory(str(tmp_path), pattern="*.json", max_workers=1)
    )

    assert order == ["z-small.json", "a-large.json"]


def test_memory_keeps_dedup_and_quality_without_strategy_recommendation(tmp_path):
    memory = AgentMemory({"persist_file": str(tmp_path / "memory.json")})
    memory.mark_seen("CVE-2026-5001", "CVE")
    memory.record_success("CVE", quality_score=0.9)
    memory.record_failure("CVE")
    memory.end_batch()

    profile = memory.get_source_profile("CVE")
    persisted = (tmp_path / "memory.json").read_text(encoding="utf-8")

    assert memory.is_seen("CVE-2026-5001", "CVE")
    assert profile["total_processed"] == 2
    assert profile["total_success"] == 1
    assert profile["total_failed"] == 1
    assert profile["avg_quality"] == 0.9
    assert not hasattr(memory, "get_recommended_strategy")
    assert "strategy_effectiveness" not in persisted
    assert "best_strategy" not in persisted
