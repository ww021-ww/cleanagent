import json
from pathlib import Path

import yaml

from graph.builder import route_after_clean
from graph.recovery_nodes import diagnose_failure_node
from graph.state import create_initial_state


CASES = json.loads(
    (Path(__file__).parent / "fixtures" / "recovery_cases.json").read_text(
        encoding="utf-8"
    )
)
CONFIG_PATH = Path(__file__).parents[1] / "config" / "agent_config.yaml"


def test_recovery_cases_keep_normal_path_and_classify_anomalies():
    config = {
        "agents": {"cleaner_validator": {"quality_threshold": 0.7}},
        "agentic": {"recovery": {"enabled": True}},
    }

    for case in CASES:
        assert route_after_clean(case, config) == case["expected_route"]
        if case["expected_failure"] is None:
            continue

        state = create_initial_state(case["name"], f"{case['name']}.json")
        state.update(
            source=case["source"],
            cleaned_data=case["candidate"],
            validation_result=case["validation"],
            quality_score=case["quality_score"],
        )
        result = diagnose_failure_node(state, {})
        assert result["failure_profile"]["failure_type"] == case["expected_failure"]
        assert result["trace_events"][-1]["reason_code"] == case["expected_failure"]


def test_prompt_injection_is_data_not_a_trace_instruction():
    case = next(item for item in CASES if item["name"] == "prompt_injection_text")
    state = create_initial_state(case["name"], "prompt.json")
    state.update(
        source=case["source"],
        cleaned_data=case["candidate"],
        validation_result=case["validation"],
        quality_score=case["quality_score"],
    )

    result = diagnose_failure_node(state, {})

    assert result["trace_events"][-1]["reason_code"] == "missing_required_fields"
    assert "Ignore validation" not in json.dumps(result["trace_events"])


def test_phase_one_recovery_config_is_bounded():
    config = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))

    assert config["agentic"]["recovery"] == {
        "enabled": True,
        "agent_loop_enabled": False,
        "trace_max_chars": 512,
        "max_steps": 3,
        "max_tool_calls": 5,
        "max_llm_calls": 2,
        "deadline_seconds": 30,
        "tool_timeout_seconds": 8,
        "max_result_chars": 2000,
    }
