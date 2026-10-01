import json

from agent.recovery.planner import ConstrainedRecoveryPlanner
from agent.recovery.tool_registry import RecoveryToolRegistry


class FakeResponse:
    def __init__(self, tool_calls):
        self.tool_calls = tool_calls


class FakeToolModel:
    def __init__(self, tool_calls=None, error=None):
        self.tool_calls = tool_calls or []
        self.error = error
        self.bound_schemas = []
        self.messages = []

    def bind_tools(self, schemas):
        self.bound_schemas = schemas
        return self

    def invoke(self, messages):
        self.messages = messages
        if self.error:
            raise self.error
        return FakeResponse(self.tool_calls)


def context():
    return {
        "failure_profile": {
            "failure_type": "missing_required_fields",
            "missing_fields": ["description"],
            "quality_score": 0.3,
            "source": "CVE",
        },
        "observations": [
            {
                "tool_name": "search_raw_text",
                "success": False,
                "error": "no_evidence_found",
                "data": "SECRET_OBSERVATION_DATA",
            }
        ],
        "remaining_budget": {"steps": 2, "tools": 4, "llm": 1},
        "raw_content": "SECRET_RAW_CONTENT",
        "candidate": {"private": "SECRET_CANDIDATE"},
        "api_key": "SECRET_API_KEY",
    }


def test_planner_maps_one_allowed_tool_call_to_structured_decision():
    model = FakeToolModel(
        [
            {
                "name": "search_raw_text",
                "args": {"field_hint": "description", "keywords": ["summary"]},
                "id": "call-1",
                "type": "tool_call",
            }
        ]
    )
    planner = ConstrainedRecoveryPlanner(model, RecoveryToolRegistry())

    result = planner.plan(context())

    assert result.decision == "CALL_TOOL"
    assert result.tool_name == "search_raw_text"
    assert result.target_fields == ["description"]
    assert result.reason_code == "tool_selected"
    assert [schema["function"]["name"] for schema in model.bound_schemas] == [
        "search_raw_text",
        "parse_json_path",
        "normalize_field",
        "nvd_lookup",
        "recovery_control",
    ]


def test_planner_maps_control_call_without_exposing_free_form_execution():
    model = FakeToolModel(
        [
            {
                "name": "recovery_control",
                "args": {"decision": "REVIEW", "reason_code": "authority_conflict"},
                "id": "call-2",
                "type": "tool_call",
            }
        ]
    )

    result = ConstrainedRecoveryPlanner(model, RecoveryToolRegistry()).plan(context())

    assert result.decision == "REVIEW"
    assert result.reason_code == "authority_conflict"
    assert result.tool_name is None


def test_planner_safely_stops_on_missing_unknown_or_invalid_tool_calls():
    cases = [
        ([], "no_tool_call"),
        ([{"name": "shell", "args": {"command": "whoami"}}], "unknown_tool"),
        (
            [
                {
                    "name": "search_raw_text",
                    "args": {
                        "field_hint": "description",
                        "keywords": [],
                        "command": "whoami",
                    },
                }
            ],
            "invalid_tool_args",
        ),
    ]

    for tool_calls, expected_reason in cases:
        result = ConstrainedRecoveryPlanner(
            FakeToolModel(tool_calls), RecoveryToolRegistry()
        ).plan(context())
        assert result.decision == "STOP"
        assert result.reason_code == expected_reason


def test_planner_safely_stops_on_model_error():
    result = ConstrainedRecoveryPlanner(
        FakeToolModel(error=TimeoutError("model timeout")),
        RecoveryToolRegistry(),
    ).plan(context())

    assert result.decision == "STOP"
    assert result.reason_code == "planner_error"


def test_planner_context_excludes_raw_candidate_secrets_and_tool_data():
    model = FakeToolModel([])
    ConstrainedRecoveryPlanner(model, RecoveryToolRegistry()).plan(context())

    serialized = json.dumps(model.messages, ensure_ascii=False)
    assert "SECRET_RAW_CONTENT" not in serialized
    assert "SECRET_CANDIDATE" not in serialized
    assert "SECRET_API_KEY" not in serialized
    assert "SECRET_OBSERVATION_DATA" not in serialized
    assert "missing_required_fields" in serialized
