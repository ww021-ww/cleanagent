"""Code-level authorization for model-proposed recovery actions."""

from typing import Any, Dict, Union

from pydantic import ValidationError

from .models import (
    ActionRejection,
    AuthorizedAction,
    RecoveryBudget,
    RecoveryDecision,
)
from .tool_registry import RecoveryToolRegistry


class RecoveryActionGuard:
    def __init__(self, budget: RecoveryBudget):
        self.budget = budget

    def authorize(
        self,
        decision: RecoveryDecision,
        state: Dict[str, Any],
        registry: RecoveryToolRegistry,
        now: float = None,
    ) -> Union[AuthorizedAction, ActionRejection]:
        # Graph counters already include the Planner call that produced this action.
        current_call = state.get("recovery_decision") == decision.model_dump()
        if self.budget.is_exhausted(
            max(0, state.get("step_count", 0) - int(current_call)),
            state.get("tool_call_count", 0),
            max(0, state.get("llm_call_count", 0) - int(current_call)),
            state.get("deadline_at", 0.0),
            now=now,
        ):
            return ActionRejection(reason_code="budget_exhausted")
        if decision.decision != "CALL_TOOL" or not decision.tool_name:
            return ActionRejection(reason_code="decision_not_action")

        specs = {spec.name: spec for spec in registry.describe_allowed(state)}
        spec = specs.get(decision.tool_name)
        if not spec:
            return ActionRejection(reason_code="unknown_tool")
        try:
            args = registry.validate_args(decision.tool_name, decision.tool_args)
        except (ValidationError, ValueError) as exc:
            return ActionRejection(reason_code="invalid_tool_args", details=str(exc))

        if "*" not in spec.allowed_fields and any(
            field not in spec.allowed_fields for field in decision.target_fields
        ):
            return ActionRejection(reason_code="field_not_allowed")
        if not self._targets_match_args(decision, args):
            return ActionRejection(reason_code="target_mismatch")

        candidate = state.get("cleaned_data") or state.get("candidate") or {}
        if decision.tool_name == "nvd_lookup":
            known_ids = {
                str(value).upper()
                for key, value in candidate.items()
                if value and "cve" in key.lower() and "id" in key.lower()
            }
            if args["cve_id"].upper() not in known_ids:
                return ActionRejection(reason_code="identifier_mismatch")
        if decision.tool_name == "normalize_field":
            if candidate.get(args["field"]) != args["value"]:
                return ActionRejection(reason_code="value_not_from_candidate")

        return AuthorizedAction(
            tool_name=decision.tool_name,
            tool_args=args,
            target_fields=decision.target_fields,
        )

    @staticmethod
    def _targets_match_args(
        decision: RecoveryDecision, args: Dict[str, Any]
    ) -> bool:
        if decision.tool_name == "search_raw_text":
            return decision.target_fields == [args["field_hint"]]
        if decision.tool_name == "parse_json_path":
            return decision.target_fields == [args["target_field"]]
        if decision.tool_name == "normalize_field":
            return decision.target_fields == [args["field"]]
        if decision.tool_name == "nvd_lookup":
            return set(decision.target_fields) == set(args["target_fields"])
        return False
