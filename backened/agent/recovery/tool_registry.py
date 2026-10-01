"""Small, schema-validated tool registry for recovery actions."""

import json
import re
import time
from datetime import date
from typing import Any, Callable, Dict, List, Type

from pydantic import Field

from tools.builtin import nvd_lookup

from .models import StrictModel, ToolResult, ToolSpec


class SearchRawTextArgs(StrictModel):
    field_hint: str
    keywords: List[str] = Field(default_factory=list)


class ParseJsonPathArgs(StrictModel):
    path: str = Field(pattern=r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*$")
    target_field: str


class NormalizeFieldArgs(StrictModel):
    field: str
    value: Any


class NvdLookupArgs(StrictModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")
    target_fields: List[str] = Field(min_length=1)


class RecoveryToolRegistry:
    """Expose four bounded tools through one validation/result contract."""

    def __init__(
        self,
        nvd_lookup_fn: Callable = nvd_lookup,
        nvd_api_key: str = "",
        max_result_chars: int = 2000,
    ):
        self.nvd_lookup_fn = nvd_lookup_fn
        self.nvd_api_key = nvd_api_key
        self.max_result_chars = max(1, int(max_result_chars))
        self._arg_models: Dict[str, Type[StrictModel]] = {
            "search_raw_text": SearchRawTextArgs,
            "parse_json_path": ParseJsonPathArgs,
            "normalize_field": NormalizeFieldArgs,
            "nvd_lookup": NvdLookupArgs,
        }
        self._handlers = {
            "search_raw_text": self._search_raw_text,
            "parse_json_path": self._parse_json_path,
            "normalize_field": self._normalize_field,
            "nvd_lookup": self._nvd_lookup,
        }

    def describe_allowed(self, context: Dict[str, Any]) -> List[ToolSpec]:
        local_fields = [
            "title", "description", "overview", "impact", "solutions",
            "affected_products", "affected_versions", "repair_suggestion",
        ]
        descriptions = {
            "search_raw_text": "Locate evidence in the current input text",
            "parse_json_path": "Read one value from the current JSON input",
            "normalize_field": "Normalize an existing precise field value",
            "nvd_lookup": "Read official structured fields for a real CVE ID",
        }
        allowed = {
            "search_raw_text": local_fields,
            "parse_json_path": local_fields,
            "normalize_field": ["*"],
            "nvd_lookup": [
                "cve_id", "description", "cvss_score", "published", "references"
            ],
        }
        return [
            ToolSpec(
                name=name,
                description=descriptions[name],
                args_schema=model.model_json_schema(),
                allowed_fields=allowed[name],
                external=name == "nvd_lookup",
            )
            for name, model in self._arg_models.items()
        ]

    def validate_args(self, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        if name not in self._arg_models:
            raise ValueError("unknown_tool")
        return self._arg_models[name].model_validate(args).model_dump()

    def invoke(
        self, name: str, args: Dict[str, Any], context: Dict[str, Any]
    ) -> ToolResult:
        started = time.perf_counter()
        try:
            validated = self.validate_args(name, args)
            payload = self._handlers[name](validated, context)
            payload["data"] = {
                key: self._bound_value(value)
                for key, value in payload.get("data", {}).items()
            }
            return ToolResult(
                success=True,
                tool_name=name,
                latency_ms=(time.perf_counter() - started) * 1000,
                **payload,
            )
        except Exception as exc:
            return ToolResult(
                success=False,
                tool_name=name,
                latency_ms=(time.perf_counter() - started) * 1000,
                error=str(exc),
            )

    def _clip(self, value: Any) -> str:
        text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        return text[: self.max_result_chars]

    def _bound_value(self, value: Any) -> Any:
        serialized = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        return value if len(serialized) <= self.max_result_chars else serialized[: self.max_result_chars]

    def _search_raw_text(
        self, args: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        content = context.get("raw_content", "")
        terms = [*args["keywords"], args["field_hint"]]
        positions = [content.lower().find(term.lower()) for term in terms if term]
        positions = [position for position in positions if position >= 0]
        if not positions:
            raise ValueError("no_evidence_found")
        start = min(positions)
        snippet_start = max(0, start - 30)
        snippet = self._clip(content[snippet_start:start + self.max_result_chars])
        return {
            "data": {args["field_hint"]: snippet},
            "evidence": snippet,
            "source_name": "current_file",
            "evidence_location": f"chars:{snippet_start}-{snippet_start + len(snippet)}",
        }

    def _parse_json_path(
        self, args: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        value: Any = json.loads(context.get("raw_content", ""))
        for part in args["path"].split("."):
            value = value[int(part)] if isinstance(value, list) else value[part]
        evidence = self._clip(value)
        return {
            "data": {args["target_field"]: value},
            "evidence": evidence,
            "source_name": "current_file",
            "evidence_location": f"json:{args['path']}",
        }

    def _normalize_field(
        self, args: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        field = args["field"]
        value = args["value"]
        lower = field.lower()
        if lower.endswith("id") or lower.endswith("_id"):
            normalized = str(value).strip().upper()
            patterns = (
                r"CVE-\d{4}-\d{4,}",
                r"CNVD-\d{4}-\d+",
                r"JVN(?:VU)?#?\d+",
            )
            if not any(re.fullmatch(pattern, normalized) for pattern in patterns):
                raise ValueError("invalid_identifier")
        elif "date" in lower or lower.endswith("_at"):
            normalized = date.fromisoformat(str(value).strip().replace("/", "-")).isoformat()
        elif "cvss" in lower and "score" in lower:
            normalized = float(value)
            if not 0 <= normalized <= 10:
                raise ValueError("invalid_cvss_score")
        elif "cvss" in lower and "vector" in lower:
            normalized = str(value).strip().upper()
            if not (normalized.startswith("CVSS:") or "/AV:" in normalized):
                raise ValueError("invalid_cvss_vector")
        else:
            raise ValueError("unsupported_normalization")
        return {
            "data": {field: normalized},
            "evidence": self._clip(value),
            "source_name": "deterministic_normalizer",
            "evidence_location": f"candidate:{field}",
        }

    def _nvd_lookup(
        self, args: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        record = self.nvd_lookup_fn(args["cve_id"], self.nvd_api_key)
        if not record:
            raise ValueError("nvd_not_found")
        data = {
            field: record[field]
            for field in args["target_fields"]
            if record.get(field) is not None
        }
        if not data:
            raise ValueError("requested_fields_not_found")
        return {
            "data": data,
            "evidence": self._clip(data),
            "source_name": "NVD",
            "source_url": f"https://nvd.nist.gov/vuln/detail/{args['cve_id']}",
            "evidence_location": "NVD API 2.0",
        }
