"""Evidence-first verification; this module never mutates the candidate."""

from typing import Any, Dict, List

from .models import (
    AuthorizedAction,
    FieldPatch,
    ToolResult,
    VerificationResult,
)


class EvidenceVerifier:
    def __init__(self, field_config_loader):
        self.field_config_loader = field_config_loader

    def verify(
        self,
        candidate: Dict[str, Any],
        action: AuthorizedAction,
        result: ToolResult,
        source: str,
    ) -> VerificationResult:
        if not result.success:
            return self._rejected("tool_failed", action.target_fields)
        if result.tool_name != action.tool_name:
            return self._rejected("tool_result_mismatch", action.target_fields)
        if not result.evidence or not result.evidence_location or not result.source_name:
            return self._rejected("evidence_missing", action.target_fields)

        patches: List[FieldPatch] = []
        review = action.tool_name == "search_raw_text"
        for field in action.target_fields:
            if field not in result.data or result.data[field] in (None, ""):
                continue
            authoritative = self._is_authoritative(field, source)
            if authoritative and not self._trusted_for_authoritative(
                action, result, candidate, field
            ):
                return self._rejected("authoritative_source_required", [field])

            old_value = candidate.get(field)
            conflicts = authoritative and old_value not in (None, "") and old_value != result.data[field]
            review = review or conflicts
            patches.append(
                FieldPatch(
                    field=field,
                    old_value=old_value,
                    proposed_value=result.data[field],
                    method=action.tool_name,
                    source_name=result.source_name,
                    source_url=result.source_url,
                    evidence=result.evidence,
                    evidence_location=result.evidence_location,
                    confidence=1.0 if authoritative else 0.9,
                    verification_status=(
                        "review"
                        if conflicts or action.tool_name == "search_raw_text"
                        else "accepted"
                    ),
                )
            )

        if not patches:
            return self._rejected("target_value_missing", action.target_fields)
        return VerificationResult(
            status="review" if review else "accepted",
            reason_code=(
                "raw_text_requires_review"
                if action.tool_name == "search_raw_text"
                else "authoritative_conflict" if review else "evidence_supported"
            ),
            accepted_patches=patches,
            rejected_fields=[],
        )

    def _is_authoritative(self, field: str, source: str) -> bool:
        lower = field.lower()
        id_field = self.field_config_loader.get_id_field(source)
        return (
            field == id_field
            or lower.endswith("_id")
            or "cvss" in lower
            or "cwe" in lower
            or "date" in lower
            or "published" in lower
            or "updated" in lower
            or lower.endswith("url")
        )

    @staticmethod
    def _trusted_for_authoritative(
        action: AuthorizedAction,
        result: ToolResult,
        candidate: Dict[str, Any],
        field: str,
    ) -> bool:
        if (
            action.tool_name == "nvd_lookup"
            and result.source_name == "NVD"
            and (result.source_url or "").startswith("https://nvd.nist.gov/")
        ):
            return True
        if action.tool_name == "parse_json_path" and result.source_name == "current_file":
            return True
        return (
            action.tool_name == "normalize_field"
            and result.source_name == "deterministic_normalizer"
            and candidate.get(field) not in (None, "")
        )

    @staticmethod
    def _rejected(reason_code: str, fields: List[str]) -> VerificationResult:
        return VerificationResult(
            status="rejected",
            reason_code=reason_code,
            accepted_patches=[],
            rejected_fields=fields,
        )
