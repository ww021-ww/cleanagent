"""Native LangGraph human-review nodes for low-confidence records."""

import asyncio
import time

from langgraph.types import interrupt

from graph.state import VulnProcessingState


def _review_reason(state):
    return (
        (state.get("recovery_decision") or {}).get("reason_code")
        or (state.get("verification") or {}).get("reason_code")
        or "human_review_required"
    )


async def prepare_review_node(state: VulnProcessingState, config) -> VulnProcessingState:
    task_id = state["task_id"]
    if config.get("processing", {}).get("dry_run", False):
        return {
            **state,
            "raw_content": None,
            "review_task_id": task_id,
            "review_status": "dry_run",
            "final_status": "review_pending",
            "end_time": time.time(),
        }

    storage = config.get("_storage")
    if not storage or not getattr(storage, "db", None):
        raise RuntimeError("Storage is required to persist a review task")
    source = state.get("source") or "unknown"
    source_config = storage.db.config_loader.get_source_config(source)
    id_field = source_config.get("id_field")
    candidate = dict(state.get("cleaned_data") or {})
    await asyncio.to_thread(
        storage.db.reliability.enqueue_review,
        task_id=task_id,
        source=source,
        vuln_id=candidate.get(id_field) if id_field else None,
        file_path=state.get("file_path", ""),
        reason_code=_review_reason(state),
        candidate_data=candidate,
        proposed_patches=state.get("proposed_patches") or [],
        subtable_data=state.get("cleaned_subtable_data") or [],
    )
    return {
        **state,
        "raw_content": None,
        "review_task_id": task_id,
        "review_status": "pending",
        "final_status": "review_pending",
    }


def human_review_node(state: VulnProcessingState, config) -> VulnProcessingState:
    response = interrupt(
        {
            "task_id": state.get("review_task_id") or state["task_id"],
            "source": state.get("source"),
            "reason_code": _review_reason(state),
            "candidate_data": state.get("cleaned_data") or {},
            "proposed_patches": state.get("proposed_patches") or [],
        }
    )
    return {**state, "review_response": response}


async def apply_review_node(state: VulnProcessingState, config) -> VulnProcessingState:
    response = state.get("review_response") or {}
    corrected = response.get("corrected_fields") or {}
    storage = config.get("_storage")
    cleaner = config.get("_cleaner")
    if not storage or not cleaner:
        raise RuntimeError("Storage and cleaner are required to apply a review")

    source = state["source"]
    source_config = storage.db.config_loader.get_source_config(source)
    id_field = source_config.get("id_field")
    allowed = {field["name"] for field in source_config.get("fields", [])}
    unknown = set(corrected) - allowed
    if unknown:
        raise ValueError(f"Unknown correction fields: {sorted(unknown)}")

    candidate = dict(state.get("cleaned_data") or {})
    if id_field in corrected and corrected[id_field] != candidate.get(id_field):
        raise ValueError(f"Protected ID field cannot be changed: {id_field}")
    candidate.update(corrected)
    cleaned = await asyncio.to_thread(cleaner.cleaner.clean, candidate)
    validation = await asyncio.to_thread(cleaner.validate, cleaned, source)
    quality_score = cleaner.calculate_quality_score(
        cleaned,
        validation,
        state.get("extraction_confidence", 0.0),
    )
    threshold = config.get("agents", {}).get("cleaner_validator", {}).get(
        "quality_threshold", 0.7
    )
    if not validation.get("is_valid") or quality_score < threshold:
        error = "Reviewed data failed validation"
        await asyncio.to_thread(
            storage.db.reliability.release_review,
            state.get("review_task_id") or state["task_id"],
            error,
        )
        return {
            **state,
            "cleaned_data": cleaned,
            "validation_result": validation,
            "quality_score": quality_score,
            "review_status": "invalid",
            "final_status": "failed",
            "errors": state.get("errors", []) + [error],
        }
    return {
        **state,
        "cleaned_data": cleaned,
        "validation_result": validation,
        "quality_score": quality_score,
        "review_status": "approved",
    }


async def reject_review_node(state: VulnProcessingState, config) -> VulnProcessingState:
    response = state.get("review_response") or {}
    storage = config.get("_storage")
    if storage and not config.get("processing", {}).get("dry_run", False):
        rejected = await asyncio.to_thread(
            storage.db.reliability.mark_review_rejected,
            state.get("review_task_id") or state["task_id"],
            response.get("reviewer", ""),
            response.get("note", ""),
        )
        if not rejected:
            raise RuntimeError("Review task is not claimed")
    return {
        **state,
        "review_status": "rejected",
        "final_status": "rejected",
        "end_time": time.time(),
    }
