import asyncio

from fastapi import HTTPException


def _public_review(row):
    if row is None:
        return None
    result = dict(row)
    candidate = dict(result.get("candidate_data") or {})
    candidate.pop("raw_content", None)
    result["candidate_data"] = candidate
    return result


class ReviewService:
    def __init__(self, runtime, lease_seconds=60):
        self.runtime = runtime
        self.store = runtime.db_manager.reliability
        self.lease_seconds = lease_seconds

    def list(self, *, status=None, page=1, page_size=20):
        result = self.store.list_reviews(
            status=status, page=page, page_size=page_size
        )
        result["items"] = [_public_review(row) for row in result["items"]]
        return result

    def get(self, task_id):
        row = _public_review(self.store.get_review(task_id))
        if row is None:
            raise HTTPException(status_code=404, detail="Review task not found")
        return row

    def _validate_correction_keys(self, row, corrected_fields):
        config = self.runtime.db_manager.config_loader.get_source_config(row["source"])
        id_field = config.get("id_field")
        allowed = {field["name"] for field in config.get("fields", [])}
        unknown = set(corrected_fields) - allowed
        if unknown:
            raise HTTPException(
                status_code=422,
                detail=f"Unknown correction fields: {sorted(unknown)}",
            )
        if id_field in corrected_fields:
            original = (row.get("candidate_data") or {}).get(id_field)
            if corrected_fields[id_field] != original:
                raise HTTPException(
                    status_code=422,
                    detail=f"Protected ID field cannot be changed: {id_field}",
                )

    async def approve(self, task_id, request):
        row = self.get(task_id)
        corrected = dict(request.corrected_fields)
        self._validate_correction_keys(row, corrected)
        claimed = self.store.claim_review(
            task_id=task_id,
            reviewer=request.reviewer,
            note=request.note,
            corrected_data=corrected,
            lease_seconds=self.lease_seconds,
        )
        if claimed is None:
            raise HTTPException(status_code=409, detail="Review task is already claimed")

        candidate = dict(row.get("candidate_data") or {})
        candidate.update(corrected)
        cleaner = self.runtime.cleaner
        cleaned = await asyncio.to_thread(cleaner.cleaner.clean, candidate)
        validation = await asyncio.to_thread(cleaner.validate, cleaned, row["source"])
        if not validation.get("is_valid"):
            self.store.release_review(task_id, "Reviewed data failed validation")
            raise HTTPException(
                status_code=422,
                detail={"message": "Reviewed data failed validation", "validation": validation},
            )

        return await self._resume(
            task_id,
            {
                "action": "approve",
                "reviewer": request.reviewer,
                "note": request.note,
                "corrected_fields": corrected,
            },
        )

    async def reject(self, task_id, request):
        self.get(task_id)
        claimed = self.store.claim_review(
            task_id=task_id,
            reviewer=request.reviewer,
            note=request.note,
            corrected_data={},
            lease_seconds=self.lease_seconds,
        )
        if claimed is None:
            raise HTTPException(status_code=409, detail="Review task is already claimed")
        return await self._resume(
            task_id,
            {
                "action": "reject",
                "reviewer": request.reviewer,
                "note": request.note,
            },
        )

    async def _resume(self, task_id, review_input):
        try:
            return await self.runtime.controller.resume_review(task_id, review_input)
        except HTTPException:
            raise
        except Exception as exc:
            current = self.store.get_review(task_id)
            if current and current.get("status") == "processing":
                self.store.release_review(task_id, str(exc))
            raise HTTPException(
                status_code=409,
                detail=f"Review checkpoint could not be resumed: {exc}",
            ) from exc
