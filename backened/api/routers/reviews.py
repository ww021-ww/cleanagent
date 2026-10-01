import hmac
import os

from fastapi import APIRouter, Depends, Header, HTTPException, Query

from api.deps import get_processing_runtime
from api.schemas.review import ReviewDecisionRequest
from api.services.review_service import ReviewService


router = APIRouter(prefix="/api/v1/reviews", tags=["reviews"])


def require_review_token(authorization: str | None = Header(default=None)):
    expected = os.getenv("HIL_REVIEW_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="HIL_REVIEW_TOKEN is not configured")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    token = authorization[7:]
    if not hmac.compare_digest(token, expected):
        raise HTTPException(status_code=401, detail="Invalid bearer token")


@router.get("")
def list_reviews(
    status: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    runtime=Depends(get_processing_runtime),
):
    return ReviewService(runtime).list(status=status, page=page, page_size=page_size)


@router.get("/{task_id}")
def get_review(task_id: str, runtime=Depends(get_processing_runtime)):
    return ReviewService(runtime).get(task_id)


@router.post("/{task_id}/approve")
async def approve_review(
    task_id: str,
    request: ReviewDecisionRequest,
    _token=Depends(require_review_token),
    runtime=Depends(get_processing_runtime),
):
    return await ReviewService(runtime).approve(task_id, request)


@router.post("/{task_id}/reject")
async def reject_review(
    task_id: str,
    request: ReviewDecisionRequest,
    _token=Depends(require_review_token),
    runtime=Depends(get_processing_runtime),
):
    return await ReviewService(runtime).reject(task_id, request)
