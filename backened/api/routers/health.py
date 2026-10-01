from fastapi import APIRouter

from api.schemas.response import success

router = APIRouter(prefix="/api/v1", tags=["health"])


@router.get("/health")
def health():
    return success({"status": "up"})
