from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.deps import get_db_session
from api.schemas.response import success
from api.services.stats_service import StatsService

router = APIRouter(prefix="/api/v1/stats", tags=["stats"])


@router.get("/overview")
def overview(session: Session = Depends(get_db_session)):
    service = StatsService(session)
    return success(service.overview())
