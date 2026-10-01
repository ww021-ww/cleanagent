from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from api.deps import get_db_session
from api.schemas.response import success
from api.services.search_service import VulnSearchService
from api.services.detail_service import VulnDetailService

router = APIRouter(prefix="/api/v1/vulns", tags=["vulns"])


@router.get("")
def search_vulns(
    q: str | None = Query(default=None),
    source: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    date_from: str | None = Query(default=None),
    date_to: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    sort_by: str = Query(default="published_date"),
    sort_order: str = Query(default="desc"),
    session: Session = Depends(get_db_session),
):
    service = VulnSearchService(session)
    data = service.search(
        q=q,
        source=source,
        severity=severity,
        date_from=date_from,
        date_to=date_to,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return success(data)


@router.get("/{source}/{vuln_id}")
def vuln_detail(
    source: str,
    vuln_id: str,
    session: Session = Depends(get_db_session),
):
    service = VulnDetailService(session)
    data = service.get_detail(source, vuln_id)
    if not data:
        raise HTTPException(status_code=404, detail="漏洞不存在")
    return success(data)
