from typing import List, Optional, Dict, Any
from pydantic import BaseModel


class VulnItem(BaseModel):
    source: str
    vuln_id: str
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    published_date: Optional[str] = None
    last_updated: Optional[str] = None
    cve_id: Optional[str] = None
    vendor: Optional[str] = None


class Pagination(BaseModel):
    page: int
    page_size: int
    total: int
    total_pages: int


class VulnSearchData(BaseModel):
    items: List[VulnItem]
    pagination: Pagination


class VulnDetailData(BaseModel):
    source: str
    vuln_id: str
    raw: Dict[str, Any]
