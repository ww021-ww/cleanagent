from math import ceil
from typing import Any, Dict, List, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from api.mappings.source_field_map import SOURCE_TABLE_MAP


class VulnSearchService:
    def __init__(self, session: Session):
        self.session = session

    def search(
        self,
        q: Optional[str],
        source: Optional[str],
        severity: Optional[str],
        date_from: Optional[str],
        date_to: Optional[str],
        page: int,
        page_size: int,
        sort_by: str,
        sort_order: str,
    ) -> Dict[str, Any]:
        sources = [source.lower()] if source else list(SOURCE_TABLE_MAP.keys())
        all_items: List[Dict[str, Any]] = []
        total = 0

        fetch_limit = max(200, page * page_size + 200)

        for src in sources:
            if src not in SOURCE_TABLE_MAP:
                continue
            mapping = SOURCE_TABLE_MAP[src]
            count_sql, count_params = self._build_count_sql(mapping, q, severity, date_from, date_to)
            total += self.session.execute(text(count_sql), count_params).scalar() or 0

            data_sql, data_params = self._build_list_sql(mapping, src, q, severity, date_from, date_to, fetch_limit)
            rows = self.session.execute(text(data_sql), data_params).mappings().all()
            all_items.extend([dict(row) for row in rows])

        date_field = "last_updated" if sort_by == "last_updated" else "published_date"
        reverse = sort_order.lower() != "asc"
        all_items.sort(key=lambda x: x.get(date_field) or "", reverse=reverse)

        start = (page - 1) * page_size
        end = start + page_size
        page_items = all_items[start:end]

        return {
            "items": page_items,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "total_pages": ceil(total / page_size) if page_size else 0,
            },
        }

    def _build_count_sql(
        self,
        m: Dict[str, str],
        q: Optional[str],
        severity: Optional[str],
        date_from: Optional[str],
        date_to: Optional[str],
    ):
        sql = f"SELECT COUNT(1) AS cnt FROM {m['table']} WHERE is_deleted = 0"
        params: Dict[str, Any] = {}

        if q:
            sql += (
                f" AND (CAST({m['id']} AS CHAR) LIKE :q"
                f" OR CAST({m['title']} AS CHAR) LIKE :q"
                f" OR CAST({m['description']} AS CHAR) LIKE :q"
                f" OR CAST({m['cve_id']} AS CHAR) LIKE :q)"
            )
            params["q"] = f"%{q}%"

        if severity and m["severity"] != "NULL":
            sql += f" AND {m['severity']} = :severity"
            params["severity"] = severity

        if date_from:
            sql += f" AND {m['published']} >= :date_from"
            params["date_from"] = date_from

        if date_to:
            sql += f" AND {m['published']} <= :date_to"
            params["date_to"] = date_to

        return sql, params

    def _build_list_sql(
        self,
        m: Dict[str, str],
        src: str,
        q: Optional[str],
        severity: Optional[str],
        date_from: Optional[str],
        date_to: Optional[str],
        limit: int,
    ):
        sql = (
            f"SELECT '{src}' AS source, "
            f"CAST({m['id']} AS CHAR) AS vuln_id, "
            f"CAST({m['title']} AS CHAR) AS title, "
            f"CAST({m['description']} AS CHAR) AS description, "
            f"CAST({m['severity']} AS CHAR) AS severity, "
            f"CAST({m['published']} AS CHAR) AS published_date, "
            f"CAST({m['updated']} AS CHAR) AS last_updated, "
            f"CAST({m['cve_id']} AS CHAR) AS cve_id, "
            f"CAST({m['vendor']} AS CHAR) AS vendor "
            f"FROM {m['table']} WHERE is_deleted = 0"
        )
        params: Dict[str, Any] = {}

        if q:
            sql += (
                f" AND (CAST({m['id']} AS CHAR) LIKE :q"
                f" OR CAST({m['title']} AS CHAR) LIKE :q"
                f" OR CAST({m['description']} AS CHAR) LIKE :q"
                f" OR CAST({m['cve_id']} AS CHAR) LIKE :q)"
            )
            params["q"] = f"%{q}%"

        if severity and m["severity"] != "NULL":
            sql += f" AND {m['severity']} = :severity"
            params["severity"] = severity

        if date_from:
            sql += f" AND {m['published']} >= :date_from"
            params["date_from"] = date_from

        if date_to:
            sql += f" AND {m['published']} <= :date_to"
            params["date_to"] = date_to

        sql += " ORDER BY " + m["published"] + " DESC LIMIT :limit"
        params["limit"] = limit

        return sql, params
