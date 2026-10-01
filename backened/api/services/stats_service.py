from typing import Dict

from sqlalchemy import text
from sqlalchemy.orm import Session

from api.mappings.source_field_map import SOURCE_TABLE_MAP


class StatsService:
    def __init__(self, session: Session):
        self.session = session

    def overview(self) -> Dict:
        by_source = {}
        total = 0
        updated_today = 0
        high_risk_total = 0

        for source, mapping in SOURCE_TABLE_MAP.items():
            count_sql = f"SELECT COUNT(1) AS cnt FROM {mapping['table']} WHERE is_deleted = 0"
            cnt = self.session.execute(text(count_sql)).scalar() or 0
            by_source[source] = cnt
            total += cnt

            updated_sql = (
                f"SELECT COUNT(1) AS cnt FROM {mapping['table']} "
                f"WHERE is_deleted = 0 AND {mapping['updated']} IS NOT NULL "
                f"AND DATE({mapping['updated']}) = CURDATE()"
            )
            updated_today += self.session.execute(text(updated_sql)).scalar() or 0

            if mapping['severity'] != 'NULL':
                risk_sql = (
                    f"SELECT COUNT(1) AS cnt FROM {mapping['table']} "
                    f"WHERE is_deleted = 0 AND {mapping['severity']} IS NOT NULL "
                    f"AND (LOWER({mapping['severity']}) LIKE '%critical%' "
                    f"OR LOWER({mapping['severity']}) LIKE '%high%' "
                    f"OR {mapping['severity']} LIKE '%严重%' "
                    f"OR {mapping['severity']} LIKE '%高%')"
                )
                high_risk_total += self.session.execute(text(risk_sql)).scalar() or 0

        return {
            "total": total,
            "by_source": by_source,
            "updated_today": updated_today,
            "high_risk_total": high_risk_total,
        }
