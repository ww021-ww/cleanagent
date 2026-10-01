from typing import Any, Dict, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session

from api.mappings.source_field_map import SOURCE_TABLE_MAP


class VulnDetailService:
    def __init__(self, session: Session):
        self.session = session

    def _get_metrics_row(self, source: str, vuln_id: str) -> Optional[Dict[str, Any]]:
        """从子表获取 CVSS metrics 数据，合并到主表 raw 中"""
        if source == "cve":
            sql = "SELECT * FROM t_cve_metrics WHERE cve_id = :cve_id LIMIT 1"
        elif source == "nvd":
            sql = "SELECT * FROM t_nvd_metrics WHERE cve_id = :cve_id LIMIT 1"
        else:
            return None

        row = self.session.execute(text(sql), {"cve_id": vuln_id}).mappings().first()
        if not row:
            return None
        return dict(row)

    def get_detail(self, source: str, vuln_id: str) -> Dict[str, Any]:
        source = source.lower()
        if source not in SOURCE_TABLE_MAP:
            return {}

        mapping = SOURCE_TABLE_MAP[source]
        sql = f"SELECT * FROM {mapping['table']} WHERE {mapping['id']} = :vuln_id LIMIT 1"
        row = self.session.execute(text(sql), {"vuln_id": vuln_id}).mappings().first()

        if not row:
            return {}

        raw = dict(row)

        # 合并 CVE/NVD 子表的 CVSS metrics 数据
        metrics = self._get_metrics_row(source, vuln_id)
        if metrics:
            # 子表字段合并到 raw，不覆盖主表已有的同名字段
            for k, v in metrics.items():
                if k not in raw or raw[k] is None:
                    raw[k] = v

        return {
            "source": source,
            "vuln_id": vuln_id,
            "raw": raw,
        }
