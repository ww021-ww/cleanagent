"""Single-process MySQL-to-Milvus outbox worker."""

import argparse
import logging
import time

from api.mappings.source_field_map import SOURCE_TABLE_MAP


logger = logging.getLogger(__name__)


class VectorIndexWorker:
    def __init__(self, db_manager, rag, config):
        self.db = db_manager
        self.rag = rag
        cfg = config.get("agentic", {}).get("vector_outbox", {})
        self.batch_size = cfg.get("batch_size", 50)
        self.poll_seconds = cfg.get("poll_seconds", 2)
        self.lease_seconds = cfg.get("lease_seconds", 60)
        self.max_attempts = cfg.get("max_attempts", 5)
        self.retry_base_seconds = cfg.get("retry_base_seconds", 5)
        self.retry_max_seconds = cfg.get("retry_max_seconds", 300)

    @staticmethod
    def _vector_record(record, source):
        mapping = SOURCE_TABLE_MAP.get(source.lower(), {})

        def mapped(name):
            field = mapping.get(name)
            return None if not field or field == "NULL" else record.get(field)

        return {
            **record,
            "vuln_id": mapped("id"),
            "title": mapped("title"),
            "description": mapped("description"),
            "severity": mapped("severity"),
        }

    def run_once(self):
        jobs = self.db.reliability.claim_vector_jobs(
            limit=self.batch_size,
            lease_seconds=self.lease_seconds,
        )
        stats = {"claimed": len(jobs), "succeeded": 0, "failed": 0}
        for job in jobs:
            try:
                record = self.db.get_record(job["source"], job["vuln_id"])
                if record is None:
                    raise LookupError("source record no longer exists")
                self.rag.index_vulnerability(
                    self._vector_record(record, job["source"]),
                    job["source"],
                )
                self.db.reliability.mark_vector_success(job["id"])
                stats["succeeded"] += 1
            except Exception as exc:
                logger.warning("Vector indexing failed for job %s: %s", job["id"], exc)
                self.db.reliability.mark_vector_failure(
                    job_id=job["id"],
                    error=str(exc),
                    max_attempts=self.max_attempts,
                    retry_base_seconds=self.retry_base_seconds,
                    retry_max_seconds=self.retry_max_seconds,
                )
                stats["failed"] += 1
        return stats

    def run_forever(self):
        while True:
            result = self.run_once()
            if result["claimed"] == 0:
                time.sleep(self.poll_seconds)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Process pending Milvus index jobs")
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args(argv)

    from agent.storage import StorageAgent
    from config import load_yaml_config
    from rag.retriever import RAGRetriever

    config = load_yaml_config()
    storage = StorageAgent(config, None)
    worker = VectorIndexWorker(storage.db, RAGRetriever(config), config)
    try:
        if args.once:
            print(worker.run_once())
        else:
            worker.run_forever()
    finally:
        storage.db.close()


if __name__ == "__main__":
    main()
