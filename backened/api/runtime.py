"""Application-lifetime resources for resumable vulnerability processing."""

from contextlib import asynccontextmanager
from dataclasses import dataclass

from graph.checkpoint import open_checkpointer
from graph.controller import LangGraphController


@dataclass
class ProcessingRuntime:
    controller: object
    db_manager: object
    cleaner: object


@asynccontextmanager
async def open_processing_runtime(config):
    checkpoint_path = config.get("processing", {}).get(
        "checkpoint_db", "logs/processing_state.db"
    )
    async with open_checkpointer(checkpoint_path) as checkpointer:
        controller = LangGraphController(config, checkpointer=checkpointer)
        storage = controller.storage_agent
        if not storage or not getattr(storage, "db", None) or not controller.cleaner_agent:
            raise RuntimeError("Review runtime requires storage and cleaner agents")
        try:
            yield ProcessingRuntime(
                controller=controller,
                db_manager=storage.db,
                cleaner=controller.cleaner_agent,
            )
        finally:
            storage.db.close()
