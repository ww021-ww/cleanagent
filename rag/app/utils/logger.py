import logging
import sys
import os

logger = logging.getLogger("rag")
logger.setLevel(logging.DEBUG)

log_dir = "logs"
os.makedirs(log_dir, exist_ok=True)

if not logger.handlers:
    stream_handler = logging.StreamHandler(sys.stdout)
    file_handler = logging.FileHandler(os.path.join(log_dir, "app.log"), encoding="utf-8")
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    stream_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
