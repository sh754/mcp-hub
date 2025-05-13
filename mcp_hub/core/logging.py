import sys
import os
from loguru import logger
from pathlib import Path
from .config import settings

LOG_DIR = Path("./logs")
LOG_DIR.mkdir(exist_ok=True)

logger.remove()

logger.add(
    sys.stderr,
    level=settings.LOG_LEVEL,
    format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - <level>{message}</level>",
)

logger.add(
    LOG_DIR / "mcp_hub_{time:YYYY-MM-DD}.log",
    rotation="00:00", 
    retention="7 days",
    level=settings.LOG_LEVEL,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}",
    encoding="utf-8",
)


def get_logger(name: str):
    """获取命名的logger实例"""
    return logger.bind(name=name) 