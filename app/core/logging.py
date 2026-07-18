"""One place to configure logging. Call setup_logging() once at app startup so the
whole app (our code + uvicorn + SQLAlchemy) shares one format and level."""

import logging

from app.config import settings


def setup_logging() -> None:
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
