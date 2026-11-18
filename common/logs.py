"""Spójne logowanie (rich, z fallbackiem do zwykłego logging) – działa w kontenerach i na Windows/Linux/macOS."""
from __future__ import annotations

import logging
import os
import sys

try:  # rich jest opcjonalny w kontenerach (fallback poniżej)
    from rich.console import Console
    from rich.logging import RichHandler

    HAVE_RICH = True
except ImportError:  # pragma: no cover
    HAVE_RICH = False


def get_logger(name: str, level: str | None = None) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    lvl = (level or os.getenv("LOG_LEVEL", "INFO")).upper()
    logger.setLevel(lvl)
    if HAVE_RICH:
        handler: logging.Handler = RichHandler(
            console=Console(file=sys.stdout, width=int(os.getenv("LOG_WIDTH", "140"))),
            show_path=False,
            markup=False,
            rich_tracebacks=True,
            log_time_format="%H:%M:%S",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
    else:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s [%(name)s] %(message)s", "%H:%M:%S"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger
