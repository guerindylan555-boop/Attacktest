"""Shared logging and metrics bootstrap for automation services.

This module centralises Loguru configuration and exposes a reusable
Prometheus registry so restart, replay, and catalog modules emit
consistent telemetry.  The configuration is intentionally lightweight
for now; downstream tasks will extend it with file sinks and HTTP metric
exporters.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

try:  # pragma: no cover - optional dependency
    from loguru import logger as _loguru_logger
    _LOGURU_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - fallback
    import logging

    _LOGURU_AVAILABLE = False
    _logging = logging
    _fallback_logger = logging.getLogger("automation")

try:  # pragma: no cover - optional dependency
    from prometheus_client import CollectorRegistry
except ModuleNotFoundError:  # pragma: no cover - fallback
    class CollectorRegistry:  # type: ignore[override]
        def __init__(self, *_, **__) -> None:
            pass

_DEFAULT_LOG_LEVEL = os.environ.get("AUTOMATION_LOG_LEVEL", "INFO")
_LOG_CONFIGURED = False
_METRICS_REGISTRY = CollectorRegistry(auto_describe=True)


def configure_logging(*, level: Optional[str] = None, log_file: Optional[Path] = None) -> None:
    """Initialise the shared Loguru logger.

    Parameters
    ----------
    level:
        Override the default log level (defaults to ``AUTOMATION_LOG_LEVEL``
        environment variable or ``INFO``).
    log_file:
        Optional path to a JSONL log sink. Parents are created on demand.
    """

    global _LOG_CONFIGURED

    if _LOG_CONFIGURED and level is None and log_file is None:
        return

    resolved_level = level or _DEFAULT_LOG_LEVEL

    if _LOGURU_AVAILABLE:
        logger = _loguru_logger  # type: ignore[name-defined]
        logger.remove()
        logger.add(
            sys.stdout,
            level=resolved_level,
            serialize=True,
            enqueue=True,
            backtrace=False,
            diagnose=False,
        )

        if log_file is not None:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            logger.add(
                log_path,
                level=resolved_level,
                serialize=True,
                enqueue=True,
                rotation="10 MB",
                retention=10,
            )
    else:  # pragma: no cover - standard logging fallback
        level_value = getattr(_logging, resolved_level.upper(), _logging.INFO)
        _fallback_logger.setLevel(level_value)
        handler = _logging.StreamHandler(sys.stdout)
        handler.setLevel(level_value)
        formatter = _logging.Formatter(
            fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
        )
        handler.setFormatter(formatter)
        _fallback_logger.handlers = [handler]
        if log_file is not None:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = _logging.FileHandler(log_path)
            file_handler.setFormatter(formatter)
            file_handler.setLevel(level_value)
            _fallback_logger.addHandler(file_handler)

    _LOG_CONFIGURED = True


def get_logger(component: str = "automation"):  # -> loguru.Logger
    """Return a component-scoped logger instance."""

    if not _LOG_CONFIGURED:
        configure_logging()

    if _LOGURU_AVAILABLE:
        return _loguru_logger.bind(component=component)  # type: ignore[name-defined]

    logger = _logging.getLogger(component)  # type: ignore[name-defined]
    return _StructuredLogger(logger, component)


class _StructuredLogger:
    def __init__(self, logger, component: str) -> None:  # pragma: no cover - simple wrapper
        self._logger = logger
        self._component = component

    def bind(self, **extra):  # noqa: D401
        return self

    def info(self, message: str, **context) -> None:
        self._logger.info(self._format(message, context))

    def warning(self, message: str, **context) -> None:
        self._logger.warning(self._format(message, context))

    def error(self, message: str, **context) -> None:
        self._logger.error(self._format(message, context))

    def _format(self, message: str, context: dict) -> str:
        if not context:
            return f"[{self._component}] {message}"
        formatted = " ".join(f"{key}={value}" for key, value in context.items())
        return f"[{self._component}] {message} | {formatted}"


def get_metrics_registry() -> CollectorRegistry:
    """Return the shared Prometheus registry used across automation modules."""

    return _METRICS_REGISTRY


__all__ = ["configure_logging", "get_logger", "get_metrics_registry"]
