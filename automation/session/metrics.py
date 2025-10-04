"""Prometheus metrics for session orchestration."""
from __future__ import annotations

try:  # pragma: no cover - optional dependency
    from prometheus_client import Counter, Histogram

    from automation.logs import get_metrics_registry

    _REGISTRY = get_metrics_registry()

    RESTART_DURATION_SECONDS = Histogram(
        "automation_restart_duration_seconds",
        "Duration of restart attempts until ready state",
        labelnames=("app_id",),
        registry=_REGISTRY,
    )

    RESTART_FAILURES_TOTAL = Counter(
        "automation_restart_failures_total",
        "Count of restart failures grouped by error code",
        labelnames=("app_id", "error_code"),
        registry=_REGISTRY,
    )

    def observe_restart_duration(*, app_id: str, duration_seconds: float) -> None:
        RESTART_DURATION_SECONDS.labels(app_id=app_id).observe(duration_seconds)

    def increment_restart_failure(*, app_id: str, error_code: str) -> None:
        RESTART_FAILURES_TOTAL.labels(app_id=app_id, error_code=error_code).inc()

except ModuleNotFoundError:  # pragma: no cover - fallback no-op metrics

    class _NoopMetric:
        def labels(self, **_):  # type: ignore[override]
            return self

        def observe(self, *_args, **_kwargs) -> None:
            pass

        def inc(self, *_args, **_kwargs) -> None:
            pass

    RESTART_DURATION_SECONDS = _NoopMetric()
    RESTART_FAILURES_TOTAL = _NoopMetric()

    def observe_restart_duration(*, app_id: str, duration_seconds: float) -> None:  # noqa: D401
        return None

    def increment_restart_failure(*, app_id: str, error_code: str) -> None:  # noqa: D401
        return None


__all__ = [
    "RESTART_DURATION_SECONDS",
    "RESTART_FAILURES_TOTAL",
    "observe_restart_duration",
    "increment_restart_failure",
]
