"""Restart orchestration for the automation session pipeline."""
from __future__ import annotations

import time
from typing import Callable, Iterable, Optional, Protocol

from automation.logs import get_logger

from .state import (
    ReadinessCheck,
    ReadinessStatus,
    SessionError,
    SessionState,
    SessionStatus,
)


class ReadinessProbe(Protocol):
    """Protocol that restart readiness probes must follow."""

    name: str

    def run(self, session: SessionState) -> ReadinessCheck:  # pragma: no cover - typed protocol
        ...


class RestartDriver(Protocol):
    """Driver responsible for manipulating the target application."""

    def terminate_app(self, app_id: str) -> None:  # pragma: no cover - typed protocol
        ...

    def activate_app(self, app_id: str) -> None:  # pragma: no cover - typed protocol
        ...

    def clear_app_data(self, app_id: str) -> None:  # pragma: no cover - typed protocol
        ...

    def restore_snapshot(self, snapshot_tag: str) -> None:  # pragma: no cover - typed protocol
        ...


class MonotonicClock(Protocol):
    def monotonic(self) -> float:  # pragma: no cover - typed protocol
        ...


class SessionRestartError(RuntimeError):
    """Raised when restart fails to reach a clean ready state."""

    def __init__(self, *, code: str, message: str, session: SessionState):
        super().__init__(message)
        self.code = code
        self.message = message
        self.session = session


class SessionController:
    """Coordinates restart actions and readiness probes."""

    def __init__(
        self,
        *,
        driver: RestartDriver,
        readiness_probes: Iterable[ReadinessProbe],
        clock: Optional[MonotonicClock] = None,
        session_factory: Optional[Callable[[str], SessionState]] = None,
    ) -> None:
        self._driver = driver
        self._probes = list(readiness_probes)
        self._clock = clock or time
        self._session_factory = session_factory or (lambda app_id: SessionState(app_id=app_id))
        self._logger = get_logger("session.controller")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def restart(
        self,
        *,
        app_id: str,
        timeout_seconds: int,
        force_clear_data: bool = False,
        snapshot_tag: Optional[str] = None,
    ) -> SessionState:
        """Perform an idempotent restart and return the ready state."""

        session = self._session_factory(app_id).transition_to(SessionStatus.RESTARTING)
        start = self._clock.monotonic()

        self._logger.info("restart requested", app_id=app_id, timeout=timeout_seconds)

        try:
            if snapshot_tag:
                self._driver.restore_snapshot(snapshot_tag)
            self._driver.terminate_app(app_id)
            if force_clear_data:
                self._driver.clear_app_data(app_id)
            self._driver.activate_app(app_id)
        except Exception as exc:  # pragma: no cover - defensive path
            error = SessionError(
                code="DRIVER_FAILURE",
                message=str(exc),
                remediation="Inspect emulator/driver logs",
            )
            session = session.with_error(error)
            raise SessionRestartError(code=error.code, message=error.message, session=session) from exc

        while True:
            checks: list[ReadinessCheck] = []
            for probe in self._probes:
                result = probe.run(session)
                checks.append(result)

            session = session.replace_checks(checks)

            failing = [check for check in checks if check.status is ReadinessStatus.FAIL]
            fatal = _select_fatal_failure(failing)
            if fatal is not None:
                code = _error_code_for_probe(fatal)
                detail = fatal.details or "no details provided"
                message = f"Readiness probe {fatal.name} failed: {detail}"
                error = SessionError(code=code, message=message, remediation="Resolve failing probe and retry")
                session = session.with_error(error)
                self._logger.warning("restart readiness failure", code=code, details=message)
                raise SessionRestartError(code=code, message=message, session=session)

            if checks and all(check.status is ReadinessStatus.PASS for check in checks):
                ready = session.transition_to(SessionStatus.READY)
                self._logger.info("restart complete", app_id=app_id)
                return ready

            now = self._clock.monotonic()
            if now - start > timeout_seconds:
                message = f"Restart exceeded timeout of {timeout_seconds} seconds"
                error = SessionError(
                    code="SESSION_TIMEOUT",
                    message=message,
                    remediation="Increase timeout or inspect emulator performance",
                )
                session = session.with_error(error)
                self._logger.error("restart timed out", app_id=app_id, timeout=timeout_seconds)
                raise SessionRestartError(code=error.code, message=message, session=session)


def _error_code_for_probe(check: ReadinessCheck) -> str:
    """Map readiness probe names to contract error codes."""

    if check.name.lower().startswith("frida"):
        return "HOOK_HEARTBEAT_MISSING"
    if check.name.lower().startswith("login") or check.name.lower().endswith("ui"):
        return "UI_NOT_READY"
    return "UI_NOT_READY"


def _select_fatal_failure(checks: list[ReadinessCheck]) -> Optional[ReadinessCheck]:
    """Return the readiness check that should cause an immediate failure, if any."""

    for check in checks:
        if check.name.lower().startswith("frida"):
            return check
    return None


__all__ = ["SessionController", "SessionRestartError"]
