"""Session state models for restart and replay orchestration."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum
from typing import Optional, Tuple
from uuid import UUID, uuid4


class SessionStatus(str, Enum):
    IDLE = "idle"
    RESTARTING = "restarting"
    READY = "ready"
    REPLAY_RUNNING = "replay_running"
    ERROR = "error"


class ReadinessStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"


@dataclass(frozen=True)
class ReadinessCheck:
    name: str
    status: ReadinessStatus
    details: Optional[str] = None
    checked_at: datetime = field(default_factory=datetime.utcnow)


@dataclass(frozen=True)
class SessionError:
    code: str
    message: str
    remediation: Optional[str] = None


_ALLOWED_TRANSITIONS = {
    SessionStatus.IDLE: {SessionStatus.RESTARTING},
    SessionStatus.RESTARTING: {SessionStatus.READY, SessionStatus.ERROR},
    SessionStatus.READY: {SessionStatus.REPLAY_RUNNING, SessionStatus.RESTARTING, SessionStatus.ERROR},
    SessionStatus.REPLAY_RUNNING: {SessionStatus.READY, SessionStatus.ERROR},
    SessionStatus.ERROR: {SessionStatus.RESTARTING, SessionStatus.IDLE},
}


@dataclass(frozen=True)
class SessionState:
    app_id: str
    id: UUID = field(default_factory=uuid4)
    status: SessionStatus = SessionStatus.IDLE
    started_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    readiness_checks: Tuple[ReadinessCheck, ...] = field(default_factory=tuple)
    error: Optional[SessionError] = None

    def transition_to(self, next_status: SessionStatus) -> "SessionState":
        allowed = _ALLOWED_TRANSITIONS.get(self.status, set())
        if next_status not in allowed:
            raise ValueError(f"Invalid transition from {self.status} to {next_status}")

        return _refresh_timestamp(
            replace(
                self,
                status=next_status,
                error=None if next_status is SessionStatus.READY else self.error,
            )
        )

    def add_check(self, check: ReadinessCheck) -> "SessionState":
        checks = self.readiness_checks + (check,)
        return _refresh_timestamp(replace(self, readiness_checks=checks))

    def replace_checks(self, checks) -> "SessionState":
        return _refresh_timestamp(replace(self, readiness_checks=tuple(checks)))

    def with_error(self, error: SessionError) -> "SessionState":
        return _refresh_timestamp(replace(self, status=SessionStatus.ERROR, error=error))

    def clear_error(self) -> "SessionState":
        return _refresh_timestamp(replace(self, error=None))


def _refresh_timestamp(state: SessionState) -> SessionState:
    return replace(state, updated_at=datetime.utcnow())


__all__ = [
    "SessionStatus",
    "ReadinessStatus",
    "ReadinessCheck",
    "SessionError",
    "SessionState",
]
