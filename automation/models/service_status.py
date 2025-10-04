"""Retry-aware service health models for the automation control center."""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional


def _utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


class ServiceState(Enum):
    """Enumeration of possible service states."""

    PENDING = "pending"
    STARTING = "starting"
    RUNNING = "running"
    FAILED = "failed"
    STOPPED = "stopped"
    ERROR = "error"  # Kept for backward compatibility


@dataclass
class ServiceStatus:
    """Tracks lifecycle information for a managed background service."""

    service_name: str
    status: str = ServiceState.STOPPED.value
    retry_attempt: int = 0  # Legacy field, kept for backward compatibility
    retry_count: int = 0  # New retry tracking field
    max_retries: int = 3
    retry_delay: float = 5.0  # Delay in seconds between retries
    last_retry_at: Optional[datetime] = None  # Timestamp of last retry
    startup_time: float = 0.0
    pid: Optional[int] = None
    error_message: Optional[str] = None
    last_error_code: Optional[int] = None
    last_check: datetime = field(default_factory=_utcnow)
    last_transition: datetime = field(default_factory=_utcnow)

    def __post_init__(self) -> None:
        valid_services = {"emulator", "proxy", "frida"}
        if self.service_name not in valid_services:
            raise ValueError(f"service_name must be one of {sorted(valid_services)}")
        valid_states = {state.value for state in ServiceState}
        if self.status not in valid_states:
            raise ValueError(f"status must be one of {sorted(valid_states)}")

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------
    @property
    def state(self) -> ServiceState:
        """Get the current state as ServiceState enum."""
        return ServiceState(self.status)

    # ------------------------------------------------------------------
    # Lifecycle helpers
    # ------------------------------------------------------------------
    def begin_start_attempt(self) -> None:
        """Mark the beginning of a startup attempt and bump retry counter."""

        self.retry_attempt = min(self.retry_attempt + 1, self.max_retries)
        self._transition(ServiceState.STARTING.value)

    def mark_running(self, *, pid: Optional[int] = None, startup_time: Optional[float] = None) -> None:
        """Mark the service as running and reset retry metadata."""

        if startup_time is not None:
            self.startup_time = startup_time
        self.pid = pid
        self.error_message = None
        self.last_error_code = None
        self.retry_attempt = 0  # Legacy field
        self.retry_count = 0  # Reset retry count on successful start
        self._transition(ServiceState.RUNNING.value)

    def mark_stopped(self) -> None:
        """Mark the service as stopped."""

        self.pid = None
        self.error_message = None
        self._transition(ServiceState.STOPPED.value)

    def mark_error(self, message: str, *, error_code: Optional[int] = None) -> None:
        """Mark the service as failed with the provided error message."""

        self.error_message = message
        self.last_error_code = error_code
        self._transition(ServiceState.ERROR.value)

    def should_retry(self) -> bool:
        """Check if service should be retried based on current retry count.
        
        Returns:
            True if retry_count < max_retries, False otherwise
        """
        return self.retry_count < self.max_retries

    def begin_retry_attempt(self) -> None:
        """Mark the beginning of a retry attempt.
        
        Increments retry_count and updates last_retry_at timestamp.
        """
        self.retry_count += 1
        self.last_retry_at = _utcnow()
        self._transition(ServiceState.STARTING.value)

    def update_status(
        self,
        new_status: str,
        error_message: Optional[str] = None,
        pid: Optional[int] = None,
    ) -> None:
        """Backward-compatible helper for legacy callers."""

        if new_status == ServiceState.RUNNING.value:
            self.mark_running(pid=pid)
        elif new_status == ServiceState.ERROR.value:
            self.mark_error(error_message or "Unknown error")
        elif new_status == ServiceState.STARTING.value:
            self.begin_start_attempt()
        elif new_status == ServiceState.STOPPED.value:
            self.mark_stopped()
        else:
            self._transition(new_status)
        if error_message and new_status != ServiceState.ERROR.value:
            self.error_message = error_message

    def _transition(self, status: str) -> None:
        valid_states = {state.value for state in ServiceState}
        if status not in valid_states:
            raise ValueError(f"status must be one of {sorted(valid_states)}")
        self.status = status
        now = _utcnow()
        self.last_transition = now
        self.last_check = now

    def record_health_check(self) -> None:
        """Update the last_check timestamp without altering status."""

        self.last_check = _utcnow()

    # ------------------------------------------------------------------
    # Derived helpers
    # ------------------------------------------------------------------
    @property
    def is_running(self) -> bool:
        return self.status == ServiceState.RUNNING.value

    @property
    def is_starting(self) -> bool:
        return self.status == ServiceState.STARTING.value

    @property
    def has_error(self) -> bool:
        return self.status == ServiceState.ERROR.value

    @property
    def retries_exhausted(self) -> bool:
        return self.has_error and self.retry_attempt >= self.max_retries

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the status for contract responses."""

        payload: Dict[str, Any] = {
            "name": self.service_name,
            "status": self.status,
            "retry_attempt": self.retry_attempt,
            "max_retries": self.max_retries,
            "startup_time": self.startup_time,
            "last_check": self.last_check.isoformat(),
            "last_transition": self.last_transition.isoformat(),
        }
        if self.error_message is not None:
            payload["error_message"] = self.error_message
        if self.last_error_code is not None:
            payload["last_error_code"] = self.last_error_code
        if self.pid is not None:
            payload["pid"] = self.pid
        return payload

    def validate(self) -> bool:
        return self.service_name in {"emulator", "proxy", "frida"}

    # ------------------------------------------------------------------
    # Health check helpers
    # ------------------------------------------------------------------
    @classmethod
    def check_emulator_status(cls, device_id: str = "emulator-5554") -> "ServiceStatus":
        status = cls("emulator")
        status.begin_start_attempt()
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "get-state"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            status.record_health_check()
            if result.returncode == 0 and result.stdout.strip() == "device":
                status.mark_running()
            else:
                status.mark_error("Emulator not running")
        except subprocess.TimeoutExpired:
            status.mark_error("ADB command timeout")
        except FileNotFoundError:
            status.mark_error("ADB not found")
        except Exception as exc:  # noqa: BLE001
            status.mark_error(f"Unexpected error: {exc}")
        return status

    @classmethod
    def check_proxy_status(cls) -> "ServiceStatus":
        status = cls("proxy")
        status.begin_start_attempt()
        try:
            result = subprocess.run(
                ["tmux", "has-session", "-t", "mitmproxy_session"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            status.record_health_check()
            if result.returncode == 0:
                status.mark_running()
            else:
                status.mark_error("Proxy not running")
        except subprocess.TimeoutExpired:
            status.mark_error("tmux command timeout")
        except FileNotFoundError:
            status.mark_error("tmux not found")
        except Exception as exc:  # noqa: BLE001
            status.mark_error(f"Unexpected error: {exc}")
        return status

    @classmethod
    def check_frida_status(cls, device_id: str = "emulator-5554") -> "ServiceStatus":
        status = cls("frida")
        status.begin_start_attempt()
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "ps -A | grep frida-server"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            status.record_health_check()
            if result.returncode == 0 and "frida-server" in result.stdout:
                status.mark_running()
            else:
                status.mark_error("frida-server not running")
        except subprocess.TimeoutExpired:
            status.mark_error("ADB command timeout")
        except FileNotFoundError:
            status.mark_error("ADB not found")
        except Exception as exc:  # noqa: BLE001
            status.mark_error(f"Unexpected error: {exc}")
        return status


@dataclass
class ServiceManagerSnapshot:
    """Aggregated status payload returned to the UI layer."""

    services: List[ServiceStatus]
    last_updated: datetime = field(default_factory=_utcnow)

    @classmethod
    def from_services(cls, services: Iterable[ServiceStatus]) -> "ServiceManagerSnapshot":
        return cls(list(services))

    @property
    def all_ready(self) -> bool:
        return all(status.is_running for status in self.services)

    @property
    def initializing(self) -> bool:
        return any(status.is_starting for status in self.services)

    @property
    def blocking_errors(self) -> List[str]:
        return [status.service_name for status in self.services if status.retries_exhausted]

    @property
    def failed_services(self) -> List[str]:
        """Get list of services in failed/error state."""
        return [
            status.service_name 
            for status in self.services 
            if status.status in ("failed", "error")
        ]

    @property
    def retry_in_progress(self) -> bool:
        """Check if any service is currently retrying."""
        return any(
            status.retry_count > 0 and status.status != "running"
            for status in self.services
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "services": [status.to_dict() for status in self.services],
            "all_ready": self.all_ready,
            "initializing": self.initializing,
            "blocking_errors": self.blocking_errors,
            "failed_services": self.failed_services,
            "retry_in_progress": self.retry_in_progress,
            "timestamp": self.last_updated.isoformat(),
            "last_updated": self.last_updated.isoformat(),
        }
