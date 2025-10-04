"""Readiness probes bridging ServiceManager state into SessionController."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from automation.services.service_manager import ServiceManager
from .state import ReadinessCheck, ReadinessStatus, SessionState


@dataclass
class ServiceReadinessProbe:
    """Probe that ensures core services report a running state."""

    service_manager: ServiceManager
    required_services: List[str] = None
    name: str = "login_ui"

    def __post_init__(self) -> None:
        if self.required_services is None:
            self.required_services = ["emulator", "proxy", "frida", "appium"]

    def run(self, session: SessionState) -> ReadinessCheck:
        snapshot = self.service_manager.get_service_snapshot(refresh=True)
        services = {item["name"]: item for item in snapshot.get("services", [])}
        missing = [name for name in self.required_services if services.get(name, {}).get("status") != "running"]
        status = ReadinessStatus.PASS if not missing else ReadinessStatus.FAIL
        details = "All automation services running" if status is ReadinessStatus.PASS else f"Services not ready: {', '.join(missing)}"
        return ReadinessCheck(name=self.name, status=status, details=details)


@dataclass
class FridaHeartbeatProbe:
    """Probe that checks Frida service readiness."""

    service_manager: ServiceManager
    name: str = "frida_hook"

    def run(self, session: SessionState) -> ReadinessCheck:
        snapshot = self.service_manager.get_service_snapshot(refresh=True)
        services = {item["name"]: item for item in snapshot.get("services", [])}
        frida = services.get("frida", {})
        running = frida.get("status") == "running"
        status = ReadinessStatus.PASS if running else ReadinessStatus.FAIL
        details = "Frida hook active" if status is ReadinessStatus.PASS else frida.get("error_message", "Frida hook inactive")
        return ReadinessCheck(name=self.name, status=status, details=details)


@dataclass
class MetricsEndpointProbe:
    """Probe that ensures structured logging has been initialised."""

    log_path: str
    name: str = "metrics_endpoint"

    def run(self, session: SessionState) -> ReadinessCheck:
        try:
            from pathlib import Path

            path = Path(self.log_path)
            status = ReadinessStatus.PASS if path.exists() else ReadinessStatus.WARN
            details = "Log sink initialised" if status is ReadinessStatus.PASS else f"Log sink missing at {path}"
            return ReadinessCheck(name=self.name, status=status, details=details)
        except Exception as exc:  # pragma: no cover - defensive guard
            return ReadinessCheck(name=self.name, status=ReadinessStatus.WARN, details=str(exc))


__all__ = [
    "ServiceReadinessProbe",
    "FridaHeartbeatProbe",
    "MetricsEndpointProbe",
]
