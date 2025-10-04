"""Contract tests for service management endpoints."""
from __future__ import annotations

from datetime import datetime
from typing import Dict

import pytest


@pytest.fixture()
def managed_services(monkeypatch) -> "ServiceManager":
    from automation.services.service_manager import ServiceManager

    manager = ServiceManager()

    # Prevent real subprocess calls during contract tests.
    def fake_start(service_name: str) -> Dict[str, object]:
        return {
            "name": service_name,
            "status": "running",
            "retry_attempt": 0,
            "max_retries": 3,
            "startup_time": 0.1,
            "pid": 1234,
            "error_message": None,
            "last_transition": datetime.utcnow().isoformat(),
        }

    monkeypatch.setattr(manager, "_start_service", fake_start, raising=False)
    monkeypatch.setattr(manager, "_stop_service", lambda name: None, raising=False)
    monkeypatch.setattr(manager, "_check_service_health", lambda name: None, raising=False)

    return manager


def _assert_snapshot(snapshot: Dict[str, object], *, expect_ready: bool) -> None:
    assert set(snapshot.keys()) >= {"services", "all_ready", "initializing", "blocking_errors", "last_updated"}
    services = snapshot["services"]
    assert isinstance(services, list)
    assert len(services) == 3
    for entry in services:
        assert set(entry.keys()) >= {"name", "status", "retry_attempt", "max_retries", "last_transition"}
        assert entry["name"] in {"emulator", "proxy", "frida"}
    assert snapshot["all_ready"] is expect_ready


def test_start_returns_retry_aware_snapshot(managed_services):
    """`/services/start` returns a retry-aware snapshot payload."""
    result = managed_services.start_all_services()
    assert result["status"] == "success"
    _assert_snapshot(result["snapshot"], expect_ready=True)


def test_status_returns_snapshot(managed_services):
    """`/services/status` exposes retry counters and error details."""
    snapshot = managed_services.get_service_status()
    _assert_snapshot(snapshot, expect_ready=False)


def test_stop_returns_stopped_services_list(managed_services):
    """`/services/stop` returns the set of services that were halted."""
    result = managed_services.stop_all_services()
    assert result["status"] == "success"
    assert set(result["stopped_services"]) == {"emulator", "proxy", "frida"}


def test_retry_endpoint_accepts_selection(monkeypatch, managed_services):
    """`/services/retry` accepts a subset of services and returns snapshot."""
    # Mark emulator as exhausted to force retry payload.
    status = managed_services.services["emulator"]
    assert hasattr(status, "retry_attempt")
    assert hasattr(status, "max_retries")
    status.retry_attempt = status.max_retries
    status.update_status("error", error_message="previous failure", pid=None)

    snapshot = managed_services.retry_services(["emulator"])
    _assert_snapshot(snapshot, expect_ready=False)
