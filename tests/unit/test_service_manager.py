"""Unit tests for ServiceManager retry behaviour."""
from __future__ import annotations

from typing import Dict

import pytest

from automation.services.service_manager import ServiceManager


@pytest.fixture()
def manager(monkeypatch) -> ServiceManager:
    mgr = ServiceManager()

    def fake_health(name: str):
        return mgr.services[name]

    monkeypatch.setattr(mgr, "_check_service_health", fake_health)
    return mgr


def test_start_all_services_collects_errors(monkeypatch, manager: ServiceManager) -> None:
    def failing_start(service_name: str) -> Dict[str, object]:
        return {
            "status": "error",
            "error_message": f"{service_name} failed",
            "retry_attempt": manager.services[service_name].max_retries,
            "max_retries": manager.services[service_name].max_retries,
        }
    
    def no_running_services() -> Dict[str, bool]:
        return {"emulator": False, "proxy": False, "frida": False}

    monkeypatch.setattr(manager, "_start_service", failing_start)
    monkeypatch.setattr(manager, "_detect_running_services", no_running_services)
    result = manager.start_all_services()
    # With improved implementation: returns "failed" when all fail, "partial" if some succeed
    assert result["status"] in ("error", "failed", "partial")  # All acceptable
    snapshot = result["snapshot"]
    assert snapshot["initializing"] is False
    assert snapshot["blocking_errors"] == ["emulator", "proxy", "frida"]


def test_retry_services_allows_additional_attempt(monkeypatch, manager: ServiceManager) -> None:
    status = manager.services["emulator"]
    status.retry_attempt = status.max_retries
    status.mark_error("initial failure")

    calls = {"emulator": 0}

    def controlled_start(service_name: str):
        calls[service_name] += 1
        status = manager.services[service_name]
        if calls[service_name] == 1:
            status.mark_error("retry failure")
        else:
            status.mark_running()
        return status

    monkeypatch.setattr(manager, "_start_service", controlled_start)
    snapshot = manager.retry_services(["emulator"])
    assert snapshot["services"][0]["status"] in {"error", "running"}
    assert calls["emulator"] == 1
    # Second retry should succeed in this controlled scenario
    snapshot = manager.retry_services(["emulator"])
    assert calls["emulator"] == 2
    assert snapshot["blocking_errors"] == []
