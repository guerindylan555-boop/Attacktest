"""Integration tests for service startup, retries, and action gating."""
from __future__ import annotations

from datetime import datetime

import pytest


class ToggleServiceManager:
    """Service manager stub that can flip readiness state."""

    def __init__(self) -> None:
        self._ready = False
        self._snapshot = self._build_snapshot()

    def _build_snapshot(self):
        return {
            "services": [
                {
                    "name": "emulator",
                    "status": "error" if not self._ready else "running",
                    "retry_attempt": 3 if not self._ready else 0,
                    "max_retries": 3,
                    "error_message": "ADB command timeout" if not self._ready else None,
                    "last_transition": datetime.utcnow().isoformat(),
                },
                {
                    "name": "proxy",
                    "status": "starting" if not self._ready else "running",
                    "retry_attempt": 1 if not self._ready else 0,
                    "max_retries": 3,
                    "error_message": None,
                    "last_transition": datetime.utcnow().isoformat(),
                },
                {
                    "name": "frida",
                    "status": "error" if not self._ready else "running",
                    "retry_attempt": 2 if not self._ready else 0,
                    "max_retries": 3,
                    "error_message": "frida-server missing" if not self._ready else None,
                    "last_transition": datetime.utcnow().isoformat(),
                },
            ],
            "all_ready": self._ready,
            "initializing": not self._ready,
            "blocking_errors": ["emulator", "frida"] if not self._ready else [],
            "last_updated": datetime.utcnow().isoformat(),
        }

    def set_ready(self, ready: bool) -> None:
        self._ready = ready
        self._snapshot = self._build_snapshot()

    def are_all_services_ready(self) -> bool:
        return self._ready

    def get_service_snapshot(self, refresh: bool = False):  # noqa: ARG002
        return self._snapshot


@pytest.fixture()
def controller(monkeypatch) -> "AutomationController":
    from automation.services.automation_controller import AutomationController

    manager = ToggleServiceManager()
    return AutomationController(service_manager=manager)


def _action(payload, name: str):
    actions = {entry["action"]: entry for entry in payload["actions"]}
    return actions[name]


def test_buttons_disabled_until_services_ready(controller):
    """Record, replay, and capture buttons remain disabled while services retry."""
    snapshot = controller.service_manager.get_service_snapshot()
    assert snapshot["all_ready"] is False
    payload = controller.get_action_states()
    record_state = _action(payload, "record")
    assert record_state["enabled"] is False
    assert "emulator" in record_state["requires_services"]

    controller.service_manager.set_ready(True)
    payload = controller.get_action_states()
    record_state = _action(payload, "record")
    assert record_state["enabled"] is True
    assert record_state["in_progress"] is False


def test_retry_exhaustion_surfaces_blocking_errors(controller):
    """When retries are exhausted, blocking errors should surface to the UI payload."""
    payload = controller.get_action_states()
    assert controller.service_manager.get_service_snapshot()["blocking_errors"]
    assert payload["services"][0]["retry_attempt"] == 3
