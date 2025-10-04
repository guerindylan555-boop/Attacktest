"""Contract tests for automation controller endpoints."""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List

import pytest


class DummyServiceManager:
    """Stub service manager returning a fixed retry snapshot."""

    def __init__(self, ready: bool = True) -> None:
        self._ready = ready
        self._snapshot = {
            "services": [
                {
                    "name": "emulator",
                    "status": "running" if ready else "error",
                    "retry_attempt": 0 if ready else 3,
                    "max_retries": 3,
                    "error_message": None if ready else "ADB command timeout",
                },
                {
                    "name": "proxy",
                    "status": "running" if ready else "starting",
                    "retry_attempt": 0,
                    "max_retries": 3,
                    "error_message": None,
                },
                {
                    "name": "frida",
                    "status": "running" if ready else "error",
                    "retry_attempt": 1 if ready else 3,
                    "max_retries": 3,
                    "error_message": None if ready else "frida-server missing",
                },
            ],
            "all_ready": ready,
            "initializing": not ready,
            "blocking_errors": [] if ready else ["emulator"],
            "last_updated": datetime.utcnow().isoformat(),
        }

    def are_all_services_ready(self) -> bool:
        return self._ready

    def get_service_snapshot(self, refresh: bool = False) -> Dict[str, object]:  # noqa: ARG002
        return self._snapshot


@pytest.fixture()
def ready_controller(monkeypatch) -> "AutomationController":
    from automation.services.automation_controller import AutomationController

    dummy_manager = DummyServiceManager(ready=True)
    controller = AutomationController(service_manager=dummy_manager)

    # Avoid writing real files during tests.
    from automation.models.recording import AutomationRecording

    monkeypatch.setattr(
        AutomationRecording,
        "save_to_file",
        lambda self, recordings_dir=None: self.metadata.get("test_path", "recordings/test.json"),
        raising=False,
    )

    return controller


@pytest.fixture()
def unready_controller() -> "AutomationController":
    from automation.services.automation_controller import AutomationController

    return AutomationController(service_manager=DummyServiceManager(ready=False))


def _assert_action_state_schema(actions: List[Dict[str, object]]) -> None:
    assert isinstance(actions, list)
    assert {entry.get("action") for entry in actions} == {"record", "replay", "capture_token"}
    for entry in actions:
        assert set(entry.keys()) >= {"action", "enabled", "requires_services", "in_progress"}
        assert isinstance(entry["enabled"], bool)
        assert isinstance(entry["requires_services"], list)
        assert isinstance(entry["in_progress"], bool)


def test_actions_endpoint_returns_three_actions(ready_controller):
    """`/automation/actions` must expose three action states."""
    actions_payload = ready_controller.get_action_states()
    assert set(actions_payload.keys()) == {"actions", "services"}
    _assert_action_state_schema(actions_payload["actions"])


def test_start_recording_includes_ui_state(ready_controller):
    """`/automation/record` success returns ui_state that disables the button."""
    result = ready_controller.start_recording()
    assert result["status"] == "success"
    assert isinstance(result["recording_id"], str)
    assert "ui_state" in result
    ui_state = result["ui_state"]
    assert ui_state["action"] == "record"
    assert ui_state["in_progress"] is True
    assert ui_state["enabled"] is False


def test_start_recording_unready_services_returns_retry_payload(unready_controller):
    """`/automation/record` error must include retry-aware service payload."""
    result = unready_controller.start_recording()
    assert result["status"] == "error"
    assert result["reason"] == "services_not_ready"
    assert "services" in result
    services = result["services"]
    assert isinstance(services, list)
    assert {svc["name"] for svc in services} == {"emulator", "proxy", "frida"}
    first = services[0]
    assert set(first.keys()) >= {"name", "status", "retry_attempt", "max_retries"}


def test_stop_recording_returns_file_path_and_ui_state(ready_controller):
    """`/automation/stop-record` response includes evidence file and ui_state."""
    start_result = ready_controller.start_recording()
    result = ready_controller.stop_recording(start_result["recording_id"])
    assert result["status"] == "success"
    assert "file_path" in result
    assert result["file_path"].endswith(".json")
    ui_state = result["ui_state"]
    assert ui_state["action"] == "record"
    assert ui_state["enabled"] is True
    assert ui_state["in_progress"] is False


def test_replay_missing_recording_returns_error_payload(ready_controller):
    """`/automation/replay` missing recording surfaces contract error payload."""
    result = ready_controller.replay_recording("missing-recording")
    assert result["status"] == "error"
    assert result["reason"] == "recording_not_found"
    assert "ui_state" in result
    ui_state = result["ui_state"]
    assert ui_state["action"] == "replay"
    assert ui_state["enabled"] is True
    assert ui_state["in_progress"] is False
