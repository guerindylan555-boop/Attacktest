"""Integration tests for the automation recording workflow."""
from __future__ import annotations

import pytest

from tests.integration.test_service_startup import ToggleServiceManager, _action


@pytest.fixture()
def ready_controller(monkeypatch, tmp_path) -> "AutomationController":
    from automation.services.automation_controller import AutomationController
    from automation.models.recording import AutomationRecording

    manager = ToggleServiceManager()
    manager.set_ready(True)
    controller = AutomationController(service_manager=manager)

    monkeypatch.setattr(
        AutomationRecording,
        "save_to_file",
        lambda self, recordings_dir=None: tmp_path / f"{self.id}.json",
        raising=False,
    )

    return controller


def test_record_start_sets_in_progress_state(ready_controller):
    """Starting a recording must disable the record button and mark it in progress."""
    actions = ready_controller.get_action_states()
    assert _action(actions, "record")["enabled"] is True

    result = ready_controller.start_recording()
    ui_state = result["ui_state"]
    assert ui_state["action"] == "record"
    assert ui_state["enabled"] is False
    assert ui_state["in_progress"] is True


def test_stop_recording_emits_evidence_bundle(ready_controller):
    """Stopping a recording produces evidence metadata and re-enables the action."""
    start_result = ready_controller.start_recording()
    stop_result = ready_controller.stop_recording(start_result["recording_id"])

    assert stop_result["status"] == "success"
    assert stop_result["file_path"].endswith(".json")
    evidence = stop_result["evidence"]
    assert isinstance(evidence, list)
    assert evidence[0]["artifact_type"] == "recording"

    actions = ready_controller.get_action_states()
    record_state = _action(actions, "record")
    assert record_state["enabled"] is True
    assert record_state["in_progress"] is False
