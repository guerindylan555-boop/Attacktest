"""Integration tests for the replay workflow."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict

import json
import pytest

from tests.integration.test_service_startup import ToggleServiceManager, _action


def _write_recording(tmp_path: Path) -> Dict[str, object]:
    recording_id = "test-recording"
    payload = {
        "id": recording_id,
        "timestamp": datetime.utcnow().isoformat(),
        "duration": 1.2,
        "interactions": [],
        "metadata": {"source": "unit-test"},
    }
    file_path = tmp_path / f"20250101_000000_automation_recording_{recording_id}.json"
    file_path.write_text(json.dumps(payload))
    return {"id": recording_id, "path": file_path}


@pytest.fixture()
def replay_controller(monkeypatch, tmp_path) -> "AutomationController":
    from automation.services.automation_controller import AutomationController

    manager = ToggleServiceManager()
    manager.set_ready(True)
    controller = AutomationController(service_manager=manager)

    recording = _write_recording(tmp_path)
    monkeypatch.setattr(
        controller,
        "_find_recording_file",
        lambda recording_id: recording["path"] if recording_id == recording["id"] else None,
        raising=False,
    )
    monkeypatch.setattr(controller, "_execute_replay", lambda recording, replay_id: None, raising=False)

    return controller


def test_replay_sets_in_progress_state(replay_controller):
    """Starting a replay should disable the replay button and mark it in progress."""
    result = replay_controller.replay_recording("test-recording")
    assert result["status"] == "success"
    ui_state = result["ui_state"]
    assert ui_state["action"] == "replay"
    assert ui_state["enabled"] is False
    assert ui_state["in_progress"] is True

    actions = replay_controller.get_action_states()
    replay_state = _action(actions, "replay")
    assert replay_state["in_progress"] is True


def test_replay_completion_resets_action_state(replay_controller):
    """When replay completes, the button returns to enabled state."""
    replay_controller.replay_recording("test-recording")
    replay_controller.finalize_replay()

    actions = replay_controller.get_action_states()
    replay_state = _action(actions, "replay")
    assert replay_state["enabled"] is True
    assert replay_state["in_progress"] is False
