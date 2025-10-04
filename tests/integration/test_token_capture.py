"""Integration tests for token capture workflow."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict

import json
import pytest

from tests.integration.test_service_startup import ToggleServiceManager, _action


@pytest.fixture()
def token_controller(monkeypatch, tmp_path) -> "TokenCaptureController":
    from automation.services.token_controller import TokenCaptureController
    from automation.models.token_session import TokenCaptureSession

    manager = ToggleServiceManager()
    manager.set_ready(True)
    controller = TokenCaptureController(service_manager=manager)

    monkeypatch.setattr(
        controller,
        "_run_capture_script",
        lambda: {"success": True, "tokens": ["token-123"], "output": "ok"},
        raising=False,
    )

    def fake_save(self, sessions_dir=None):
        path = tmp_path / f"{self.session_id}.json"
        path.write_text(json.dumps({"session_id": self.session_id, "tokens": self.captured_tokens}))
        return path

    monkeypatch.setattr(TokenCaptureSession, "save_to_file", fake_save, raising=False)

    return controller


def test_token_capture_start_sets_action_state(token_controller):
    """Starting token capture disables the capture button."""
    result = token_controller.start_token_capture()
    assert result["status"] == "success"
    ui_state = result["ui_state"]
    assert ui_state["action"] == "capture_token"
    assert ui_state["enabled"] is False
    assert ui_state["in_progress"] is True


def test_token_capture_completion_emits_evidence(token_controller):
    """Completing token capture surfaces evidence metadata and re-enables the action."""
    start_result = token_controller.start_token_capture()
    session_id = start_result["session_id"]
    result = token_controller.complete_token_capture(session_id, ["token-abc"])
    assert result["status"] == "success"
    evidence = result["evidence"]
    assert any(item["artifact_type"] == "token_json" for item in evidence)

    from automation.services.automation_controller import AutomationController

    automation_controller = AutomationController(service_manager=token_controller.service_manager)
    actions = automation_controller.get_action_states()
    capture_state = _action(actions, "capture_token")
    assert capture_state["enabled"] is True


def test_missing_credentials_returns_contract_payload(monkeypatch):
    """Missing credentials should return a structured error payload."""
    from automation.services.token_controller import TokenCaptureController

    manager = ToggleServiceManager()
    manager.set_ready(True)
    controller = TokenCaptureController(service_manager=manager)
    monkeypatch.setattr(controller, "_get_blhack_credentials", lambda: None)

    result = controller.start_token_capture()
    assert result["status"] == "error"
    assert result["reason"] == "credentials_missing"
    assert "ui_state" in result
    state = result["ui_state"]
    assert state["action"] == "capture_token"
    assert state["enabled"] is False
