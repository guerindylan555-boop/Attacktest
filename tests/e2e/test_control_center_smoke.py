from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
import time
import os

import pytest
from PySide6.QtWidgets import QApplication

from automation.logs import configure_logging
from automation.ui.control_center import ControlCenter


@pytest.fixture(autouse=True)
def _configure_logging(tmp_path: Path) -> None:
    log_path = tmp_path / "logs" / "session.jsonl"
    os.environ["AUTOMATION_LOG_FILE"] = str(log_path)
    configure_logging(log_file=log_path)
    yield
    os.environ.pop("AUTOMATION_LOG_FILE", None)


class DummyAutomationController:
    def __init__(self, service_manager) -> None:  # noqa: D401
        self.service_manager = service_manager

    def get_action_states(self) -> Dict[str, Any]:  # pragma: no cover - simple stub
        return {"actions": [], "services": []}


class DummyServiceManager:
    def get_service_snapshot(self, refresh: bool = False) -> Dict[str, Any]:
        return {"services": []}


class DummyTokenController:
    def __init__(self, service_manager) -> None:
        self.service_manager = service_manager


def test_smoke_control_center_initialises(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("automation.ui.control_center.ServiceManager", DummyServiceManager)
    monkeypatch.setattr("automation.ui.control_center.AutomationController", DummyAutomationController)
    monkeypatch.setattr("automation.ui.control_center.TokenCaptureController", DummyTokenController)
    monkeypatch.setattr("automation.ui.control_center.ControlCenter._start_services_automatically", lambda self: None)
    monkeypatch.setattr("automation.ui.control_center.ControlCenter._start_timers", lambda self: None)
    monkeypatch.setattr("automation.ui.control_center.ControlCenter.closeEvent", lambda self, event: event.accept())

    app = QApplication.instance() or QApplication([])
    window = ControlCenter()
    window.show()

    assert window.windowTitle() == "MaynDrive Control Center - Simplified"
    assert window.btn_restart_app.isEnabled()

    log_file = Path(window.log_file_path)
    window.logger.info("smoke test event")
    app.processEvents()
    assert log_file.parent.exists()

    window.close()
    app.processEvents()
