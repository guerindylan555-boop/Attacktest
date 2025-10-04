"""Reusable Qt worker helpers for background tasks in the control center UI."""
from __future__ import annotations

import subprocess
from typing import Optional

from PySide6.QtCore import QObject, QRunnable, Signal

from automation.services.service_manager import ServiceManager
from automation.session.controller import SessionController, SessionRestartError
from automation.session.metrics import (
    increment_restart_failure,
    observe_restart_duration,
)

import time


class ScreenCaptureSignals(QObject):
    """Signals emitted by the screen capture worker."""

    frameReady = Signal(bytes)
    error = Signal(str)


class ScreenCaptureWorker(QRunnable):
    """Capture a screen frame from the connected emulator via adb."""

    def __init__(self, device_id: str = "emulator-5554", timeout: int = 5) -> None:
        super().__init__()
        self.device_id = device_id
        self.timeout = timeout
        self.signals = ScreenCaptureSignals()

    def run(self) -> None:  # noqa: D401
        try:
            result = subprocess.run(
                ["adb", "-s", self.device_id, "exec-out", "screencap", "-p"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout,
            )
            if result.returncode == 0 and result.stdout:
                self.signals.frameReady.emit(result.stdout)
            else:
                message = result.stderr.decode("utf-8", "ignore") or "Failed to capture screen"
                self.signals.error.emit(message)
        except subprocess.TimeoutExpired:
            self.signals.error.emit("Screen capture timed out")
        except FileNotFoundError:
            self.signals.error.emit("adb executable not found")
        except Exception as exc:  # noqa: BLE001
            self.signals.error.emit(str(exc))


class ServiceSnapshotSignals(QObject):
    """Signals emitted by the service snapshot worker."""

    snapshotReady = Signal(dict)
    error = Signal(str)


class ServiceSnapshotWorker(QRunnable):
    """Fetch a retry-aware service snapshot off the UI thread."""

    def __init__(self, service_manager: ServiceManager, refresh: bool = True) -> None:
        super().__init__()
        self.service_manager = service_manager
        self.refresh = refresh
        self.signals = ServiceSnapshotSignals()

    def run(self) -> None:  # noqa: D401
        try:
            snapshot = self.service_manager.get_service_snapshot(refresh=self.refresh)
            self.signals.snapshotReady.emit(snapshot)
        except Exception as exc:  # noqa: BLE001
            self.signals.error.emit(str(exc))


class ResetSignals(QObject):
    done = Signal(dict)
    error = Signal(str)


class ResetAppFridaWorker(QRunnable):
    """Run reset_app_and_frida in background and emit result."""

    def __init__(self, service_manager: ServiceManager) -> None:
        super().__init__()
        self.service_manager = service_manager
        self.signals = ResetSignals()

    def run(self) -> None:  # noqa: D401
        try:
            result = self.service_manager.reset_app_and_frida()
            if result.get("status") == "success":
                self.signals.done.emit(result)
            else:
                self.signals.error.emit(result.get("error", "reset failed"))
        except Exception as exc:  # noqa: BLE001
            self.signals.error.emit(str(exc))


class SessionRestartSignals(QObject):
    completed = Signal(dict)
    failed = Signal(dict)


class SessionRestartWorker(QRunnable):
    """Execute SessionController.restart in a background thread."""

    def __init__(
        self,
        session_controller: SessionController,
        *,
        app_id: str,
        timeout_seconds: int,
        force_clear_data: bool,
        snapshot_tag: str | None,
    ) -> None:
        super().__init__()
        self.session_controller = session_controller
        self.app_id = app_id
        self.timeout_seconds = timeout_seconds
        self.force_clear_data = force_clear_data
        self.snapshot_tag = snapshot_tag
        self.signals = SessionRestartSignals()

    def run(self) -> None:  # noqa: D401
        start = time.perf_counter()
        try:
            state = self.session_controller.restart(
                app_id=self.app_id,
                timeout_seconds=self.timeout_seconds,
                force_clear_data=self.force_clear_data,
                snapshot_tag=self.snapshot_tag,
            )
            duration = time.perf_counter() - start
            observe_restart_duration(app_id=self.app_id, duration_seconds=duration)
            self.signals.completed.emit({"state": state, "duration": duration})
        except SessionRestartError as exc:
            increment_restart_failure(app_id=self.app_id, error_code=exc.code)
            self.signals.failed.emit(
                {
                    "code": exc.code,
                    "message": exc.message,
                    "session": exc.session,
                }
            )
        except Exception as exc:  # noqa: BLE001
            self.signals.failed.emit(
                {
                    "code": "UNEXPECTED",
                    "message": str(exc),
                    "session": None,
                }
            )
