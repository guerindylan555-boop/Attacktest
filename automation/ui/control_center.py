from __future__ import annotations

import sys
from pathlib import Path
import subprocess
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple
import xml.etree.ElementTree as ET

from PySide6.QtCore import Qt, QThreadPool, QTimer
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from automation.logs import configure_logging, get_logger
from automation.services.automation_controller import AutomationController
from automation.services.service_manager import ServiceManager
from automation.services.token_controller import TokenCaptureController
from automation.session.controller import SessionController, SessionRestartError
from automation.session.drivers import ADBRestartDriver
from automation.session.probes import (
    ServiceReadinessProbe,
    FridaHeartbeatProbe,
    MetricsEndpointProbe,
)
from automation.session.state import SessionState
from automation.ui.qt_workers import (
    ScreenCaptureWorker,
    ServiceSnapshotWorker,
    ResetAppFridaWorker,
    SessionRestartWorker,
)

DEFAULT_DEVICE_ID = "emulator-5554"
LOG_OUTPUT_PATH = Path(
    os.getenv(
        "AUTOMATION_LOG_FILE",
        Path(__file__).resolve().parents[2] / "automation" / "logs" / "control_center.jsonl",
    )
)

configure_logging(log_file=LOG_OUTPUT_PATH)


class ControlCenter(QMainWindow):
    """PySide6 control center UI with retry-aware service management."""

    def __init__(self) -> None:
        super().__init__()
        logger = get_logger("control_center.gui")
        self.log_file_path = self._resolve_log_file_path(logger)
        self.logger = logger
        self.logger.info("initialising control center UI", log_path=str(self.log_file_path))
        self.setWindowTitle("MaynDrive Control Center - Simplified")
        self.resize(1280, 720)

        self.service_manager = ServiceManager()
        self.automation_controller = AutomationController(self.service_manager)
        self.token_controller = TokenCaptureController(self.service_manager)
        self.session_controller = self._build_session_controller()
        self.session_state: Optional[SessionState] = None
        self.restart_timeout = int(os.getenv("AUTOMATION_RESTART_TIMEOUT", "30"))
        self.restart_force_clear = os.getenv("AUTOMATION_FORCE_CLEAR", "false").lower() in {"1", "true", "yes"}
        self.restart_snapshot_tag = os.getenv("AUTOMATION_SNAPSHOT_TAG")

        self.thread_pool = QThreadPool.globalInstance()
        self._screen_worker_active = False
        self._status_worker_active = False
        self._last_frame_size = None  # (width, height) of last device frame
        self._last_pixmap_size = None  # QSize of last scaled pixmap

        self._record_in_progress = False
        self._replay_in_progress = False
        self._capture_in_progress = False

        self.status_labels: Dict[str, QLabel] = {}

        self._build_ui()
        self._start_timers()
        self._start_services_automatically()
        self._refresh_action_buttons()

    def _build_session_controller(self) -> Optional[SessionController]:
        try:
            device_id = os.getenv("ANDROID_DEVICE_ID", DEFAULT_DEVICE_ID)
            package = os.getenv("MAYNDRIVE_APP_PACKAGE", "fr.mayndrive.app")
            activity = os.getenv("MAYNDRIVE_APP_ACTIVITY")
            driver = ADBRestartDriver(device_id=device_id, package=package, activity=activity)
            probes = [
                ServiceReadinessProbe(self.service_manager),
                FridaHeartbeatProbe(self.service_manager),
                MetricsEndpointProbe(str(self.log_file_path)),
            ]
            return SessionController(driver=driver, readiness_probes=probes)
        except Exception as exc:  # noqa: BLE001
            self.logger.warning("failed to initialise session controller", error=str(exc))
            return None

    def _resolve_log_file_path(self, logger) -> Path:
        env_path = os.getenv("AUTOMATION_LOG_FILE")
        if env_path:
            return Path(env_path)
        sink_path: Optional[str] = None
        if hasattr(logger, "_core"):
            handlers = getattr(logger._core, "handlers", [])
            if handlers:
                sink = handlers[0]._sink  # type: ignore[attr-defined]
                sink_path = getattr(sink, "name", None)

        if sink_path:
            return Path(str(sink_path))

        return LOG_OUTPUT_PATH

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)

        root_layout = QHBoxLayout(central)
        control_column = QVBoxLayout()
        control_column.setSpacing(15)
        root_layout.addLayout(control_column, 1)

        title_label = QLabel("Automation Control")
        title_label.setStyleSheet(
            "font-size: 18px; font-weight: bold; color: #2c3e50; margin-bottom: 10px;"
        )
        control_column.addWidget(title_label)

        self.btn_record_automation = self._build_primary_button(
            "Record Automation", "#3498db"
        )
        self.btn_record_automation.clicked.connect(self._on_record_clicked)
        control_column.addWidget(self.btn_record_automation)

        self.btn_replay_automation = self._build_primary_button(
            "Replay Automation", "#27ae60"
        )
        self.btn_replay_automation.clicked.connect(self._on_replay_clicked)
        control_column.addWidget(self.btn_replay_automation)

        self.btn_capture_token = self._build_primary_button(
            "Capture Token", "#e74c3c"
        )
        self.btn_capture_token.clicked.connect(self._on_capture_clicked)
        control_column.addWidget(self.btn_capture_token)

        self.btn_delete_recording = self._build_primary_button(
            "Delete Recording", "#f39c12", enabled=True
        )
        self.btn_delete_recording.clicked.connect(self._on_delete_recording_clicked)
        control_column.addWidget(self.btn_delete_recording)

        self.btn_reset_app_frida = self._build_primary_button(
            "Reset App + Frida", "#8e44ad", enabled=True
        )
        self.btn_reset_app_frida.clicked.connect(self._on_reset_app_frida_clicked)
        control_column.addWidget(self.btn_reset_app_frida)

        self.btn_restart_app = self._build_primary_button(
            "Restart App", "#16a085", enabled=True
        )
        self.btn_restart_app.clicked.connect(self._on_restart_app_clicked)
        control_column.addWidget(self.btn_restart_app)

        self._action_buttons = {
            "record": self.btn_record_automation,
            "replay": self.btn_replay_automation,
            "capture_token": self.btn_capture_token,
        }

        control_column.addStretch(1)

        status_title = QLabel("Service Status")
        status_title.setStyleSheet(
            "font-size: 14px; font-weight: bold; color: #2c3e50; margin-top: 20px;"
        )
        control_column.addWidget(status_title)

        for key, title in [
            ("emulator", "Emulator"),
            ("proxy", "Proxy"),
            ("frida", "Frida"),
            ("appium", "Appium"),
            ("restart", "Restart Flow"),
            ("replay", "Replay Flow"),
            ("catalog", "UI Catalog"),
            ("logs", "Structured Logs"),
        ]:
            layout = QVBoxLayout()
            label_title = QLabel(title)
            label_title.setStyleSheet("font-weight: bold; color: #34495e;")
            status_label = QLabel("Starting...")
            status_label.setStyleSheet("color: #bdc3c7; font-size: 12px;")
            layout.addWidget(label_title)
            layout.addWidget(status_label)
            control_column.addLayout(layout)
            self.status_labels[key] = status_label

        self._set_status_label("restart", "Idle", "#bdc3c7")
        self._set_status_label("replay", "Idle", "#bdc3c7")
        self._set_status_label("catalog", "Idle", "#bdc3c7")
        self._set_status_label("logs", str(self.log_file_path), "#34495e")

        screen_layout = QVBoxLayout()
        root_layout.addLayout(screen_layout, 3)

        self.screen_label = QLabel("Screen preview will appear here")
        self.screen_label.setAlignment(Qt.AlignCenter)
        self.screen_label.setSizePolicy(
            QSizePolicy.Expanding, QSizePolicy.Expanding
        )
        self.screen_label.setStyleSheet(
            "background-color: #1e1e1e; color: #ecf0f1; border-radius: 8px;"
        )
        # Enable mouse tracking for interaction capture
        self.screen_label.setMouseTracking(True)
        self.screen_label.mousePressEvent = self._on_screen_click
        screen_layout.addWidget(self.screen_label)

        log_layout = QVBoxLayout()
        log_title = QLabel("Activity Log")
        log_title.setStyleSheet("font-weight: bold; color: #2c3e50;")
        log_layout.addWidget(log_title)

        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumHeight(200)
        self.log_view.setStyleSheet(
            """
            QPlainTextEdit {
                background-color: #2c3e50;
                color: #ecf0f1;
                border: 1px solid #34495e;
                border-radius: 4px;
                font-family: 'Courier New', monospace;
                font-size: 11px;
            }
            """
        )
        log_layout.addWidget(self.log_view)
        screen_layout.addLayout(log_layout)

    def _build_primary_button(self, text: str, color: str, *, enabled: bool = False) -> QPushButton:
        button = QPushButton(text)
        button.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {color};
                color: white;
                border: none;
                padding: 12px;
                font-size: 14px;
                font-weight: bold;
                border-radius: 6px;
            }}
            QPushButton:hover {{
                background-color: {self._darken(color)};
            }}
            QPushButton:pressed {{
                background-color: {self._darken(color, 0.15)};
            }}
            QPushButton:disabled {{
                background-color: #bdc3c7;
                color: #7f8c8d;
            }}
            """
        )
        button.setEnabled(enabled)
        return button

    @staticmethod
    def _darken(color: str, factor: float = 0.1) -> str:
        color = color.lstrip("#")
        r = int(color[0:2], 16)
        g = int(color[2:4], 16)
        b = int(color[4:6], 16)
        r = max(0, int(r * (1 - factor)))
        g = max(0, int(g * (1 - factor)))
        b = max(0, int(b * (1 - factor)))
        return f"#{r:02x}{g:02x}{b:02x}"

    # ------------------------------------------------------------------
    # Timers and background work
    # ------------------------------------------------------------------
    def _start_timers(self) -> None:
        self.status_timer = QTimer(self)
        self.status_timer.setInterval(5000)
        self.status_timer.timeout.connect(self._request_service_snapshot)
        self.status_timer.start()

        self.screen_timer = QTimer(self)
        self.screen_timer.setInterval(100)  # 10 Hz (100ms intervals) for smooth preview
        self.screen_timer.timeout.connect(self.schedule_screen_capture)
        self.screen_timer.start()

    def _request_service_snapshot(self) -> None:
        if self._status_worker_active:
            return
        worker = ServiceSnapshotWorker(self.service_manager, refresh=True)
        worker.signals.snapshotReady.connect(self._handle_snapshot)
        worker.signals.error.connect(self._handle_snapshot_error)
        self.thread_pool.start(worker)
        self._status_worker_active = True

    def schedule_screen_capture(self) -> None:
        if self._screen_worker_active:
            return
        worker = ScreenCaptureWorker(device_id=DEFAULT_DEVICE_ID)
        worker.signals.frameReady.connect(self._handle_screen_bytes)
        worker.signals.error.connect(self._handle_screen_error)
        self.thread_pool.start(worker)
        self._screen_worker_active = True

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------
    def _handle_snapshot(self, snapshot: Dict[str, Any]) -> None:
        self._status_worker_active = False
        self._apply_service_status(snapshot.get("services", []))
        self._refresh_action_buttons()

    def _handle_snapshot_error(self, message: str) -> None:
        self._status_worker_active = False
        self.append_log(f"[ERROR] Status refresh failed: {message}")

    def _handle_screen_bytes(self, data: bytes) -> None:
        self._screen_worker_active = False
        image = QImage.fromData(data, "PNG")
        if image.isNull():
            self._handle_screen_error("Invalid screen data")
            return
        pixmap = QPixmap.fromImage(image)
        # Keep original device frame size for coordinate mapping
        self._last_frame_size = (image.width(), image.height())
        scaled = pixmap.scaled(self.screen_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self._last_pixmap_size = scaled.size()
        self.screen_label.setPixmap(scaled)

    def _handle_screen_error(self, message: str) -> None:
        self._screen_worker_active = False
        self.append_log(f"[SCREEN] {message}")

    # ------------------------------------------------------------------
    # Button callbacks
    # ------------------------------------------------------------------
    def _on_record_clicked(self) -> None:
        if self._record_in_progress:
            self._stop_recording()
        else:
            self._start_recording()

    def _on_replay_clicked(self) -> None:
        if self._replay_in_progress:
            self.append_log("[INFO] Replay already running; waiting for completion")
        else:
            self._start_replay()

    def _on_capture_clicked(self) -> None:
        if self._capture_in_progress:
            self.append_log("[INFO] Token capture already in progress")
        else:
            self._start_token_capture()

    def _on_screen_click(self, event) -> None:
        """Handle click on screen preview - with recording gate check."""
        # Check if interaction is allowed (recording must be active)
        # Allow controlling the device even when not recording
        
        # Map click within label to device coordinates
        label_w = self.screen_label.width()
        label_h = self.screen_label.height()
        if self._last_frame_size is None or self._last_pixmap_size is None:
            self._handle_screen_error("No frame available for coordinate mapping")
            return
        pix_w = self._last_pixmap_size.width()
        pix_h = self._last_pixmap_size.height()
        # Offsets due to aspect-fit centering
        off_x = max(0, (label_w - pix_w) // 2)
        off_y = max(0, (label_h - pix_h) // 2)
        click_x = event.pos().x() - off_x
        click_y = event.pos().y() - off_y
        if click_x < 0 or click_y < 0 or click_x >= pix_w or click_y >= pix_h:
            # Click landed in letterboxed area; ignore
            self.append_log("[SCREEN] Click outside preview area; ignored")
            return
        dev_w, dev_h = self._last_frame_size
        # Scale from preview pixels to device pixels
        scale_x = dev_w / float(pix_w)
        scale_y = dev_h / float(pix_h)
        dev_x = int(click_x * scale_x)
        dev_y = int(click_y * scale_y)

        # Identify UI element at the click position (best-effort)
        element_info = self._identify_ui_element_at(dev_x, dev_y)

        # Perform the tap on the device via adb
        try:
            subprocess.run([
                "adb", "-s", DEFAULT_DEVICE_ID, "shell", "input", "tap", str(dev_x), str(dev_y)
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        except FileNotFoundError:
            self.append_log("[ERROR] adb executable not found; cannot send tap")
        except subprocess.TimeoutExpired:
            self.append_log("[ERROR] adb tap command timed out")

        # If recording, append the interaction; otherwise just log the tap
        if self._record_in_progress:
            result = self.automation_controller.add_interaction(
                "click",
                x=dev_x,
                y=dev_y,
                view_x=int(event.pos().x()),
                view_y=int(event.pos().y()),
                element=element_info or None,
            )
            if result.get("status") == "success":
                if element_info:
                    label = element_info.get("resource_id") or element_info.get("content_desc") or element_info.get("text") or element_info.get("class")
                    self.append_log(
                        f"[INFO] Interaction captured: click ({dev_x}, {dev_y}) on '{label}'"
                    )
                else:
                    self.append_log(f"[INFO] Interaction captured: click ({dev_x}, {dev_y})")
            else:
                self.append_log(f"[ERROR] Failed to capture interaction: {result.get('message', 'Unknown error')}")
        else:
            if element_info:
                label = element_info.get("resource_id") or element_info.get("content_desc") or element_info.get("text") or element_info.get("class")
                self.append_log(f"[INFO] Tap sent: ({dev_x}, {dev_y}) on '{label}'")
            else:
                self.append_log(f"[INFO] Tap sent: ({dev_x}, {dev_y})")

    # ------------------------------------------------------------------
    # Recording handlers
    # ------------------------------------------------------------------
    def _start_recording(self) -> None:
        result = self.automation_controller.start_recording()
        self._apply_button_state(result.get("ui_state"))

        if result.get("status") == "success":
            self._record_in_progress = True
            self.btn_record_automation.setText("Stop Recording")
            self.append_log(
                f"[INFO] Recording started: {result['recording_id']}"
            )
        else:
            self._record_in_progress = False
            self.btn_record_automation.setText("Record Automation")
            self._log_error("record", result)

        if "services" in result:
            self._apply_service_status(result["services"])
        self._refresh_action_buttons()

    def _stop_recording(self) -> None:
        if not self._record_in_progress:
            self.append_log("[WARN] No recording in progress")
            return
        recording_id = self.automation_controller.current_recording.id if self.automation_controller.current_recording else None
        if not recording_id:
            self.append_log("[WARN] Controller missing active recording id")
            return
        # Prompt for optional recording name
        name, ok = QInputDialog.getText(
            self,
            "Name Recording",
            "Enter a name for this recording (optional):",
        )
        display_name = name.strip() if ok and name.strip() else None
        result = self.automation_controller.stop_recording(recording_id, display_name=display_name)
        self._apply_button_state(result.get("ui_state"))

        if result.get("status") == "success":
            self._record_in_progress = False
            self.btn_record_automation.setText("Record Automation")
            self.append_log(
                f"[INFO] Recording stopped: {result['duration']:.1f}s ({result['interactions_count']} interactions)"
            )
            self.append_log(f"[INFO] Evidence saved: {result['file_path']}")
        else:
            self._log_error("record", result)
        self._refresh_action_buttons()

    # ------------------------------------------------------------------
    # Replay handlers
    # ------------------------------------------------------------------
    def _start_replay(self) -> None:
        recordings = self.automation_controller.list_available_recordings()
        if not recordings:
            QMessageBox.information(self, "No Recordings", "No automation recordings found.")
            return
        selected = self._choose_recording(recordings)
        if not selected:
            self.append_log("[INFO] Replay cancelled")
            return
        result = self.automation_controller.replay_recording(selected)
        self._apply_button_state(result.get("ui_state"))

        if result.get("status") == "success":
            self._replay_in_progress = True
            self.btn_replay_automation.setText("Replaying...")
            self.append_log(
                f"[INFO] Replay started: {result['replay_id']} for recording {result['recording_id']}"
            )
        else:
            self._log_error("replay", result)
        self._refresh_action_buttons()

    def _on_delete_recording_clicked(self) -> None:
        recordings = self.automation_controller.list_available_recordings()
        if not recordings:
            QMessageBox.information(self, "No Recordings", "No automation recordings found.")
            return
        # Choose recording
        def _label(rec: Dict[str, Any]) -> str:
            name = rec.get("name") or (rec.get("metadata") or {}).get("name") if isinstance(rec.get("metadata"), dict) else None
            prefix = f"{name} — " if name else ""
            return f"{prefix}{rec['timestamp']} — {rec['id']}"
        items = [_label(r) for r in recordings]
        item, ok = QInputDialog.getItem(
            self,
            "Delete Recording",
            "Select a recording to delete:",
            items,
            0,
            False,
        )
        if not ok:
            self.append_log("[INFO] Delete cancelled")
            return
        index = items.index(item)
        rec_id = recordings[index]["id"]
        # Confirm
        confirm = QMessageBox.question(
            self,
            "Confirm Delete",
            f"Are you sure you want to delete recording {rec_id}?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            self.append_log("[INFO] Delete aborted by user")
            return
        result = self.automation_controller.delete_recording(rec_id)
        if result.get("status") == "success":
            self.append_log(f"[INFO] Deleted: {', '.join(result.get('removed', []))}")
        elif result.get("status") == "partial":
            self.append_log(f"[WARN] Partially deleted: {result}")
        else:
            self.append_log(f"[ERROR] Delete failed: {result.get('error', 'Unknown error')}")
        self._refresh_action_buttons()

    def _on_reset_app_frida_clicked(self) -> None:
        self.append_log("[RESET] Resetting MaynDrive app data and Frida…")
        worker = ResetAppFridaWorker(self.service_manager)
        worker.signals.done.connect(lambda payload: self._handle_reset_done(payload))
        worker.signals.error.connect(lambda msg: self._handle_reset_error(msg))
        self.thread_pool.start(worker)

    def _on_restart_app_clicked(self) -> None:
        self.append_log("[APP] Restarting MaynDrive app…")
        self.btn_restart_app.setEnabled(False)

        if not self.session_controller:
            self.append_log("[WARN] Session controller unavailable; running legacy restart path")
            result = self.service_manager.restart_app()
            if result.get("status") == "success":
                self._handle_restart_done({"state": None, "duration": 0.0})
            else:
                self._handle_restart_error(
                    {
                        "code": "LEGACY_FAILURE",
                        "message": result.get("error", "restart failed"),
                        "session": None,
                    }
                )
            return

        worker = SessionRestartWorker(
            self.session_controller,
            app_id=os.getenv("MAYNDRIVE_APP_PACKAGE", "fr.mayndrive.app"),
            timeout_seconds=self.restart_timeout,
            force_clear_data=self.restart_force_clear,
            snapshot_tag=self.restart_snapshot_tag,
        )
        worker.signals.completed.connect(self._handle_restart_done)
        worker.signals.failed.connect(self._handle_restart_error)
        self.thread_pool.start(worker)

    def _handle_reset_done(self, payload: Dict[str, Any]) -> None:
        self.append_log("[RESET] Success: MaynDrive relaunched fresh and Frida reattached")
        self._request_service_snapshot()

    def _handle_reset_error(self, message: str) -> None:
        self.append_log(f"[RESET] Failed: {message}")

    def _handle_restart_done(self, payload: Dict[str, Any]) -> None:
        duration = float(payload.get("duration", 0.0))
        state = payload.get("state")
        if isinstance(state, SessionState):
            self.session_state = state
        pkg = os.getenv("MAYNDRIVE_APP_PACKAGE", "fr.mayndrive.app")
        self.append_log(f"[APP] Restarted: {pkg} (ready in {duration:.1f}s)")
        self._set_status_label("restart", f"Ready ({duration:.1f}s)", "#27ae60")
        self.btn_restart_app.setEnabled(True)
        self._request_service_snapshot()

    def _handle_restart_error(self, payload: Dict[str, Any]) -> None:
        code = payload.get("code", "ERROR")
        message = payload.get("message", "restart failed")
        self.append_log(f"[APP] Restart failed ({code}): {message}")
        self._set_status_label("restart", f"Error ({code})", "#e74c3c")
        self.btn_restart_app.setEnabled(True)

    # ------------------------------------------------------------------
    # Token capture handlers
    # ------------------------------------------------------------------
    def _start_token_capture(self) -> None:
        result = self.token_controller.start_token_capture()
        self._apply_button_state(result.get("ui_state"))

        if result.get("status") == "success":
            self._capture_in_progress = True
            self.btn_capture_token.setText("Capturing...")
            self.append_log(f"[INFO] Token capture started: {result['session_id']}")
        else:
            self._capture_in_progress = False
            self.btn_capture_token.setText("Capture Token")
            self._log_error("capture_token", result)
        self._refresh_action_buttons()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _start_services_automatically(self) -> None:
        self.append_log("=" * 60)
        self.append_log("[STARTUP] Automatic Service Initialization")
        self.append_log("=" * 60)
        self.append_log("[STARTUP] Starting emulator, proxy, Frida, and Appium...")
        self.append_log("[STARTUP] This may take 60-90 seconds if emulator needs to boot...")
        self.append_log("[STARTUP] MaynDrive app will launch automatically...")
        self.append_log("")
        
        result = self.service_manager.start_all_services()
        snapshot = result.get("snapshot", {})
        self._apply_service_status(snapshot.get("services", []))

        self.append_log("")
        if result.get("status") == "success":
            self.append_log("✓ [SUCCESS] All services started successfully!")
            self.append_log("✓ Emulator is running")
            self.append_log("✓ Mitmproxy is capturing traffic")
            self.append_log("✓ Frida is hooked into MaynDrive app")
            self.append_log("")
            self.append_log("[READY] You can now use the automation controls!")
        else:
            self.append_log("⚠ [WARN] Some services failed to start automatically")
            self.append_log("   Check the service status indicators on the left")
            self.append_log("   You may need to manually start failed services")
        self.append_log("=" * 60)

    def _apply_service_status(self, services: List[Dict[str, Any]]) -> None:
        for entry in services:
            label = self.status_labels.get(entry["name"])
            if not label:
                continue
            status = entry.get("status", "unknown")
            color = "#bdc3c7"
            if status == "running":
                color = "#27ae60"
            elif status == "error":
                color = "#e74c3c"
            text = status.capitalize()
            if entry.get("error_message"):
                text = f"Error: {entry['error_message']}"
            elif status == "starting":
                text = "Starting..."
            label.setText(text)
            label.setStyleSheet(f"color: {color}; font-weight: bold")

    def _apply_button_state(self, state: Optional[Dict[str, Any]]) -> None:
        if not state:
            return
        button = self._action_buttons.get(state["action"])
        if not button:
            return
        # Enable the Record button while in progress to allow stopping
        if state["action"] == "record" and state.get("in_progress", False):
            button.setEnabled(True)
        else:
            button.setEnabled(state.get("enabled", False))
        reason = state.get("disabled_reason")
        if reason:
            button.setToolTip(reason)
        else:
            button.setToolTip("")

        if state["action"] == "record":
            self._record_in_progress = state.get("in_progress", False)
            button.setText("Stop Recording" if state.get("in_progress") else "Record Automation")
        elif state["action"] == "replay":
            self._replay_in_progress = state.get("in_progress", False)
            button.setText("Replaying..." if state.get("in_progress") else "Replay Automation")
        elif state["action"] == "capture_token":
            self._capture_in_progress = state.get("in_progress", False)
            button.setText("Capturing..." if state.get("in_progress") else "Capture Token")

    def _refresh_action_buttons(self) -> None:
        try:
            payload = self.automation_controller.get_action_states()
            for state in payload.get("actions", []):
                self._apply_button_state(state)
            self._apply_service_status(payload.get("services", []))
        except Exception as exc:  # noqa: BLE001
            self.append_log(f"[ERROR] Failed to refresh automation actions: {exc}")

        try:
            capture_state = self.token_controller.get_action_state()
            self._apply_button_state(capture_state.get("action"))
        except Exception as exc:  # noqa: BLE001
            self.append_log(f"[ERROR] Failed to refresh token capture state: {exc}")

    def _set_status_label(self, key: str, text: str, color: str) -> None:
        label = self.status_labels.get(key)
        if not label:
            return
        label.setText(text)
        label.setStyleSheet(f"color: {color}; font-size: 12px;")

    def _log_error(self, action: str, result: Dict[str, Any]) -> None:
        message = result.get("error", "Unknown error")
        reason = result.get("reason")
        self.append_log(f"[ERROR] {action}: {message} ({reason})")
        if "services" in result:
            self._apply_service_status(result["services"])

    def append_log(self, message: str) -> None:
        self.log_view.appendPlainText(message)
        self.log_view.verticalScrollBar().setValue(
            self.log_view.verticalScrollBar().maximum()
        )

    # ------------------------------------------------------------------
    # UI element identification
    # ------------------------------------------------------------------
    def _identify_ui_element_at(self, x: int, y: int) -> Optional[Dict[str, Any]]:
        """Dump UI hierarchy and find the deepest node containing (x, y).

        Returns a dict of key attributes (resource_id, content_desc, text, class, bounds, center, selector).
        """
        device_id = os.getenv("ANDROID_DEVICE_ID", DEFAULT_DEVICE_ID)
        # Create fresh dump (best-effort)
        dumped = False
        for args in (
            ["adb", "-s", device_id, "shell", "uiautomator", "dump", "--compressed", "/sdcard/uidump.xml"],
            ["adb", "-s", device_id, "shell", "uiautomator", "dump", "/sdcard/uidump.xml"],
        ):
            try:
                res = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
                if res.returncode == 0:
                    dumped = True
                    break
            except Exception:
                continue
        if not dumped:
            return None

        try:
            # Read back the dump without pulling to host FS
            res = subprocess.run(
                ["adb", "-s", device_id, "shell", "cat", "/sdcard/uidump.xml"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
            if res.returncode != 0 or not res.stdout:
                return None
            xml_data = res.stdout.decode("utf-8", "ignore")
            return self._find_node_in_xml(xml_data, x, y)
        except Exception:
            return None

    @staticmethod
    def _parse_bounds(bounds: str) -> Optional[Tuple[int, int, int, int]]:
        m = re.search(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds or "")
        if not m:
            return None
        x1, y1, x2, y2 = map(int, m.groups())
        return x1, y1, x2, y2

    def _find_node_in_xml(self, xml_data: str, x: int, y: int) -> Optional[Dict[str, Any]]:
        try:
            root = ET.fromstring(xml_data)
        except Exception:
            return None

        best: Optional[Dict[str, Any]] = None

        def walk(node, path_parts: List[str]) -> None:
            nonlocal best
            tag = node.tag
            # Attributes can be with dashes or camelcase depending on dumper
            attrs = node.attrib
            bounds = attrs.get("bounds") or attrs.get("bounds")
            if bounds:
                parsed = self._parse_bounds(bounds)
                if parsed:
                    x1, y1, x2, y2 = parsed
                    if x1 <= x <= x2 and y1 <= y <= y2:
                        # Build candidate info
                        info = {
                            "resource_id": attrs.get("resource-id") or attrs.get("resourceId") or "",
                            "content_desc": attrs.get("content-desc") or attrs.get("contentDescription") or "",
                            "text": attrs.get("text") or "",
                            "class": attrs.get("class") or tag,
                            "bounds": [x1, y1, x2, y2],
                        }
                        info["center"] = [int((x1 + x2) / 2), int((y1 + y2) / 2)]
                        # Path component
                        cls = info["class"].split(".")[-1] if info.get("class") else tag
                        # index heuristic: count siblings with same tag before this node
                        index = 1
                        parent = node.getparent() if hasattr(node, "getparent") else None
                        # xml.etree doesn't have getparent; skip reliable index
                        path_parts_local = path_parts + [f"{cls}"]
                        info["path"] = "/" + "/".join(path_parts_local)
                        # Preferred selector
                        selector = (
                            info.get("resource_id")
                            or info.get("content_desc")
                            or info.get("text")
                            or info.get("class")
                        )
                        info["selector"] = selector
                        best = info
            for child in list(node):
                walk(child, path_parts + [node.attrib.get("class", node.tag).split(".")[-1]])

        walk(root, [])
        return best

    def _choose_recording(self, recordings: List[Dict[str, Any]]) -> Optional[str]:
        if len(recordings) == 1:
            return recordings[0]["id"]
        def _label(rec: Dict[str, Any]) -> str:
            name = rec.get("name") or (rec.get("metadata") or {}).get("name") if isinstance(rec.get("metadata"), dict) else None
            prefix = f"{name} — " if name else ""
            return f"{prefix}{rec['timestamp']} — {rec['id']}"
        items = [_label(record) for record in recordings]
        item, ok = QInputDialog.getItem(
            self,
            "Select Recording",
            "Choose an automation recording to replay:",
            items,
            0,
            False,
        )
        if not ok:
            return None
        index = items.index(item)
        return recordings[index]["id"]

    # ------------------------------------------------------------------
    # Qt events
    # ------------------------------------------------------------------
    def closeEvent(self, event) -> None:  # noqa: D401
        self.append_log("[INFO] Shutting down application...")
        self.status_timer.stop()
        self.screen_timer.stop()

        if self._record_in_progress and self.automation_controller.current_recording:
            self.append_log("[INFO] Stopping active recording before exit")
            try:
                self._stop_recording()
            except Exception as exc:  # noqa: BLE001
                self.append_log(f"[ERROR] Failed to stop recording: {exc}")

        if self._replay_in_progress:
            self.append_log("[INFO] Finalizing replay before exit")
            try:
                self.automation_controller.finalize_replay()
            except Exception as exc:  # noqa: BLE001
                self.append_log(f"[ERROR] Failed to finalize replay: {exc}")

        if self._capture_in_progress and self.token_controller.current_session:
            self.append_log("[INFO] Marking token capture session as cancelled")
            try:
                session = self.token_controller.current_session
                session.fail_capture("Application shutdown")
            except Exception as exc:  # noqa: BLE001
                self.append_log(f"[ERROR] Failed to mark capture session failed: {exc}")
            finally:
                self._capture_in_progress = False
                self.btn_capture_token.setText("Capture Token")

        try:
            result = self.service_manager.cleanup()
            if isinstance(result, dict) and result.get("stopped_services"):
                self.append_log(
                    f"[INFO] Services stopped: {', '.join(result['stopped_services'])}"
                )
            else:
                self.append_log("[INFO] Services cleanup requested")
        except Exception as exc:  # noqa: BLE001
            self.append_log(f"[ERROR] Error stopping services: {exc}")

        super().closeEvent(event)


def main() -> None:
    app = QApplication(sys.argv)
    window = ControlCenter()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
