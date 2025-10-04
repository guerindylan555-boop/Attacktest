import json
import os
import sys
import subprocess
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, List

import re

from lxml import etree

from PySide6.QtCore import (QObject, QProcess, QProcessEnvironment, QPointF,
                            QTimer, Signal, Slot, Qt)
from PySide6.QtGui import QImage, QPainter, QPixmap, QColor, QPen
from PySide6.QtWidgets import (QApplication, QComboBox, QHBoxLayout, QLabel,
                               QMainWindow, QMessageBox, QPlainTextEdit,
                               QPushButton, QSizePolicy, QVBoxLayout, QWidget,
                               QInputDialog, QLineEdit)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ANDROID_TOOLS_DIR = Path.home() / "android-tools"
DEFAULT_DEVICE_ID = "emulator-5554"
BOUNDS_RE = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")
ROUTE_LOG_DIR = PROJECT_ROOT / "automation" / "routes"
MAYNDRIVE_APK_DIR = PROJECT_ROOT / "mayndrive_extracted"
RECORDINGS_DIR = PROJECT_ROOT / "automation" / "recordings"
MAYNDRIVE_PACKAGE = os.getenv("MAYNDRIVE_APP_PACKAGE", "fr.mayndrive.app")
MAYNDRIVE_ACTIVITY = os.getenv(
    "MAYNDRIVE_APP_ACTIVITY", "city.knot.mayndrive.ui.MainActivity"
)
MAX_MAYNDRIVE_LAUNCH_ATTEMPTS = 5
MAX_MAYNDRIVE_INSTALL_ATTEMPTS = 3
DEFAULT_TAP_DELAY_MS = 800
DEFAULT_SWIPE_DELAY_MS = 1200
MIN_REPLAY_DELAY_MS = 250


class ScreenBridge(QObject):
    frameReady = Signal(QImage)
    error = Signal(str)


class InteractiveScreen(QLabel):
    tapRequested = Signal(float, float)
    swipeRequested = Signal(float, float, float, float)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._press_pos: Optional[QPointF] = None
        self._press_time_ms: Optional[int] = None
        self.setMouseTracking(True)

    def _map_to_pixmap_point(self, event) -> Optional[QPointF]:  # noqa: ANN001
        pix = self.pixmap()
        if not pix:
            return None
        pix_width = pix.width()
        pix_height = pix.height()
        if pix_width <= 0 or pix_height <= 0:
            return None
        label_width = self.width()
        label_height = self.height()
        offset_x = (label_width - pix_width) / 2
        offset_y = (label_height - pix_height) / 2
        x = event.position().x() - offset_x
        y = event.position().y() - offset_y
        if x < 0 or y < 0 or x > pix_width or y > pix_height:
            return None
        return QPointF(x, y)

    def mousePressEvent(self, event):  # noqa: D401
        """Record press position for tap/swipe detection."""
        if event.button() == Qt.LeftButton:
            mapped = self._map_to_pixmap_point(event)
            if mapped is None:
                self._press_pos = None
                super().mousePressEvent(event)
                return
            self._press_pos = mapped
            self._press_time_ms = event.timestamp()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):  # noqa: D401
        """Emit tap or swipe based on release position."""
        if event.button() == Qt.LeftButton and self.pixmap():
            mapped_release = self._map_to_pixmap_point(event)
            pix = self.pixmap()
            if pix and self._press_pos is not None and mapped_release is not None:
                delta = mapped_release - self._press_pos
                # If movement is small treat as tap
                if delta.manhattanLength() < 20:
                    self.tapRequested.emit(
                        mapped_release.x() / pix.width(),
                        mapped_release.y() / pix.height(),
                    )
                else:
                    self.swipeRequested.emit(
                        self._press_pos.x() / pix.width(),
                        self._press_pos.y() / pix.height(),
                        mapped_release.x() / pix.width(),
                        mapped_release.y() / pix.height(),
                    )
        self._press_pos = None
        self._press_time_ms = None
        super().mouseReleaseEvent(event)


class ControlCenter(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("MaynDrive Control Center")
        self.resize(1280, 720)

        self.processes: Dict[str, QProcess] = {}
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.screen_future = None
        self.screen_error_reported = False
        self.device_resolution: Optional[tuple[int, int]] = None
        self.highlight_annotations: list[dict[str, object]] = []
        self.recorded_actions: list[dict] = []
        self.action_counter = 0
        self.session_started = datetime.utcnow()
        ROUTE_LOG_DIR.mkdir(parents=True, exist_ok=True)
        RECORDINGS_DIR.mkdir(parents=True, exist_ok=True)
        self.route_file = ROUTE_LOG_DIR / (
            self.session_started.strftime("%Y%m%d_%H%M%S") + "_route.json"
        )
        self.mayndrive_launched = False
        self.mayndrive_launch_attempts = 0
        self.mayndrive_install_attempts = 0
        self.mayndrive_foreground_checks = 0
        self.resolved_mayndrive_component: Optional[str] = None
        self.recording_active = False
        self.current_recording_actions: list[dict] = []
        self.recording_start_time: Optional[datetime] = None
        self.recording_files: Dict[str, Path] = {}
        self.replay_queue: list[dict] = []
        self.replay_in_progress = False
        self.last_recorded_action_time: Optional[datetime] = None
        self.last_recording_action_time: Optional[datetime] = None
        self.last_keyboard_visible = False
        self.pending_keyboard_wait = False
        self.keyboard_wait_deadline: Optional[datetime] = None
        self.keyboard_wait_target = False

        self.emulator_script = ANDROID_TOOLS_DIR / "restart_mayndrive_emulator.sh"
        self.frida_script = PROJECT_ROOT / "automation" / "scripts" / "run_hooks.py"
        self.frida_setup_script = PROJECT_ROOT / "automation" / "scripts" / "frida_setup.py"
        self.token_capture_script = PROJECT_ROOT / "capture_working_final.py"
        self.appium_script = PROJECT_ROOT / "automation" / "scripts" / "run_appium_token_flow.py"
        self.login_capture_script = PROJECT_ROOT / "automation" / "scripts" / "capture_login_token.py"

        self.screen_bridge = ScreenBridge()
        self.screen_bridge.frameReady.connect(self.update_screen_label)
        self.screen_bridge.error.connect(self.handle_screen_error)

        self._build_ui()
        self._start_timers()
        self.load_recordings()
        QTimer.singleShot(0, self.persist_route)
        QTimer.singleShot(
            0, lambda: self.append_log(f"[INFO] Recording route to {self.route_file}")
        )
        QTimer.singleShot(1000, self.auto_start_services)

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)

        root_layout = QHBoxLayout(central)

        # Left control column
        control_column = QVBoxLayout()
        control_column.setSpacing(10)

        self.btn_start_emulator = QPushButton("Start Emulator")
        self.btn_start_emulator.clicked.connect(self.start_emulator)
        control_column.addWidget(self.btn_start_emulator)

        self.btn_stop_emulator = QPushButton("Stop Emulator")
        self.btn_stop_emulator.clicked.connect(self.stop_emulator)
        control_column.addWidget(self.btn_stop_emulator)

        self.btn_start_proxy = QPushButton("Start mitmdump")
        self.btn_start_proxy.clicked.connect(self.start_proxy)
        control_column.addWidget(self.btn_start_proxy)

        self.btn_stop_proxy = QPushButton("Stop mitmdump")
        self.btn_stop_proxy.clicked.connect(self.stop_proxy)
        control_column.addWidget(self.btn_stop_proxy)

        self.btn_setup_frida = QPushButton("Setup Frida Server")
        self.btn_setup_frida.clicked.connect(self.setup_frida_server)
        control_column.addWidget(self.btn_setup_frida)

        self.btn_start_frida = QPushButton("Start Frida Hooks")
        self.btn_start_frida.clicked.connect(self.start_frida)
        control_column.addWidget(self.btn_start_frida)

        self.btn_stop_frida = QPushButton("Stop Frida Hooks")
        self.btn_stop_frida.clicked.connect(self.stop_frida)
        control_column.addWidget(self.btn_stop_frida)

        self.btn_run_token_capture = QPushButton("Run Token Capture Script")
        self.btn_run_token_capture.clicked.connect(self.run_token_capture)
        control_column.addWidget(self.btn_run_token_capture)

        self.btn_stop_token_capture = QPushButton("Stop Token Capture Script")
        self.btn_stop_token_capture.clicked.connect(self.stop_token_capture)
        control_column.addWidget(self.btn_stop_token_capture)

        self.btn_run_appium_flow = QPushButton("Run Appium Flow")
        self.btn_run_appium_flow.clicked.connect(self.run_appium_flow)
        control_column.addWidget(self.btn_run_appium_flow)

        self.btn_stop_appium_flow = QPushButton("Stop Appium Flow")
        self.btn_stop_appium_flow.clicked.connect(self.stop_appium_flow)
        control_column.addWidget(self.btn_stop_appium_flow)

        self.btn_run_login_capture = QPushButton("Run Login Capture")
        self.btn_run_login_capture.clicked.connect(self.run_login_capture)
        control_column.addWidget(self.btn_run_login_capture)

        self.btn_stop_login_capture = QPushButton("Stop Login Capture")
        self.btn_stop_login_capture.clicked.connect(self.stop_login_capture)
        control_column.addWidget(self.btn_stop_login_capture)

        self.btn_start_recording = QPushButton("Start Recording")
        self.btn_start_recording.clicked.connect(self.start_recording_session)
        control_column.addWidget(self.btn_start_recording)

        self.btn_stop_recording = QPushButton("Stop Recording")
        self.btn_stop_recording.clicked.connect(self.stop_recording_session)
        control_column.addWidget(self.btn_stop_recording)

        recordings_label = QLabel("Saved Recordings")
        recordings_label.setStyleSheet("font-weight: bold")
        control_column.addWidget(recordings_label)

        self.recordings_combo = QComboBox()
        control_column.addWidget(self.recordings_combo)

        self.btn_replay_recording = QPushButton("Replay Recording")
        self.btn_replay_recording.clicked.connect(self.replay_selected_recording)
        control_column.addWidget(self.btn_replay_recording)

        self.btn_refresh_recordings = QPushButton("Refresh Recordings")
        self.btn_refresh_recordings.clicked.connect(self.load_recordings)
        control_column.addWidget(self.btn_refresh_recordings)

        control_column.addStretch(1)

        # Status labels
        self.status_labels: Dict[str, QLabel] = {}
        status_titles = [
            ("emulator", "Emulator"),
            ("proxy", "Proxy"),
            ("frida_server", "Frida Server"),
            ("frida", "Frida Hooks"),
            ("token", "Token Script"),
            ("appium", "Appium Flow"),
            ("login_capture", "Login Capture"),
        ]
        for key, title in status_titles:
            layout = QVBoxLayout()
            label_title = QLabel(title)
            label_title.setStyleSheet("font-weight: bold")
            status_label = QLabel("Unknown")
            status_label.setStyleSheet("color: #bdc3c7;")
            layout.addWidget(label_title)
            layout.addWidget(status_label)
            control_column.addLayout(layout)
            self.status_labels[key] = status_label

        root_layout.addLayout(control_column, 1)

        # Screen area
        screen_layout = QVBoxLayout()
        self.screen_label = InteractiveScreen("Screen preview will appear here")
        self.screen_label.setAlignment(Qt.AlignCenter)
        self.screen_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.screen_label.setStyleSheet("background-color: #1e1e1e; color: #ecf0f1;")
        self.screen_label.tapRequested.connect(self.handle_tap)
        self.screen_label.swipeRequested.connect(self.handle_swipe)
        screen_layout.addWidget(self.screen_label)

        root_layout.addLayout(screen_layout, 3)

        # Log panel below
        log_layout = QVBoxLayout()
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumHeight(200)
        log_layout.addWidget(self.log_view)
        screen_layout.addLayout(log_layout)

    def _start_timers(self) -> None:
        # Status refresh timer
        self.status_timer = QTimer(self)
        self.status_timer.setInterval(5000)
        self.status_timer.timeout.connect(self.update_statuses)
        self.status_timer.start()

        # Screen refresh timer (interactive, quicker)
        self.screen_timer = QTimer(self)
        self.screen_timer.setInterval(800)
        self.screen_timer.timeout.connect(self.schedule_screen_capture)
        self.screen_timer.start()

    # ------------------------------------------------------------------
    # Command helpers
    # ------------------------------------------------------------------
    def _prepare_process(self) -> QProcess:
        process = QProcess(self)
        env = QProcessEnvironment.systemEnvironment()
        local_bin = str(Path.home() / ".local" / "bin")
        path_value = env.value("PATH", "")
        if local_bin not in path_value.split(":"):
            env.insert("PATH", f"{local_bin}:{path_value}")
        process.setProcessEnvironment(env)
        process.setWorkingDirectory(str(PROJECT_ROOT))
        process.setProcessChannelMode(QProcess.SeparateChannels)
        return process

    def run_command(self, key: str, program: str, arguments: Optional[list[str]] = None,
                    hold_reference: bool = True) -> None:
        if arguments is None:
            arguments = []
        if hold_reference and key in self.processes:
            self.append_log(f"[WARN] {key} is already running.")
            return

        process = self._prepare_process()
        process.setProgram(program)
        process.setArguments(arguments)

        process.readyReadStandardOutput.connect(
            lambda proc=process, name=key: self.handle_output(name, proc.readAllStandardOutput().data())
        )
        process.readyReadStandardError.connect(
            lambda proc=process, name=key: self.handle_output(name, proc.readAllStandardError().data())
        )
        process.finished.connect(lambda code, status, name=key: self.process_finished(name, code, status))

        process.start()

        if hold_reference:
            self.processes[key] = process
        self.append_log(f"[INFO] Started {key} ({program} {' '.join(arguments)})")

    def run_shell_command(self, key: str, command: str, hold_reference: bool = False) -> None:
        self.run_command(key, "bash", ["-lc", command], hold_reference=hold_reference)

    # ------------------------------------------------------------------
    # Button actions
    # ------------------------------------------------------------------
    def start_emulator(self) -> None:
        if not self.emulator_script.exists():
            QMessageBox.critical(self, "Missing script",
                                 f"Could not find {self.emulator_script}")
            return
        self.run_shell_command("emulator_start", str(self.emulator_script))

    def stop_emulator(self) -> None:
        self.run_shell_command("emulator_stop", "pkill -f \"emulator.*MaynDriveTest\"")

    def start_proxy(self) -> None:
        command = (
            "tmux has-session -t mitmproxy_session 2>/dev/null || "
            "tmux new-session -d -s mitmproxy_session "
            "\"export PATH=$PATH:/home/ubuntu/.local/bin && "
            "mitmdump --listen-port 8080 --set block_global=false --set "
            "save_stream_file=/home/ubuntu/android-tools/proxy/flows.mitm\""
        )
        self.run_shell_command("proxy_start", command)

    def stop_proxy(self) -> None:
        self.run_shell_command("proxy_stop", "tmux kill-session -t mitmproxy_session", hold_reference=False)

    def setup_frida_server(self) -> None:
        if not self.frida_setup_script.exists():
            QMessageBox.critical(self, "Missing script",
                                 f"Could not find {self.frida_setup_script}")
            return
        self.run_command("frida_setup", sys.executable, [str(self.frida_setup_script), "setup"])

    def start_frida(self) -> None:
        if "frida" in self.processes:
            self.append_log("[WARN] Frida hook process already running.")
            return
        # Ensure Frida server is ready before starting hooks
        self.append_log("[INFO] Ensuring Frida server is ready...")
        self.run_command("frida_ensure", sys.executable, [str(self.frida_setup_script), "ensure"])
        # Start hooks after a short delay
        QTimer.singleShot(2000, lambda: self.run_command("frida", sys.executable, [str(self.frida_script)]))

    def stop_frida(self) -> None:
        self.stop_process("frida")

    def run_token_capture(self) -> None:
        if "token_capture" in self.processes:
            self.append_log("[WARN] Token capture already running.")
            return
        self.run_command("token_capture", sys.executable, [str(self.token_capture_script)])

    def stop_token_capture(self) -> None:
        self.stop_process("token_capture")

    def run_appium_flow(self) -> None:
        if not self.appium_script.exists():
            QMessageBox.critical(self, "Missing script",
                                 f"Could not find {self.appium_script}")
            return
        if "appium_flow" in self.processes:
            self.append_log("[WARN] Appium flow already running.")
            return
        self.run_command("appium_flow", sys.executable, [str(self.appium_script)])

    def stop_appium_flow(self) -> None:
        self.stop_process("appium_flow")

    def run_login_capture(self) -> None:
        if not self.login_capture_script.exists():
            QMessageBox.critical(
                self,
                "Missing script",
                f"Could not find {self.login_capture_script}",
            )
            return
        if "login_capture" in self.processes:
            self.append_log("[WARN] Login capture already running.")
            return
        if self.recording_active or self.replay_in_progress:
            QMessageBox.warning(
                self,
                "Automation busy",
                "Finish the current recording/replay before starting the login capture.",
            )
            return

        arguments = [str(self.login_capture_script)]
        recording_path = self.recordings_combo.currentData()
        
        # Check if a valid recording is selected
        if recording_path and recording_path is not None:
            path_obj = Path(recording_path)
            if not path_obj.exists():
                QMessageBox.warning(
                    self,
                    "Recording missing",
                    f"Could not find recording file: {path_obj}",
                )
                return
            self.append_log(
                f"[INFO] Launching login capture with recording {path_obj.name}."
            )
            arguments.extend(["--recording", str(path_obj)])
        else:
            # Only require credentials if no recording is selected
            if not os.getenv("MAYNDRIVE_TEST_EMAIL") or not os.getenv("MAYNDRIVE_TEST_PASSWORD"):
                QMessageBox.warning(
                    self,
                    "Missing credentials",
                    "Set MAYNDRIVE_TEST_EMAIL and MAYNDRIVE_TEST_PASSWORD or select a saved recording before running the login capture.",
                )
                return
            self.append_log("[INFO] Launching login capture via Appium flow.")

        self.run_command("login_capture", sys.executable, arguments)

    def stop_login_capture(self) -> None:
        self.stop_process("login_capture")

    # ------------------------------------------------------------------
    def stop_process(self, key: str) -> None:
        process = self.processes.get(key)
        if not process:
            self.append_log(f"[WARN] No running process for {key}.")
            return
        process.terminate()
        if not process.waitForFinished(3000):
            process.kill()
            process.waitForFinished(1000)
        self.append_log(f"[INFO] Stopped {key}.")
        self.processes.pop(key, None)

    # ------------------------------------------------------------------
    def handle_output(self, key: str, data: bytes) -> None:
        if not data:
            return
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = str(data)
        for line in text.rstrip().splitlines():
            self.append_log(f"[{key}] {line}")

    def process_finished(self, key: str, exit_code: int, status: QProcess.ExitStatus) -> None:
        if key in self.processes:
            self.processes.pop(key, None)
        self.append_log(f"[INFO] {key} finished with code {exit_code} (status {status}).")

    def append_log(self, message: str) -> None:
        self.log_view.appendPlainText(message)
        self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())

    # ------------------------------------------------------------------
    # Status updates
    # ------------------------------------------------------------------
    def set_status(self, name: str, text: str, ok: Optional[bool]) -> None:
        label = self.status_labels.get(name)
        if not label:
            return
        color = "#bdc3c7"
        if ok is True:
            color = "#27ae60"
        elif ok is False:
            color = "#e74c3c"
        label.setText(text)
        label.setStyleSheet(f"color: {color}; font-weight: bold")

    def update_statuses(self) -> None:
        # Emulator status
        try:
            result = subprocess.run(
                ["adb", "-s", DEFAULT_DEVICE_ID, "get-state"],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0 and result.stdout.strip() == "device":
                self.set_status("emulator", "Online", True)
            else:
                self.set_status("emulator", "Offline", False)
        except Exception as exc:  # noqa: BLE001
            self.set_status("emulator", f"Error: {exc}", False)

        # Proxy status
        try:
            proxy_result = subprocess.run(
                ["tmux", "has-session", "-t", "mitmproxy_session"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2
            )
            if proxy_result.returncode == 0:
                self.set_status("proxy", "Running", True)
            else:
                self.set_status("proxy", "Stopped", False)
        except Exception as exc:  # noqa: BLE001
            self.set_status("proxy", f"Error: {exc}", False)

        # Frida server status
        try:
            frida_result = subprocess.run(
                ["adb", "-s", DEFAULT_DEVICE_ID, "shell", "ps -A | grep frida-server"],
                capture_output=True, text=True, timeout=3
            )
            if frida_result.returncode == 0 and "frida-server" in frida_result.stdout:
                self.set_status("frida_server", "Running", True)
            else:
                self.set_status("frida_server", "Stopped", False)
        except Exception as exc:  # noqa: BLE001
            self.set_status("frida_server", f"Error: {exc}", False)

        # Frida hooks status
        process = self.processes.get("frida")
        if process and process.state() == QProcess.Running:
            self.set_status("frida", "Running", True)
        else:
            self.set_status("frida", "Stopped", False)

        # Token capture status
        process = self.processes.get("token_capture")
        if process and process.state() == QProcess.Running:
            self.set_status("token", "Running", True)
        else:
            self.set_status("token", "Stopped", False)

        appium_proc = self.processes.get("appium_flow")
        if appium_proc and appium_proc.state() == QProcess.Running:
            self.set_status("appium", "Running", True)
        else:
            self.set_status("appium", "Stopped", False)

        login_proc = self.processes.get("login_capture")
        if login_proc and login_proc.state() == QProcess.Running:
            self.set_status("login_capture", "Running", True)
        else:
            self.set_status("login_capture", "Stopped", False)

        # No livestream status (interactive view always available)

    # ------------------------------------------------------------------
    # Screen capture handling
    # ------------------------------------------------------------------
    def schedule_screen_capture(self) -> None:
        if self.screen_future and not self.screen_future.done():
            return
        self.screen_future = self.executor.submit(self.capture_screen_frame)
        self.screen_future.add_done_callback(self._handle_screen_future)

    def auto_start_services(self) -> None:
        # Start emulator if not already running
        if not self.is_emulator_online():
            self.start_emulator()

        # Start proxy (mitmdump) session if not active
        if not self.is_proxy_running():
            self.start_proxy()

        # Ensure Frida server is ready (wait longer for emulator to be ready)
        if not self.is_frida_server_running():
            self.append_log("[INFO] Frida server not running, setting up...")
            QTimer.singleShot(10000, self.setup_frida_server)  # Wait 10 seconds for emulator
        
        # Start Frida hooks if not running
        if not self.is_frida_running():
            QTimer.singleShot(15000, self.start_frida)  # Wait 15 seconds total

        # Ensure Appium server is available
        if not self.is_appium_running():
            self.start_appium_server()

        if not self.mayndrive_launched:
            QTimer.singleShot(2000, self.launch_mayndrive_app)

    def capture_screen_frame(self) -> Optional[bytes]:
        try:
            result = subprocess.run(
                ["adb", "-s", DEFAULT_DEVICE_ID, "exec-out", "screencap", "-p"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout
            return None
        except Exception:  # noqa: BLE001
            return None

    def _handle_screen_future(self, future) -> None:  # noqa: ANN001
        data = future.result()
        if not data:
            self.screen_bridge.error.emit("Failed to capture screen.")
            return
        image = QImage.fromData(data, "PNG")
        if image.isNull():
            self.screen_bridge.error.emit("Invalid screen data.")
            return
        self.screen_bridge.frameReady.emit(image)
        if not self.device_resolution:
            self.device_resolution = self.query_device_resolution()

    @Slot(QImage)
    def update_screen_label(self, image: QImage) -> None:
        pixmap = QPixmap.fromImage(image)
        if self.highlight_annotations:
            pixmap = self.draw_highlights(pixmap)
        self.screen_label.setPixmap(pixmap.scaled(
            self.screen_label.size(),
            Qt.KeepAspectRatio,
            Qt.SmoothTransformation
        ))
        self.screen_error_reported = False

    @Slot(str)
    def handle_screen_error(self, message: str) -> None:
        if not self.screen_error_reported:
            self.append_log(f"[SCREEN] {message}")
            self.screen_error_reported = True

    # ------------------------------------------------------------------
    # Interactive commands
    # ------------------------------------------------------------------
    def draw_highlights(self, pixmap: QPixmap) -> QPixmap:
        if not self.highlight_annotations:
            return pixmap
        painter = QPainter(pixmap)
        highlight_pen = QPen(QColor("#e67e22"))
        highlight_pen.setWidth(4)
        highlight_brush = QColor(230, 126, 34, 60)
        painter.setPen(highlight_pen)
        painter.setBrush(highlight_brush)
        width = pixmap.width()
        height = pixmap.height()
        for annotation in self.highlight_annotations:
            rect = annotation.get("rect")
            if not rect:
                continue
            label = annotation.get("label", "")
            x1 = int(rect[0] * width)
            y1 = int(rect[1] * height)
            x2 = int(rect[2] * width)
            y2 = int(rect[3] * height)
            painter.drawRect(x1, y1, x2 - x1, y2 - y1)
            if label:
                metrics = painter.fontMetrics()
                padding_x = 8
                padding_y = 4
                text_width = metrics.horizontalAdvance(label) + padding_x * 2
                text_height = metrics.height() + padding_y * 2
                text_x = x1 + 6
                text_y = max(y1 - text_height - 6, 0)
                painter.setPen(Qt.NoPen)
                painter.setBrush(QColor(44, 62, 80, 200))
                painter.drawRect(text_x, text_y, text_width, text_height)
                painter.setPen(QPen(QColor("#ecf0f1")))
                painter.setBrush(Qt.NoBrush)
                painter.drawText(
                    text_x + padding_x,
                    text_y + text_height - padding_y - 2,
                    label,
                )
                painter.setPen(highlight_pen)
                painter.setBrush(highlight_brush)
        painter.end()
        return pixmap

    def query_device_resolution(self) -> Optional[tuple[int, int]]:
        try:
            result = subprocess.run(
                ["adb", "-s", DEFAULT_DEVICE_ID, "shell", "wm size"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if result.returncode == 0:
                # Expect "Physical size: 1080x2340"
                for line in result.stdout.splitlines():
                    if "Physical size" in line:
                        _, value = line.split(":", 1)
                        width_str, height_str = value.strip().split("x")
                        return int(width_str), int(height_str)
        except Exception:  # noqa: BLE001
            pass
        return None

    def ensure_device_resolution(self) -> tuple[int, int]:
        if not self.device_resolution:
            self.device_resolution = self.query_device_resolution()
        if not self.device_resolution:
            # Fall back to a common portrait resolution
            self.device_resolution = (1080, 2340)
        return self.device_resolution

    @Slot(float, float)
    def handle_tap(self, ratio_x: float, ratio_y: float) -> None:
        width, height = self.ensure_device_resolution()
        x = int(ratio_x * width)
        y = int(ratio_y * height)
        self.append_log(f"[TAP] {x}, {y} (ratios {ratio_x:.2f}, {ratio_y:.2f})")
        subprocess.run(
            ["adb", "-s", DEFAULT_DEVICE_ID, "shell", "input", "tap", str(x), str(y)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.record_element("tap", x, y)
        QTimer.singleShot(500, self.schedule_screen_capture)

    @Slot(float, float, float, float)
    def handle_swipe(self, start_x: float, start_y: float, end_x: float, end_y: float) -> None:
        width, height = self.ensure_device_resolution()
        x1 = int(start_x * width)
        y1 = int(start_y * height)
        x2 = int(end_x * width)
        y2 = int(end_y * height)
        self.append_log(
            f"[SWIPE] {x1},{y1} -> {x2},{y2}"
        )
        subprocess.run(
            [
                "adb",
                "-s",
                DEFAULT_DEVICE_ID,
                "shell",
                "input",
                "swipe",
                str(x1),
                str(y1),
                str(x2),
                str(y2),
                "250",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.record_element("swipe", x1, y1, x2=x2, y2=y2, duration_ms=250)
        QTimer.singleShot(600, self.schedule_screen_capture)

    # ------------------------------------------------------------------
    # Service helpers
    # ------------------------------------------------------------------
    def is_emulator_online(self) -> bool:
        try:
            result = subprocess.run(
                ["adb", "-s", DEFAULT_DEVICE_ID, "get-state"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return result.returncode == 0 and result.stdout.strip() == "device"
        except Exception:  # noqa: BLE001
            return False

    def is_proxy_running(self) -> bool:
        try:
            return subprocess.run(
                ["tmux", "has-session", "-t", "mitmproxy_session"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            ).returncode == 0
        except Exception:  # noqa: BLE001
            return False

    def is_frida_server_running(self) -> bool:
        try:
            result = subprocess.run(
                ["adb", "-s", DEFAULT_DEVICE_ID, "shell", "ps -A | grep frida-server"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return result.returncode == 0 and "frida-server" in result.stdout
        except Exception:  # noqa: BLE001
            return False

    def is_frida_running(self) -> bool:
        proc = self.processes.get("frida")
        if proc and proc.state() == QProcess.Running:
            return True
        return False

    def is_appium_running(self) -> bool:
        proc = self.processes.get("appium_server")
        if proc and proc.state() == QProcess.Running:
            return True
        try:
            result = subprocess.run(
                ["pgrep", "-f", "appium"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
            return result.returncode == 0
        except Exception:  # noqa: BLE001
            return False

    def start_appium_server(self) -> None:
        proc = self.processes.get("appium_server")
        if proc and proc.state() == QProcess.Running:
            self.append_log("[WARN] Appium server already running.")
            return
        self.run_command(
            "appium_server",
            "npx",
            [
                "--yes",
                "appium@2.11.0",
                "--allow-insecure",
                "chromedriver_autodownload",
            ],
        )

    def stop_appium_server(self) -> None:
        self.stop_process("appium_server")

    def is_mayndrive_running(self) -> bool:
        try:
            result = subprocess.run(
                [
                    "adb",
                    "-s",
                    DEFAULT_DEVICE_ID,
                    "shell",
                    "pidof",
                    MAYNDRIVE_PACKAGE,
                ],
                capture_output=True,
                text=True,
                timeout=3,
            )
            return result.returncode == 0 and bool(result.stdout.strip())
        except Exception:  # noqa: BLE001
            return False

    def is_mayndrive_installed(self) -> bool:
        try:
            result = subprocess.run(
                [
                    "adb",
                    "-s",
                    DEFAULT_DEVICE_ID,
                    "shell",
                    "pm",
                    "path",
                    MAYNDRIVE_PACKAGE,
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.returncode == 0 and "package:" in result.stdout
        except Exception:  # noqa: BLE001
            return False

    def collect_apk_splits(self) -> List[str]:
        if not MAYNDRIVE_APK_DIR.exists():
            self.append_log(
                f"[WARN] MaynDrive APK directory not found: {MAYNDRIVE_APK_DIR}"
            )
            return []
        apk_files = sorted(MAYNDRIVE_APK_DIR.glob("*.apk"))
        apk_files.sort(key=lambda path: (0 if path.name.startswith("base") else 1, path.name))
        if not apk_files:
            self.append_log(
                f"[WARN] No APK files found in {MAYNDRIVE_APK_DIR}"
            )
            return []
        return [str(path) for path in apk_files]

    def install_mayndrive(self) -> bool:
        if self.mayndrive_install_attempts >= MAX_MAYNDRIVE_INSTALL_ATTEMPTS:
            self.append_log("[WARN] Skipping install; attempts exhausted.")
            return False
        self.mayndrive_install_attempts += 1
        apk_paths = self.collect_apk_splits()
        if not apk_paths:
            return False
        if not self.is_emulator_online():
            self.append_log("[WARN] Emulator offline; deferring MaynDrive install.")
            return False
        self.append_log(
            "[INFO] Installing MaynDrive package (attempt "
            f"{self.mayndrive_install_attempts}/{MAX_MAYNDRIVE_INSTALL_ATTEMPTS})."
        )
        try:
            result = subprocess.run(
                [
                    "adb",
                    "-s",
                    DEFAULT_DEVICE_ID,
                    "install-multiple",
                    "-r",
                    "-g",
                    *apk_paths,
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except Exception as exc:  # noqa: BLE001
            self.append_log(f"[WARN] Exception during MaynDrive install: {exc}")
            return False

        success = result.returncode == 0 and "Success" in result.stdout
        if success:
            self.append_log("[INFO] MaynDrive APK installed successfully.")
            self.resolve_mayndrive_component(force=True)
            return True

        self.append_log(
            "[WARN] MaynDrive install failed: "
            f"{result.stdout.strip() or result.stderr.strip() or 'no output'}"
        )
        return False

    def resolve_mayndrive_component(self, force: bool = False) -> Optional[str]:
        if self.resolved_mayndrive_component and not force:
            return self.resolved_mayndrive_component
        if not self.is_emulator_online():
            return None
        try:
            result = subprocess.run(
                [
                    "adb",
                    "-s",
                    DEFAULT_DEVICE_ID,
                    "shell",
                    "cmd",
                    "package",
                    "resolve-activity",
                    "--brief",
                    "-a",
                    "android.intent.action.MAIN",
                    "-c",
                    "android.intent.category.LAUNCHER",
                    MAYNDRIVE_PACKAGE,
                ],
                capture_output=True,
                text=True,
                timeout=6,
            )
        except Exception as exc:  # noqa: BLE001
            self.append_log(f"[WARN] Unable to resolve MaynDrive launcher: {exc}")
            return None

        if result.returncode != 0:
            self.append_log(
                "[WARN] resolve-activity failed: "
                f"{result.stderr.strip() or result.stdout.strip() or 'no output'}"
            )
            return None

        combined = "\n".join(
            line.strip()
            for line in (result.stdout + "\n" + result.stderr).splitlines()
            if line.strip()
        )
        for line in reversed(combined.splitlines()):
            component = line
            if component.lower().startswith("warning"):
                continue
            if component.startswith("name="):
                component = component.split("=", 1)[1]
            if "/" in component:
                if component.startswith("."):
                    component = f"{MAYNDRIVE_PACKAGE}/{component}"
                elif not component.startswith(f"{MAYNDRIVE_PACKAGE}/"):
                    # e.g. fr.mayndrive.app/.MainActivity
                    if component.startswith(MAYNDRIVE_PACKAGE):
                        pass
                    else:
                        component = f"{MAYNDRIVE_PACKAGE}/{component}"
                self.resolved_mayndrive_component = component
                self.append_log(f"[INFO] Resolved MaynDrive component: {component}")
                return component
        self.append_log("[WARN] Could not resolve launcher activity for MaynDrive.")
        return None

    def compose_mayndrive_component(self) -> Optional[str]:
        if self.resolved_mayndrive_component:
            return self.resolved_mayndrive_component
        activity = MAYNDRIVE_ACTIVITY
        if not activity:
            return None
        if "/" in activity:
            component = activity
        elif activity.startswith("."):
            component = f"{MAYNDRIVE_PACKAGE}/{activity}"
        else:
            component = f"{MAYNDRIVE_PACKAGE}/{activity}"
        return component

    def start_mayndrive_activity(self) -> bool:
        component = self.compose_mayndrive_component()
        if not component:
            component = self.resolve_mayndrive_component(force=True)
            if not component:
                self.append_log("[WARN] No component available for MaynDrive launch.")
                return False
        try:
            result = subprocess.run(
                [
                    "adb",
                    "-s",
                    DEFAULT_DEVICE_ID,
                    "shell",
                    "am",
                    "start",
                    "--activity-clear-top",
                    "--activity-single-top",
                    "-n",
                    component,
                ],
                capture_output=True,
                text=True,
                timeout=7,
            )
        except Exception as exc:  # noqa: BLE001
            self.append_log(f"[WARN] Exception while launching MaynDrive: {exc}")
            return False

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        has_error = (
            result.returncode != 0
            and "Starting:" not in stdout
        ) or "Error" in stdout or "Error" in stderr
        if not has_error:
            if stdout:
                self.append_log(f"[DEBUG] am start output: {stdout}")
            if component != self.resolved_mayndrive_component:
                self.resolved_mayndrive_component = component
            return True

        self.append_log(
            "[WARN] MaynDrive launch command failed: "
            f"{stdout or stderr or 'no output'}"
        )
        self.resolve_mayndrive_component(force=True)
        return False

    def start_mayndrive_via_monkey(self) -> bool:
        try:
            result = subprocess.run(
                [
                    "adb",
                    "-s",
                    DEFAULT_DEVICE_ID,
                    "shell",
                    "monkey",
                    "-p",
                    MAYNDRIVE_PACKAGE,
                    "-c",
                    "android.intent.category.LAUNCHER",
                    "1",
                ],
                capture_output=True,
                text=True,
                timeout=7,
            )
        except Exception as exc:  # noqa: BLE001
            self.append_log(f"[WARN] Monkey launch exception: {exc}")
            return False

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        if result.returncode == 0 and "Events injected" in stdout:
            self.append_log("[INFO] Triggered MaynDrive via launcher intent (monkey).")
            return True
        self.append_log(
            "[WARN] Monkey launch failed: "
            f"{stdout or stderr or 'no output'}"
        )
        return False

    def is_mayndrive_foreground(self) -> bool:
        try:
            result = subprocess.run(
                [
                    "adb",
                    "-s",
                    DEFAULT_DEVICE_ID,
                    "shell",
                    "dumpsys",
                    "window",
                    "windows",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except Exception:  # noqa: BLE001
            return False

        if result.returncode != 0:
            return False
        output = result.stdout or ""
        marker = f"{MAYNDRIVE_PACKAGE}/"
        if "mCurrentFocus" in output and marker in output:
            return True
        if "mFocusedApp" in output and marker in output:
            return True
        return False

    def verify_mayndrive_foreground(self) -> None:
        if self.is_mayndrive_foreground():
            if not self.mayndrive_launched:
                self.mayndrive_launched = True
                self.append_log("[INFO] MaynDrive foreground confirmed.")
            return
        self.mayndrive_foreground_checks += 1
        if self.mayndrive_foreground_checks >= MAX_MAYNDRIVE_LAUNCH_ATTEMPTS:
            self.append_log("[WARN] MaynDrive never reached foreground; giving up.")
            return
        self.append_log("[WARN] MaynDrive not in foreground; retrying with launcher intent.")
        if self.start_mayndrive_via_monkey():
            self.mayndrive_foreground_checks = 0
            QTimer.singleShot(2500, self.verify_mayndrive_foreground)
        else:
            QTimer.singleShot(4000, self.launch_mayndrive_app)

    def launch_mayndrive_app(self) -> None:
        if self.mayndrive_launched and self.is_mayndrive_running() and self.is_mayndrive_foreground():
            return
        if self.mayndrive_launch_attempts >= MAX_MAYNDRIVE_LAUNCH_ATTEMPTS:
            self.append_log("[WARN] MaynDrive launch attempts exhausted.")
            return
        if not self.is_emulator_online():
            self.mayndrive_launch_attempts += 1
            QTimer.singleShot(3000, self.launch_mayndrive_app)
            return
        if not self.is_mayndrive_installed():
            if not self.install_mayndrive():
                if self.mayndrive_install_attempts < MAX_MAYNDRIVE_INSTALL_ATTEMPTS:
                    QTimer.singleShot(5000, self.launch_mayndrive_app)
                return
        if not self.resolved_mayndrive_component:
            self.resolve_mayndrive_component()
        self.mayndrive_launch_attempts += 1
        self.mayndrive_foreground_checks = 0
        self.append_log(
            f"[INFO] Launch attempt {self.mayndrive_launch_attempts}/{MAX_MAYNDRIVE_LAUNCH_ATTEMPTS}."
        )
        
        # Try direct activity launch first
        if self.start_mayndrive_activity():
            self.append_log("[INFO] Requested MaynDrive launch.")
            QTimer.singleShot(3000, self.verify_mayndrive_foreground)  # Wait longer
            return
        
        # Try monkey launcher as fallback
        self.append_log("[WARN] Direct activity launch failed; trying launcher intent.")
        if self.start_mayndrive_via_monkey():
            QTimer.singleShot(3000, self.verify_mayndrive_foreground)  # Wait longer
            return
        
        # If both fail, wait longer before retry
        self.append_log("[WARN] Both launch methods failed, retrying in 6 seconds...")
        QTimer.singleShot(6000, self.launch_mayndrive_app)

    def stop_mayndrive_app(self) -> None:
        try:
            subprocess.run(
                [
                    "adb",
                    "-s",
                    DEFAULT_DEVICE_ID,
                    "shell",
                    "am",
                    "force-stop",
                    MAYNDRIVE_PACKAGE,
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
        except Exception:  # noqa: BLE001
            pass
        self.mayndrive_launched = False
        self.mayndrive_launch_attempts = 0
        self.mayndrive_foreground_checks = 0

    # ------------------------------------------------------------------
    # Element capture utilities
    # ------------------------------------------------------------------
    def fetch_ui_dump(self) -> Optional[etree._Element]:
        try:
            result = subprocess.run(
                [
                    "adb",
                    "-s",
                    DEFAULT_DEVICE_ID,
                    "exec-out",
                    "uiautomator",
                    "dump",
                    "/dev/tty",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
            if result.returncode != 0:
                return None
            output = result.stdout.decode("utf-8", errors="ignore")
            start = output.find("<?xml")
            end = output.rfind("</hierarchy>")
            if start == -1 or end == -1:
                return None
            xml_data = output[start : end + len("</hierarchy>")]
            return etree.fromstring(xml_data.encode("utf-8"))
        except Exception:  # noqa: BLE001
            return None

    def parse_bounds(self, bounds_str: str) -> Optional[tuple[int, int, int, int]]:
        match = BOUNDS_RE.match(bounds_str)
        if not match:
            return None
        x1, y1, x2, y2 = map(int, match.groups())
        return x1, y1, x2, y2

    def is_keyboard_visible(self) -> bool:
        try:
            result = subprocess.run(
                [
                    "adb",
                    "-s",
                    DEFAULT_DEVICE_ID,
                    "shell",
                    "dumpsys",
                    "input_method",
                ],
                capture_output=True,
                text=True,
                timeout=4,
            )
        except Exception:  # noqa: BLE001
            return False
        output = result.stdout or ""
        if "mInputShown=true" in output:
            return True
        if "mInputViewShown" in output and "true" in output:
            # handle e.g. mInputViewShown: true
            for line in output.splitlines():
                line = line.strip().lower()
                if "minputviewshown" in line and "true" in line:
                    return True
        if "ImeWindowVisibility=" in output:
            for line in output.splitlines():
                if "ImeWindowVisibility=" in line and "1" in line:
                    return True
        return False

    def calculate_delay(
        self,
        now: datetime,
        previous: Optional[datetime],
        base_default: int,
    ) -> int:
        if previous is not None:
            delta = now - previous
            diff_ms = int(delta.total_seconds() * 1000)
            if diff_ms > 0:
                return max(base_default, diff_ms)
        return base_default

    def record_element(self, action: str, x: int, y: int, **extra) -> None:
        tree = self.fetch_ui_dump()
        width, height = self.ensure_device_resolution()
        info = None
        if tree is not None:
            info = self.find_element_for_point(tree, x, y, width, height)
        self.action_counter += 1
        now = datetime.utcnow()
        base_default = DEFAULT_SWIPE_DELAY_MS if action == "swipe" else DEFAULT_TAP_DELAY_MS
        delay_ms = self.calculate_delay(now, self.last_recorded_action_time, base_default)
        self.last_recorded_action_time = now
        keyboard_visible = self.is_keyboard_visible()
        keyboard_transition = keyboard_visible and not self.last_keyboard_visible
        keyboard_hidden = (not keyboard_visible) and self.last_keyboard_visible
        self.last_keyboard_visible = keyboard_visible
        attrs = info["attributes"] if info else {}
        rect = info["rect"] if info else None
        label = self.build_element_label(action, attrs)
        if rect:
            self.highlight_annotations = [
                {
                    "rect": (
                        rect[0] / width,
                        rect[1] / height,
                        rect[2] / width,
                        rect[3] / height,
                    ),
                    "label": label,
                }
            ]
            attrs_str = ", ".join(
                f"{key}='{value}'" for key, value in attrs.items() if value
            )
            self.append_log(
                f"[ELEMENT {self.action_counter}] {action.upper()} bounds={rect} {attrs_str}"
            )
        else:
            self.highlight_annotations = []
            self.append_log(
                f"[ELEMENT {self.action_counter}] {action.upper()} at {x},{y} (no element found)"
            )

        record = {
            "action": action,
            "index": self.action_counter,
            "timestamp": now.isoformat() + "Z",
            "x": x,
            "y": y,
            "bounds": rect,
            "attributes": attrs,
            "label": label,
            "delay_ms": delay_ms,
            "keyboard_visible": keyboard_visible,
            "keyboard_transition": keyboard_transition,
            "keyboard_hidden": keyboard_hidden,
        }
        record.update(extra)
        self.recorded_actions.append(record)
        self.persist_route()
        if self.recording_active:
            recording_delay = self.calculate_delay(now, self.last_recording_action_time, base_default)
            self.last_recording_action_time = now
            record_copy = deepcopy(record)
            record_copy["delay_ms"] = recording_delay
            self.current_recording_actions.append(record_copy)

    def find_element_for_point(
        self, tree: etree._Element, x: int, y: int, width: int, height: int
    ) -> Optional[dict]:
        candidates = []
        for node in tree.iter():
            bounds = node.get("bounds")
            if not bounds:
                continue
            parsed = self.parse_bounds(bounds)
            if not parsed:
                continue
            x1, y1, x2, y2 = parsed
            if x1 <= x <= x2 and y1 <= y <= y2:
                area = (x2 - x1) * (y2 - y1)
                attrs = {
                    "resource-id": node.get("resource-id"),
                    "content-desc": node.get("content-desc"),
                    "text": node.get("text"),
                    "class": node.get("class"),
                }
                candidates.append((area, {"rect": parsed, "attributes": attrs}))
        if not candidates:
            return None
        candidates.sort(key=lambda item: item[0])
        return candidates[0][1]

    def build_element_label(self, action: str, attrs: dict) -> str:
        primary = (
            attrs.get("resource-id")
            or attrs.get("content-desc")
            or attrs.get("text")
            or attrs.get("class")
            or "element"
        )
        return f"#{self.action_counter} {action.upper()} {primary}".strip()

    def default_delay_for_action(self, action: dict) -> int:
        return (
            DEFAULT_SWIPE_DELAY_MS
            if action.get("action") == "swipe"
            else DEFAULT_TAP_DELAY_MS
        )

    def persist_route(self) -> None:
        payload = {
            "started_at": self.session_started.isoformat() + "Z",
            "updated_at": datetime.utcnow().isoformat() + "Z",
            "actions": self.recorded_actions,
        }
        try:
            with self.route_file.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
        except Exception as exc:  # noqa: BLE001
            self.append_log(f"[WARN] Failed to persist route log: {exc}")

    # ------------------------------------------------------------------
    # Recording & replay controls
    # ------------------------------------------------------------------
    def update_recording_controls(self) -> None:
        can_record = not self.replay_in_progress
        self.btn_start_recording.setEnabled(can_record and not self.recording_active)
        self.btn_stop_recording.setEnabled(self.recording_active)
        has_selection = (
            self.recordings_combo.count() > 0
            and bool(self.recordings_combo.currentData())
        )
        self.btn_replay_recording.setEnabled(
            not self.recording_active and not self.replay_in_progress and has_selection
        )

    def start_recording_session(self) -> None:
        if self.replay_in_progress:
            self.append_log("[WARN] Cannot start recording during replay.")
            return
        if self.recording_active:
            self.append_log("[WARN] Recording already active.")
            return
        self.recording_active = True
        self.current_recording_actions = []
        self.recording_start_time = datetime.utcnow()
        self.last_recording_action_time = None
        self.last_keyboard_visible = self.is_keyboard_visible()
        self.append_log("[INFO] Recording started.")
        self.update_recording_controls()

    def stop_recording_session(self) -> None:
        if not self.recording_active:
            self.append_log("[WARN] No recording in progress.")
            return
        self.recording_active = False
        start_time = self.recording_start_time
        self.recording_start_time = None
        self.last_recording_action_time = None
        self.last_keyboard_visible = False
        self.update_recording_controls()
        if not self.current_recording_actions:
            self.append_log("[INFO] Recording stopped (no actions captured).")
            return

        default_name = ""
        if start_time:
            default_name = start_time.strftime("Session %H:%M:%S")
        name, ok = QInputDialog.getText(
            self,
            "Save Recording",
            "Recording name:",
            QLineEdit.Normal,
            default_name,
        )
        if not ok:
            self.append_log("[INFO] Recording discarded (no name provided).")
            self.current_recording_actions = []
            return
        cleaned = name.strip()
        if not cleaned:
            cleaned = "Recording"
        safe = re.sub(r"[^a-zA-Z0-9_-]+", "_", cleaned)
        if not safe:
            safe = "Recording"
        timestamp = (start_time or datetime.utcnow()).strftime(
            "%Y%m%d_%H%M%S"
        )
        filename = f"{timestamp}_{safe}.json"
        path = RECORDINGS_DIR / filename
        payload = {
            "name": cleaned,
            "saved_at": datetime.utcnow().isoformat() + "Z",
            "actions": self.current_recording_actions,
        }
        try:
            with path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
        except Exception as exc:  # noqa: BLE001
            self.append_log(f"[WARN] Failed to save recording: {exc}")
            return
        self.append_log(
            f"[INFO] Recording saved as {path.name} ({len(self.current_recording_actions)} actions)."
        )
        self.current_recording_actions = []
        self.load_recordings()

    def load_recordings(self) -> None:
        self.recording_files = {}
        self.recordings_combo.blockSignals(True)
        self.recordings_combo.clear()
        try:
            recordings = sorted(
                RECORDINGS_DIR.glob("*.json"),
                key=lambda item: item.stat().st_mtime,
                reverse=True,
            )
        except Exception as exc:  # noqa: BLE001
            self.append_log(f"[WARN] Could not list recordings: {exc}")
            recordings = []
        for path in recordings:
            try:
                with path.open("r", encoding="utf-8") as handle:
                    data = json.load(handle)
                display_name = data.get("name") or path.stem
            except Exception:  # noqa: BLE001
                display_name = path.stem
            self.recordings_combo.addItem(display_name, str(path))
            self.recording_files[display_name] = path
        if not recordings:
            self.recordings_combo.addItem("No recordings", None)
        self.recordings_combo.blockSignals(False)
        self.update_recording_controls()

    def replay_selected_recording(self) -> None:
        if self.recording_active:
            self.append_log("[WARN] Stop recording before replaying.")
            return
        if self.replay_in_progress:
            self.append_log("[WARN] Replay already in progress.")
            return
        path_str = self.recordings_combo.currentData()
        if not path_str:
            self.append_log("[WARN] No recording selected.")
            return
        path = Path(path_str)
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception as exc:  # noqa: BLE001
            self.append_log(f"[WARN] Failed to load recording: {exc}")
            return
        actions = data.get("actions") or []
        if not isinstance(actions, list) or not actions:
            self.append_log("[WARN] Recording has no actions to replay.")
            return
        self.replay_in_progress = True
        self.replay_queue = [deepcopy(action) for action in actions]
        name = data.get("name") or path.stem
        self.append_log(
            f"[INFO] Replaying '{name}' with {len(self.replay_queue)} actions."
        )
        self.update_recording_controls()
        self.process_next_replay_action()

    def process_next_replay_action(self) -> None:
        if not self.replay_queue:
            self.append_log("[INFO] Replay finished.")
            self.replay_in_progress = False
            self.update_recording_controls()
            return
        action = self.replay_queue.pop(0)
        raw_delay = action.get("delay_ms", self.default_delay_for_action(action))
        try:
            delay_ms = int(raw_delay)
        except (TypeError, ValueError):  # noqa: PERF203
            delay_ms = self.default_delay_for_action(action)
        delay_ms = max(MIN_REPLAY_DELAY_MS, delay_ms)
        self.append_log(
            f"[REPLAY] Waiting {delay_ms} ms before {action.get('action', 'action')}"
        )
        QTimer.singleShot(delay_ms, lambda act=action: self.execute_replay_step(act))

    def execute_replay_step(self, action: dict) -> None:
        self.execute_recorded_action(action)
        self.post_action_transition(action)

    def execute_recorded_action(self, action: dict) -> None:
        kind = action.get("action")
        x = int(action.get("x", 0))
        y = int(action.get("y", 0))
        if kind == "tap":
            self.append_log(f"[REPLAY] TAP {x},{y}")
            subprocess.run(
                [
                    "adb",
                    "-s",
                    DEFAULT_DEVICE_ID,
                    "shell",
                    "input",
                    "tap",
                    str(x),
                    str(y),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            QTimer.singleShot(400, self.schedule_screen_capture)
            return

        if kind == "swipe":
            x2 = int(action.get("x2", x))
            y2 = int(action.get("y2", y))
            duration = int(action.get("duration_ms", 250))
            self.append_log(f"[REPLAY] SWIPE {x},{y} -> {x2},{y2} ({duration} ms)")
            subprocess.run(
                [
                    "adb",
                    "-s",
                    DEFAULT_DEVICE_ID,
                    "shell",
                    "input",
                    "swipe",
                    str(x),
                    str(y),
                    str(x2),
                    str(y2),
                    str(duration),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            QTimer.singleShot(600, self.schedule_screen_capture)
            return

        self.append_log(f"[WARN] Unsupported action in recording: {kind}")

    def post_action_transition(self, action: dict) -> None:
        if action.get("keyboard_transition"):
            self.append_log("[REPLAY] Waiting for keyboard to appear...")
            self.start_keyboard_wait(True)
            return
        if action.get("keyboard_hidden"):
            self.append_log("[REPLAY] Waiting for keyboard to hide...")
            self.start_keyboard_wait(False)
            return
        QTimer.singleShot(0, self.process_next_replay_action)

    def start_keyboard_wait(self, target_state: bool, timeout_ms: int = 5000) -> None:
        if self.pending_keyboard_wait:
            return
        self.pending_keyboard_wait = True
        self.keyboard_wait_deadline = datetime.utcnow() + timedelta(milliseconds=timeout_ms)
        self.keyboard_wait_target = target_state
        self.poll_keyboard_wait()

    def poll_keyboard_wait(self) -> None:
        if not self.pending_keyboard_wait:
            return
        visible = self.is_keyboard_visible()
        if visible == self.keyboard_wait_target:
            state = "visible" if visible else "hidden"
            self.append_log(f"[REPLAY] Keyboard {state}; continuing.")
            self.pending_keyboard_wait = False
            self.keyboard_wait_deadline = None
            QTimer.singleShot(0, self.process_next_replay_action)
            return
        if self.keyboard_wait_deadline and datetime.utcnow() > self.keyboard_wait_deadline:
            self.append_log("[WARN] Keyboard wait timed out; continuing replay.")
            self.pending_keyboard_wait = False
            self.keyboard_wait_deadline = None
            QTimer.singleShot(0, self.process_next_replay_action)
            return
        QTimer.singleShot(200, self.poll_keyboard_wait)

    # ------------------------------------------------------------------
    def closeEvent(self, event) -> None:  # noqa: D401
        """Ensure background threads shut down when the UI closes."""
        self.status_timer.stop()
        self.screen_timer.stop()
        for key in list(self.processes.keys()):
            self.stop_process(key)
        self.stop_proxy()
        self.stop_mayndrive_app()
        self.stop_emulator()
        self.stop_appium_server()
        self.recording_active = False
        self.replay_in_progress = False
        self.last_recorded_action_time = None
        self.last_recording_action_time = None
        self.pending_keyboard_wait = False
        self.keyboard_wait_deadline = None
        self.executor.shutdown(wait=False)
        super().closeEvent(event)


def main() -> None:
    app = QApplication(sys.argv)
    window = ControlCenter()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
