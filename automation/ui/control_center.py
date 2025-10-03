import sys
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Optional

from PySide6.QtCore import (QObject, QProcess, QProcessEnvironment, QTimer,
                            Signal, Slot, Qt)
from PySide6.QtGui import QImage, QPixmap
from PySide6.QtWidgets import (QApplication, QHBoxLayout, QLabel, QMainWindow,
                               QMessageBox, QPlainTextEdit, QPushButton,
                               QSizePolicy, QVBoxLayout, QWidget)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ANDROID_TOOLS_DIR = Path.home() / "android-tools"
DEFAULT_DEVICE_ID = "emulator-5554"


class ScreenBridge(QObject):
    frameReady = Signal(QImage)
    error = Signal(str)


class ControlCenter(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("MaynDrive Control Center")
        self.resize(1280, 720)

        self.processes: Dict[str, QProcess] = {}
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.screen_future = None
        self.screen_error_reported = False

        self.emulator_script = ANDROID_TOOLS_DIR / "restart_mayndrive_emulator.sh"
        self.frida_script = PROJECT_ROOT / "automation" / "scripts" / "run_hooks.py"
        self.token_capture_script = PROJECT_ROOT / "capture_working_final.py"
        self.appium_script = PROJECT_ROOT / "automation" / "scripts" / "run_appium_token_flow.py"

        self.screen_bridge = ScreenBridge()
        self.screen_bridge.frameReady.connect(self.update_screen_label)
        self.screen_bridge.error.connect(self.handle_screen_error)

        self._build_ui()
        self._start_timers()

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

        self.btn_start_livestream = QPushButton("Start Live Stream")
        self.btn_start_livestream.clicked.connect(self.start_live_stream)
        control_column.addWidget(self.btn_start_livestream)

        self.btn_stop_livestream = QPushButton("Stop Live Stream")
        self.btn_stop_livestream.clicked.connect(self.stop_live_stream)
        control_column.addWidget(self.btn_stop_livestream)

        control_column.addStretch(1)

        # Status labels
        self.status_labels: Dict[str, QLabel] = {}
        status_titles = [
            ("emulator", "Emulator"),
            ("proxy", "Proxy"),
            ("frida", "Frida"),
            ("token", "Token Script"),
            ("appium", "Appium Flow"),
            ("livestream", "Live Stream"),
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
        self.screen_label = QLabel("Screen preview will appear here")
        self.screen_label.setAlignment(Qt.AlignCenter)
        self.screen_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.screen_label.setStyleSheet("background-color: #1e1e1e; color: #ecf0f1;")
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

        # Screen refresh timer
        self.screen_timer = QTimer(self)
        self.screen_timer.setInterval(2000)
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

    def start_frida(self) -> None:
        if "frida" in self.processes:
            self.append_log("[WARN] Frida hook process already running.")
            return
        self.run_command("frida", sys.executable, [str(self.frida_script)])

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

    def start_live_stream(self) -> None:
        if "livestream" in self.processes:
            self.append_log("[WARN] Live stream already active.")
            return
        command = (
            f"adb -s {DEFAULT_DEVICE_ID} exec-out screenrecord --output-format=h264 - "
            "| ffplay -loglevel error -framerate 30 -"
        )
        self.run_shell_command("livestream", command, hold_reference=True)

    def stop_live_stream(self) -> None:
        self.stop_process("livestream")

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

        # Frida status
        try:
            frida_result = subprocess.run(
                ["adb", "-s", DEFAULT_DEVICE_ID, "shell", "ps -A | grep frida-server"],
                capture_output=True, text=True, timeout=3
            )
            if frida_result.returncode == 0 and "frida-server" in frida_result.stdout:
                self.set_status("frida", "Active", True)
            else:
                self.set_status("frida", "Inactive", False)
        except Exception as exc:  # noqa: BLE001
            self.set_status("frida", f"Error: {exc}", False)

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

        livestream_proc = self.processes.get("livestream")
        if livestream_proc and livestream_proc.state() == QProcess.Running:
            self.set_status("livestream", "Active", True)
        else:
            self.set_status("livestream", "Off", False)

    # ------------------------------------------------------------------
    # Screen capture handling
    # ------------------------------------------------------------------
    def schedule_screen_capture(self) -> None:
        if self.screen_future and not self.screen_future.done():
            return
        self.screen_future = self.executor.submit(self.capture_screen_frame)
        self.screen_future.add_done_callback(self._handle_screen_future)

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

    @Slot(QImage)
    def update_screen_label(self, image: QImage) -> None:
        pixmap = QPixmap.fromImage(image)
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
    def closeEvent(self, event) -> None:  # noqa: D401
        """Ensure background threads shut down when the UI closes."""
        self.status_timer.stop()
        self.screen_timer.stop()
        for key in list(self.processes.keys()):
            self.stop_process(key)
        self.executor.shutdown(wait=False)
        super().closeEvent(event)


def main() -> None:
    app = QApplication(sys.argv)
    window = ControlCenter()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
