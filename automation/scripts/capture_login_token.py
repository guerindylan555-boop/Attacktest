#!/usr/bin/env python3
"""Orchestrate Frida hooks and the login Appium flow to capture tokens."""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Iterable

PROJECT_ROOT = Path(__file__).resolve().parents[2]
HOOK_SCRIPT = PROJECT_ROOT / "automation" / "hooks" / "best_capture.js"
APPIUM_FLOW = PROJECT_ROOT / "automation" / "scripts" / "run_appium_token_flow.py"
LOG_DIR = Path.home() / "android-tools" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

PACKAGE = os.getenv("MAYNDRIVE_APP_PACKAGE", "fr.mayndrive.app")
DEVICE_ID = os.getenv("MAYNDRIVE_DEVICE_ID", "emulator-5554")

TOKEN_REGEX = re.compile(r"Bearer\s+[A-Za-z0-9\-\._~+/]+=*")

DEFAULT_TAP_DELAY_MS = 800
DEFAULT_SWIPE_DELAY_MS = 1200
MIN_REPLAY_DELAY_MS = 250


class StreamWatcher(threading.Thread):
    def __init__(self, stream, queue_obj: queue.Queue[str]):
        super().__init__(daemon=True)
        self.stream = stream
        self.queue = queue_obj

    def run(self) -> None:  # noqa: D401
        """Forward each stdout line from the subprocess to a queue."""
        for raw in iter(self.stream.readline, ""):
            if not raw:
                break
            self.queue.put(raw.rstrip())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture MaynDrive tokens via Frida")
    parser.add_argument(
        "--recording",
        type=Path,
        help="Path to a recorded UI automation JSON to replay instead of running the Appium flow.",
    )
    parser.add_argument(
        "--post-wait",
        type=float,
        default=8.0,
        help="Additional seconds to wait for Frida output after automation finishes (default: 8).",
    )
    return parser.parse_args()


def ensure_credentials() -> None:
    missing = [
        key
        for key in ("MAYNDRIVE_TEST_EMAIL", "MAYNDRIVE_TEST_PASSWORD")
        if not os.getenv(key)
    ]
    if missing:
        raise SystemExit(
            "Missing credentials environment variables: "
            + ", ".join(missing)
            + "\nSet them before running (export MAYNDRIVE_TEST_EMAIL=... etc.)."
        )


def launch_frida() -> subprocess.Popen[str]:
    cmd = [
        "frida",
        "-U",
        "-f",
        PACKAGE,
        "-l",
        str(HOOK_SCRIPT),
    ]
    print(f"[INFO] Starting Frida: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError as exc:
        raise SystemExit("'frida' command not found in PATH") from exc
    assert proc.stdout is not None
    return proc


def monitor_frida(frida_proc: subprocess.Popen[str], out_queue: queue.Queue[str]) -> None:
    watcher = StreamWatcher(frida_proc.stdout, out_queue)
    watcher.start()


def run_appium_flow() -> int:
    print(f"[INFO] Launching Appium flow: {APPIUM_FLOW}")
    proc = subprocess.Popen(
        [sys.executable, str(APPIUM_FLOW)],
    )
    try:
        return proc.wait()
    except KeyboardInterrupt:
        print("[WARN] Keyboard interrupt received, terminating Appium flow.")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        return proc.returncode or 0


def write_log(lines: list[str]) -> Path:
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    path = LOG_DIR / f"appium_login_capture_{timestamp}.log"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def load_recording(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        actions = data.get("actions") or []
    elif isinstance(data, list):
        actions = data
    else:
        raise ValueError("Recording JSON must be a list or contain an 'actions' array")
    if not actions:
        raise ValueError("Recording is empty")
    return actions


def compute_delay_ms(action: dict) -> int:
    raw = action.get("delay_ms")
    try:
        delay_ms = int(raw)
    except (TypeError, ValueError):
        delay_ms = (
            DEFAULT_SWIPE_DELAY_MS
            if action.get("action") == "swipe"
            else DEFAULT_TAP_DELAY_MS
        )
    return max(MIN_REPLAY_DELAY_MS, delay_ms)


def replay_actions(actions: Iterable[dict]) -> None:
    actions = list(actions)
    print(f"[INFO] Replaying recording with {len(actions)} actions.")
    for idx, action in enumerate(actions, start=1):
        delay_sec = compute_delay_ms(action) / 1000.0
        print(f"[REPLAY] Waiting {delay_sec:.2f}s before action {idx}")
        time.sleep(delay_sec)
        kind = action.get("action")
        x = int(action.get("x", 0))
        y = int(action.get("y", 0))
        if kind == "tap":
            print(f"[REPLAY] TAP {x},{y}")
            subprocess.run(
                [
                    "adb",
                    "-s",
                    DEVICE_ID,
                    "shell",
                    "input",
                    "tap",
                    str(x),
                    str(y),
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            continue
        if kind == "swipe":
            x2 = int(action.get("x2", x))
            y2 = int(action.get("y2", y))
            duration = int(action.get("duration_ms", 250))
            print(f"[REPLAY] SWIPE {x},{y} -> {x2},{y2} ({duration} ms)")
            subprocess.run(
                [
                    "adb",
                    "-s",
                    DEVICE_ID,
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
                check=False,
            )
            continue
        print(f"[WARN] Unsupported action in recording: {kind}")


def ensure_frida_server() -> None:
    """Ensure Frida server is running on device."""
    try:
        result = subprocess.run(
            ["adb", "-s", DEVICE_ID, "shell", "ps -A | grep frida-server"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and "frida-server" in result.stdout:
            print("[INFO] Frida server is running")
            return
        
        print("[WARN] Frida server not running, attempting to start...")
        # Try to start Frida server using the Python script
        script_path = PROJECT_ROOT / "automation" / "scripts" / "start_frida_python.py"
        try:
            result = subprocess.run(
                [sys.executable, str(script_path), DEVICE_ID],
                capture_output=True, text=True, timeout=20
            )
            if result.returncode == 0:
                print("[SUCCESS] Frida server started")
            else:
                print(f"[ERROR] Frida server startup failed: {result.stderr}")
                raise SystemExit("Failed to start Frida server. Please run 'Setup Frida Server' first.")
        except Exception as e:
            raise SystemExit(f"Failed to start Frida server: {e}")
            
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"Frida server check failed: {exc}") from exc


def main() -> None:
    args = parse_args()
    recording_actions: list[dict] | None = None
    if args.recording:
        recording_path = args.recording.expanduser().resolve()
        if not recording_path.exists():
            raise SystemExit(f"Recording file not found: {recording_path}")
        try:
            recording_actions = load_recording(recording_path)
        except Exception as exc:  # noqa: BLE001
            raise SystemExit(f"Failed to load recording: {exc}") from exc
        print(f"[INFO] Loaded recording {recording_path.name} with {len(recording_actions)} actions")
    else:
        ensure_credentials()
    
    # Ensure Frida server is ready
    ensure_frida_server()

    out_queue: queue.Queue[str] = queue.Queue()
    frida_proc = launch_frida()
    monitor_frida(frida_proc, out_queue)

    captured_tokens: list[str] = []
    transcript: list[str] = []
    hook_ready = False
    try:
        print("[INFO] Waiting for Frida hook confirmation...")
        start_time = time.time()
        while True:
            try:
                line = out_queue.get(timeout=0.1)
            except queue.Empty:
                if frida_proc.poll() is not None:
                    raise SystemExit("Frida exited unexpectedly. Check device connection.")
                if hook_ready:
                    break
                if time.time() - start_time > 15:
                    raise SystemExit("Timed out waiting for Frida hooks to initialize.")
                continue
            transcript.append(line)
            print(f"[FRIDA] {line}")
            if "Hook installation finished" in line or "ALL HOOKS INSTALLED" in line:
                hook_ready = True
                break

        if not hook_ready:
            raise SystemExit("Frida hooks never became ready.")

        automation_thread: threading.Thread | None = None
        if recording_actions is not None:
            print("[INFO] Hooks ready. Starting recorded automation replay...")
            automation_thread = threading.Thread(
                target=replay_actions,
                args=(recording_actions,),
                daemon=True,
            )
        else:
            print("[INFO] Hooks ready. Starting Appium login flow...")
            automation_thread = threading.Thread(target=run_appium_flow, daemon=True)
        automation_thread.start()

        while True:
            try:
                line = out_queue.get(timeout=0.1)
            except queue.Empty:
                if frida_proc.poll() is not None:
                    break
                if automation_thread and not automation_thread.is_alive() and out_queue.empty():
                    break
                continue
            transcript.append(line)
            print(f"[FRIDA] {line}")
            match = TOKEN_REGEX.search(line)
            if match:
                token = match.group(0).strip()
                captured_tokens.append(token)
                print(f"[TOKEN] {token}")

        if automation_thread:
            automation_thread.join(timeout=2)

        if args.post_wait > 0:
            print(f"[INFO] Waiting an extra {args.post_wait:.1f}s for late Frida events...")
            end_time = time.time() + args.post_wait
            while time.time() < end_time:
                try:
                    line = out_queue.get(timeout=0.1)
                except queue.Empty:
                    continue
                transcript.append(line)
                print(f"[FRIDA] {line}")
                match = TOKEN_REGEX.search(line)
                if match:
                    token = match.group(0).strip()
                    captured_tokens.append(token)
                    print(f"[TOKEN] {token}")
    finally:
        if frida_proc.poll() is None:
            frida_proc.send_signal(signal.SIGINT)
            try:
                frida_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                frida_proc.kill()
                frida_proc.wait()

    log_path = write_log(transcript)
    print(f"[INFO] Combined Frida output saved to {log_path}")

    if captured_tokens:
        latest = captured_tokens[-1]
        print(f"[SUCCESS] Captured {len(captured_tokens)} tokens. Latest: {latest}")
        token_file = PROJECT_ROOT / "LATEST_TOKEN.txt"
        token_file.write_text(latest + "\n", encoding="utf-8")
        print(f"[INFO] Latest token written to {token_file}")
    else:
        print("[WARN] No Bearer tokens captured. Check credentials and Frida output.")


if __name__ == "__main__":
    main()
