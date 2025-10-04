#!/usr/bin/env python3
"""Spawn MaynDrive with the general Frida hooks and tee output."""

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

HOOK_PATH = Path(__file__).resolve().parent.parent / "hooks" / "general.js"
LOG_DIR = Path.home() / "android-tools" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
PACKAGE_NAME = "fr.mayndrive.app"

def _detect_device_id() -> str:
    """Detect the first emulator device ID, fallback to default."""
    default = os.getenv("ANDROID_DEVICE_ID", "emulator-5554")
    try:
        out = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=5)
        lines = out.stdout.strip().splitlines()[1:]  # skip header
        for ln in lines:
            parts = ln.split() if ln else []
            if len(parts) >= 2 and parts[0].startswith("emulator-") and parts[1] == "device":
                return parts[0]
    except Exception:
        pass
    return default

def is_app_running(package_name: str = PACKAGE_NAME, device_id: str = None) -> bool:
    """
    Check if the MaynDrive app is currently running.
    
    Args:
        package_name: Android package name to check
        device_id: Android device ID
        
    Returns:
        True if app is running, False otherwise
    """
    if device_id is None:
        device_id = _detect_device_id()

    try:
        result = subprocess.run(
            ["adb", "-s", device_id, "shell", f"pidof {package_name}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip() != "":
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass

    # Fallback: use ps and grep for older/newer Androids without pidof behavior
    try:
        result = subprocess.run(
            [
                "adb",
                "-s",
                device_id,
                "shell",
                "sh",
                "-c",
                f"(ps -A 2>/dev/null || ps) | grep {package_name} | grep -v grep",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and package_name in (result.stdout or ""):
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass

    # Fallback: check top activity from dumpsys
    try:
        result = subprocess.run(
            [
                "adb",
                "-s",
                device_id,
                "shell",
                "dumpsys",
                "activity",
                "activities",
            ],
            capture_output=True,
            text=True,
            timeout=8,
        )
        out = result.stdout or ""
        if package_name in out and ("mResumedActivity" in out or "topResumedActivity" in out):
            return True
    except Exception:
        pass
    return False

def _resolve_main_activity(package_name: str, device_id: str) -> str | None:
    """Resolve the default launchable activity component for a package.

    Returns a component string like "com.pkg/.MainActivity" or None.
    """
    # Try cmd package resolve-activity --brief
    for args in (
        ["cmd", "package", "resolve-activity", "--brief", package_name],
        [
            "cmd",
            "package",
            "resolve-activity",
            "--brief",
            "-a",
            "android.intent.action.MAIN",
            "-c",
            "android.intent.category.LAUNCHER",
            package_name,
        ],
    ):
        try:
            res = subprocess.run(
                ["adb", "-s", device_id, "shell", *args],
                capture_output=True,
                text=True,
                timeout=8,
            )
            comp = (res.stdout or "").strip().splitlines()[-1] if res.returncode == 0 else ""
            if comp and "/" in comp and not comp.startswith("No activity"):
                return comp
        except Exception:
            continue
    return None

def _wait_for_app_running(package_name: str, device_id: str, timeout_sec: int = 25) -> bool:
    import time
    start = time.time()
    while time.time() - start < timeout_sec:
        if is_app_running(package_name, device_id):
            return True
        time.sleep(1)
    return False

def launch_app(package_name: str = PACKAGE_NAME, device_id: str = None) -> bool:
    """
    Launch the MaynDrive app via adb using multiple strategies.
    
    Args:
        package_name: Android package name to launch
        device_id: Android device ID
        
    Returns:
        True if app was launched successfully, False otherwise
    """
    import time
    if device_id is None:
        device_id = _detect_device_id()

    # Strategy 1: Resolve and start the default activity, wait for it
    try:
        comp = _resolve_main_activity(package_name, device_id)
        print(f"[INFO] Launching {package_name} via am start (method 1)...")
        if comp:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "am", "start", "-W", "-n", comp],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                print("[INFO] App launch command succeeded; waiting for process...")
                if _wait_for_app_running(package_name, device_id, timeout_sec=20):
                    return True
                print("[WARN] App not yet detected; continuing...")
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        print(f"[WARN] Method 1 failed: {e}")
    
    # Strategy 2: Use monkey to launch the app (starts main activity)
    try:
        print(f"[INFO] Launching {package_name} via monkey (method 2)...")
        result = subprocess.run(
            ["adb", "-s", device_id, "shell", "monkey", "-p", package_name, "-c", 
             "android.intent.category.LAUNCHER", "1"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print(f"[INFO] App launched via monkey; waiting for process...")
            if _wait_for_app_running(package_name, device_id, timeout_sec=20):
                return True
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        print(f"[WARN] Method 2 failed: {e}")
    
    # Strategy 3: Generic intent start
    try:
        print(f"[INFO] Launching {package_name} via generic intent (method 3)...")
        result = subprocess.run(
            [
                "adb",
                "-s",
                device_id,
                "shell",
                "am",
                "start",
                "-a",
                "android.intent.action.MAIN",
                "-c",
                "android.intent.category.LAUNCHER",
                "-p",
                package_name,
            ],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print(f"[INFO] App launched via generic intent; waiting for process...")
            if _wait_for_app_running(package_name, device_id, timeout_sec=20):
                return True
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        print(f"[ERROR] All launch methods failed. Last error: {e}")

    return False

def run_frida(attach_mode: bool = True, auto_launch: bool = True):
    """
    Start Frida with MaynDrive hooks.
    
    Args:
        attach_mode: If True, attach to running app (-n). If False, spawn new app (-f).
        auto_launch: If True and attach_mode is True, launch app if not running.
    
    Returns:
        Tuple of (process, log_file)
        
    Raises:
        RuntimeError: If attach_mode is True but app is not running and auto_launch is False
    """
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    log_file = LOG_DIR / f"frida-general-{timestamp}.log"
    
    if attach_mode:
        # Check if app is running
        device_id = _detect_device_id()
        app_running = is_app_running(PACKAGE_NAME, device_id)
        print(f"[INFO] Checking if {PACKAGE_NAME} is running: {app_running}")
        
        if not app_running:
            if auto_launch:
                print(f"[INFO] App not running, attempting to launch {PACKAGE_NAME}...")
                launch_success = launch_app(PACKAGE_NAME, device_id)
                if not launch_success:
                    error_msg = (
                        f"Failed to launch {PACKAGE_NAME} for Frida attachment. "
                        f"Make sure the emulator is running and the app is installed."
                    )
                    print(f"[ERROR] {error_msg}")
                    raise RuntimeError(error_msg)
                print(f"[SUCCESS] {PACKAGE_NAME} launched successfully!")
            else:
                raise RuntimeError(f"{PACKAGE_NAME} is not running. Start the app first or use spawn mode.")
        else:
            print(f"[INFO] {PACKAGE_NAME} is already running")
        
        # Attach to running app - prefer PID for reliability
        def _get_pid() -> str | None:
            try:
                r = subprocess.run(
                    ["adb", "-s", device_id, "shell", f"pidof -s {PACKAGE_NAME}"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                pid = (r.stdout or "").strip()
                return pid if pid else None
            except Exception:
                return None

        pid = _get_pid()
        if pid:
            cmd = ["frida", "-U", "-p", pid, "-l", str(HOOK_PATH)]
        else:
            cmd = ["frida", "-U", "-n", PACKAGE_NAME, "-l", str(HOOK_PATH)]
        print(f"[INFO] Frida attaching to MaynDrive app (attach mode)")
    else:
        # Spawn new app instance
        cmd = [
            "frida", "-U", "-f", PACKAGE_NAME,
            "-l", str(HOOK_PATH)
        ]
        print(f"[INFO] Frida spawning new MaynDrive app (spawn mode)")
    
    env = os.environ.copy()
    home_local_bin = str(Path.home() / ".local" / "bin")
    env["PATH"] = f"{home_local_bin}:{env.get('PATH', '')}"
    with log_file.open("w", encoding="utf-8") as fh:
        process = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT, env=env)
    print(f"[INFO] Frida process started (PID: {process.pid})")
    print(f"[INFO] Frida logs: {log_file}")
    return process, log_file

def main():
    try:
        proc, _ = run_frida()
        proc.wait()
    except KeyboardInterrupt:
        print("[INFO] Received Ctrl+C; terminating Frida session...")
        proc.terminate()
        proc.wait(timeout=5)

if __name__ == "__main__":
    main()
