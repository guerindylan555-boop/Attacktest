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

def is_app_running(package_name: str = PACKAGE_NAME, device_id: str = "emulator-5554") -> bool:
    """
    Check if the MaynDrive app is currently running.
    
    Args:
        package_name: Android package name to check
        device_id: Android device ID
        
    Returns:
        True if app is running, False otherwise
    """
    try:
        result = subprocess.run(
            ["adb", "-s", device_id, "shell", f"pidof {package_name}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0 and result.stdout.strip() != ""
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return False

def launch_app(package_name: str = PACKAGE_NAME, device_id: str = "emulator-5554") -> bool:
    """
    Launch the MaynDrive app via adb using multiple strategies.
    
    Args:
        package_name: Android package name to launch
        device_id: Android device ID
        
    Returns:
        True if app was launched successfully, False otherwise
    """
    import time
    
    # Strategy 1: Use am start with explicit activity
    try:
        print(f"[INFO] Launching {package_name} via am start (method 1)...")
        result = subprocess.run(
            ["adb", "-s", device_id, "shell", "am", "start", "-n", 
             f"{package_name}/city.knot.mayndrive.ui.MainActivity"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print(f"[INFO] App launched successfully via am start")
            time.sleep(3)  # Give app time to start
            if is_app_running(package_name, device_id):
                return True
            print(f"[WARN] App launched but not detected as running yet, waiting...")
            time.sleep(2)
            return is_app_running(package_name, device_id)
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
            print(f"[INFO] App launched via monkey")
            time.sleep(3)
            return is_app_running(package_name, device_id)
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
        print(f"[WARN] Method 2 failed: {e}")
    
    # Strategy 3: Generic intent start
    try:
        print(f"[INFO] Launching {package_name} via generic intent (method 3)...")
        result = subprocess.run(
            ["adb", "-s", device_id, "shell", "am", "start", 
             "-a", "android.intent.action.MAIN",
             "-c", "android.intent.category.LAUNCHER",
             package_name],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print(f"[INFO] App launched via generic intent")
            time.sleep(3)
            return is_app_running(package_name, device_id)
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
        app_running = is_app_running(PACKAGE_NAME)
        print(f"[INFO] Checking if {PACKAGE_NAME} is running: {app_running}")
        
        if not app_running:
            if auto_launch:
                print(f"[INFO] App not running, attempting to launch {PACKAGE_NAME}...")
                launch_success = launch_app(PACKAGE_NAME)
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
        
        # Attach to running app - won't spawn a new instance
        cmd = [
            "frida", "-U", "-n", PACKAGE_NAME,
            "-l", str(HOOK_PATH)
        ]
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
