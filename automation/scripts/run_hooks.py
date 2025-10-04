#!/usr/bin/env python3
"""Spawn MaynDrive with the general Frida hooks and tee output."""

import subprocess
import sys
from datetime import datetime
from pathlib import Path

HOOK_PATH = Path(__file__).resolve().parent.parent / "hooks" / "general.js"
LOG_DIR = Path.home() / "android-tools" / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

def run_frida():
    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    log_file = LOG_DIR / f"frida-general-{timestamp}.log"
    cmd = [
        "frida", "-U", "-f", "fr.mayndrive.app",
        "-l", str(HOOK_PATH)
    ]
    with log_file.open("w", encoding="utf-8") as fh:
        process = subprocess.Popen(cmd, stdout=fh, stderr=subprocess.STDOUT)
    print(f"[INFO] Frida spawned MaynDrive, logs: {log_file}")
    return process

def main():
    try:
        proc = run_frida()
        proc.wait()
    except KeyboardInterrupt:
        print("[INFO] Received Ctrl+C; terminating Frida session...")
        proc.terminate()
        proc.wait(timeout=5)

if __name__ == "__main__":
    main()
