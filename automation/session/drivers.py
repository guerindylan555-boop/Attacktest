"""Device control drivers used by session orchestration."""
from __future__ import annotations

import os
import subprocess
from typing import Optional


DEFAULT_ACTIVITY = os.getenv(
    "MAYNDRIVE_APP_ACTIVITY_DEFAULT",
    "city.knot.mayndrive.ui.MainActivity",
)


class ADBRestartDriver:
    """Simple driver that delegates restart actions to adb commands."""

    def __init__(self, *, device_id: str, package: str, activity: Optional[str]) -> None:
        self.device_id = device_id
        self.package = package
        self.activity = activity or os.getenv("MAYNDRIVE_APP_ACTIVITY", DEFAULT_ACTIVITY)

    def terminate_app(self, app_id: str) -> None:
        subprocess.run(
            ["adb", "-s", self.device_id, "shell", "am", "force-stop", app_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )

    def clear_app_data(self, app_id: str) -> None:
        subprocess.run(
            ["adb", "-s", self.device_id, "shell", "pm", "clear", app_id],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )

    def activate_app(self, app_id: str) -> None:
        if self.activity:
            result = subprocess.run(
                [
                    "adb",
                    "-s",
                    self.device_id,
                    "shell",
                    "am",
                    "start",
                    "-n",
                    f"{app_id}/{self.activity}",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                return
        subprocess.run(
            [
                "adb",
                "-s",
                self.device_id,
                "shell",
                "monkey",
                "-p",
                app_id,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )

    def restore_snapshot(self, snapshot_tag: str) -> None:
        if not snapshot_tag:
            return
        subprocess.run(
            [
                "adb",
                "-s",
                self.device_id,
                "emu",
                "avd",
                "snapshot",
                "load",
                snapshot_tag,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )


__all__ = ["ADBRestartDriver"]
