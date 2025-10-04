#!/usr/bin/env python3
"""Run a single restart cycle and report readiness probes in JSON."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Dict

from automation.logs import configure_logging, get_logger
from automation.services.service_manager import ServiceManager
from automation.session.controller import SessionController, SessionRestartError
from automation.session.drivers import ADBRestartDriver
from automation.session.metrics import (
    increment_restart_failure,
    observe_restart_duration,
)
from automation.session.probes import (
    ServiceReadinessProbe,
    FridaHeartbeatProbe,
    MetricsEndpointProbe,
)
from automation.session.state import SessionState


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Restart automation target and validate readiness probes.")
    parser.add_argument("--app-id", default=os.getenv("MAYNDRIVE_APP_PACKAGE", "fr.mayndrive.app"), help="Android package id to restart")
    parser.add_argument("--device-id", default=os.getenv("ANDROID_DEVICE_ID", "emulator-5554"), help="ADB device id")
    parser.add_argument("--activity", default=os.getenv("MAYNDRIVE_APP_ACTIVITY"), help="Fully-qualified main activity (optional)")
    parser.add_argument("--timeout", type=int, default=int(os.getenv("AUTOMATION_RESTART_TIMEOUT", "30")), help="Timeout in seconds before declaring failure")
    parser.add_argument("--force-clear", action="store_true", help="Force clear app data before relaunch")
    parser.add_argument("--snapshot-tag", default=os.getenv("AUTOMATION_SNAPSHOT_TAG"), help="Optional emulator snapshot to restore")
    parser.add_argument("--log-file", default=os.getenv("AUTOMATION_LOG_FILE"), help="Structured log file location (overrides env)")
    return parser.parse_args()


def serialize_state(state: SessionState) -> Dict[str, object]:
    return {
        "id": str(state.id),
        "app_id": state.app_id,
        "status": state.status.value,
        "started_at": state.started_at.isoformat(),
        "updated_at": state.updated_at.isoformat(),
        "readiness_checks": [
            {
                "name": check.name,
                "status": check.status.value,
                "details": check.details,
                "checked_at": check.checked_at.isoformat(),
            }
            for check in state.readiness_checks
        ],
        "error": None
        if state.error is None
        else {
            "code": state.error.code,
            "message": state.error.message,
            "remediation": state.error.remediation,
        },
    }


def main() -> int:
    args = parse_args()

    if args.log_file:
        configure_logging(log_file=Path(args.log_file))
    else:
        configure_logging()

    logger = get_logger("scripts.restart_healthcheck")

    service_manager = ServiceManager()
    driver = ADBRestartDriver(device_id=args.device_id, package=args.app_id, activity=args.activity)
    probes = [
        ServiceReadinessProbe(service_manager),
        FridaHeartbeatProbe(service_manager),
        MetricsEndpointProbe(args.log_file or "automation/logs/control_center.jsonl"),
    ]
    controller = SessionController(driver=driver, readiness_probes=probes)

    start = time.perf_counter()
    try:
        state = controller.restart(
            app_id=args.app_id,
            timeout_seconds=args.timeout,
            force_clear_data=args.force_clear,
            snapshot_tag=args.snapshot_tag,
        )
        duration = time.perf_counter() - start
        observe_restart_duration(app_id=args.app_id, duration_seconds=duration)
        payload = {
            "status": "success",
            "duration_seconds": duration,
            "state": serialize_state(state),
        }
        print(json.dumps(payload, indent=2))
        return 0
    except SessionRestartError as exc:
        duration = time.perf_counter() - start
        increment_restart_failure(app_id=args.app_id, error_code=exc.code)
        payload = {
            "status": "error",
            "duration_seconds": duration,
            "error": {
                "code": exc.code,
                "message": exc.message,
            },
            "state": serialize_state(exc.session),
        }
        logger.error("restart healthcheck failed", code=exc.code, message=exc.message)
        print(json.dumps(payload, indent=2), file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        logger.error("restart healthcheck encountered unexpected error", message=str(exc))
        print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
