#!/usr/bin/env python3
"""Dry-run a replay script and report drift metrics."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Iterable

from automation.logs import configure_logging, get_logger
from automation.replay.models import ReplayScript
from automation.replay.player import ReplayPlayer
from automation.replay.validator import ReplayValidator


class DryRunDriver:
    def __init__(self, logger) -> None:
        self.logger = logger

    def tap(self, coordinate) -> None:  # pragma: no cover - simple logging
        self.logger.info("dry-run tap", coordinate=coordinate.model_dump())

    def long_press(self, coordinate) -> None:
        self.logger.info("dry-run long_press", coordinate=coordinate.model_dump())

    def type_text(self, coordinate, value: str) -> None:
        self.logger.info("dry-run type_text", coordinate=coordinate.model_dump(), value=value)


class ScriptTimeSource:
    def __init__(self, script: ReplayScript) -> None:
        self._start = time.monotonic()
        offsets = [step.timestamp_offset_ms / 1000 for step in script.ordered_steps()]
        self._offset_iter = iter(offsets)

    def monotonic(self) -> float:
        try:
            delta = next(self._offset_iter)
        except StopIteration:
            delta = 0.0
        return self._start + delta


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate a replay script against drift thresholds")
    parser.add_argument("script_path", help="Path to replay script JSON file")
    parser.add_argument("--max-drift-ms", type=int, default=250, help="Maximum timing drift threshold in milliseconds")
    parser.add_argument("--max-coordinate-px", type=int, default=10, help="Maximum coordinate tolerance in pixels")
    parser.add_argument("--stop-on-missing", action="store_true", help="Abort when a replay step is missing")
    parser.add_argument("--artifact-dir", default="automation/replay/reports", help="Directory to store drift artifacts")
    parser.add_argument("--log-file", default=os.getenv("AUTOMATION_LOG_FILE"), help="Structured log file path")
    return parser.parse_args()


def load_script(path: Path) -> ReplayScript:
    data = json.loads(path.read_text())
    return ReplayScript.from_dict(data)


def main() -> int:
    args = parse_args()

    if args.log_file:
        configure_logging(log_file=Path(args.log_file))
    else:
        configure_logging()

    logger = get_logger("scripts.replay_validation")

    script_path = Path(args.script_path)
    if not script_path.exists():
        print(json.dumps({"status": "error", "error": f"Script not found: {script_path}"}), file=sys.stderr)
        return 1

    script = load_script(script_path)
    validator = ReplayValidator(
        max_timing_drift_ms=args.max_drift_ms,
        max_coordinate_tolerance_px=args.max_coordinate_px,
    )
    driver = DryRunDriver(logger)
    time_source = ScriptTimeSource(script)
    artifact_dir = Path(args.artifact_dir)

    player = ReplayPlayer(
        driver=driver,
        validator=validator,
        time_source=time_source,
        artifact_dir=artifact_dir,
    )

    outcome = player.play(
        script=script,
        max_timing_drift_ms=args.max_drift_ms,
        max_coordinate_tolerance_px=args.max_coordinate_px,
        stop_on_missing_element=args.stop_on_missing,
    )

    payload = {
        "status": outcome.status.value,
        "drift_report": None,
    }
    if outcome.drift_report is not None:
        payload["drift_report"] = {
            "total_steps": outcome.drift_report.total_steps,
            "steps_with_drift": outcome.drift_report.steps_with_drift,
            "max_timing_drift_ms": outcome.drift_report.max_timing_drift_ms,
            "max_coordinate_drift_px": outcome.drift_report.max_coordinate_drift_px,
        }

    print(json.dumps(payload, indent=2))
    return 0 if outcome.status.value == "success" else 2


if __name__ == "__main__":
    raise SystemExit(main())
