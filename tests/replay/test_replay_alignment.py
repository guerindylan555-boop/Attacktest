from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List

import pytest

from automation.replay.player import ReplayPlayer, ReplayResult
from automation.replay.validator import DriftResult
from automation.replay.models import (
    Coordinate,
    GoldenTrace,
    ReplayScript,
    ReplayStep,
)


@dataclass
class FakeTimeSource:
    timestamps: List[float]

    def monotonic(self) -> float:
        if not self.timestamps:
            return self.timestamps[-1]
        return self.timestamps.pop(0)


class FakeInputDriver:
    def __init__(self) -> None:
        self.events: List[tuple[str, Coordinate, str | None]] = []

    def tap(self, coordinate: Coordinate) -> None:
        self.events.append(("tap", coordinate, None))

    def long_press(self, coordinate: Coordinate) -> None:
        self.events.append(("long_press", coordinate, None))

    def type_text(self, coordinate: Coordinate, value: str) -> None:
        self.events.append(("type_text", coordinate, value))


class FakeValidator:
    def __init__(self, *, drift_ok: bool, timing_drift_ms: float = 0.0, coord_drift_px: float = 0.0) -> None:
        self.drift_ok = drift_ok
        self.timing_drift_ms = timing_drift_ms
        self.coord_drift_px = coord_drift_px
        self.steps: List[ReplayStep] = []

    def validate_step(self, step: ReplayStep, actual_ms: float, coordinate: Coordinate) -> DriftResult:
        self.steps.append(step)
        return DriftResult(
            step=step,
            timing_drift_ms=self.timing_drift_ms,
            coordinate_drift_px=self.coord_drift_px,
            within_threshold=self.drift_ok,
        )

    def finalize(self) -> DriftResult:
        return DriftResult(
            step=None,
            timing_drift_ms=self.timing_drift_ms,
            coordinate_drift_px=self.coord_drift_px,
            within_threshold=self.drift_ok,
        )


def _script() -> ReplayScript:
    return ReplayScript(
        id="script-1",
        name="admin-escalation",
        version="1.0.0",
        steps=[
            ReplayStep(
                order=1,
                element_label="login.email",
                action="tap",
                value=None,
                expected_screen="login",
                timestamp_offset_ms=0,
                coordinate=Coordinate(x=0.5, y=0.2, tolerance_px=10),
            ),
            ReplayStep(
                order=2,
                element_label="login.password",
                action="text_input",
                value="hunter2",
                expected_screen="login",
                timestamp_offset_ms=150,
                coordinate=Coordinate(x=0.5, y=0.3, tolerance_px=10),
            ),
        ],
        golden_trace=GoldenTrace(
            log_digest="abc123",
            metrics_snapshot={},
            replay_duration_ms=400,
        ),
    )


def test_replay_succeeds_when_drift_within_threshold(tmp_path: Path) -> None:
    driver = FakeInputDriver()
    validator = FakeValidator(drift_ok=True)
    player = ReplayPlayer(
        driver=driver,
        validator=validator,
        time_source=FakeTimeSource([0.0, 0.15, 0.40]),
        artifact_dir=tmp_path,
    )

    result = player.play(script=_script(), max_timing_drift_ms=250, max_coordinate_tolerance_px=10)

    assert result.status is ReplayResult.SUCCESS
    assert len(driver.events) == 2
    assert validator.steps[-1].order == 2


def test_replay_flags_drift_when_threshold_exceeded(tmp_path: Path) -> None:
    driver = FakeInputDriver()
    validator = FakeValidator(drift_ok=False, timing_drift_ms=500, coord_drift_px=20)
    player = ReplayPlayer(
        driver=driver,
        validator=validator,
        time_source=FakeTimeSource([0.0, 0.8, 1.2]),
        artifact_dir=tmp_path,
    )

    result = player.play(script=_script(), max_timing_drift_ms=250, max_coordinate_tolerance_px=10)

    assert result.status is ReplayResult.DRIFT_DETECTED
    assert result.drift_report is not None
    assert result.drift_report.max_timing_drift_ms >= 500
    assert result.drift_report.max_coordinate_drift_px >= 20


def test_replay_errors_when_missing_element(tmp_path: Path) -> None:
    driver = FakeInputDriver()
    validator = FakeValidator(drift_ok=True)
    player = ReplayPlayer(
        driver=driver,
        validator=validator,
        time_source=FakeTimeSource([0.0]),
        artifact_dir=tmp_path,
    )

    with pytest.raises(RuntimeError):
        player.play(script=_script(), max_timing_drift_ms=250, max_coordinate_tolerance_px=10, stop_on_missing_element=True)
