from __future__ import annotations

import time
from pathlib import Path

from automation.replay.models import Coordinate, GoldenTrace, ReplayScript, ReplayStep
from automation.replay.player import ReplayPlayer, ReplayResult
from automation.replay.validator import ReplayValidator


class NoopDriver:
    def __init__(self) -> None:
        self.events = []

    def tap(self, coordinate: Coordinate) -> None:
        self.events.append(("tap", coordinate))

    def long_press(self, coordinate: Coordinate) -> None:
        self.events.append(("long_press", coordinate))

    def type_text(self, coordinate: Coordinate, value: str) -> None:
        self.events.append(("type_text", coordinate, value))


class FixedTimeSource:
    def __init__(self, offsets_ms: list[int]) -> None:
        self._base = time.perf_counter()
        self._offsets = iter(offsets_ms)

    def monotonic(self) -> float:
        try:
            offset = next(self._offsets)
        except StopIteration:
            offset = 0
        return self._base + (offset / 1000.0)


def _script() -> ReplayScript:
    steps = [
        ReplayStep(
            order=idx + 1,
            element_label=f"step-{idx}" ,
            action="tap",
            value=None,
            expected_screen="screen",
            timestamp_offset_ms=idx * 100,
            coordinate=Coordinate(x=0.2 + idx * 0.1, y=0.4, tolerance_px=10),
        )
        for idx in range(3)
    ]
    return ReplayScript(
        id="perf-script",
        name="performance-check",
        version="1.0.0",
        steps=steps,
        golden_trace=GoldenTrace(log_digest="", metrics_snapshot={}, replay_duration_ms=300),
    )


def test_replay_execution_stays_within_latency_budget(tmp_path: Path) -> None:
    script = _script()
    driver = NoopDriver()
    validator = ReplayValidator(max_timing_drift_ms=250, max_coordinate_tolerance_px=10)
    time_source = FixedTimeSource([0, 100, 200, 300])
    player = ReplayPlayer(
        driver=driver,
        validator=validator,
        time_source=time_source,
        artifact_dir=tmp_path,
    )

    start = time.perf_counter()
    outcome = player.play(
        script=script,
        max_timing_drift_ms=250,
        max_coordinate_tolerance_px=10,
    )
    duration = time.perf_counter() - start

    assert outcome.status is ReplayResult.SUCCESS
    assert duration < 0.2
    assert len(driver.events) == 3
