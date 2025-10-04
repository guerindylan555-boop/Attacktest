"""Replay drift validation helpers."""
from __future__ import annotations

from dataclasses import dataclass
from math import hypot
from typing import List, Optional

from automation.replay.models import Coordinate, ReplayStep


@dataclass
class DriftResult:
    step: Optional[ReplayStep]
    timing_drift_ms: float
    coordinate_drift_px: float
    within_threshold: bool


@dataclass
class ReplayDriftReport:
    total_steps: int
    steps_with_drift: int
    max_timing_drift_ms: float
    max_coordinate_drift_px: float


class ReplayValidator:
    """Default implementation that validates drift against thresholds."""

    def __init__(self, *, max_timing_drift_ms: int, max_coordinate_tolerance_px: int) -> None:
        self.max_timing_drift_ms = max_timing_drift_ms
        self.max_coordinate_tolerance_px = max_coordinate_tolerance_px
        self._results: List[DriftResult] = []

    def validate_step(self, step: ReplayStep, actual_ms: float, coordinate: Coordinate) -> DriftResult:
        timing_drift = abs(actual_ms - step.timestamp_offset_ms)
        coordinate_drift = _coordinate_distance(step.coordinate, coordinate)
        within = timing_drift <= self.max_timing_drift_ms and coordinate_drift <= self.max_coordinate_tolerance_px
        result = DriftResult(
            step=step,
            timing_drift_ms=timing_drift,
            coordinate_drift_px=coordinate_drift,
            within_threshold=within,
        )
        self._results.append(result)
        return result

    def finalize(self) -> ReplayDriftReport:
        total_steps = len([r for r in self._results if r.step is not None])
        steps_with_drift = len([r for r in self._results if r.step is not None and not r.within_threshold])
        max_timing = max((r.timing_drift_ms for r in self._results), default=0.0)
        max_coordinate = max((r.coordinate_drift_px for r in self._results), default=0.0)
        return ReplayDriftReport(
            total_steps=total_steps,
            steps_with_drift=steps_with_drift,
            max_timing_drift_ms=max_timing,
            max_coordinate_drift_px=max_coordinate,
        )


def _coordinate_distance(expected: Coordinate, actual: Coordinate) -> float:
    # Interpret coordinates as normalized positions and scale by the larger tolerance
    scale = max(expected.tolerance_px, actual.tolerance_px)
    return hypot(expected.x - actual.x, expected.y - actual.y) * scale


__all__ = [
    "DriftResult",
    "ReplayDriftReport",
    "ReplayValidator",
]
