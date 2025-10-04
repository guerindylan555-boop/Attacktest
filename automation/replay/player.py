"""Deterministic replay executor for recorded automation scripts."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Protocol

from automation.logs import get_logger

from .models import Coordinate, ReplayScript, ReplayStep
from .validator import DriftResult, ReplayDriftReport


class InputDriver(Protocol):
    def tap(self, coordinate: Coordinate) -> None:  # pragma: no cover - protocol
        ...

    def long_press(self, coordinate: Coordinate) -> None:  # pragma: no cover - protocol
        ...

    def type_text(self, coordinate: Coordinate, value: str) -> None:  # pragma: no cover - protocol
        ...


class TimeSource(Protocol):
    def monotonic(self) -> float:  # pragma: no cover - protocol
        ...


class ReplayResult(Enum):
    SUCCESS = "success"
    DRIFT_DETECTED = "drift_detected"
    MISSING_ELEMENT = "missing_element"
    ERROR = "error"


@dataclass
class ReplayOutcome:
    status: ReplayResult
    drift_report: Optional[ReplayDriftReport] = None


class ReplayPlayer:
    """Executes replay scripts and validates drift metrics."""

    def __init__(
        self,
        *,
        driver: InputDriver,
        validator,
        time_source: TimeSource,
        artifact_dir: Path,
    ) -> None:
        self._driver = driver
        self._validator = validator
        self._time_source = time_source
        self._artifact_dir = artifact_dir
        self._logger = get_logger("replay.player")

    def play(
        self,
        *,
        script: ReplayScript,
        max_timing_drift_ms: int,
        max_coordinate_tolerance_px: int,
        stop_on_missing_element: bool = True,
    ) -> ReplayOutcome:
        self._artifact_dir.mkdir(parents=True, exist_ok=True)
        start_time = self._time_source.monotonic()
        drift_results: list[DriftResult] = []
        drift_detected = False

        for step in script.ordered_steps():
            self._logger.info("executing replay step", step=step.order, action=step.action)
            try:
                self._execute_step(step)
            except Exception as exc:  # pragma: no cover - defensive guard
                self._logger.error("driver execution failed", step=step.order, error=str(exc))
                raise

            try:
                now = self._time_source.monotonic()
            except Exception as exc:
                self._logger.error("timing source unavailable", error=str(exc))
                if stop_on_missing_element:
                    raise RuntimeError("Failed to capture replay timing; missing element or timing source") from exc
                continue

            elapsed_ms = (now - start_time) * 1000
            drift_result = self._validator.validate_step(
                step=step,
                actual_ms=elapsed_ms,
                coordinate=step.coordinate,
            )
            drift_results.append(drift_result)
            if not drift_result.within_threshold:
                drift_detected = True

        final_report = _build_report(drift_results, getattr(self._validator, "finalize", None))

        if drift_detected:
            status = ReplayResult.DRIFT_DETECTED
        else:
            status = ReplayResult.SUCCESS

        return ReplayOutcome(status=status, drift_report=final_report)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _execute_step(self, step: ReplayStep) -> None:
        action = step.action.lower()
        if action == "tap":
            self._driver.tap(step.coordinate)
        elif action in {"long_press", "longpress"}:
            self._driver.long_press(step.coordinate)
        elif action in {"text_input", "type_text", "text"}:
            value = step.value or ""
            self._driver.type_text(step.coordinate, value)
        else:  # pragma: no cover - unsupported action
            raise ValueError(f"Unsupported replay action: {step.action}")


def _build_report(
    drift_results: list[DriftResult],
    finalize_callable,
) -> Optional[ReplayDriftReport]:
    results = list(drift_results)

    if callable(finalize_callable):
        final = finalize_callable()
        if isinstance(final, DriftResult):
            results.append(final)
        elif isinstance(final, ReplayDriftReport):
            # Replace aggregated results entirely.
            return final

    if not results:
        return ReplayDriftReport(
            total_steps=0,
            steps_with_drift=0,
            max_timing_drift_ms=0.0,
            max_coordinate_drift_px=0.0,
        )

    total_steps = len([r for r in results if r.step is not None])
    steps_with_drift = len([r for r in results if r.step is not None and not r.within_threshold])
    max_timing = max((r.timing_drift_ms for r in results), default=0.0)
    max_coordinate = max((r.coordinate_drift_px for r in results), default=0.0)
    return ReplayDriftReport(
        total_steps=total_steps,
        steps_with_drift=steps_with_drift,
        max_timing_drift_ms=max_timing,
        max_coordinate_drift_px=max_coordinate,
    )


__all__ = ["ReplayPlayer", "ReplayResult", "ReplayOutcome"]
