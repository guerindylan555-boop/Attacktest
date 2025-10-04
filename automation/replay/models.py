"""Data models supporting replay execution."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from typing import Dict, List, Optional


@dataclass(frozen=True)
class _ModelMixin:
    def model_copy(self, update: Optional[Dict[str, object]] = None):
        return replace(self, **(update or {}))

    def model_dump(self, mode: str = "python") -> Dict[str, object]:  # noqa: D401
        return asdict(self)


@dataclass(frozen=True)
class Coordinate(_ModelMixin):
    x: float
    y: float
    tolerance_px: int = 10


@dataclass(frozen=True)
class ReplayStep(_ModelMixin):
    order: int
    element_label: str
    action: str
    value: Optional[str] = None
    expected_screen: Optional[str] = None
    timestamp_offset_ms: int = 0
    coordinate: Coordinate = field(default_factory=lambda: Coordinate(0.0, 0.0, 0))


@dataclass(frozen=True)
class GoldenTrace(_ModelMixin):
    log_digest: str
    metrics_snapshot: Dict[str, float]
    replay_duration_ms: int


@dataclass(frozen=True)
class ReplayScript(_ModelMixin):
    id: str
    name: str
    version: str
    steps: List[ReplayStep]
    golden_trace: GoldenTrace

    def ordered_steps(self) -> List[ReplayStep]:
        return sorted(self.steps, key=lambda step: step.order)

    @classmethod
    def from_dict(cls, payload: Dict[str, object]) -> "ReplayScript":
        steps_payload = payload.get("steps", [])
        steps = [
            ReplayStep(
                order=step["order"],
                element_label=step["element_label"],
                action=step["action"],
                value=step.get("value"),
                expected_screen=step.get("expected_screen"),
                timestamp_offset_ms=step.get("timestamp_offset_ms", 0),
                coordinate=Coordinate(**step.get("coordinate", {"x": 0.0, "y": 0.0, "tolerance_px": 0})),
            )
            for step in steps_payload
        ]
        golden_payload = payload.get("golden_trace", {})
        golden = GoldenTrace(
            log_digest=golden_payload.get("log_digest", ""),
            metrics_snapshot=golden_payload.get("metrics_snapshot", {}),
            replay_duration_ms=golden_payload.get("replay_duration_ms", 0),
        )
        return cls(
            id=payload["id"],
            name=payload.get("name", payload["id"]),
            version=payload.get("version", "0.0.0"),
            steps=steps,
            golden_trace=golden,
        )


__all__ = [
    "Coordinate",
    "ReplayStep",
    "GoldenTrace",
    "ReplayScript",
]
