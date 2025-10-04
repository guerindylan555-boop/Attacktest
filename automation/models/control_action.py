"""UI control state and evidence artefact models for the automation control center."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ControlActionState:
    """Represents the readiness of a single UI action button."""

    action: str
    enabled: bool
    requires_services: Set[str] = field(default_factory=set)
    in_progress: bool = False
    disabled_reason: Optional[str] = None
    last_started_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        valid_actions = {"record", "replay", "capture_token"}
        if self.action not in valid_actions:
            raise ValueError(f"action must be one of {sorted(valid_actions)}")
        if self.in_progress and self.enabled:
            raise ValueError("in_progress actions must have enabled == False")

    def to_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "action": self.action,
            "enabled": self.enabled,
            "requires_services": sorted(self.requires_services),
            "in_progress": self.in_progress,
        }
        if self.disabled_reason is not None:
            payload["disabled_reason"] = self.disabled_reason
        if self.last_started_at is not None:
            payload["last_started_at"] = self.last_started_at.isoformat()
        return payload

    @classmethod
    def disabled(cls, action: str, *, reason: str, requires: Iterable[str]) -> "ControlActionState":
        return cls(
            action=action,
            enabled=False,
            requires_services=set(requires),
            in_progress=False,
            disabled_reason=reason,
        )

    @classmethod
    def ready(cls, action: str, *, requires: Iterable[str]) -> "ControlActionState":
        return cls(
            action=action,
            enabled=True,
            requires_services=set(requires),
            in_progress=False,
        )

    def mark_started(self) -> None:
        self.enabled = False
        self.in_progress = True
        self.disabled_reason = None
        self.last_started_at = _utcnow()

    def mark_completed(self) -> None:
        self.enabled = True
        self.in_progress = False
        self.disabled_reason = None


@dataclass
class EvidenceArtifact:
    """Metadata describing captured evidence artefacts for automation workflows."""

    path: Path
    artifact_type: str
    related_id: str
    created_at: datetime = field(default_factory=_utcnow)
    digest: Optional[str] = None

    def __post_init__(self) -> None:
        valid_types = {"recording", "token_json", "token_text", "log"}
        if self.artifact_type not in valid_types:
            raise ValueError(f"artifact_type must be one of {sorted(valid_types)}")

    def to_dict(self) -> Dict[str, object]:
        payload: Dict[str, object] = {
            "path": str(self.path),
            "artifact_type": self.artifact_type,
            "related_id": self.related_id,
            "created_at": self.created_at.isoformat(),
        }
        if self.digest is not None:
            payload["hash"] = self.digest
        return payload
