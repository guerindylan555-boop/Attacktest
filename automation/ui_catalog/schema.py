"""Dataclass schemas for UI catalog entries."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class _ModelMixin:
    def model_copy(self, update: Optional[Dict[str, object]] = None):
        return replace(self, **(update or {}))

    def model_dump(self) -> Dict[str, object]:  # noqa: D401
        return asdict(self)


@dataclass(frozen=True)
class UICatalogEntry(_ModelMixin):
    id: str
    label: str
    selectors: Dict[str, str]
    hierarchy_path: str
    screenshot_path: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    last_validated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    sensitive: bool = False


@dataclass(frozen=True)
class LabelCollision(_ModelMixin):
    label: str
    selectors: List[str]
    requires_redaction: bool = False


@dataclass(frozen=True)
class UICatalogVersion(_ModelMixin):
    version: str
    generated_at: datetime
    device_profile: str
    json_path: str
    yaml_path: str
    screenshot_directory: str
    replay_scripts: List[str] = field(default_factory=list)
    notes: Optional[str] = None


__all__ = ["UICatalogEntry", "LabelCollision", "UICatalogVersion"]
