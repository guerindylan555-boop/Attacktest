"""Catalog export pipeline that synchronises JSON/YAML outputs."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, List

import yaml

from automation.logs import get_logger
from automation.ui_catalog.discovery import UIDiscoveryService
from automation.ui_catalog.schema import LabelCollision, UICatalogEntry, UICatalogVersion


class ExportResult(Enum):
    SUCCESS = "success"
    COLLISIONS = "collisions"
    ERROR = "error"


@dataclass
class CatalogExportOutcome:
    status: ExportResult
    json_path: Path
    yaml_path: Path
    label_collisions: List[LabelCollision]
    version: str


class CatalogExporter:
    """Coordinates discovery and dual-format catalog exports."""

    def __init__(self, *, discovery: UIDiscoveryService, encryptor, output_dir: Path) -> None:
        self._discovery = discovery
        self._encryptor = encryptor
        self._output_dir = output_dir
        self._logger = get_logger("ui_catalog.exporter")

    @property
    def discovery(self) -> UIDiscoveryService:
        return self._discovery

    def export(
        self,
        *,
        session_id: str,
        device_profile: str,
        include_screenshots: bool = True,
        redact_sensitive: bool = True,
    ) -> CatalogExportOutcome:
        self._logger.info("exporting ui catalog", session_id=session_id, device_profile=device_profile)
        discovery_result = self._discovery.discover(session_id=session_id, device_profile=device_profile)
        entries = list(discovery_result.entries)

        sanitized_entries = _sanitize_entries(
            entries,
            encryptor=self._encryptor,
            redact_sensitive=redact_sensitive,
        )

        collisions = _detect_label_collisions(sanitized_entries)
        status = ExportResult.COLLISIONS if collisions else ExportResult.SUCCESS

        version = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        version_dir = self._output_dir / version
        screens_dir = version_dir / "screens"
        version_dir.mkdir(parents=True, exist_ok=True)
        screens_dir.mkdir(parents=True, exist_ok=True)

        if include_screenshots:
            for path, payload in discovery_result.screenshots.items():
                target = screens_dir / Path(path).name
                target.write_bytes(payload)

        json_path = version_dir / "catalog.json"
        yaml_path = version_dir / "catalog.yaml"

        version_metadata = UICatalogVersion(
            version=version,
            generated_at=datetime.utcnow(),
            device_profile=device_profile,
            json_path=str(json_path),
            yaml_path=str(yaml_path),
            screenshot_directory=str(screens_dir),
        )

        metadata_dump = version_metadata.model_dump()
        generated_at = metadata_dump.get("generated_at")
        if isinstance(generated_at, datetime):
            metadata_dump["generated_at"] = generated_at.isoformat()

        payload: Dict[str, object] = {
            "entries": [entry.model_dump() for entry in sanitized_entries],
            "version_metadata": metadata_dump,
            "label_collisions": [collision.model_dump() for collision in collisions],
        }

        json_path.write_text(json.dumps(payload, indent=2))
        yaml_path.write_text(yaml.safe_dump(payload, sort_keys=False))

        return CatalogExportOutcome(
            status=status,
            json_path=json_path,
            yaml_path=yaml_path,
            label_collisions=collisions,
            version=version,
        )


def _sanitize_entries(
    entries: Iterable[UICatalogEntry],
    *,
    encryptor,
    redact_sensitive: bool,
) -> List[UICatalogEntry]:
    sanitized: List[UICatalogEntry] = []
    for entry in entries:
        selectors = dict(entry.selectors)
        if redact_sensitive and entry.sensitive:
            selectors = {key: encryptor.encrypt(value) for key, value in selectors.items()}
        sanitized.append(entry.model_copy(update={"selectors": selectors}))
    return sanitized


def _detect_label_collisions(entries: Iterable[UICatalogEntry]) -> List[LabelCollision]:
    by_label: Dict[str, List[UICatalogEntry]] = {}
    for entry in entries:
        by_label.setdefault(entry.label, []).append(entry)

    collisions: List[LabelCollision] = []
    for label, group in by_label.items():
        if len(group) <= 1:
            continue
        selectors = sorted({value for entry in group for value in entry.selectors.values()})
        requires_redaction = any(entry.sensitive for entry in group)
        collisions.append(
            LabelCollision(
                label=label,
                selectors=selectors,
                requires_redaction=requires_redaction,
            )
        )
    return collisions


__all__ = [
    "CatalogExporter",
    "CatalogExportOutcome",
    "ExportResult",
    "_detect_label_collisions",
]
