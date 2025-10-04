from __future__ import annotations

from pathlib import Path

import json
import yaml
import pytest

from automation.ui_catalog.catalog_sync import CatalogExporter, ExportResult
from automation.ui_catalog.discovery import DiscoveryResult, UIDiscoveryService
from automation.ui_catalog.schema import UICatalogEntry, UICatalogVersion
from automation.ui_catalog.encryption import CatalogEncryptor


class FakeDiscovery(UIDiscoveryService):
    def __init__(self, *, entries: list[UICatalogEntry]) -> None:
        self.entries = entries

    def discover(self, *, session_id: str, device_profile: str) -> DiscoveryResult:
        return DiscoveryResult(entries=self.entries, screenshots={})


ENTRY = UICatalogEntry(
    id="entry-1",
    label="login.submit_button",
    selectors={"accessibility_id": "login-submit"},
    hierarchy_path="/root/login/button",
    screenshot_path="screens/button.png",
    metadata={"text": "Unlock"},
    last_validated_at="2025-10-04T12:00:00Z",
    sensitive=False,
)


@pytest.fixture
def exporter(tmp_path: Path) -> CatalogExporter:
    discovery = FakeDiscovery(entries=[ENTRY])
    return CatalogExporter(
        discovery=discovery,
        encryptor=CatalogEncryptor("test-secret"),
        output_dir=tmp_path / "exports",
    )


def test_export_generates_json_and_yaml_files(exporter: CatalogExporter) -> None:
    result = exporter.export(
        session_id="session-123",
        device_profile="pixel-emulator",
        include_screenshots=False,
    )

    assert result.status is ExportResult.SUCCESS
    assert result.json_path.exists()
    assert result.yaml_path.exists()

    json_data = json.loads(result.json_path.read_text())
    yaml_data = yaml.safe_load(result.yaml_path.read_text())

    assert json_data["entries"][0]["label"] == ENTRY.label
    assert yaml_data["entries"][0]["label"] == ENTRY.label
    assert json_data["version_metadata"]["device_profile"] == "pixel-emulator"


def test_export_reports_label_collisions(exporter: CatalogExporter) -> None:
    duplicate = ENTRY.model_copy(update={"id": "entry-2", "selectors": {"xpath": "//button"}})
    exporter.discovery.entries.append(duplicate)

    result = exporter.export(
        session_id="session-123",
        device_profile="pixel-emulator",
        include_screenshots=False,
    )

    assert result.status is ExportResult.COLLISIONS
    assert len(result.label_collisions) == 1
    assert result.label_collisions[0].label == ENTRY.label


def test_export_encrypts_sensitive_selectors(exporter: CatalogExporter) -> None:
    sensitive_entry = ENTRY.model_copy(update={"id": "entry-3", "sensitive": True})
    exporter.discovery.entries.append(sensitive_entry)

    result = exporter.export(
        session_id="session-123",
        device_profile="pixel-emulator",
        include_screenshots=False,
        redact_sensitive=True,
    )

    json_data = json.loads(result.json_path.read_text())
    selectors = json_data["entries"][1]["selectors"]
    assert selectors["accessibility_id"] != ENTRY.selectors["accessibility_id"]
    assert isinstance(selectors["accessibility_id"], str)
    assert len(selectors["accessibility_id"]) > 0
