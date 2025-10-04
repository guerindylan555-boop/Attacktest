from __future__ import annotations

import pytest

from automation.ui_catalog.schema import LabelCollision, UICatalogEntry
from automation.ui_catalog.catalog_sync import _detect_label_collisions


def entry(label: str, entry_id: str = "entry-1", sensitive: bool = False) -> UICatalogEntry:
    return UICatalogEntry(
        id=entry_id,
        label=label,
        selectors={"accessibility_id": f"{label}-id"},
        hierarchy_path="/root",
        screenshot_path="screenshots/path.png",
        metadata={},
        last_validated_at="2025-10-04T12:00:00Z",
        sensitive=sensitive,
    )


def test_detect_label_collisions_returns_unique_collisions() -> None:
    collisions = _detect_label_collisions([entry("login.submit"), entry("login.submit", entry_id="entry-2")])
    assert len(collisions) == 1
    assert collisions[0].label == "login.submit"


def test_no_collisions_produces_empty_list() -> None:
    collisions = _detect_label_collisions([entry("login.submit"), entry("login.email")])
    assert collisions == []


def test_sensitive_entries_marked_for_redaction() -> None:
    colliding = entry("login.pin", sensitive=True)
    collisions = _detect_label_collisions([colliding, entry("login.pin", entry_id="entry-3")])
    assert collisions[0].requires_redaction is True
