"""UI discovery service contracts and helpers."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Protocol
import xml.etree.ElementTree as ET

from automation.ui_catalog.schema import UICatalogEntry
from automation.logs import get_logger


@dataclass
class DiscoveryResult:
    entries: List[UICatalogEntry]
    screenshots: Dict[str, bytes]


class UIDiscoveryService(Protocol):
    """Abstraction for gathering UI widgets from a running session."""

    def discover(self, *, session_id: str, device_profile: str) -> DiscoveryResult:  # pragma: no cover - protocol contract
        ...


class AppiumUIDiscoveryService:
    """Appium-powered discovery of the active view hierarchy."""

    def __init__(self, driver, screenshot_root: Path) -> None:
        self._driver = driver
        self._screenshot_root = screenshot_root
        self._logger = get_logger("ui_catalog.discovery")

    def discover(self, *, session_id: str, device_profile: str) -> DiscoveryResult:
        page_source = self._driver.page_source
        root = ET.fromstring(page_source)
        entries: List[UICatalogEntry] = []

        for index, element in enumerate(root.iter()):
            label = self._make_label(element, index)
            if not label:
                continue

            entry = UICatalogEntry(
                id=f"{session_id}-{index}",
                label=label,
                selectors=self._build_selectors(element),
                hierarchy_path=self._hierarchy_path(element),
                screenshot_path=f"screens/{label}.png",
                metadata={
                    "text": element.attrib.get("text"),
                    "class": element.attrib.get("class"),
                    "package": element.attrib.get("package"),
                },
                last_validated_at=self._timestamp(),
                sensitive=False,
            )
            entries.append(entry)

        screenshots: Dict[str, bytes] = {}
        try:
            png = self._driver.get_screenshot_as_png()
            screenshot_dir = self._screenshot_root / device_profile
            screenshot_dir.mkdir(parents=True, exist_ok=True)
            path = screenshot_dir / f"{session_id}.png"
            path.write_bytes(png)
            screenshots[str(path)] = png
        except Exception:  # pragma: no cover - optional asset capture
            self._logger.warning("unable to capture screenshot", device_profile=device_profile)

        return DiscoveryResult(entries=entries, screenshots=screenshots)

    def _build_selectors(self, element: ET.Element) -> Dict[str, str]:
        selectors: Dict[str, str] = {}
        resource_id = element.attrib.get("resource-id")
        content_desc = element.attrib.get("content-desc")
        if resource_id:
            selectors["resource_id"] = resource_id
        if content_desc:
            selectors["accessibility_id"] = content_desc
        if element.attrib.get("bounds"):
            selectors["bounds"] = element.attrib["bounds"]
        return selectors

    def _hierarchy_path(self, element: ET.Element) -> str:
        tag = element.tag.split('}')[-1]
        xpath = element.attrib.get("xpath")
        return xpath or f"/{tag}"

    def _make_label(self, element: ET.Element, index: int) -> str:
        resource_id = element.attrib.get("resource-id")
        content_desc = element.attrib.get("content-desc")
        if resource_id:
            sanitized = resource_id.split(":")[-1].replace("/", "_")
            return sanitized
        if content_desc:
            sanitized = content_desc.lower().replace(" ", "_")
            return sanitized
        text = element.attrib.get("text")
        if text:
            return f"text_{index}"
        return f"node_{index}"

    def _timestamp(self) -> str:
        from datetime import datetime

        return datetime.utcnow().isoformat()


__all__ = ["DiscoveryResult", "UIDiscoveryService"]
