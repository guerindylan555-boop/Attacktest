#!/usr/bin/env python3
"""Discover UI elements and export synchronized JSON/YAML catalogs."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional

from automation.logs import configure_logging, get_logger
from automation.session.controller import SessionController, SessionRestartError
from automation.session.drivers import ADBRestartDriver
from automation.session.probes import (
    ServiceReadinessProbe,
    FridaHeartbeatProbe,
    MetricsEndpointProbe,
)
from automation.services.service_manager import ServiceManager
from automation.ui_catalog.catalog_sync import CatalogExporter
from automation.ui_catalog.discovery import AppiumUIDiscoveryService, DiscoveryResult, UIDiscoveryService
from automation.ui_catalog.schema import UICatalogEntry


class SimpleEncryptor:
    def __init__(self, secret: Optional[str] = None) -> None:
        self.secret = secret or os.getenv("AUTOMATION_ENCRYPTION_KEY", "attacktest")

    def encrypt(self, value: str) -> str:
        return f"enc::{self.secret}:{value}"  # pragma: no cover - trivial helper


class DryRunDiscovery(UIDiscoveryService):
    def discover(self, *, session_id: str, device_profile: str) -> DiscoveryResult:
        return DiscoveryResult(entries=[], screenshots={})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Capture the current UI tree and export catalog artifacts")
    parser.add_argument("--session-id", default="session", help="Identifier for the capture session")
    parser.add_argument("--device-profile", default="pixel-emulator", help="Device profile name used for metadata")
    parser.add_argument("--out", default="automation/ui_catalog/exports", help="Output directory for catalog artifacts")
    parser.add_argument("--appium-url", default=os.getenv("MAYNDRIVE_APPIUM_SERVER", "http://127.0.0.1:4723/wd/hub"), help="Appium server URL")
    parser.add_argument("--dry-run", action="store_true", help="Skip Appium discovery and produce empty catalog")
    parser.add_argument("--include-screenshots", action="store_true", help="Capture screenshots alongside catalog entries")
    parser.add_argument("--redact-sensitive", action="store_true", default=True, help="Encrypt sensitive selectors")
    parser.add_argument("--log-file", default=os.getenv("AUTOMATION_LOG_FILE"), help="Structured log output path")
    return parser.parse_args()


def build_catalog_exporter(args: argparse.Namespace) -> CatalogExporter:
    if args.dry_run:
        discovery = DryRunDiscovery()
    else:
        try:
            from appium import webdriver
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise SystemExit("Appium package not installed; rerun with --dry-run or install dependencies") from exc

        desired_caps = {
            "platformName": "Android",
            "automationName": "UiAutomator2",
            "appPackage": os.getenv("MAYNDRIVE_APP_PACKAGE", "fr.mayndrive.app"),
            "appActivity": os.getenv("MAYNDRIVE_APP_ACTIVITY"),
            "noReset": True,
        }
        driver = webdriver.Remote(command_executor=args.appium_url, desired_capabilities=desired_caps)
        discovery = AppiumUIDiscoveryService(driver, Path(args.out) / "screens")
    encryptor = SimpleEncryptor()
    return CatalogExporter(discovery=discovery, encryptor=encryptor, output_dir=Path(args.out))


def ensure_session_ready(args: argparse.Namespace, logger) -> None:
    service_manager = ServiceManager()
    driver = ADBRestartDriver(
        device_id=os.getenv("ANDROID_DEVICE_ID", "emulator-5554"),
        package=os.getenv("MAYNDRIVE_APP_PACKAGE", "fr.mayndrive.app"),
        activity=os.getenv("MAYNDRIVE_APP_ACTIVITY"),
    )
    probes = [
        ServiceReadinessProbe(service_manager),
        FridaHeartbeatProbe(service_manager),
        MetricsEndpointProbe(args.log_file or "automation/logs/control_center.jsonl"),
    ]
    controller = SessionController(driver=driver, readiness_probes=probes)
    try:
        controller.restart(
            app_id=os.getenv("MAYNDRIVE_APP_PACKAGE", "fr.mayndrive.app"),
            timeout_seconds=int(os.getenv("AUTOMATION_RESTART_TIMEOUT", "30")),
            force_clear_data=False,
            snapshot_tag=os.getenv("AUTOMATION_SNAPSHOT_TAG"),
        )
    except SessionRestartError as exc:  # pragma: no cover - best-effort guard
        logger.warning("session restart prior to catalog export failed", code=exc.code, message=exc.message)


def main() -> int:
    args = parse_args()

    if args.log_file:
        configure_logging(log_file=Path(args.log_file))
    else:
        configure_logging()
    logger = get_logger("scripts.export_ui_catalog")

    exporter = build_catalog_exporter(args)

    if not args.dry_run:
        ensure_session_ready(args, logger)

    result = exporter.export(
        session_id=args.session_id,
        device_profile=args.device_profile,
        include_screenshots=args.include_screenshots,
        redact_sensitive=args.redact_sensitive,
    )

    payload = {
        "status": result.status.value,
        "json_path": str(result.json_path),
        "yaml_path": str(result.yaml_path),
        "label_collisions": [collision.model_dump() for collision in result.label_collisions],
        "version": result.version,
    }
    print(json.dumps(payload, indent=2))
    return 0 if result.status.value != "error" else 2


if __name__ == "__main__":
    raise SystemExit(main())
