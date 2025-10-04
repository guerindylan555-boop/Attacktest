"""Shared pytest fixtures and helpers for the automation control test suite."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Iterator

import pytest

# Ensure the repository root is importable for tests that reference automation.* packages.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(scope="session", autouse=True)
def _configure_qt_platform() -> None:
    """Force Qt to use the offscreen platform in headless CI environments."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def qt_app() -> Iterator["QApplication"]:
    """Provide a reusable QApplication instance for PySide6-based tests."""
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    yield app

    # Do not quit the app explicitly; pytest will exit the process after tests finish.
