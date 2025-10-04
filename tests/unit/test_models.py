"""Unit tests for retry-aware models and action state helpers."""
from __future__ import annotations

from pathlib import Path

import pytest

from automation.models.control_action import ControlActionState, EvidenceArtifact
from automation.models.service_status import ServiceManagerSnapshot, ServiceState, ServiceStatus


def test_control_action_state_transitions() -> None:
    state = ControlActionState.ready("record", requires={"emulator"})
    assert state.enabled is True
    assert state.in_progress is False
    state.mark_started()
    assert state.enabled is False
    assert state.in_progress is True
    assert state.last_started_at is not None
    state.mark_completed()
    assert state.enabled is True
    assert state.in_progress is False


def test_control_action_state_disabled_reason() -> None:
    state = ControlActionState.disabled(
        "capture_token",
        reason="Frida offline",
        requires={"emulator", "frida"},
    )
    payload = state.to_dict()
    assert payload["enabled"] is False
    assert payload["disabled_reason"] == "Frida offline"


def test_evidence_artifact_to_dict() -> None:
    artifact = EvidenceArtifact(
        path=Path("/tmp/file.json"),
        artifact_type="token_json",
        related_id="session-123",
    )
    payload = artifact.to_dict()
    assert payload["path"].endswith("file.json")
    assert payload["artifact_type"] == "token_json"
    assert payload["related_id"] == "session-123"
    assert "created_at" in payload


def test_service_status_retry_cycle() -> None:
    status = ServiceStatus("emulator")
    assert status.retry_attempt == 0
    status.begin_start_attempt()
    assert status.retry_attempt == 1
    status.mark_error("timeout")
    assert status.has_error is True
    assert status.retries_exhausted is False
    status.retry_attempt = status.max_retries
    assert status.retries_exhausted is True
    status.mark_running(pid=1234, startup_time=0.5)
    assert status.is_running is True
    assert status.retry_attempt == 0
    payload = status.to_dict()
    assert payload["status"] == ServiceState.RUNNING.value
    assert payload["startup_time"] == pytest.approx(0.5, rel=1e-3)


def test_service_manager_snapshot_flags() -> None:
    statuses = [
        ServiceStatus("emulator", status=ServiceState.RUNNING.value),
        ServiceStatus("proxy", status=ServiceState.STARTING.value),
        ServiceStatus("frida", status=ServiceState.ERROR.value, error_message="missing"),
    ]
    statuses[2].retry_attempt = statuses[2].max_retries
    snapshot = ServiceManagerSnapshot.from_services(statuses)
    data = snapshot.to_dict()
    assert data["all_ready"] is False
    assert data["initializing"] is True
    assert data["blocking_errors"] == ["frida"]
