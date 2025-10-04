from __future__ import annotations

import uuid

import pytest

from automation.session.state import (
    ReadinessCheck,
    ReadinessStatus,
    SessionError,
    SessionState,
    SessionStatus,
)


@pytest.fixture
def session_state() -> SessionState:
    return SessionState(
        id=uuid.uuid4(),
        app_id="fr.mayndrive.app",
        status=SessionStatus.IDLE,
        readiness_checks=[],
        error=None,
    )


def test_transition_to_restarting(session_state: SessionState) -> None:
    updated = session_state.transition_to(SessionStatus.RESTARTING)
    assert updated.status is SessionStatus.RESTARTING
    assert updated.error is None


def test_transition_to_ready_resets_errors(session_state: SessionState) -> None:
    error_state = session_state.with_error(
        SessionError(code="HOOK_HEARTBEAT_MISSING", message="missing heartbeat", remediation="restart frida-server")
    )
    updated = error_state.transition_to(SessionStatus.READY)
    assert updated.status is SessionStatus.READY
    assert updated.error is None


def test_transition_prohibits_invalid_moves(session_state: SessionState) -> None:
    with pytest.raises(ValueError):
        session_state.transition_to(SessionStatus.REPLAY_RUNNING)


def test_add_readiness_check_appends_records(session_state: SessionState) -> None:
    check = ReadinessCheck(name="login_ui", status=ReadinessStatus.PASS, details="visible")
    updated = session_state.add_check(check)
    assert len(updated.readiness_checks) == 1
    assert updated.readiness_checks[0].name == "login_ui"


def test_error_round_trip(session_state: SessionState) -> None:
    error = SessionError(code="SESSION_TIMEOUT", message="elapsed", remediation="increase timeout")
    errored = session_state.with_error(error)
    assert errored.error == error
    recovered = errored.clear_error()
    assert recovered.error is None
