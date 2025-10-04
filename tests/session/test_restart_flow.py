import uuid
from dataclasses import dataclass
from typing import List

import pytest

from automation.session.controller import (
    SessionController,
    SessionRestartError,
)
from automation.session.state import (
    ReadinessCheck,
    ReadinessStatus,
    SessionState,
    SessionStatus,
)


@dataclass
class FakeReadinessProbe:
    name: str
    statuses: List[ReadinessStatus]
    details: str = ""

    def run(self, session: SessionState) -> ReadinessCheck:
        if not self.statuses:
            status = ReadinessStatus.FAIL
        else:
            status = self.statuses.pop(0)
        return ReadinessCheck(
            name=self.name,
            status=status,
            details=self.details or f"probe {self.name} returned {status.value}",
        )


class FakeRestartDriver:
    def __init__(self, *, terminate_ok: bool = True, activate_ok: bool = True) -> None:
        self.terminate_ok = terminate_ok
        self.activate_ok = activate_ok
        self.clear_data_called: List[str] = []
        self.terminate_calls: List[str] = []
        self.activate_calls: List[str] = []
        self.restore_calls: List[str] = []

    def terminate_app(self, app_id: str) -> None:
        self.terminate_calls.append(app_id)
        if not self.terminate_ok:
            raise RuntimeError("terminate failed")

    def activate_app(self, app_id: str) -> None:
        self.activate_calls.append(app_id)
        if not self.activate_ok:
            raise RuntimeError("activate failed")

    def clear_app_data(self, app_id: str) -> None:
        self.clear_data_called.append(app_id)

    def restore_snapshot(self, snapshot_tag: str) -> None:
        self.restore_calls.append(snapshot_tag)


class FakeClock:
    def __init__(self, values: List[float]) -> None:
        self.values = values

    def monotonic(self) -> float:
        if not self.values:
            return self.values[-1]
        return self.values.pop(0)


def _controller(*, probes: List[FakeReadinessProbe], clock: FakeClock) -> SessionController:
    driver = FakeRestartDriver()
    controller = SessionController(
        driver=driver,
        readiness_probes=probes,
        clock=clock,
        session_factory=lambda app_id: SessionState(
            id=uuid.uuid4(),
            app_id=app_id,
            status=SessionStatus.IDLE,
            readiness_checks=[],
            error=None,
        ),
    )
    return controller


def test_restart_success_sets_ready_status_and_runs_all_probes() -> None:
    controller = _controller(
        probes=[
            FakeReadinessProbe("login_ui", [ReadinessStatus.PASS]),
            FakeReadinessProbe("frida_hook", [ReadinessStatus.PASS]),
            FakeReadinessProbe("metrics_endpoint", [ReadinessStatus.PASS]),
        ],
        clock=FakeClock([0.0, 1.0]),
    )

    state = controller.restart(app_id="fr.mayndrive.app", timeout_seconds=5)

    assert state.status is SessionStatus.READY
    assert {check.name: check.status for check in state.readiness_checks} == {
        "login_ui": ReadinessStatus.PASS,
        "frida_hook": ReadinessStatus.PASS,
        "metrics_endpoint": ReadinessStatus.PASS,
    }


def test_restart_raises_when_hook_probe_fails() -> None:
    controller = _controller(
        probes=[
            FakeReadinessProbe("login_ui", [ReadinessStatus.PASS]),
            FakeReadinessProbe("frida_hook", [ReadinessStatus.FAIL], details="heartbeat missing"),
        ],
        clock=FakeClock([0.0, 1.0]),
    )

    with pytest.raises(SessionRestartError) as exc:
        controller.restart(app_id="fr.mayndrive.app", timeout_seconds=5)

    assert exc.value.code == "HOOK_HEARTBEAT_MISSING"
    assert exc.value.message.startswith("Readiness probe frida_hook")


def test_restart_times_out_when_probes_never_pass() -> None:
    controller = _controller(
        probes=[
            FakeReadinessProbe("login_ui", [ReadinessStatus.FAIL, ReadinessStatus.FAIL]),
        ],
        clock=FakeClock([0.0, 4.0, 8.1]),
    )

    with pytest.raises(SessionRestartError) as exc:
        controller.restart(app_id="fr.mayndrive.app", timeout_seconds=5)

    assert exc.value.code == "SESSION_TIMEOUT"
    assert "timeout" in exc.value.message.lower()
