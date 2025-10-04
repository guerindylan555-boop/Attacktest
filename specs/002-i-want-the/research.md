# Research: Simplified Automation App Interface

## PySide6 Threading + Segfault Research

### Decision: Replace Python `ThreadPoolExecutor` usage with Qt-managed workers for UI-adjacent tasks.
**Rationale**: The simplified control center schedules screen captures with a `ThreadPoolExecutor` callback chain triggered by `QTimer` (see `schedule_screen_capture` and `_handle_screen_future` in `automation/ui/control_center.py`). Qt for Python warns that emitting signals or touching QObjects from non-Qt threads during shutdown can dereference deleted objects, which matches the startup segfault. Using `QThread`/`QThreadPool` (or `QtConcurrent`) keeps lifetime management inside the Qt event loop and lets the window block on worker completion before teardown.

**Alternatives considered**:
- Keep `ThreadPoolExecutor` but wrap callbacks with `QMetaObject.invokeMethod` - rejected because cleanup ordering remains manual and the executor can still outlive the GUI.
- Run ADB screen captures synchronously inside the timer slot - rejected; screencap latency regularly exceeds the 500 ms interaction budget.
- Drop the live preview - rejected; spec and constitution demand live service evidence.

## Legacy Control Center Process Management

### Decision: Mirror the backup UI's `QProcess`-driven command orchestration inside `ServiceManager` retries.
**Rationale**: The legacy interface launches emulator, proxy, and Frida via `QProcess`, wiring readyRead/finished signals back to the GUI (`automation/ui/control_center.py.backup`). Reusing that pattern keeps PATH manipulation, working-directory context, and stdout/stderr capture on the Qt thread, avoiding the orphaned `subprocess.Popen` handles currently stored in `ServiceManager` (`automation/services/service_manager.py`). It also gives automatic retries the same start/stop ordering that already works in production.

**Alternatives considered**:
- Leave `ServiceManager` on raw `subprocess` calls - rejected; we lose per-process signal hooks and granular error text for retries.
- Introduce a standalone supervisor process - rejected; adds deployment and IPC overhead for a single-desktop tool.
- Depend solely on tmux shell wrappers - rejected; lacks structured error feedback and complicates retry accounting.

## Error Messaging in Simplified UI

### Decision: Surface retry failures through service labels bound to `ServiceStatus.error_message`, while duplicating entries in the activity log.
**Rationale**: `ServiceManager.get_service_status()` already exposes `error_message` fields for each service (`automation/services/service_manager.py`). Feeding those into the UI's `set_status` call and log view ensures operators see the exact failure text while retries run, meeting FR-008 and FR-012. Updating labels via queued signals keeps UI work on the main thread and avoids modal spam.

**Alternatives considered**:
- Pop `QMessageBox` alerts on every retry - rejected; interrupts unattended automation runs.
- Show only a generic "Starting..." state - rejected; hides actionable diagnostics the plan requires.
- Rely on the log panel alone - rejected; testers need glanceable status plus preserved evidence history.

## Evidence Capture Paths

### Decision: Retain the current file-system evidence outputs and document them for the retry refactor.
**Rationale**: Automation recordings persist under `automation/recordings` via `AutomationRecording.save_to_file`, and token sessions write to `automation/sessions` while the controller exports root-level `CAPTURED_TOKEN_*` artifacts (`automation/models/recording.py`, `automation/models/token_session.py`, `automation/services/token_controller.py`). These paths already satisfy the constitution's evidence mandate and integrate with existing review tooling.

**Alternatives considered**:
- Redirect evidence to temporary directories - rejected; violates persistence requirements.
- Store tokens only in memory - rejected; breaks post-assessment reporting.
- Replace JSON/text outputs with SQLite - rejected; adds schema work without improving the retry fix.

## Environment Prerequisites

### Decision: Document mandatory adb, tmux, mitmdump, and Frida setup with quick health checks before the UI enables action buttons.
**Rationale**: Both the legacy UI and the current `ServiceManager` assume adb and tmux binaries are available and that mitmproxy/frida can spawn successfully (`automation/ui/control_center.py.backup`, `automation/services/service_manager.py`). Calling out package requirements and pre-flight commands in Phase 1 ensures testers can reproduce automatic startup and understand why buttons remain disabled until services report "running."

**Alternatives considered**:
- Bundle tooling into the app - rejected; large maintenance burden and slows updates.
- Assume dependencies exist without documentation - rejected; undermines the reproducibility gate in the plan.
- Replace tmux with custom Python daemons - rejected; loses existing session management operators rely on.
