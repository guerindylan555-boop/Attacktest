# Quickstart: Simplified Automation App Interface

Use this guide to get the refactored Control Center running, validate automatic retries, and capture evidence required by the constitution.

## 1. Environment Prerequisites

Run the following checks from the repository root (`/home/ubuntu/Desktop/Project/Attacktest`). All commands must succeed before launching the UI.

```bash
python3 --version
pip show PySide6
adb version
tmux -V
mitmdump --version
frida --version
adb shell "ls /data/local/tmp/frida-server"
```

If the Android emulator host tools live outside `~/android-tools`, adjust `$PATH` accordingly. The Frida daemon (`frida-server`) must already be deployed on the target emulator/device.

### Health Checklist
- `adb devices` lists `emulator-5554` as `device`.
- `tmux has-session -t mitmproxy_session` exits with status `1` (no session yet).
- `frida-ps -U | grep frida-server` returns the running daemon once the emulator boots.
- `adb shell "ls /data/local/tmp/frida-server"` confirms the device has the expected frida-server binary (copy it there and `chmod 755` if missing).

## 2. Launch the Control Center

```bash
cd /home/ubuntu/Desktop/Project/Attacktest
python3 -m automation.ui.control_center
```

On startup the UI should:
- Disable Record/Replay/Capture buttons while services show `Starting...`.
- Kick off automatic retries (max three per service) with log messages prefixed `[ServiceManager]`.
- Render the legacy-style screen preview once `adb exec-out screencap` succeeds.

### Observing Service Retries
Watch the Activity Log for entries like:
```
[ServiceManager] emulator retry 2/3: ADB command timeout
```
Exact stderr text is mirrored into the log and the Service Status panel.

## 3. Verify Readiness and UI State

1. Wait until all three services show green `Running` and the log records `[INFO] All services started successfully`.
2. Hover each disabled button before readiness to confirm the tooltip matches the `disabled_reason` (e.g., `Waiting for proxy (retry 1 of 3)`).
3. Once services are ready, confirm the `/automation/actions` dev console call exposes:
   ```json
   {
     "actions": [
       {"action": "record", "enabled": true, "requires_services": ["emulator", "proxy", "frida"]},
       {"action": "replay", "enabled": true, ...},
       {"action": "capture_token", "enabled": true, ...}
     ]
   }
   ```
   Use a Python REPL inside the app process or add a temporary debug log invoking `AutomationController.serialize_action_state()`.

## 4. Core Workflows

### 4.1 Record Automation (TDD target)
1. Click `Record Automation`.
2. Perform a short interaction sequence inside the emulator.
3. Click `Stop Recording` once the button re-enables.

Expected artefacts:
- Log entry `Recording started: <recording_id>` followed by `Recording stopped...`.
- JSON file in `automation/recordings/` matching `{timestamp}_automation_recording_<id>.json`.
- Control Action state resets to enabled with `in_progress = false`.

### 4.2 Replay Automation
1. Ensure at least one recording exists.
2. Click `Replay Automation`; the UI reuses the most recent recording until a picker is implemented.
3. Confirm the button disables while `in_progress = true` and automatically re-enables after the replay window (`QTimer.singleShot`).

Expected artefacts:
- Log entry `Replay started: <replay_id>`.
- Optional replay transcript in Activity Log (for debugging).

### 4.3 Capture Token
1. Click `Capture Token`.
2. Observe log output from `capture_working_final.py` streaming through `[token_capture]`.
3. After completion, locate:
   - `CAPTURED_TOKEN_<timestamp>_<session>.json`
   - `CAPTURED_TOKEN_<timestamp>_<session>.txt`

If credentials are missing, the UI must display a modal warning and keep the button disabled until resolved.

## 5. Evidence and Logging

- All service retry failures must appear verbatim in both the Activity Log and the Service Status panel.
- Token capture evidence files persist in the repository root; keep them for audits.
- Optional: run `python3 scripts/verify_evidence_paths.py` (to be added in implementation) to assert artefacts exist before closing the app.
- Developers can fetch structured evidence metadata via `AutomationController.get_evidence_catalog()` and `TokenCaptureController.get_evidence_catalog()` for post-run reporting.
- Button tooltips mirror `disabled_reason` payloads so operators can see which service gate is blocking an action without opening logs.
- Frida hook output is written to `~/android-tools/logs/frida-general-*.log`; check the most recent file if the log panel reports "Frida hook exited".

## 6. Shutdown Procedure

Close the window or press `Ctrl+C` in the terminal. Confirm:
- Log reports `[INFO] Stopping background services...` followed by the list of stopped services.
- `tmux has-session -t mitmproxy_session` returns non-zero (session terminated).
- `adb -s emulator-5554 get-state` eventually returns `offline` or `error` as the emulator shuts down.

## 7. Troubleshooting Reference

| Symptom | Likely Cause | Next Steps |
|---------|-------------|------------|
| Buttons remain disabled after 3 retries | Service dependency failed persistently | Inspect `blocking_errors` in `/services/status`, resolve root cause, trigger `/services/retry` or relaunch app |
| Screen preview blank | `adb exec-out screencap` timing out | Verify emulator display, increase capture interval, ensure `adb` accessible |
| Token capture never completes | `capture_working_final.py` stalled | Check stdout in log, ensure required Android activity reachable, confirm credentials |
| Replay button disabled despite recordings | No files detected or service not ready | Confirm JSON files in `automation/recordings/`; check service snapshot for non-running statuses |

## 8. Success Criteria
- All prerequisites verified before launch.
- Automatic startup completes (or surfaces actionable error messages) within three retries per service.
- Buttons remain disabled until `ServiceManagerSnapshot.all_ready == true`.
- Recording, replay, and token capture flows produce the documented artefacts.
- Closing the UI stops background services and leaves no orphaned tmux or frida processes.
