# Quickstart: Automation App Stabilization Validation

## Prerequisites
- Python 3.10 environment with project `requirements.txt` installed (`pip install -r requirements.txt`).
- Android emulator running the MaynDrive build with developer options enabled.
- `adb` and `frida-server` running (matching host Frida version).
- Appium server available at `http://127.0.0.1:4723/wd/hub` (override via `MAYNDRIVE_APPIUM_SERVER`).
- Environment variables populated for login selectors and credentials (see `README.md`).

## 1. Verify Restart Stability
```bash
python automation/scripts/run_restart_healthcheck.py --app fr.mayndrive.app --timeout 30
```
Expected outcome:
- Script terminates app, clears residual processes, and reports `SessionState=ready` within 30 s.
- Structured log written to `automation/logs/<session_id>.jsonl` containing readiness checks.
- Exit code `0`; non-zero indicates restart failure and prints remediation steps.

## 2. Validate Replay Determinism
```bash
python automation/scripts/run_replay_validation.py --script admin-escalation-happy-path --max-drift-ms 250
```
Expected outcome:
- Each replay step logs timing and coordinate deltas.
- Command exits successfully when all steps remain inside ±250 ms / ±10 px thresholds.
- If drift detected, script aborts, captures a screenshot diff, and writes drift report to `automation/replay/reports/`.

## 3. Export & Inspect UI Catalog
```bash
python automation/scripts/export_ui_catalog.py --device-profile pixel-emulator --out automation/ui_catalog/exports
```
Expected outcome:
- JSON and YAML catalogs generated under `automation/ui_catalog/exports/<version>/`.
- Associated screenshots saved in `automation/ui_catalog/exports/<version>/screens/`.
- Catalog metadata recorded in `automation/ui_catalog/exports/<version>/catalog.json` including linked replay scripts.

## 4. Run Automated Test Suite
```bash
pytest tests/session tests/replay tests/ui_catalog -q
```
- All unit and integration tests must pass.
- Contract fixtures simulate restart failures, replay drift, and label collisions.

## 5. Lint & Type Checks
```bash
automation/scripts/run_lint.sh
```
- Runs `compileall` across automation modules and invokes `mypy` when available.
- Fails fast if type errors or syntax issues are detected.

## 6. Manual GUI Smoke Check
1. Launch the control center GUI: `python -m automation.ui`.
2. Click **Kill & Restart** and observe status indicator turn green once `ready`.
3. Trigger saved replay from GUI; verify on-screen overlay matches expected steps.
4. Open the UI Catalog panel; confirm latest version/date and ability to open JSON/YAML artifacts.

## 7. Post-Run Hygiene
- Commit generated catalogs and traces after review; archive superseded outputs into `automation/archive/`.
- Update root `README.md` with any new selectors or environment variables introduced.
- Review weekly automation health metrics exported by `automation/session/metrics.py`.
