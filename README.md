# MaynDrive Traffic Capture Toolkit

This repository has been trimmed down to the scripts and evidence that reliably captured MaynDrive tokens and telemetry on-device. Everything else (experiments, planning docs, broken PoCs) has been removed so only the proven workflow remains.

## Working Scripts
- `capture_working_final.py` — launches the production app, injects `capture_WORKING_FINAL.js`, and records lock/unlock requests, including Bearer tokens and scooter metadata.
- `capture_new_account.py` — same injector with added ADB handling so you can spin up a clean session, log in with a brand-new account, and grab the first-use token safely.
- `capture_WORKING_FINAL.js` — Frida hook set targeting the discovered coroutine classes plus a Cipher hook for plaintext telemetry.

Both Python entry points write structured JSON and human-readable logs so you can diff captures, replay them through other tooling, or hand the evidence to the API team.

## Requirements
- Python 3.9+
- Frida Python bindings (`pip install frida-tools frida`)
- PySide6 (`pip install PySide6`) and lxml (`pip install lxml`) inside `.venv`
- Appium stack (Node.js + `npm install -g appium`) for automated flows
- USB debugging with a rooted test device (needed for restarting `frida-server` via `adb shell su -c ...`)
- `frida-server` running on the device (matching the Frida version on the workstation)

## Usage
1. Connect the device via USB, ensure `adb devices` shows it, and that `frida-ls-devices` lists it as `usb`.
2. (Optional but recommended) Restart the on-device frida-server: `adb shell su -c 'pkill frida-server'; adb shell su -c '/data/local/tmp/frida-server &'`.
3. For a staffed account capture: `python capture_working_final.py`
   - Follow the console instructions: log in, unlock, then lock a scooter.
   - Tokens land in `CAPTURED_WORKING_FINAL.txt` and `CAPTURED_WORKING_FINAL.json`; the latest token is mirrored to `LATEST_TOKEN.txt`.
4. For a brand-new account flow: `python capture_new_account.py`
   - Script restarts `frida-server` automatically when possible.
   - Unlock/lock actions are recorded in `CAPTURED_NEW_ACCOUNT.*` with matching JSON rows.
5. Stop capture with `Ctrl+C`. The script prints the output locations before exiting.

## Verification Artifacts
- `CAPTURED_WORKING_FINAL.txt/json` — multiple lock/unlock events with Bearer tokens, pass IDs, and coroutine class names (e.g., `B4.x`, `B4.P3`).
- `CAPTURED_NEW_ACCOUNT.txt/json` — unlock + lock sequence from a fresh account, confirming repeatable token capture.
- `LATEST_TOKEN.txt` — convenience copy of the most recent token (ASCII cleaned).

## Directory Layout
```
.
├── capture_new_account.py
├── capture_working_final.py
├── capture_WORKING_FINAL.js
├── automation
│   ├── hooks
│   │   └── general.js
│   ├── scripts
│   │   ├── run_appium_token_flow.py
│   │   └── run_hooks.py
│   └── ui
├── CAPTURED_NEW_ACCOUNT.json
├── CAPTURED_NEW_ACCOUNT.txt
├── CAPTURED_WORKING_FINAL.json
├── CAPTURED_WORKING_FINAL.txt
├── LATEST_TOKEN.txt
└── CAPTURE_LOG_SUMMARY.md (high-level notes on the retained captures)
```

## Next Steps
- Rotate the captured tokens if they belong to production services.
- Point any downstream automation at the JSON logs instead of rebuilding parsers.
- If you need additional hooks (e.g., admin endpoints), create them in a new branch so the main tree stays clean.

## Control Center GUI
- Install dependencies: `pip install PySide6` (Frida/mitmproxy CLI tools are already part of the base setup).
- Launch the dashboard with `python -m automation.ui` from the project root.
- When the dashboard launches it spins up the emulator (if needed), mitmdump, Frida hooks, and an Appium server (`npx appium@2.11.0`) automatically. Buttons remain available for manual restarts or shutdowns.
- The left column exposes one-click controls for the emulator, mitmdump proxy, Frida hooks, the working token capture script, and a "Run Login Capture" button. Select a saved recording to have the button replay it automatically while Frida runs; otherwise it falls back to the Appium login flow (requires `MAYNDRIVE_TEST_EMAIL` / `MAYNDRIVE_TEST_PASSWORD`).
- The left column also drives the Appium token flow. The screen panel itself is interactive—clicks become taps and drags become swipes via `adb input`—so you can explore the UI directly from the dashboard while it records which element was touched (resource-id/text/bounds) and highlights it in the preview.
- The centre panel refreshes emulator screenshots (≈1 Hz) while remaining interactive; the bottom log view tails command output for fast troubleshooting. If you still want a full-motion mirror, open `scrcpy` separately.
- Buttons orchestrate the existing workflow (`restart_mayndrive_emulator.sh`, mitmdump tmux session, Frida runner, capture scripts) so everything stays in sync during a run.

### Appium Automation
- Configure an Appium server (default `http://127.0.0.1:4723/wd/hub`). Update `MAYNDRIVE_APPIUM_SERVER` if you use a remote node.
- Provide selectors/credentials through environment variables (examples):
  - `export MAYNDRIVE_TEST_EMAIL="user@example.com"`
  - `export MAYNDRIVE_TEST_PASSWORD="hunter2"`
  - `export MAYNDRIVE_SELECTOR_EMAIL="fr.mayndrive.app:id/email"` (override as necessary)
  - `export MAYNDRIVE_SELECTOR_PASSWORD="fr.mayndrive.app:id/password"`
  - `export MAYNDRIVE_SELECTOR_LOGIN="fr.mayndrive.app:id/login"`
  - `export MAYNDRIVE_SELECTOR_UNLOCK="fr.mayndrive.app:id/unlock"`
  - `export MAYNDRIVE_SELECTOR_LOCK="fr.mayndrive.app:id/lock"`
- The new script `automation/scripts/run_appium_token_flow.py` performs: login → unlock → lock. Adjust selectors to match the current APK (use `uiautomatorviewer`/Appium Inspector to confirm resource IDs).
- Kick off the flow via the GUI (“Run Appium Flow”) or CLI `source .venv/bin/activate && python automation/scripts/run_appium_token_flow.py`.
- To capture tokens end-to-end automatically run `python automation/scripts/capture_login_token.py`; it spawns the Frida hooks, executes the login Appium flow, and saves any Bearer tokens to `LATEST_TOKEN.txt` plus a timestamped log in `~/android-tools/logs/`.

### Live Stream
- For high-frame-rate monitoring launch `adb exec-out screenrecord --output-format=h264 - | ffplay -framerate 30 -` manually (requires FFmpeg) or use `scrcpy`.

## Automation Blueprint
This high-level plan wires the emulator, Frida, mitmproxy, and UI automation together while keeping the option to view the screen when you need to debug.

### 1. Provision the Emulator Host
- Install Android SDK command-line tools, create an x86_64 AVD (userdebug/AOSP image) with writable system: `avdmanager create avd -n MaynDriveTest -k "system-images;android-34;googleapis;x86_64"`.
- Enable nested virtualization/KVM on the VPS; fall back to software rendering only if hardware acceleration is unavailable.
- Snapshot the pristine boot state after first launch (faster resets between test runs).

### 2. Launch Profiles (Headless + Viewable)
- Primary automation profile: `emulator -avd MaynDriveTest -no-window -no-audio -no-boot-anim -writable-system -accel on` and wait for `adb shell getprop sys.boot_completed`.
- Verification profile (ad-hoc): same launch but omit `-no-window` when you connect through remote desktop, or run headless and mirror with `scrcpy --serial emulator-5554 --max-fps 30` (requires host display, which remote desktop provides).
- For quick peeks on a headless run you can still stream frames manually: `adb exec-out screenrecord --output-format=h264 - | ffplay -framerate 30 -i -`.
- Daily workflow: `tmux new -s mitmproxy_session` then `mitmdump --listen-port 8080 --set block_global=false --set save_stream_file=/home/ubuntu/android-tools/proxy/flows.mitm`. Detach with `Ctrl+b d`; reattach via `tmux attach -t mitmproxy_session` to view traffic in real time.

### 3. Frida Server Lifecycle
- Host side: `pipx install frida-tools`; download matching `frida-server-<ver>-android-x86_64`.
- Deploy per boot: `adb root && adb remount && adb push frida-server... /data/local/tmp/ && adb shell chmod 755 ... && adb shell "/data/local/tmp/frida-server &"`.
- Health check: `frida-ps -U | head` before each scenario; keep a tiny supervisor script that restarts the daemon if the process vanishes.

### 4. Network Interception Stack
- Run `mitmdump --listen-port 8080 --set save_stream_file=flows.mitm` (or Burp if you prefer GUI via remote desktop).
- Configure proxy on the emulator: `adb shell settings put global http_proxy 10.0.2.2:8080` and disable after tests with `... :0`.
- Install CA into system store once: `adb root && adb remount`, push hashed cert to `/system/etc/security/cacerts/`, set `chmod 644`, and reboot.
- Track pinning bypass scripts (Frida snippets) alongside your main hook file; toggle them on when the proxy stops seeing TLS flows.

### 5. Hook Design & Logging
- Maintain `hooks/general.js` with try/catch wrappers for: OkHttp builders, request headers (Authorization), `Cipher.doFinal`, and trust manager overrides.
- Prefix every console log with ISO timestamps plus action tags (`[LOGIN_REQUEST]` etc.) so automation can correlate events.
- Store hooks in git with versioned subfolders keyed to app releases (e.g., `hooks/v1.12.0.js`).

### 6. UI Automation Strategy
- Baseline: ADB input helpers (`input tap`, `input text`, `keyevent 66`) orchestrated via Python subprocess; pull `uiautomator dump` XML to validate states when needed.
- Scalable path: install Node.js + Appium (`npm install -g appium @appium/doctor`) and the Python client; script flows using resource ids extracted from APK. Run server under `xvfb-run` only if the host complains about display.
- Shared helpers: disable animations (`adb shell settings put global animator_duration_scale 0` etc.) and clear app state before each run (`adb shell pm clear fr.mayndrive.app`).

### 7. Orchestration Skeleton (No Coding Yet)
- Sequencing order per run: reset emulator snapshot → ensure proxy + Frida up → launch app via Frida spawn (`frida -U -f fr.mayndrive.app -l hooks/current.js --no-pause`) → kick off UI automation → wait for completion → collect logs (`frida` stdout, mitm flows, `adb logcat -d` subset) → archive artifacts with timestamp.
- Define environment variables (`FRIDA_VERSION`, `MITM_PORT`, `AVD_NAME`) in a `.env` file to keep shell scripts minimal once implemented.
- Convenience helpers:
  - `~/android-tools/restart_mayndrive_emulator.sh` — restarts the AVD with sane defaults and waits for `adb root` readiness.
  - `automation/scripts/run_hooks.py` — spawns MaynDrive with `automation/hooks/general.js` attached and writes Frida logs to `~/android-tools/logs/`.

### 8. Validation & Maintenance
- Smoke test weekly: manual login run while watching `scrcpy` window to confirm UI automation still hits correct views.
- After app updates, diff new APK against previous (use `jadx` or `apktool`) and adjust hook targets; update plan checklist with findings.
- Monitor resource usage (`top`, `adb shell dumpsys meminfo`) so the 8 GB VPS stays within limits; scale emulator resolution down if memory pressure appears.

This blueprint keeps implementation work staged, while preserving the ability to inspect the emulator visually whenever required.
