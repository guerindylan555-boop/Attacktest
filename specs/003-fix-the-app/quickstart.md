# Quickstart: Control Center Reliability - Manual Testing Guide

**Feature**: 003-fix-the-app  
**Date**: 2025-10-04  
**Purpose**: Manual test scenarios to validate service startup reliability and recording functionality

## Prerequisites

Before running these tests:

1. ✅ Android emulator installed (Android SDK)
2. ✅ ADB in PATH (`adb version` succeeds)
3. ✅ Frida installed (`frida --version` succeeds)
4. ✅ mitmproxy installed (`mitmdump --version` succeeds)
5. ✅ MaynDrive APK installed on emulator (`adb shell pm list packages | grep mayndrive`)
6. ✅ frida-server running on emulator (`adb shell ps | grep frida-server`)
7. ✅ Python venv activated (`.venv/bin/python --version` shows Python 3.10+)
8. ✅ PySide6 installed (`.venv/bin/python -c "import PySide6"` succeeds)

## Test Environment Setup

```bash
# Start from clean state
./run_control_center.sh  # This should now auto-start services
```

---

## Scenario 1: Clean Startup (All Services Auto-Start)

**Acceptance Criteria**: FR-001, FR-002, FR-003, FR-004, FR-005, FR-006

### Steps

1. **Ensure all services stopped**:
   ```bash
   # Kill any running services
   pkill -f mitmdump
   pkill -f frida
   adb emu kill  # kills emulator
   ```

2. **Launch Control Center**:
   ```bash
   ./run_control_center.sh
   ```

3. **Observe UI**:
   - Within 5 seconds: "Automatic Service Initialization" message appears in log panel
   - Within 10 seconds: Emulator service indicator shows "starting" or "running"
   - Within 90 seconds: All three indicators (emulator, proxy, frida) show "running" (green)
   - Log panel shows timestamps for each service start attempt

4. **Verify services actually running**:
   ```bash
   adb devices  # should show emulator-5554
   netstat -tnlp | grep 8080  # should show mitmdump
   ps aux | grep frida  # should show frida process
   ```

5. **Verify MaynDrive app launched**:
   ```bash
   adb shell dumpsys window | grep -i mayndrive  # should show app in foreground
   ```

### Expected Results

- ✅ All services reach "running" state within 90 seconds
- ✅ Log shows "Emulator → Proxy → Frida" start order
- ✅ MaynDrive app visible on emulator screen
- ✅ No error messages in log panel
- ✅ "Start Recording" button becomes enabled

### Failure Scenarios

If emulator takes >90 seconds to boot:
- Log should show retry attempts: "Retry 1/3", "Retry 2/3", "Retry 3/3"
- After 3 attempts: emulator indicator shows "failed" (red)
- Manual retry button appears next to failed service

---

## Scenario 2: Service Retry Logic

**Acceptance Criteria**: FR-007, FR-008

### Steps

1. **Start Control Center with emulator already running**:
   ```bash
   # Manually start emulator first
   ~/android-tools/restart_mayndrive_emulator.sh &
   sleep 60  # wait for boot
   
   # Now launch Control Center
   ./run_control_center.sh
   ```

2. **Observe behavior**:
   - Emulator service should detect running emulator (no restart attempt)
   - Proxy and Frida start normally
   - Log shows: "[INFO] Emulator already running, attaching to existing instance"

3. **Simulate proxy port conflict**:
   ```bash
   # In another terminal, occupy port 8080
   python3 -m http.server 8080 &
   
   # Launch Control Center
   ./run_control_center.sh
   ```

4. **Observe retry behavior**:
   - Proxy service attempts start
   - Fails with "port conflict" error
   - After 5 seconds: "Retry 1/3"
   - After 10 seconds: "Retry 2/3"
   - After 15 seconds: "Retry 3/3"
   - After 20 seconds: Proxy indicator shows "failed"
   - Error message shows: "Proxy failed: port 8080 already in use"

5. **Test manual retry**:
   - Kill the conflicting process: `pkill -f "http.server 8080"`
   - Click "Retry" button next to failed proxy service
   - Within 5 seconds: Proxy indicator shows "running"

### Expected Results

- ✅ Attach detection works (no duplicate emulator start)
- ✅ Retry attempts visible in UI (count updates)
- ✅ 5-second delays between retries (timestamps confirm)
- ✅ Specific error messages (not generic "failed")
- ✅ Manual retry works without app restart

---

## Scenario 3: Recording Basic Workflow

**Acceptance Criteria**: FR-010, FR-011, FR-012, FR-013, FR-014, FR-015, FR-016, FR-017

### Steps

1. **Start recording**:
   - Ensure all services running (green indicators)
   - Click "Start Recording" button
   - Observe:
     - Button text changes to "Recording..." or becomes disabled
     - "Stop Recording" button becomes enabled
     - Status indicator shows "Recording in progress"
     - Log shows: "[INFO] Recording started: {session_id}"

2. **Perform interactions on emulator screen preview**:
   - Click at coordinates (540, 960) - should relay to device
   - Type text "test@example.com" in input field
   - Scroll down 300 pixels
   - Perform 5-10 varied interactions

3. **Verify incremental persistence**:
   ```bash
   # While recording is active, check file exists
   ls -lh automation/recordings/*.jsonl
   
   # Watch file grow as interactions happen
   tail -f automation/recordings/*_automation_recording_*.jsonl
   ```

4. **Stop recording**:
   - Click "Stop Recording" button
   - Observe:
     - Status changes to "Recording stopped"
     - Log shows: "[INFO] Recording saved: {file_path}"
     - Log shows: "Duration: {duration}s, Interactions: {count}"

5. **Verify persistence**:
   ```bash
   # Check both files exist
   ls -lh automation/recordings/*.jsonl
   ls -lh automation/recordings/*.json
   
   # Verify JSON structure
   cat automation/recordings/*_automation_recording_*.json | jq .
   ```

### Expected Results

- ✅ Recording session has unique UUID
- ✅ Each interaction appears in `.jsonl` file immediately
- ✅ Final `.json` file contains all interactions + metadata
- ✅ Timestamps are ISO 8601 format
- ✅ Duration calculated correctly
- ✅ Interaction coordinates match click positions

---

## Scenario 4: Recording Duration Limit (30 Minutes)

**Acceptance Criteria**: FR-017a, FR-017b

### Steps

**Note**: Full 30-minute test is time-consuming. For manual testing, reduce limit to 2 minutes by modifying code:

```python
# In automation/models/recording.py temporarily change:
duration_limit_seconds: int = 120  # 2 minutes for testing
```

1. **Start recording** (with 2-minute limit for testing)
2. **Wait 1 minute 50 seconds** (or use debugger to advance time)
3. **At 2:00 mark**:
   - Recording automatically stops
   - Log shows: "[WARN] Recording auto-stopped: duration limit reached"
   - Message box or toast appears with warning
   - Recording file has `auto_stopped: true` field

4. **Verify file contents**:
   ```bash
   cat automation/recordings/*_automation_recording_*.json | jq '.auto_stopped'
   # Should output: true
   
   cat automation/recordings/*_automation_recording_*.json | jq '.duration'
   # Should output: ~120.0 or slightly higher
   ```

### Expected Results

- ✅ Recording stops automatically at duration limit
- ✅ Warning message displayed to user
- ✅ `auto_stopped` flag is `true` in JSON
- ✅ All interactions up to limit are saved

---

## Scenario 5: Interaction Blocking (Recording Not Active)

**Acceptance Criteria**: FR-021a

### Steps

1. **Ensure recording NOT active** (no session in progress)
2. **Attempt to click emulator screen preview**:
   - Click anywhere on the preview image
3. **Observe behavior**:
   - Click is blocked (does NOT relay to device)
   - Error message appears: "Recording must be started first"
   - Log shows: "[ERROR] Interaction blocked: recording not active"

4. **Verify device did NOT receive interaction**:
   ```bash
   adb logcat -d | grep -i "touch"  # should not show recent touch event
   ```

5. **Start recording and retry**:
   - Click "Start Recording"
   - Click same position on preview
   - This time: interaction relays to device
   - Log shows: "[INFO] Interaction captured: click (540, 960)"

### Expected Results

- ✅ Interactions blocked when recording inactive
- ✅ Clear error message shown to user
- ✅ No ADB commands sent to device when blocked
- ✅ Interactions allowed once recording starts

---

## Scenario 6: Screen Preview Refresh Rate

**Acceptance Criteria**: FR-020

### Steps

1. **Launch Control Center with services running**
2. **Observe screen preview panel**:
   - Image should update smoothly (not jerky)
   - Use stopwatch to count updates: should be ~10 per second

3. **Perform rapid action on device**:
   ```bash
   # Drag finger rapidly across screen
   adb shell input swipe 200 500 800 500 100
   ```

4. **Observe preview**:
   - Swipe motion should be visible (not completely missed)
   - Multiple frames captured during swipe

5. **Check performance logs** (if implemented):
   ```bash
   grep "Screen capture took" logs/control_center.log
   # Should show times < 100ms per capture
   ```

### Expected Results

- ✅ Preview updates 10 times per second (±1 Hz tolerance)
- ✅ Motion appears smooth (no >500ms freezes)
- ✅ ADB screencap latency < 100ms per capture

---

## Scenario 7: Service Failure with Clear Diagnostics

**Acceptance Criteria**: FR-024, FR-025, FR-026, FR-027

### Steps

1. **Uninstall MaynDrive app to simulate failure**:
   ```bash
   adb uninstall fr.mayndrive.app
   ```

2. **Launch Control Center**:
   ```bash
   ./run_control_center.sh
   ```

3. **Observe emulator and proxy start successfully, Frida fails**:
   - Emulator: green (running)
   - Proxy: green (running)
   - Frida: red (failed) after retries

4. **Check error details**:
   - Hover over Frida indicator: tooltip shows "App fr.mayndrive.app not found"
   - Log panel shows:
     ```
     [ERROR] Frida failed: Application fr.mayndrive.app not installed
     [ERROR] Retry 1/3 failed (5s delay)
     [ERROR] Retry 2/3 failed (5s delay)
     [ERROR] Retry 3/3 failed (5s delay)
     [ERROR] Frida startup failed permanently. Please install MaynDrive APK.
     ```
   - Error shows diagnostic: "Check: adb shell pm list packages | grep mayndrive"

5. **Reinstall app and retry**:
   ```bash
   adb install Mayn\ Drive_1.1.34.xapk
   ```
   - Click "Retry" button next to Frida
   - Within 10 seconds: Frida indicator turns green

### Expected Results

- ✅ Error message is specific (not "Unknown error")
- ✅ Error indicates dependency: "Frida failed because app not installed"
- ✅ Error includes diagnostic command
- ✅ Logs preserved even after failure (can review later)
- ✅ Manual retry succeeds after fixing issue

---

## Scenario 8: Concurrent Service Startup (Edge Case)

**Acceptance Criteria**: FR-002 (dependency order)

### Steps

1. **Monitor service start order**:
   ```bash
   ./run_control_center.sh 2>&1 | ts '[%Y-%m-%d %H:%M:%.S]'
   ```

2. **Verify timestamps**:
   - Emulator start timestamp: T0
   - Proxy start timestamp: T1 (where T1 > T0 + emulator_boot_time)
   - Frida start timestamp: T2 (where T2 > T1)

3. **Confirm no race conditions**:
   - Proxy does NOT start before emulator is ready
   - Frida does NOT start before emulator + app are ready

### Expected Results

- ✅ Services start in strict order: emulator → proxy → frida
- ✅ Each service waits for predecessor to reach "running" state
- ✅ No "Connection refused" errors from premature starts

---

## Cleanup

After testing:

```bash
# Stop all services
pkill -f mitmdump
pkill -f frida
adb emu kill

# Archive test recordings
mkdir -p test_evidence/003-fix-the-app/
mv automation/recordings/*.json test_evidence/003-fix-the-app/
mv automation/recordings/*.jsonl test_evidence/003-fix-the-app/

# Reset temporary changes (if you modified duration_limit for testing)
git restore automation/models/recording.py
```

---

## Success Criteria Summary

All scenarios must pass for feature to be considered complete:

- [x] Scenario 1: Clean startup works
- [x] Scenario 2: Retry logic works
- [x] Scenario 3: Recording workflow works
- [x] Scenario 4: Duration limit enforced
- [x] Scenario 5: Interaction blocking works
- [x] Scenario 6: Screen refresh at 10 Hz
- [x] Scenario 7: Error diagnostics clear
- [x] Scenario 8: Service order correct

---

## Troubleshooting

### Control Center won't start

```bash
# Check Python/PySide6 installed
.venv/bin/python -c "import PySide6; print('OK')"

# Check display available
echo $DISPLAY  # should output :0 or similar

# Try with verbose logging
PYTHONUNBUFFERED=1 ./run_control_center.sh 2>&1 | tee debug.log
```

### Emulator won't boot

```bash
# Check emulator available
~/android-tools/restart_mayndrive_emulator.sh
# Wait 2 minutes, then check
adb devices

# Check logs
cat ~/.android/avd/MaynDriveTest.avd/hardware-qemu.ini
```

### Frida fails to attach

```bash
# Check Frida server running
adb shell ps | grep frida-server

# Restart Frida server
adb shell "su -c 'pkill frida-server'"
adb shell "su -c '/data/local/tmp/frida-server &'"

# Check Frida version match
frida --version  # host
adb shell /data/local/tmp/frida-server --version  # device
```

---

## Evidence Collection

For each test run, collect:

1. Screenshots of Control Center UI (service indicators, log panel)
2. Recording JSON files (`.json` and `.jsonl`)
3. Terminal output logs (timestamped)
4. ADB logcat snippets (if relevant to failure investigation)

Store in: `test_evidence/003-fix-the-app/{scenario_name}/`

