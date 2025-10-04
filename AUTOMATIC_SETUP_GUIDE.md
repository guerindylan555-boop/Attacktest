# Automatic Setup Guide - Control Center

## 🚀 One-Command Startup

Everything is now **fully automated**. Just run:

```bash
./run_control_center.sh
```

That's it! The system will automatically:

1. ✅ **Start ADB server**
2. ✅ **Check if emulator is running** (or start it)
3. ✅ **Wait for Android boot to complete**
4. ✅ **Install MaynDrive app** (if not already installed)
5. ✅ **Start mitmproxy** (for traffic capture)
6. ✅ **Start frida-server** (on device)
7. ✅ **Launch MaynDrive app** (if not running)
8. ✅ **Attach Frida hooks** (for interception)
9. ✅ **Open Control Center UI** (ready to use)

## ⏱️ Expected Timing

### If Everything Is Already Running
- **~10-15 seconds** - Quick checks and hook attachment

### If Emulator Needs to Start
- **~60-90 seconds** - Emulator boot + app install + hooks

### First Time Setup
- **~2-3 minutes** - Emulator boot + app install + frida setup

## 📊 What You'll See

### Terminal Output
```
[EMULATOR] Starting ADB server...
[EMULATOR] Checking if device is already running...
[EMULATOR] Device is already ready!
[EMULATOR] Waiting for boot to complete...
[EMULATOR] Boot completed!
[EMULATOR] MaynDrive app is installed and ready!

[PROXY] Checking if mitmproxy is already running...
[PROXY] Mitmproxy started successfully on port 8080!

[FRIDA] Starting Frida service...
[FRIDA] Checking device connection...
[FRIDA] Ensuring frida-server is running on device...
[FRIDA] frida-server is running!
[FRIDA] Launching Frida with auto-attach mode...
[FRIDA] This will automatically launch MaynDrive app if not running...
[INFO] Checking if fr.mayndrive.app is running: False
[INFO] App not running, attempting to launch fr.mayndrive.app...
[INFO] Launching fr.mayndrive.app via am start (method 1)...
[INFO] App launched successfully via am start
[SUCCESS] fr.mayndrive.app launched successfully!
[INFO] Frida attaching to MaynDrive app (attach mode)
[FRIDA] Verifying Frida process is stable...
[FRIDA] Success! Frida is running (PID: 12345)
```

### Control Center UI
```
============================================================
[STARTUP] Automatic Service Initialization
============================================================
[STARTUP] Starting emulator, proxy, and Frida...
[STARTUP] This may take 60-90 seconds if emulator needs to boot...
[STARTUP] MaynDrive app will launch automatically...

✓ [SUCCESS] All services started successfully!
✓ Emulator is running
✓ Mitmproxy is capturing traffic
✓ Frida is hooked into MaynDrive app

[READY] You can now use the automation controls!
============================================================
```

- **Status badges**: Restart, Replay, Catalog, and Logs panels reflect the
  new automation modules. Green = healthy, red = failure with error code.
- **Structured logs**: Default sink lives at `automation/logs/control_center.jsonl`.
  Override via `AUTOMATION_LOG_FILE=/path/to/run.jsonl` before launching.
- **Metrics endpoint**: Set `AUTOMATION_METRICS_PORT=8008` (or another port)
  to start an embedded Prometheus HTTP server exposing restart durations,
  failure counters, and replay drift.
- **CLI validation** – each command emits JSON and honours the same
  environment variables as the GUI:
  - `python automation/scripts/run_restart_healthcheck.py --timeout 30`
  - `python automation/scripts/run_replay_validation.py exports/replay/admin.json`
  - `python automation/scripts/export_ui_catalog.py --device-profile pixel`
  Use these in CI to confirm automation health before running GUI flows.
- **Lint/type gate** – run `automation/scripts/run_lint.sh` locally or in CI to
  execute `compileall` (and `mypy` when installed) across the new modules.

## 🎯 Service Details

### 1. Emulator Service
**What it does:**
- Starts ADB server
- Checks if emulator-5554 is already running
- Launches emulator if needed (via `~/android-tools/restart_mayndrive_emulator.sh`)
- Waits for boot completion (`sys.boot_completed = 1`)
- Verifies MaynDrive app is installed

**Timeout:** 90 seconds for full boot

### 2. Proxy Service
**What it does:**
- Checks if mitmproxy tmux session exists
- Starts `mitmdump` on port 8080 in background tmux session
- Ready to capture HTTP/HTTPS traffic

**Session name:** `mitmproxy_session`

### 3. Frida Service
**What it does:**
- Ensures device is connected
- Pushes and starts `frida-server` on device
- Checks if MaynDrive app is running
- **Automatically launches app** if not running (3 fallback methods)
- Attaches Frida hooks to intercept API calls
- Logs all activity to `~/android-tools/logs/frida-general-*.log`

**Attach mode:** Uses `-n` (attach to running process), not `-f` (spawn new)

## 🔧 App Launch Strategies

The system uses **3 fallback methods** to ensure the app launches:

### Method 1: Direct Activity Launch (Primary)
```bash
adb shell am start -n fr.mayndrive.app/city.knot.mayndrive.ui.MainActivity
```
- Most reliable and fastest
- Directly launches the main activity

### Method 2: Monkey Launcher (Fallback)
```bash
adb shell monkey -p fr.mayndrive.app -c android.intent.category.LAUNCHER 1
```
- Uses Android's monkey tool
- Simulates launcher tap

### Method 3: Generic Intent (Last Resort)
```bash
adb shell am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER fr.mayndrive.app
```
- Generic launcher intent
- Broadest compatibility

All methods include:
- ✅ Verification that app actually started
- ✅ 3-5 second wait for initialization
- ✅ Clear error messages on failure

## 🐛 Troubleshooting

### Problem: "Device offline"
**Solution:**
```bash
# Restart ADB
adb kill-server
adb start-server
adb devices

# Then try again
./run_control_center.sh
```

### Problem: "Emulator timeout"
**Solution:**
- Check if emulator script exists: `~/android-tools/restart_mayndrive_emulator.sh`
- Try starting emulator manually first
- Increase timeout in `service_manager.py` if needed

### Problem: "App not installed"
**Solution:**
Place MaynDrive APK or XAPK in one of these locations:
- `/home/ubuntu/Desktop/Project/Attacktest/Mayn Drive_1.1.34.xapk` ✓ (already exists)
- `/home/ubuntu/Desktop/Project/Attacktest/mayndrive.apk`
- `~/android-tools/mayndrive.apk`

### Problem: "Frida failed to attach"
**Solution:**
```bash
# Check if frida-server is running
adb shell ps -A | grep frida-server

# Manual start if needed
adb push ~/android-tools/frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Check logs
tail -f ~/android-tools/logs/frida-general-*.log
```

### Problem: "Mitmproxy not starting"
**Solution:**
```bash
# Check if tmux is installed
which tmux

# Check if mitmdump is installed
which mitmdump

# Manual start
tmux new-session -d -s mitmproxy_session mitmdump --listen-port 8080
```

## 📝 Manual Control

If you need to manually control services:

### Start Emulator
```bash
~/android-tools/restart_mayndrive_emulator.sh
```

### Start Proxy
```bash
tmux new-session -d -s mitmproxy_session mitmdump --listen-port 8080
```

### Launch App
```bash
adb shell am start -n fr.mayndrive.app/city.knot.mayndrive.ui.MainActivity
```

### Start Frida
```bash
cd /home/ubuntu/Desktop/Project/Attacktest
python3 automation/scripts/run_hooks.py
```

## 🧪 Testing

Verify everything works:

```bash
# Automated test
python3 test_app_launch.py

# Check services manually
adb devices                          # Emulator running?
tmux ls | grep mitmproxy            # Proxy running?
adb shell ps -A | grep frida        # Frida running?
adb shell pidof fr.mayndrive.app    # App running?
```

## 📂 Important Paths

| Component | Path |
|-----------|------|
| Emulator Script | `~/android-tools/restart_mayndrive_emulator.sh` |
| Frida Server | `/data/local/tmp/frida-server` (on device) |
| Frida Logs | `~/android-tools/logs/frida-general-*.log` |
| Frida Hooks | `automation/hooks/general.js` |
| MaynDrive APK | `Mayn Drive_1.1.34.xapk` (project root) |
| Control Center | `automation/ui/control_center.py` |

## 🎓 How It Works

```
./run_control_center.sh
    │
    ├─> Activates virtualenv (.venv)
    │
    └─> python -m automation.ui.control_center
            │
            ├─> __init__()
            │   ├─> Creates ServiceManager
            │   ├─> Creates AutomationController
            │   ├─> Creates TokenCaptureController
            │   └─> Calls _start_services_automatically()
            │
            └─> _start_services_automatically()
                ├─> ServiceManager.start_all_services()
                │   │
                │   ├─> Start Emulator
                │   │   ├─> Check if running
                │   │   ├─> Launch if needed
                │   │   ├─> Wait for boot
                │   │   └─> Install app
                │   │
                │   ├─> Start Proxy
                │   │   ├─> Check tmux session
                │   │   └─> Start mitmdump
                │   │
                │   └─> Start Frida
                │       ├─> Start frida-server
                │       ├─> Check if app running
                │       ├─> Launch app (3 methods)
                │       └─> Attach hooks
                │
                └─> Show success message
```

## ✨ What's Automatic Now

Before this update:
- ❌ Had to start emulator manually
- ❌ Had to install app manually
- ❌ Had to launch app manually
- ❌ Frida spawned app at wrong time
- ❌ No feedback on what's happening

After this update:
- ✅ Emulator starts automatically
- ✅ App installs automatically
- ✅ App launches automatically (when needed)
- ✅ Frida attaches at right time
- ✅ Clear progress messages
- ✅ Smart fallback strategies
- ✅ Boot completion detection
- ✅ One-command operation

## 🎉 Summary

**Just run:**
```bash
./run_control_center.sh
```

**Everything else is automatic!** 🚀

The system will:
1. Check what's already running
2. Start what's not running
3. Wait for everything to be ready
4. Launch the app
5. Attach Frida hooks
6. Open the UI

**You're ready to record, replay, and capture tokens!**
