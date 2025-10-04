# Quick Start - One Command Setup

## 🎯 Launch Everything

```bash
./run_control_center.sh
```

**That's it!** Everything starts automatically:
- ✅ Emulator (if not running)
- ✅ MaynDrive app (auto-installed & launched)
- ✅ Mitmproxy (port 8080)
- ✅ Frida hooks (auto-attached)
- ✅ Control Center UI

## ⏱️ Wait Time

- **Already running:** ~10 seconds
- **Cold start:** ~60-90 seconds

## 🎮 Using the Control Center

Once the UI opens and shows "READY":

1. **Record Automation** - Record your interactions with the app
2. **Replay Automation** - Play back recorded sessions
3. **Capture Token** - Capture authentication tokens

## 🔍 Check Status

### Terminal Output
Watch for these success messages:
```
[EMULATOR] MaynDrive app is installed and ready!
[PROXY] Mitmproxy started successfully on port 8080!
[FRIDA] Success! Frida is running (PID: xxxxx)
```

### UI Log
Look for:
```
✓ [SUCCESS] All services started successfully!
[READY] You can now use the automation controls!
```

### Service Indicators
Left side of UI shows:
- 🟢 **Emulator: Running**
- 🟢 **Proxy: Running**
- 🟢 **Frida: Running**

## 🐛 Quick Fixes

### Services Won't Start?
```bash
# Reset everything
adb kill-server
tmux kill-session -t mitmproxy_session
adb shell am force-stop fr.mayndrive.app

# Try again
./run_control_center.sh
```

### App Won't Launch?
```bash
# Manual launch
adb shell am start -n fr.mayndrive.app/city.knot.knotapp.ui.MainActivity
```

### Check Logs
```bash
# Frida logs
tail -f ~/android-tools/logs/frida-general-*.log

# Check what's running
adb devices
tmux ls
adb shell pidof fr.mayndrive.app
```

## 📚 More Info

- Full guide: `AUTOMATIC_SETUP_GUIDE.md`
- Frida timing fix: `FRIDA_TIMING_FIX.md`
- Test suite: `python3 test_app_launch.py`

---

**TL;DR:** Run `./run_control_center.sh` and wait for "READY" message. 🚀

