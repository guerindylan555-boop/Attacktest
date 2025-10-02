# ✅ Final Installation Instructions

## Your Device is Connected and Authorized!

Device ID: `7HOZ4XKNB6CINNNV`

---

## Quick Install (Easiest Method)

### Option 1: Use android-unpinner (Recommended - Auto-signs APK)

```bash
# 1. Install android-unpinner
pip install android-unpinner

# 2. Run automated process
android-unpinner all MaynDrive/base.apk

# 3. Install the result
platform-tools/adb.exe uninstall fr.mayndrive.app
platform-tools/adb.exe install MaynDrive/base.unpinned.apk

# 4. Push script
platform-tools/adb.exe push ssl-unpinning.js /data/local/tmp/
```

### Option 2: Manual Transfer to Phone

```bash
# 1. Copy APK to phone
platform-tools/adb.exe push "MaynDrive/base_decoded.apk" /sdcard/Download/mayndrive_modified.apk

# 2. On your phone:
# - Open Files/Downloads
# - Tap on mayndrive_modified.apk
# - Allow installation from unknown sources
# - Install (ignore signature warnings)
```

---

## After Installation

### 1. Install Frida Tools

```bash
pip install frida-tools
```

### 2. Launch App and Run Frida

```bash
# Open MaynDrive app on phone first, then:
frida -U Gadget -l ssl-unpinning.js
```

###  3. Install mitmproxy

```bash
pip install mitmproxy
mitmweb -p 8080
```

### 4. Configure Phone Proxy

**Find your PC IP:**
```bash
ipconfig
# Look for "IPv4 Address"
```

**On your phone:**
1. Settings → WiFi
2. Long press your network
3. Modify network
4. Show advanced options
5. Proxy: Manual
6. Hostname: `<Your PC IP>`
7. Port: `8080`

### 5. Install mitmproxy Certificate

1. On phone browser, go to: `http://mitm.it`
2. Download Android certificate
3. Settings → Security → Install from storage
4. Select the downloaded certificate

### 6. Capture Traffic!

1. Open MaynDrive app
2. Login with your credentials
3. Perform actions
4. Watch traffic at: `http://localhost:8081`

---

## Alternative: Use HTTP Toolkit (Easiest for Beginners)

1. Download: https://httptoolkit.com
2. Launch HTTP Toolkit
3. Click "Android Device via ADB"
4. Open MaynDrive app
5. All traffic appears automatically!

---

## Troubleshooting

### "App not installed" Error

Try manual transfer method (Option 2 above) - some phones are more lenient when installing manually from Downloads.

### App Crashes

If app crashes on launch, use android-unpinner method which is more compatible:

```bash
pip install android-unpinner
android-unpinner all MaynDrive/base.apk
platform-tools/adb.exe install MaynDrive/base.unpinned.apk
```

### Can't Find Frida Gadget

If Frida shows "Gadget" not found:

```bash
# List all processes
frida-ps -U

# Look for MaynDrive process name and use it:
frida -U -n "MaynDrive" -l ssl-unpinning.js
```

---

## Quick Commands

```bash
# Install android-unpinner and use it
pip install android-unpinner
android-unpinner all MaynDrive/base.apk
platform-tools/adb.exe install MaynDrive/base.unpinned.apk

# Install Frida
pip install frida-tools

# Run Frida
frida -U Gadget -l ssl-unpinning.js

# Install and start mitmproxy
pip install mitmproxy
mitmweb -p 8080

# Analyze captured traffic
python traffic_analyzer.py captured.har
```

---

## What You'll Get

Once you capture traffic, you'll see:
- ✅ Real API endpoints
- ✅ Authentication headers
- ✅ Request/response formats
- ✅ Admin endpoint availability
- ✅ Whether scope escalation works

Then update `mayn_drive_api.py` and re-run exploit demo!

---

## Files You Have

- ✅ `platform-tools/adb.exe` - ADB installed
- ✅ `MaynDrive/base_decoded.apk` - Modified APK with Frida
- ✅ `ssl-unpinning.js` - SSL unpinning script
- ✅ `traffic_analyzer.py` - Traffic analysis tool
- ✅ Device authorized and ready!

**Recommendation:** Start with android-unpinner method (Option 1) - it's most reliable! 🚀

