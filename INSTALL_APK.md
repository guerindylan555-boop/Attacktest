# Install Modified APK

## ✅ APK Created Successfully!

**Location:** `mayndrive_frida_injected.apk` (in root folder)

### What's Included:
- ✅ Frida Gadget embedded (ARM64)
- ✅ Gadget load call injected into MainActivity
- ✅ Ready for SSL unpinning

---

## Installation Instructions

### Method 1: Using ADB (Recommended)

```bash
# 1. Enable USB debugging on your phone:
#    Settings → About Phone → Tap "Build Number" 7 times
#    Settings → Developer Options → Enable "USB Debugging"

# 2. Connect phone via USB and verify connection
adb devices

# 3. Uninstall original app (backup your login credentials!)
adb uninstall fr.mayndrive.app

# 4. Install modified APK
adb install mayndrive_frida_injected.apk
```

**Note:** If you get a signature error, you may need to enable "Install unknown apps" for ADB:
- Settings → Security → Unknown Sources (or Install unknown apps) → Enable for your file manager or ADB

---

### Method 2: Manual Install via File Manager

```bash
# 1. Copy APK to phone
adb push mayndrive_frida_injected.apk /sdcard/Download/

# 2. On your phone:
#    - Open File Manager
#    - Navigate to Downloads
#    - Tap on mayndrive_frida_injected.apk
#    - Allow installation from unknown sources if prompted
#    - Install
```

---

## After Installation

### 1. Push SSL Unpinning Script

```bash
adb push ssl-unpinning.js /data/local/tmp/
adb shell chmod 644 /data/local/tmp/ssl-unpinning.js
```

### 2. Launch MaynDrive App

Just open the app normally on your phone.

### 3. Run Frida from Your PC

```bash
# Connect to Frida Gadget
frida -U Gadget -l ssl-unpinning.js

# You should see: [*] Frida script loaded
```

### 4. Configure Proxy on Phone

**WiFi Proxy Settings:**
- Settings → WiFi → Long press your network → Modify
- Show advanced options
- Proxy: Manual
- Hostname: `<Your PC IP>` (find with `ipconfig`)
- Port: `8080`

**Find your PC IP:**
```bash
ipconfig
# Look for IPv4 Address
```

### 5. Start mitmproxy or HTTP Toolkit

**Option A: mitmproxy**
```bash
mitmweb -p 8080
# Open browser to http://localhost:8081
```

**Option B: HTTP Toolkit**
- Launch HTTP Toolkit
- Click "Anything" → "A phone or tablet"
- Follow on-screen instructions

### 6. Capture Traffic!

1. Open MaynDrive app
2. Login with your credentials
3. Perform actions (view scooters, unlock, etc.)
4. All API calls will appear in mitmproxy/HTTP Toolkit!

### 7. Export Captured Traffic

```bash
# In mitmweb, click "File" → "Export" → Save as HAR

# Then analyze:
python traffic_analyzer.py captured.har
```

---

## Troubleshooting

### App Won't Install

**Error:** "App not installed"
- **Solution:** Uninstall the original app completely first
  ```bash
  adb uninstall fr.mayndrive.app
  ```

### App Crashes on Launch

**Error:** App closes immediately
- **Cause:** Anti-tampering detection (rare)
- **Solution:** Try the android-unpinner method instead:
  ```bash
  pip install android-unpinner
  android-unpinner all mayndrive_original.apk
  ```

### Frida Can't Connect

**Error:** "Failed to attach: unable to find process with name 'Gadget'"
- **Cause:** App not running or Gadget not loaded
- **Solution:** 
  1. Make sure app is open on phone
  2. Wait 5-10 seconds after launching app
  3. Try: `frida-ps -U` to list processes

### No Traffic in Proxy

**Error:** No requests showing up
- **Cause:** Proxy not configured or SSL pinning still active
- **Solution:**
  1. Verify proxy settings on phone
  2. Check Frida script is running (no errors)
  3. Visit http://mitm.it on phone to install certificate
  4. Restart the app

### SSL Certificate Error

**Error:** "Certificate validation failed"
- **Cause:** Certificate pinning not bypassed
- **Solution:**
  1. Verify Frida script is loaded without errors
  2. Check script output for SSL unpinning messages
  3. Try restarting the app while Frida is attached

---

## Testing Without Traffic Capture

To verify the modified APK works:

1. Install the APK
2. Launch the app
3. Try to login

If the app works normally, the modification was successful! The Frida Gadget is embedded and ready to use.

---

## What You'll Discover

Once traffic is captured, you'll see:

### API Endpoints
```
POST https://api.knotcity.io/api/application/login
GET  https://api.knotcity.io/api/application/vehicles/nearby
POST https://api.knotcity.io/api/application/vehicles/unlock
POST https://api.knotcity.io/api/application/vehicles/unlock/admin
```

### Headers
```http
Authorization: Bearer eyJhbGc...
User-Agent: Knot-mayndrive v1.1.34 (android)
X-Device-ID: abc123...
X-Platform: android
```

### Login Request
```json
{
  "email": "your@email.com",
  "password": "yourpassword",
  "device": {...},
  "scope": "user"  // Try "admin" here!
}
```

### Update API Client

Then update `mayn_drive_api.py` with the real data and re-test the exploit demo!

---

## Summary

✅ **Modified APK:** `mayndrive_frida_injected.apk`  
✅ **Frida Gadget:** Embedded and ready  
✅ **SSL Unpinning:** Script provided (`ssl-unpinning.js`)  
✅ **Traffic Analysis:** Tool ready (`traffic_analyzer.py`)  

**Next:** Install APK → Capture traffic → Update API client → Re-test exploits! 🚀

