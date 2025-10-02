# ✅ YOU ARE HERE - Everything is Ready!

## What's Done

✅ ADB installed  
✅ Device connected and authorized  
✅ Modified APK transferred to your phone  
✅ SSL unpinning script pushed to phone  

---

## 📱 NOW DO THIS ON YOUR PHONE:

### Step 1: Install the APK

1. **Open Files app** or **Downloads** on your phone
2. Find: **`mayndrive_frida.apk`** (in Downloads folder)
3. **Tap on it**
4. If you see "Install unknown apps" warning:
   - Tap **Settings**
   - Enable **"Allow from this source"**
   - Go back and tap **Install**
5. **Tap Install** again
6. ✅ App installed!

---

## 💻 THEN DO THIS ON YOUR PC:

### Step 2: Install Required Tools

```bash
# Install Frida
py -m pip install frida-tools

# Install mitmproxy
py -m pip install mitmproxy
```

### Step 3: Get Your PC IP Address

```bash
ipconfig
```

Look for **"IPv4 Address"** - something like: `192.168.1.100`

### Step 4: Configure Proxy on Phone

1. Settings → WiFi
2. Long press your current network
3. Tap **Modify network**
4. **Show advanced options**
5. Proxy: **Manual**
6. Hostname: **`<Your PC IP>`** (from Step 3)
7. Port: **`8080`**
8. Save

### Step 5: Start mitmproxy on PC

```bash
mitmweb -p 8080
```

Browser will open at: `http://localhost:8081`

### Step 6: Install mitmproxy Certificate on Phone

1. On phone browser, go to: **`http://mitm.it`**
2. Tap **Android**
3. Download certificate
4. Settings → Security → **Install from storage**
5. Select the certificate you just downloaded
6. Give it a name: **"mitmproxy"**
7. Done!

### Step 7: Launch MaynDrive and Run Frida

**On your phone:**
- Open MaynDrive app

**On your PC:**
```bash
frida -U Gadget -l ssl-unpinning.js
```

You should see:
```
[*] Frida script loaded
[+] SSL Unpinning active
```

### Step 8: Capture Traffic!

1. **On phone:** Login to MaynDrive, view scooters, etc.
2. **On PC browser:** Watch traffic at `http://localhost:8081`
3. **See API calls in real-time!**

### Step 9: Export and Analyze

In mitmweb browser:
1. Click **File** → **Export** → **Save**
2. Save as: `captured.har`

Then analyze:
```bash
py traffic_analyzer.py captured.har
```

---

## 🎯 What You'll See

```http
POST https://api.knotcity.io/api/application/login
Authorization: Bearer eyJhbGc...
X-Device-ID: abc123...

{
  "email": "your@email.com",
  "password": "yourpassword",
  "scope": "user"  ← Test "admin" here!
}
```

---

## ⚠️ Troubleshooting

### Frida Can't Find "Gadget"

```bash
# List all processes
platform-tools\adb.exe shell ps | findstr mayn

# Or list with Frida
frida-ps -U

# Use the actual process name
frida -U -n "fr.mayndrive.app" -l ssl-unpinning.js
```

### No Traffic in mitmproxy

1. Check proxy is configured on phone
2. Visit `http://mitm.it` on phone (should load)
3. Make sure Frida script is running (no errors)
4. Restart MaynDrive app

### Certificate Error

1. Make sure you installed cert from `http://mitm.it`
2. Install as "CA certificate" not "VPN"
3. You may need to set a screen lock (PIN/password) first

---

## 📊 Quick Summary

```
Phone:
✅ mayndrive_frida.apk in Downloads
✅ Install it manually
✅ Configure WiFi proxy to your PC IP:8080

PC:
✅ Run: mitmweb -p 8080
✅ Run: frida -U Gadget -l ssl-unpinning.js

Capture:
✅ Use MaynDrive app
✅ Watch traffic at localhost:8081
✅ Export as HAR file
✅ Analyze with traffic_analyzer.py
```

---

## 🚀 You're Almost There!

Just install the APK on your phone (it's already in Downloads folder) and follow the steps above!

Everything else is ready to go! 📱🔍

