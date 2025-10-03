# 🔬 MaynDrive Traffic Analysis - MASTER PLAN
## Deep, Multi-Layer Network & Application Traffic Capture Strategy

**Date:** October 2, 2025  
**Target:** MaynDrive v1.1.34 (fr.mayndrive.app)  
**Objective:** Achieve 100% visibility into ALL communication layers  
**Workspace:** `C:\Users\abesn\OneDrive\Bureau\analyse`

---

## 📊 Executive Summary

This document provides a **comprehensive, multi-layered approach** to capturing and analyzing ALL traffic from the MaynDrive scooter-sharing application. Based on extensive reverse engineering, we've identified **three distinct communication layers** that must be monitored simultaneously for complete visibility.

### Communication Architecture Discovered

```
┌─────────────────────────────────────────────────────────────────┐
│                       MaynDrive App                              │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐    │
│  │ HTTP Client  │  │ Socket.io    │  │  DTLS/UDP Client  │    │
│  │ (OkHttp3)    │  │ (WebSocket)  │  │  (Native Layer)   │    │
│  └──────┬───────┘  └──────┬───────┘  └─────────┬─────────┘    │
│         │                  │                     │               │
└─────────┼──────────────────┼─────────────────────┼──────────────┘
          │                  │                     │
          │ HTTPS            │ WSS                 │ DTLS
          │ Port 443         │ Port 443            │ Port 5684
          │                  │                     │
          ▼                  ▼                     ▼
┌─────────────────────────────────────────────────────────────────┐
│                    api.knotcity.io                               │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────┐    │
│  │ REST API     │  │ Notification │  │  IoT Gateway      │    │
│  │ (Control)    │  │ (Push)       │  │  (Telemetry)      │    │
│  └──────┬───────┘  └──────┬───────┘  └─────────┬─────────┘    │
└─────────┼──────────────────┼─────────────────────┼──────────────┘
          │                  │                     │
          │                  │                     ▼
          │                  │              ┌─────────────┐
          │                  │              │  Scooter    │
          │                  │              │  SNSC 2.0   │
          └──────────────────┴──────────────┤  (BLE/IoT)  │
                                            └─────────────┘
```

---

## 🎯 LAYER 1: Application-Level Instrumentation (Frida)

### Current Implementation Status: ✅ COMPLETE

**Location:** `capture_COMPLETE_SOLUTION.js` + `capture.py`

#### What's Already Captured:

1. **Coroutine Layer (Pre-HTTP)**
   - `B4.Y4.invokeSuspend` - Unlock operations
   - `B4.M4.invokeSuspend` - Lock operations
   - Bearer tokens extracted
   - Scooter serial numbers
   - GPS coordinates

2. **HTTP Layer (OkHttp3)**
   - `qh.h.h()` - RealCall.execute()
   - Request URLs and methods
   - Authorization headers
   - Pass IDs

3. **Cipher Layer (Pre-Encryption)**
   - `javax.crypto.Cipher.doFinal()`
   - AES/GCM plaintext before UDP encryption
   - Algorithm identification

4. **Socket.io Layer**
   - `bg.p.u` - emit() method
   - `bg.i.Q` - packet sender
   - Real-time notifications

5. **Native Layer (Raw UDP)**
   - `sendto()` - Outgoing UDP packets
   - `recvfrom()` - Incoming UDP packets
   - Destination IP:Port extraction

#### Frida Hook Enhancement Plan

**File:** `capture_ENHANCED_V2.js`

```javascript
// NEW HOOKS TO ADD:

// 1. Retrofit Adapter Layer (catches ALL API calls)
Java.use('Ki.a$b').b.implementation = function(proxy, method, args, continuation) {
    // This catches ALL Retrofit calls before they become HTTP
    console.log('[RETROFIT] Method: ' + method.getName());
    console.log('[RETROFIT] Args: ' + JSON.stringify(args));
    return this.b(proxy, method, args, continuation);
};

// 2. WebSocket Frame Decoder (for Socket.io messages)
Java.use('com.neovisionaries.ws.client.WebSocket').sendText.implementation = function(text) {
    console.log('[WEBSOCKET OUT] ' + text);
    return this.sendText(text);
};

Java.use('com.neovisionaries.ws.client.ListenerManager').callOnTextMessage.implementation = function(websocket, text) {
    console.log('[WEBSOCKET IN] ' + text);
    return this.callOnTextMessage(websocket, text);
};

// 3. SSL/TLS Key Logger (for MITM decryption)
// Hook SSLContext to log session keys
Java.use('javax.net.ssl.SSLContext').init.implementation = function(km, tm, sr) {
    console.log('[SSL] SSLContext initialized');
    // Log key material for Wireshark decryption
    return this.init(km, tm, sr);
};

// 4. Shared Preferences (for tokens/credentials)
Java.use('android.content.SharedPreferences$Editor').putString.implementation = function(key, value) {
    if (key.indexOf('token') !== -1 || key.indexOf('auth') !== -1 || key.indexOf('password') !== -1) {
        console.log('[STORAGE] Saving: ' + key + ' = ' + value.substring(0, 50) + '...');
    }
    return this.putString(key, value);
};

// 5. JSON Parser (catches all API response parsing)
Java.use('com.google.gson.Gson').fromJson.overload('java.lang.String', 'java.lang.Class').implementation = function(json, classOfT) {
    if (json.length < 10000) {  // Don't log huge responses
        console.log('[JSON PARSE] Class: ' + classOfT.getName());
        console.log('[JSON PARSE] Data: ' + json);
    }
    return this.fromJson(json, classOfT);
};

// 6. Database Queries (for local data)
Java.use('android.database.sqlite.SQLiteDatabase').rawQuery.implementation = function(sql, selectionArgs) {
    console.log('[SQL] Query: ' + sql);
    return this.rawQuery(sql, selectionArgs);
};

// 7. Bluetooth Low Energy (BLE) - if scooter uses BLE
Java.use('android.bluetooth.BluetoothGatt').writeCharacteristic.implementation = function(characteristic) {
    var value = characteristic.getValue();
    console.log('[BLE OUT] UUID: ' + characteristic.getUuid());
    console.log('[BLE OUT] Value: ' + hexdump(value));
    return this.writeCharacteristic(characteristic);
};

// 8. Location Services (track when GPS is accessed)
Java.use('android.location.LocationManager').getLastKnownLocation.implementation = function(provider) {
    var location = this.getLastKnownLocation(provider);
    if (location) {
        console.log('[GPS] Lat: ' + location.getLatitude() + ', Lng: ' + location.getLongitude());
    }
    return location;
};
```

---

## 🌐 LAYER 2: Network-Level Capture (MITM Proxy)

### Objective: Decrypt HTTPS/WSS traffic at network layer

#### Method 1: HTTP Toolkit (Recommended for Ease)

**Setup:**

```powershell
# 1. Install HTTP Toolkit
# Download from: https://httptoolkit.tech/

# 2. Connect phone via ADB
.\platform-tools\adb.exe devices

# 3. Enable USB Debugging on Xiaomi Redmi 9C
# Settings → About Phone → Tap "MIUI Version" 7 times
# Settings → Additional Settings → Developer Options → USB Debugging

# 4. Launch HTTP Toolkit
# Click "Android Device via ADB"
# Phone will auto-configure proxy

# 5. Open MaynDrive app
# All traffic appears in HTTP Toolkit!

# 6. Export HAR file
# File → Export → Save as mayndrive_traffic.har
```

**Bypassing Certificate Pinning:**

If app uses cert pinning, use Frida SSL unpinning:

```javascript
// ssl_unpinning.js
Java.perform(function() {
    // OkHttp3 Certificate Pinner bypass
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
        console.log('[SSL UNPIN] Bypassing cert pinning for: ' + hostname);
        return;
    };
    
    // Trust all certificates
    var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    
    var TrustManagerImpl = Java.registerClass({
        name: 'com.example.TrustManagerImpl',
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var TrustManagers = [TrustManagerImpl.$new()];
    var SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
    
    SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
        console.log('[SSL] Replacing TrustManagers with custom implementation');
        SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
    };
});
```

**Run both together:**

```powershell
# Terminal 1: Start Frida with SSL unpinning
frida -U -f fr.mayndrive.app -l ssl_unpinning.js --no-pause

# Terminal 2: HTTP Toolkit already running with proxy

# Now use the app - all HTTPS decrypted!
```

#### Method 2: mitmproxy (Advanced, More Control)

**Setup:**

```powershell
# 1. Install mitmproxy
pip install mitmproxy

# 2. Get computer's IP address
ipconfig
# Note your WiFi adapter IP, e.g., 192.168.1.100

# 3. Start mitmweb (web interface)
mitmweb --listen-host 0.0.0.0 --listen-port 8080 --web-port 8081

# 4. Configure phone WiFi proxy
# Phone → WiFi Settings → Long press network → Modify Network
# Proxy: Manual
# Hostname: 192.168.1.100
# Port: 8080

# 5. Install mitmproxy CA certificate on phone
# Phone browser → http://mitm.it
# Download Android certificate
# Settings → Security → Install from storage

# 6. Open browser on PC
# http://localhost:8081
# All phone traffic visible!

# 7. Save flows
mitmdump -r ~/.mitmproxy/flows -w mayndrive_complete.flow
```

**Advanced mitmproxy script for auto-analysis:**

**File:** `mitmproxy_analyzer.py`

```python
"""
Mitmproxy addon to automatically analyze MaynDrive traffic
Usage: mitmproxy -s mitmproxy_analyzer.py
"""

import json
import datetime
from mitmproxy import http

class MaynDriveAnalyzer:
    def __init__(self):
        self.requests = []
        self.admin_endpoints = []
        self.tokens = set()
    
    def request(self, flow: http.HTTPFlow):
        """Called for each HTTP request"""
        
        # Only track MaynDrive API
        if 'knotcity.io' not in flow.request.pretty_host:
            return
        
        # Extract authorization token
        auth_header = flow.request.headers.get('Authorization', '')
        if auth_header:
            self.tokens.add(auth_header)
        
        # Log request details
        request_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'method': flow.request.method,
            'url': flow.request.pretty_url,
            'headers': dict(flow.request.headers),
            'body': flow.request.text if flow.request.text else None
        }
        
        # Detect admin endpoints
        if '/admin' in flow.request.path:
            print(f"\n🚨 ADMIN ENDPOINT: {flow.request.method} {flow.request.path}")
            self.admin_endpoints.append(request_data)
        
        # Detect unlock/lock
        if 'unlock' in flow.request.path or 'lock' in flow.request.path:
            print(f"\n🔓 VEHICLE CONTROL: {flow.request.method} {flow.request.path}")
            if flow.request.text:
                try:
                    body = json.loads(flow.request.text)
                    if 'serial' in body or 'serialNumber' in body:
                        print(f"   Vehicle: {body.get('serial', body.get('serialNumber'))}")
                except:
                    pass
        
        self.requests.append(request_data)
    
    def response(self, flow: http.HTTPFlow):
        """Called for each HTTP response"""
        
        if 'knotcity.io' not in flow.request.pretty_host:
            return
        
        # Log response
        print(f"\n← Response: {flow.response.status_code} {flow.request.path}")
        
        # Extract tokens from login response
        if '/login' in flow.request.path and flow.response.status_code == 200:
            try:
                response_data = json.loads(flow.response.text)
                if 'access_token' in response_data:
                    print(f"🔑 Access Token: {response_data['access_token'][:50]}...")
                if 'scope' in response_data:
                    print(f"   Scope: {response_data['scope']}")
            except:
                pass
    
    def done(self):
        """Called when mitmproxy shuts down"""
        
        # Save all data
        with open('mitmproxy_capture.json', 'w') as f:
            json.dump({
                'requests': self.requests,
                'admin_endpoints': self.admin_endpoints,
                'tokens': list(self.tokens)
            }, f, indent=2)
        
        print(f"\n✓ Saved {len(self.requests)} requests to mitmproxy_capture.json")
        print(f"✓ Found {len(self.admin_endpoints)} admin endpoint accesses")
        print(f"✓ Captured {len(self.tokens)} unique tokens")

addons = [MaynDriveAnalyzer()]
```

---

## 🔌 LAYER 3: Packet-Level Capture (Wireshark/tcpdump)

### Objective: Capture raw packets for protocol analysis

#### Method 1: Wireshark on Desktop (via USB Tethering)

**Setup:**

```powershell
# 1. Enable USB tethering on phone
# Settings → Connection & Sharing → USB Tethering

# 2. Install Wireshark
# Download from: https://www.wireshark.org/

# 3. Find tethering interface
# Open Wireshark → Capture → Select USB/RNDIS interface

# 4. Start capture with filter
# Capture filter: host api.knotcity.io or udp port 5684

# 5. Save capture
# File → Save As → mayndrive_packets.pcapng
```

**Wireshark Display Filters:**

```
# All MaynDrive API traffic
http.host contains "knotcity.io"

# TLS handshakes (to see SNI)
ssl.handshake.type == 1

# UDP telemetry (DTLS)
udp.port == 5684

# WebSocket frames
websocket

# Decrypt HTTPS (if you have keys)
# Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename
# Point to SSLKEYLOGFILE from Frida hook
```

#### Method 2: tcpdump on Android (Root Required)

**Setup:**

```powershell
# 1. Download tcpdump for ARM
# https://www.androidtcpdump.com/android-tcpdump/downloads

# 2. Push to device
.\platform-tools\adb.exe push tcpdump /data/local/tmp/
.\platform-tools\adb.exe shell "su -c 'chmod 755 /data/local/tmp/tcpdump'"

# 3. Start capture
.\platform-tools\adb.exe shell "su -c '/data/local/tmp/tcpdump -i wlan0 -s 0 -w /sdcard/mayndrive.pcap'"

# 4. Use the app, then stop capture (Ctrl+C)

# 5. Pull capture file
.\platform-tools\adb.exe pull /sdcard/mayndrive.pcap .

# 6. Open in Wireshark
wireshark mayndrive.pcap
```

#### Method 3: Remote Packet Capture (No Root)

**Using Wireshark with ADB:**

```powershell
# 1. Create named pipe (Windows PowerShell)
# Install: https://nmap.org/ncat/

# 2. Start ADB tcpdump forwarding
.\platform-tools\adb.exe shell "tcpdump -i wlan0 -s 0 -w - 'host api.knotcity.io'" | wireshark -k -S -i -

# Wireshark will open and show live packets!
```

---

## 🧪 LAYER 4: Protocol Analysis & Decryption

### TLS/DTLS Decryption

#### Extract SSL Session Keys from Frida

**File:** `ssl_keylogger.js`

```javascript
/**
 * SSL Key Logger for Wireshark
 * Logs TLS session keys to file for later decryption
 */

var keylogFile = new File('/sdcard/sslkeylog.txt', 'a');

Java.perform(function() {
    // Hook SSLEngine to capture session keys
    var SSLEngine = Java.use('javax.net.ssl.SSLEngine');
    
    SSLEngine.getSession.implementation = function() {
        var session = this.getSession();
        
        try {
            var sessionId = session.getId();
            var masterSecret = session.getAttribute('MasterSecret');
            
            if (masterSecret) {
                // Format: CLIENT_RANDOM <client_random> <master_secret>
                var keylog = 'CLIENT_RANDOM ' + bytesToHex(sessionId) + ' ' + bytesToHex(masterSecret);
                keylogFile.write(keylog + '\n');
                keylogFile.flush();
            }
        } catch (e) {
            console.log('[-] Error extracting session key: ' + e);
        }
        
        return session;
    };
});

function bytesToHex(bytes) {
    var hex = '';
    for (var i = 0; i < bytes.length; i++) {
        hex += ('0' + (bytes[i] & 0xFF).toString(16)).slice(-2);
    }
    return hex;
}
```

**Use in Wireshark:**

1. Run Frida script: `frida -U -f fr.mayndrive.app -l ssl_keylogger.js`
2. Pull keylog: `adb pull /sdcard/sslkeylog.txt`
3. Wireshark → Edit → Preferences → Protocols → TLS
4. Set "(Pre)-Master-Secret log filename" to `sslkeylog.txt`
5. Reload capture → HTTPS decrypted!

### UDP/DTLS Analysis

**Extract and analyze DTLS:**

```python
# dtls_analyzer.py
"""
Analyze DTLS packets from Wireshark export
"""

import struct
from scapy.all import *

def analyze_dtls_packet(packet):
    """Parse DTLS record layer"""
    
    # DTLS record format:
    # Content Type (1 byte)
    # Version (2 bytes)
    # Epoch (2 bytes)
    # Sequence Number (6 bytes)
    # Length (2 bytes)
    # Data (variable)
    
    if len(packet) < 13:
        return None
    
    content_type = packet[0]
    version = struct.unpack('!H', packet[1:3])[0]
    epoch = struct.unpack('!H', packet[3:5])[0]
    seq_num = struct.unpack('!Q', b'\x00\x00' + packet[5:11])[0]
    length = struct.unpack('!H', packet[11:13])[0]
    data = packet[13:13+length]
    
    content_types = {
        20: 'ChangeCipherSpec',
        21: 'Alert',
        22: 'Handshake',
        23: 'Application Data'
    }
    
    return {
        'content_type': content_types.get(content_type, f'Unknown ({content_type})'),
        'version': f'DTLS 1.{version & 0xFF}',
        'epoch': epoch,
        'sequence': seq_num,
        'length': length,
        'data_hex': data.hex()
    }

# Load pcap
packets = rdpcap('mayndrive.pcap')

for pkt in packets:
    if pkt.haslayer(UDP) and pkt[UDP].dport == 5684:
        dtls_data = bytes(pkt[UDP].payload)
        result = analyze_dtls_packet(dtls_data)
        if result:
            print(f"\n[DTLS] {result['content_type']}")
            print(f"  Version: {result['version']}, Epoch: {result['epoch']}")
            print(f"  Sequence: {result['sequence']}, Length: {result['length']}")
            if result['content_type'] == 'Application Data':
                print(f"  Data (encrypted): {result['data_hex'][:128]}...")
```

---

## 🔗 LAYER 5: Traffic Correlation & Timeline

### Objective: Correlate all capture layers into unified timeline

**File:** `traffic_correlator.py`

```python
"""
Correlate traffic from multiple capture sources
- Frida hooks (JSON)
- HTTP Toolkit (HAR)
- mitmproxy (flows)
- Wireshark (PCAP)
"""

import json
import datetime
from collections import defaultdict

class TrafficCorrelator:
    def __init__(self):
        self.timeline = []
        self.events_by_type = defaultdict(list)
    
    def load_frida_capture(self, json_file):
        """Load Frida JSON capture"""
        with open(json_file) as f:
            data = json.load(f)
        
        for event in data:
            self.timeline.append({
                'timestamp': event['timestamp'],
                'source': 'frida',
                'type': event['type'],
                'data': event
            })
    
    def load_har_file(self, har_file):
        """Load HTTP Toolkit HAR export"""
        with open(har_file) as f:
            har = json.load(f)
        
        for entry in har['log']['entries']:
            request = entry['request']
            response = entry['response']
            
            self.timeline.append({
                'timestamp': entry['startedDateTime'],
                'source': 'http_toolkit',
                'type': 'http_request',
                'data': {
                    'method': request['method'],
                    'url': request['url'],
                    'status': response['status'],
                    'request_headers': request['headers'],
                    'response_headers': response['headers']
                }
            })
    
    def load_mitmproxy_flows(self, flow_file):
        """Load mitmproxy JSON flows"""
        with open(flow_file) as f:
            flows = json.load(f)
        
        for flow in flows['requests']:
            self.timeline.append({
                'timestamp': flow['timestamp'],
                'source': 'mitmproxy',
                'type': 'http_request',
                'data': flow
            })
    
    def analyze_timeline(self):
        """Analyze correlated timeline"""
        
        # Sort by timestamp
        self.timeline.sort(key=lambda x: x['timestamp'])
        
        # Group events
        for event in self.timeline:
            self.events_by_type[event['type']].append(event)
        
        # Find patterns
        print("\n=== TRAFFIC TIMELINE ANALYSIS ===\n")
        
        # 1. Unlock sequence
        print("🔓 UNLOCK SEQUENCES:")
        unlock_events = [e for e in self.timeline if 'unlock' in e.get('type', '').lower()]
        for event in unlock_events:
            print(f"  [{event['timestamp']}] {event['source']}: {event['type']}")
        
        # 2. Admin endpoint access
        print("\n🚨 ADMIN ENDPOINT ACCESS:")
        admin_events = [e for e in self.timeline if 'admin' in str(e.get('data', ''))]
        for event in admin_events:
            print(f"  [{event['timestamp']}] {event['source']}: {event['data'].get('url', 'N/A')}")
        
        # 3. Token generation
        print("\n🔑 TOKEN EVENTS:")
        token_events = [e for e in self.timeline if 'token' in str(e.get('data', '')).lower()]
        for event in token_events[:5]:  # Show first 5
            print(f"  [{event['timestamp']}] {event['source']}")
        
        # 4. UDP telemetry
        print("\n📡 UDP TELEMETRY:")
        udp_events = [e for e in self.timeline if e.get('type') in ['udp_sendto', 'udp_recvfrom']]
        print(f"  Total UDP packets: {len(udp_events)}")
        
        return self.timeline
    
    def export_timeline(self, output_file='correlated_timeline.json'):
        """Export complete timeline"""
        with open(output_file, 'w') as f:
            json.dump(self.timeline, f, indent=2, default=str)
        print(f"\n✓ Timeline exported to {output_file}")

# Usage
correlator = TrafficCorrelator()
correlator.load_frida_capture('CAPTURED_API.json')
# correlator.load_har_file('mayndrive_traffic.har')
# correlator.load_mitmproxy_flows('mitmproxy_capture.json')
correlator.analyze_timeline()
correlator.export_timeline()
```

---

## 📋 COMPLETE CAPTURE WORKFLOW

### The Ultimate Traffic Capture Session

**Pre-requisites:**

```powershell
# Install all tools
pip install frida frida-tools mitmproxy requests scapy
# Download: HTTP Toolkit, Wireshark, ADB

# Verify phone connection
.\platform-tools\adb.exe devices

# Check Frida server is running
.\platform-tools\adb.exe shell "su -c 'ps | grep frida'"
```

**Step-by-Step Capture:**

```powershell
# =====================================
# TERMINAL 1: Frida Application Hooks
# =====================================
cd C:\Users\abesn\OneDrive\Bureau\analyse

# Start enhanced Frida capture
python capture.py

# Keep this running during entire test session


# =====================================
# TERMINAL 2: mitmproxy HTTPS Intercept
# =====================================

# Start mitmproxy with analyzer
mitmproxy -s mitmproxy_analyzer.py --listen-host 0.0.0.0 --listen-port 8080

# Configure phone WiFi proxy to PC IP:8080
# Browser on PC: http://localhost:8081


# =====================================
# TERMINAL 3: Wireshark Packet Capture
# =====================================

# Start Wireshark capture on tethering interface
# Or use tcpdump forwarding:
.\platform-tools\adb.exe shell "su -c 'tcpdump -i wlan0 -s 0 -w - host api.knotcity.io'" | wireshark -k -S -i -


# =====================================
# TERMINAL 4: SSL Key Logging
# =====================================

# Run SSL keylogger (separate Frida session)
frida -U fr.mayndrive.app -l ssl_keylogger.js

# This will create /sdcard/sslkeylog.txt


# =====================================
# PHONE: Test Actions
# =====================================

# 1. Launch app (via Frida spawn - don't open manually!)
# 2. Login to account
# 3. View scooter map
# 4. Select scooter TUF061
# 5. Press UNLOCK button
# 6. Wait 10 seconds
# 7. Press LOCK button
# 8. View ride history
# 9. Check wallet/payment
# 10. Logout


# =====================================
# POST-CAPTURE: Data Collection
# =====================================

# Stop all captures (Ctrl+C in each terminal)

# Pull SSL keys
.\platform-tools\adb.exe pull /sdcard/sslkeylog.txt

# Collect all output files:
# - CAPTURED_API.txt (Frida output)
# - CAPTURED_API.json (Frida JSON)
# - mitmproxy_capture.json (mitmproxy analyzer)
# - ~/.mitmproxy/flows (mitmproxy raw)
# - mayndrive_packets.pcapng (Wireshark)
# - sslkeylog.txt (SSL keys)


# =====================================
# ANALYSIS: Correlate All Data
# =====================================

# Run correlation script
python traffic_correlator.py

# Output: correlated_timeline.json


# =====================================
# DECRYPT: HTTPS in Wireshark
# =====================================

# 1. Open Wireshark
# 2. File → Open → mayndrive_packets.pcapng
# 3. Edit → Preferences → Protocols → TLS
# 4. Set "(Pre)-Master-Secret log filename" → sslkeylog.txt
# 5. Click OK
# 6. HTTPS packets now show decrypted HTTP!


# =====================================
# EXPORT: Final Analysis
# =====================================

# Export decrypted HTTP from Wireshark
# File → Export Objects → HTTP → Save All

# Create final report
python generate_traffic_report.py
```

---

## 🎨 LAYER 6: Visual Analysis Tools

### Traffic Flow Visualization

**File:** `visualize_traffic.py`

```python
"""
Generate visual timeline of all traffic
"""

import json
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from datetime import datetime
import numpy as np

def visualize_traffic(timeline_file='correlated_timeline.json'):
    """Create visual timeline of traffic"""
    
    with open(timeline_file) as f:
        timeline = json.load(f)
    
    # Parse timestamps
    events = []
    for event in timeline:
        try:
            ts = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            events.append({
                'time': ts,
                'type': event['type'],
                'source': event['source']
            })
        except:
            continue
    
    if not events:
        print("No events to visualize")
        return
    
    # Sort by time
    events.sort(key=lambda x: x['time'])
    start_time = events[0]['time']
    
    # Convert to seconds from start
    times = [(e['time'] - start_time).total_seconds() for e in events]
    
    # Create figure
    fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(15, 10))
    fig.suptitle('MaynDrive Traffic Timeline Analysis', fontsize=16)
    
    # Plot 1: All events over time
    event_types = list(set(e['type'] for e in events))
    colors = plt.cm.tab20(np.linspace(0, 1, len(event_types)))
    type_colors = dict(zip(event_types, colors))
    
    for i, event in enumerate(events):
        ax1.scatter(times[i], event['type'], c=[type_colors[event['type']]], s=100, alpha=0.6)
    
    ax1.set_xlabel('Time (seconds from start)')
    ax1.set_ylabel('Event Type')
    ax1.set_title('All Traffic Events')
    ax1.grid(True, alpha=0.3)
    
    # Plot 2: Events by source
    sources = list(set(e['source'] for e in events))
    source_counts = {s: sum(1 for e in events if e['source'] == s) for s in sources}
    
    ax2.bar(source_counts.keys(), source_counts.values())
    ax2.set_xlabel('Source')
    ax2.set_ylabel('Event Count')
    ax2.set_title('Events by Capture Source')
    ax2.grid(True, alpha=0.3)
    
    # Plot 3: Traffic intensity over time
    # Bin events into 1-second intervals
    max_time = max(times)
    bins = np.arange(0, max_time + 1, 1)
    hist, _ = np.histogram(times, bins=bins)
    
    ax3.plot(bins[:-1], hist, linewidth=2)
    ax3.fill_between(bins[:-1], hist, alpha=0.3)
    ax3.set_xlabel('Time (seconds)')
    ax3.set_ylabel('Events per second')
    ax3.set_title('Traffic Intensity')
    ax3.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('traffic_visualization.png', dpi=300)
    print("✓ Visualization saved to traffic_visualization.png")
    plt.show()

if __name__ == '__main__':
    visualize_traffic()
```

---

## 🔍 LAYER 7: Deep Protocol Reverse Engineering

### Analyzing Unknown Binary Protocols

If UDP telemetry uses custom binary protocol:

**File:** `protocol_analyzer.py`

```python
"""
Reverse engineer binary protocol structure
"""

import struct
from collections import Counter

class ProtocolAnalyzer:
    def __init__(self, pcap_file):
        self.packets = self.load_pcap(pcap_file)
        self.patterns = {}
    
    def load_pcap(self, filename):
        """Load UDP packets from pcap"""
        from scapy.all import rdpcap, UDP
        
        packets = []
        pcap = rdpcap(filename)
        
        for pkt in pcap:
            if pkt.haslayer(UDP) and pkt[UDP].dport == 5684:
                data = bytes(pkt[UDP].payload)
                packets.append({
                    'timestamp': float(pkt.time),
                    'data': data,
                    'length': len(data)
                })
        
        return packets
    
    def find_magic_bytes(self):
        """Find common magic bytes at start of packets"""
        
        if not self.packets:
            return
        
        # Check first 8 bytes of each packet
        first_bytes = [p['data'][:8] for p in self.packets if len(p['data']) >= 8]
        
        # Find most common prefixes
        prefix_counts = Counter(first_bytes)
        
        print("\n=== MAGIC BYTES ANALYSIS ===")
        print(f"Total packets: {len(self.packets)}")
        print(f"\nMost common packet headers:")
        
        for prefix, count in prefix_counts.most_common(5):
            print(f"  {prefix.hex()}: {count} packets ({count/len(first_bytes)*100:.1f}%)")
        
        return prefix_counts
    
    def analyze_structure(self):
        """Attempt to identify packet structure"""
        
        print("\n=== PACKET STRUCTURE ANALYSIS ===")
        
        # Length distribution
        lengths = [p['length'] for p in self.packets]
        length_counts = Counter(lengths)
        
        print(f"\nPacket length distribution:")
        for length, count in sorted(length_counts.items())[:10]:
            print(f"  {length} bytes: {count} packets")
        
        # Try to identify fixed header size
        if len(set(lengths)) > 1:
            print(f"\n⚠️ Variable-length packets detected")
            print(f"   Min: {min(lengths)}, Max: {max(lengths)}, Avg: {sum(lengths)/len(lengths):.1f}")
        else:
            print(f"\n✓ Fixed packet size: {lengths[0]} bytes")
        
        # Entropy analysis (identify encrypted regions)
        self.entropy_analysis()
    
    def entropy_analysis(self):
        """Calculate Shannon entropy to identify encrypted data"""
        import math
        
        print("\n=== ENTROPY ANALYSIS ===")
        
        for i, packet in enumerate(self.packets[:5]):  # First 5 packets
            data = packet['data']
            
            # Calculate byte frequency
            byte_counts = Counter(data)
            entropy = 0
            
            for count in byte_counts.values():
                p = count / len(data)
                entropy -= p * math.log2(p)
            
            status = "🔒 ENCRYPTED" if entropy > 7.5 else "📝 PLAINTEXT/COMPRESSED"
            print(f"Packet {i}: Length={len(data)}, Entropy={entropy:.2f} {status}")
    
    def pattern_matching(self):
        """Find repeated patterns across packets"""
        
        print("\n=== PATTERN MATCHING ===")
        
        # Look for common 4-byte sequences
        sequences = []
        for packet in self.packets:
            data = packet['data']
            for i in range(len(data) - 3):
                seq = data[i:i+4]
                sequences.append(seq)
        
        seq_counts = Counter(sequences)
        
        print("Most common 4-byte sequences:")
        for seq, count in seq_counts.most_common(10):
            if count > 2:  # Only show if appears multiple times
                print(f"  {seq.hex()}: {count} occurrences")

# Usage
analyzer = ProtocolAnalyzer('mayndrive.pcap')
analyzer.find_magic_bytes()
analyzer.analyze_structure()
analyzer.pattern_matching()
```

---

## 🛠️ AUXILIARY TOOLS

### 1. Automated Test Script

**File:** `automated_traffic_test.py`

```python
"""
Automated testing sequence with traffic capture
"""

import subprocess
import time
import os

class AutomatedTester:
    def __init__(self):
        self.adb = r'.\platform-tools\adb.exe'
        self.package = 'fr.mayndrive.app'
    
    def setup(self):
        """Prepare environment"""
        print("[*] Setting up test environment...")
        
        # Force stop app
        subprocess.run([self.adb, 'shell', 'am', 'force-stop', self.package])
        time.sleep(2)
    
    def start_captures(self):
        """Start all capture tools"""
        print("[*] Starting capture tools...")
        
        # Start Frida
        self.frida_proc = subprocess.Popen(['python', 'capture.py'])
        time.sleep(5)  # Wait for Frida to attach
        
        return self.frida_proc
    
    def perform_actions(self):
        """Automate UI actions"""
        print("[*] Performing automated actions...")
        
        actions = [
            # Wait for app to load
            ('sleep', 5),
            
            # Click login button (coords may vary by device)
            ('tap', (540, 1600)),
            ('sleep', 2),
            
            # Enter email (use your test credentials)
            ('text', 'test@example.com'),
            ('sleep', 1),
            
            # Tap password field
            ('tap', (540, 1800)),
            ('text', 'password123'),
            
            # Tap login
            ('tap', (540, 2000)),
            ('sleep', 5),
            
            # Wait for map to load
            ('sleep', 5),
            
            # Select scooter (tap on map)
            ('tap', (540, 1200)),
            ('sleep', 2),
            
            # Tap unlock button
            ('tap', (540, 1900)),
            ('sleep', 3),
            
            # Tap lock button
            ('tap', (540, 1900)),
            ('sleep', 3),
        ]
        
        for action_type, value in actions:
            if action_type == 'sleep':
                time.sleep(value)
            elif action_type == 'tap':
                x, y = value
                subprocess.run([self.adb, 'shell', 'input', 'tap', str(x), str(y)])
            elif action_type == 'text':
                subprocess.run([self.adb, 'shell', 'input', 'text', value])
    
    def stop_captures(self, frida_proc):
        """Stop all captures"""
        print("[*] Stopping captures...")
        
        # Stop Frida (Ctrl+C)
        frida_proc.terminate()
        frida_proc.wait()
    
    def run(self):
        """Run complete test sequence"""
        self.setup()
        frida_proc = self.start_captures()
        
        try:
            self.perform_actions()
        finally:
            self.stop_captures(frida_proc)
        
        print("[+] Test complete! Check output files:")
        print("    - CAPTURED_API.txt")
        print("    - CAPTURED_API.json")

if __name__ == '__main__':
    tester = AutomatedTester()
    tester.run()
```

### 2. Report Generator

**File:** `generate_traffic_report.py`

```python
"""
Generate comprehensive traffic analysis report
"""

import json
from datetime import datetime
import os

def generate_report():
    """Generate markdown report from all capture data"""
    
    report = f"""# MaynDrive Traffic Analysis Report

**Generated:** {datetime.now().isoformat()}
**Workspace:** C:\\Users\\abesn\\OneDrive\\Bureau\\analyse

---

## Executive Summary

"""
    
    # Load Frida data
    if os.path.exists('CAPTURED_API.json'):
        with open('CAPTURED_API.json') as f:
            frida_data = json.load(f)
        
        report += f"### Frida Application Hooks\n\n"
        report += f"- Total events captured: {len(frida_data)}\n"
        
        # Count by type
        event_types = {}
        for event in frida_data:
            event_type = event.get('type', 'unknown')
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        report += f"\n**Events by type:**\n\n"
        for event_type, count in sorted(event_types.items()):
            report += f"- {event_type}: {count}\n"
        
        # Extract key information
        unlock_events = [e for e in frida_data if 'unlock' in e.get('type', '')]
        lock_events = [e for e in frida_data if 'lock' in e.get('type', '')]
        
        report += f"\n**Vehicle control events:**\n\n"
        report += f"- Unlock operations: {len(unlock_events)}\n"
        report += f"- Lock operations: {len(lock_events)}\n"
        
        # Extract tokens
        tokens = set()
        for event in frida_data:
            if 'authorization' in event and event['authorization']:
                tokens.add(event['authorization'][:50])  # First 50 chars
        
        report += f"\n**Authentication:**\n\n"
        report += f"- Unique tokens captured: {len(tokens)}\n"
        
        if tokens:
            report += f"\n**Sample token:**\n```\n{list(tokens)[0]}...\n```\n"
    
    # Add protocol analysis
    report += f"\n---\n\n## Protocol Analysis\n\n"
    report += f"### Communication Layers\n\n"
    report += f"1. **HTTPS API** - Control plane (lock/unlock commands)\n"
    report += f"   - Base URL: https://api.knotcity.io\n"
    report += f"   - Authentication: Bearer token\n\n"
    report += f"2. **WebSocket/Socket.io** - Real-time notifications\n"
    report += f"   - Event-based messaging\n\n"
    report += f"3. **UDP/DTLS** - Telemetry data\n"
    report += f"   - Port: 5684\n"
    report += f"   - Encrypted with TLS 1.2\n\n"
    
    # Add API endpoints discovered
    report += f"### API Endpoints\n\n"
    report += f"#### User Endpoints\n\n"
    report += f"- `POST /api/application/vehicles/unlock`\n"
    report += f"- `POST /api/application/vehicles/freefloat/lock`\n\n"
    report += f"#### Admin Endpoints ⚠️\n\n"
    report += f"- `POST /api/application/vehicles/unlock/admin`\n"
    report += f"- `POST /api/application/vehicles/freefloat/lock/admin`\n"
    report += f"- `POST /api/application/vehicles/freefloat/identify/admin`\n"
    report += f"- `GET /api/application/vehicles/sn/{{serial}}/admin`\n\n"
    
    # Security findings
    report += f"---\n\n## Security Findings\n\n"
    report += f"### Critical Vulnerabilities\n\n"
    report += f"1. **Client-Controlled Scope Escalation**\n"
    report += f"   - Severity: CRITICAL\n"
    report += f"   - Users can request admin scope during login\n\n"
    report += f"2. **Weak Authorization**\n"
    report += f"   - Severity: HIGH\n"
    report += f"   - Admin endpoints may not verify actual admin role\n\n"
    report += f"3. **No Rate Limiting**\n"
    report += f"   - Severity: HIGH\n"
    report += f"   - Bulk operations possible\n\n"
    
    # Save report
    with open('TRAFFIC_ANALYSIS_REPORT.md', 'w') as f:
        f.write(report)
    
    print("✓ Report generated: TRAFFIC_ANALYSIS_REPORT.md")
    return report

if __name__ == '__main__':
    generate_report()
```

---

## 📊 SUCCESS METRICS

After completing this plan, you should have:

### ✅ Complete Data Collection

- [ ] Frida application hooks (coroutines, HTTP, cipher, native)
- [ ] HTTPS decrypted traffic (via mitmproxy or HTTP Toolkit)
- [ ] Raw packet capture (Wireshark/tcpdump)
- [ ] SSL session keys for decryption
- [ ] Correlated timeline of all events
- [ ] Visual traffic analysis
- [ ] Protocol structure documentation

### ✅ Full API Documentation

- [ ] All endpoints mapped (user + admin)
- [ ] Request/response formats documented
- [ ] Authentication flow understood
- [ ] Admin vulnerabilities confirmed
- [ ] Rate limiting tested
- [ ] Token structure analyzed

### ✅ Protocol Understanding

- [ ] HTTP REST API fully documented
- [ ] Socket.io events cataloged
- [ ] UDP/DTLS telemetry analyzed
- [ ] Bluetooth (if used) mapped
- [ ] Binary protocols reverse engineered

### ✅ Security Analysis

- [ ] Scope escalation vulnerability confirmed
- [ ] Admin endpoint authorization tested
- [ ] Token tampering attempted
- [ ] Device fingerprinting bypassed
- [ ] MFA requirements documented
- [ ] Complete security report generated

---

## 🎓 CONCLUSION

This master plan provides **7 layers of traffic visibility**:

1. **Application Layer** - Frida hooks at Java/native level
2. **Network Layer** - MITM proxy for HTTPS decryption
3. **Packet Layer** - Raw packet capture with Wireshark
4. **Protocol Layer** - TLS/DTLS analysis and decryption
5. **Correlation Layer** - Unified timeline of all events
6. **Visualization Layer** - Graphical traffic analysis
7. **Reverse Engineering Layer** - Binary protocol analysis

### Recommended Workflow

**For Quick Testing:**
- Use `capture.py` with Frida (Layer 1 only)
- Fastest, easiest, captures most important data

**For Complete Analysis:**
- Run all layers simultaneously
- Correlate data with `traffic_correlator.py`
- Generate visual report
- Document findings

**For Protocol Research:**
- Focus on packet capture + SSL key extraction
- Analyze in Wireshark with decryption
- Use protocol analyzer tools
- Reverse engineer binary formats

### Time Estimates

- **Quick capture** (Layer 1 only): 15-30 minutes
- **Complete capture** (Layers 1-3): 1-2 hours
- **Full analysis** (All layers): 4-8 hours
- **Protocol reverse engineering**: 8-24 hours

---

**Document Version:** 2.0  
**Last Updated:** October 2, 2025  
**Status:** COMPREHENSIVE - READY FOR EXECUTION


