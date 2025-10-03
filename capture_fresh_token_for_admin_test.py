#!/usr/bin/env python3
"""
Fresh Token Capture for Admin Test
Captures a fresh token specifically for admin unlock testing
"""

import frida
import sys
import json
import time
import subprocess
import os
import re
from datetime import datetime

PACKAGE_NAME = "fr.mayndrive.app"
SCRIPT_FILE = "capture_WORKING_FINAL.js"
OUTPUT_FILE = "CAPTURED_FRESH_TOKEN.txt"
OUTPUT_JSON = "CAPTURED_FRESH_TOKEN.json"

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
    # First check if ADB_PATH environment variable is set
    adb_path = os.environ.get('ADB_PATH')
    if adb_path and os.path.exists(adb_path):
        return adb_path
    
    # Check platform-tools directory first
    if os.path.exists("platform-tools/adb.exe"):
        return "platform-tools/adb.exe"
    
    # Check if adb is in PATH
    try:
        subprocess.run(["adb", "version"], capture_output=True, check=True)
        return "adb"
    except:
        pass
    
    # Try to find in current directory
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

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        timestamp = datetime.now().isoformat()
        
        print(f"[{timestamp}] {payload}")
        
        # Save to text file
        with open(OUTPUT_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {payload}\n")
        
        # Handle different message types
        if isinstance(payload, dict):
            if payload.get('type') == 'unlock_request':
                print(f"\n[UNLOCK] {timestamp}")
                auth = payload.get('authorization', 'N/A')
                print(f"  Token: {auth[:60] if auth and auth != 'N/A' else 'N/A'}...")
                print(f"  Scooter ID: {payload.get('scooter_id', 'N/A')}")
                print(f"  Location: {payload.get('location', 'N/A')}")
                print(f"  Class: {payload.get('className', 'N/A')}")
                
                # Save to file
                lines = [
                    f"Authorization: {payload.get('authorization', 'N/A')}",
                    f"Scooter ID: {payload.get('scooter_id', 'N/A')}",
                    f"Location: {payload.get('location', 'N/A')}",
                    f"Class: {payload.get('className', 'N/A')}"
                ]
                write_block(f"[{timestamp}] UNLOCK REQUEST", lines)
                
                # Save structured data
                record = {
                    'timestamp': timestamp,
                    'type': 'unlock_request',
                    'authorization': payload.get('authorization', 'N/A'),
                    'scooter_id': payload.get('scooter_id', 'N/A'),
                    'location': payload.get('location', 'N/A'),
                    'className': payload.get('className', 'N/A')
                }
                append_record(record)
                
                # Extract and save Bearer token
                auth = payload.get('authorization', '')
                if auth and auth.startswith('Bearer '):
                    with open('LATEST_TOKEN.txt', 'w', encoding='utf-8') as f:
                        f.write(auth)
                    print(f"[SAVED] Latest token saved to LATEST_TOKEN.txt")
                    print(f"[TOKEN] {auth[:50]}...")
                
            elif payload.get('type') == 'lock_request':
                print(f"\n[LOCK] {timestamp}")
                auth = payload.get('authorization', 'N/A')
                print(f"  Token: {auth[:60] if auth and auth != 'N/A' else 'N/A'}...")
                print(f"  Pass ID: {payload.get('pass_id', 'N/A')}")
                print(f"  Class: {payload.get('className', 'N/A')}")
                
                # Save to file
                lines = [
                    f"Authorization: {payload.get('authorization', 'N/A')}",
                    f"Pass ID: {payload.get('pass_id', 'N/A')}",
                    f"Class: {payload.get('className', 'N/A')}"
                ]
                write_block(f"[{timestamp}] LOCK REQUEST", lines)
                
                # Save structured data
                record = {
                    'timestamp': timestamp,
                    'type': 'lock_request',
                    'authorization': payload.get('authorization', 'N/A'),
                    'pass_id': payload.get('pass_id', 'N/A'),
                    'className': payload.get('className', 'N/A')
                }
                append_record(record)
                
                # Extract and save Bearer token
                auth = payload.get('authorization', '')
                if auth and auth.startswith('Bearer '):
                    with open('LATEST_TOKEN.txt', 'w', encoding='utf-8') as f:
                        f.write(auth)
                    print(f"[SAVED] Latest token saved to LATEST_TOKEN.txt")
                    print(f"[TOKEN] {auth[:50]}...")

def main():
    print("=" * 80)
    print("🔑 FRESH TOKEN CAPTURE FOR ADMIN TEST")
    print("=" * 80)
    print("⚠️  WARNING: This will capture a fresh token for admin testing!")
    print("=" * 80)
    
    # Restart Frida server
    if not restart_frida_server():
        print("[ERROR] Failed to restart Frida server")
        return
    
    try:
        device = frida.get_usb_device()
        print(f"[+] Device: {device.name}")
        
        # Load script
        with open(SCRIPT_FILE, 'r', encoding='utf-8') as f:
            script_code = f.read()
        
        # Clear output files
        open(OUTPUT_FILE, 'w').close()
        open(OUTPUT_JSON, 'w').close()
        
        # Spawn app
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
        print("🎯 INSTRUCTIONS FOR FRESH TOKEN CAPTURE")
        print("=" * 80)
        print("1. Log in with your account in the spawned app")
        print("2. Perform an UNLOCK/LOCK operation on a scooter")
        print("3. Watch for '[SAVED] Latest token saved to LATEST_TOKEN.txt'")
        print("4. Press Ctrl+C here when you have captured a fresh token")
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
        print("\n[OK] Capture session ended.")
        if 'session' in locals() and session:
            session.detach()
        print("=" * 80)

if __name__ == "__main__":
    main()
