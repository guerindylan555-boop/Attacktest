#!/usr/bin/env python3
"""
Capture New Account Token and Test Cross-Account Access
Uses the exact same approach as the working scripts
"""

import frida
import sys
import json
import time
import subprocess
from datetime import datetime

PACKAGE_NAME = "fr.mayndrive.app"
SCRIPT_FILE = "capture_WORKING_FINAL.js"
OUTPUT_FILE = "CAPTURED_NEW_ACCOUNT.txt"
OUTPUT_JSON = "CAPTURED_NEW_ACCOUNT.json"

captured_data = []

def append_record(record):
    captured_data.append(record)
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as jf:
        json.dump(captured_data, jf, indent=2, ensure_ascii=False)

def write_block(title, lines):
    with open(OUTPUT_FILE, 'a', encoding='utf-8') as f:
        separator = '=' * 100
        f.write(f"\n{separator}\n")
        f.write(f"{title}\n")
        f.write(f"{separator}\n")
        for line in lines:
            f.write(f"{line}\n")
        f.write(f"{separator}\n")

def find_adb():
    """Find adb executable like the working scripts"""
    import os
    
    # First check if ADB_PATH environment variable is set (from batch script)
    adb_path = os.environ.get('ADB_PATH')
    if adb_path and os.path.exists(adb_path):
        print(f"[DEBUG] Using ADB from environment: {adb_path}")
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
    
    # Find ADB path
    adb_path = find_adb()
    if not adb_path:
        print("[-] adb not found in PATH. Please restart frida-server manually.")
        return False
    
    print(f"[DEBUG] Using ADB: {adb_path}")
    
    commands = [
        [adb_path, "shell", "su", "-c", "pkill frida-server"],
        [adb_path, "shell", "su", "-c", "/data/local/tmp/frida-server >/dev/null 2>&1 &"]
    ]
    for cmd in commands:
        try:
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        except FileNotFoundError:
            print("[-] adb not found in PATH. Please restart frida-server manually.")
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
        
        # Save structured data for tokens
        if 'authorization' in payload.lower() or 'bearer' in payload.lower():
            record = {
                'timestamp': timestamp,
                'type': 'token_capture',
                'data': payload
            }
            append_record(record)
            
            # Extract the Bearer token from the payload
            import re
            bearer_pattern = r'Bearer eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            token_match = re.search(bearer_pattern, payload)
            
            if token_match:
                token = token_match.group(0)
                # Save the latest token to a separate file for easy access
                with open('LATEST_TOKEN.txt', 'w', encoding='utf-8') as f:
                    f.write(token)
                print(f"[SAVED] Latest token saved to LATEST_TOKEN.txt")
                print(f"[TOKEN] {token[:50]}...")
            else:
                print(f"[WARNING] Could not extract Bearer token from payload")

def main():
    print("=" * 80)
    print("🔍 NEW ACCOUNT TOKEN CAPTURE & CROSS-ACCOUNT TEST")
    print("=" * 80)
    print("⚠️  WARNING: This will test cross-account access!")
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
        
        session = device.attach(pid)
        
        # Create script
        script = session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        
        # Resume app
        device.resume(pid)
        print(f"[+] App launched! PID: {pid}")
        
        print("\n" + "=" * 80)
        print("🎯 INSTRUCTIONS FOR NEW ACCOUNT TEST")
        print("=" * 80)
        print("1. Log in with your NEW account in the spawned app")
        print("2. Navigate to a scooter (any scooter)")
        print("3. Press UNLOCK or LOCK")
        print("4. Watch for [COROUTINE] messages with Bearer tokens")
        print("5. Press Ctrl+C when you've captured the token")
        print("=" * 80)
        print("Waiting for new account token capture...")
        
        # Keep running
        sys.stdin.read()
        
    except KeyboardInterrupt:
        print("\n[+] Capture stopped")
        print(f"[+] New account data saved to:")
        print(f"   - {OUTPUT_FILE}")
        print(f"   - {OUTPUT_JSON}")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()