#!/usr/bin/env python3
"""
New Account Token Capture - Working Version
Inspired by the working capture_working_final.py
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

def restart_frida_server():
    print("[!] Restarting frida-server on device...")
    commands = [
        ["adb", "shell", "su", "-c", "pkill frida-server"],
        ["adb", "shell", "su", "-c", "/data/local/tmp/frida-server &"]
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
                
                # Save to JSON
                append_record(payload)
                
                # Extract and save Bearer token
                auth = payload.get('authorization', '')
                if auth.startswith('Bearer '):
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
                
                # Save to JSON
                append_record(payload)
                
                # Extract and save Bearer token
                auth = payload.get('authorization', '')
                if auth.startswith('Bearer '):
                    with open('LATEST_TOKEN.txt', 'w', encoding='utf-8') as f:
                        f.write(auth)
                    print(f"[SAVED] Latest token saved to LATEST_TOKEN.txt")
                    print(f"[TOKEN] {auth[:50]}...")
                
            elif payload.get('type') == 'telemetry_data':
                print(f"\n[TELEMETRY] {timestamp}")
                print(f"  Data: {payload.get('data', 'N/A')}")
                
                # Save to file
                lines = [f"Data: {payload.get('data', 'N/A')}"]
                write_block(f"[{timestamp}] TELEMETRY DATA", lines)
                
                # Save to JSON
                append_record(payload)
        else:
            # Handle string payloads (like raw messages)
            if 'authorization' in payload.lower() or 'bearer' in payload.lower():
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

def main():
    print("=" * 100)
    print("NEW ACCOUNT TOKEN CAPTURE - WORKING VERSION")
    print("=" * 100)
    print("This script captures tokens from your NEW account using the working method.")
    print("=" * 100)
    
    try:
        # Get device
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
        
        print("\n" + "=" * 100)
        print("🎯 INSTRUCTIONS FOR NEW ACCOUNT TEST")
        print("=" * 100)
        print("1. Log in with your NEW account in the spawned app")
        print("2. Find a scooter and UNLOCK it")
        print("3. Then LOCK it")
        print("4. Watch for [UNLOCK] and [LOCK] messages with Bearer tokens")
        print("5. Token will be automatically saved to LATEST_TOKEN.txt")
        print("6. Press Ctrl+C when done")
        print("=" * 100)
        
        # Keep script running
        sys.stdin.read()
        
    except KeyboardInterrupt:
        print("\n[+] Capture stopped by user")
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        print(f"[+] Items captured: {len(captured_data)}")
        print(f"Text log: {OUTPUT_FILE}")
        print(f"JSON export: {OUTPUT_JSON}")

if __name__ == "__main__":
    main()
