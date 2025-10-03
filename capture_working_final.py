#!/usr/bin/env python3
"""
Working Final Capture Script
Uses the discovered coroutine classes for unlock/lock operations
"""

import frida
import sys
import json
import time
import subprocess
from datetime import datetime

PACKAGE_NAME = "fr.mayndrive.app"
SCRIPT_FILE = "capture_WORKING_FINAL.js"
OUTPUT_FILE = "CAPTURED_WORKING_FINAL.txt"
OUTPUT_JSON = "CAPTURED_WORKING_FINAL.json"

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
    if message['type'] != 'send':
        if message['type'] == 'error':
            print(f"[ERROR] {message.get('description', message)}")
        return
    
    payload = message['payload']
    timestamp = datetime.now().isoformat()
    
    if payload.get('type') == 'unlock_request':
        print(f"\n[UNLOCK] {timestamp}")
        print(f"  Token: {payload.get('authorization', 'N/A')[:60]}...")
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
        
    elif payload.get('type') == 'lock_request':
        print(f"\n[LOCK] {timestamp}")
        print(f"  Token: {payload.get('authorization', 'N/A')[:60]}...")
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
        
    elif payload.get('type') == 'telemetry_data':
        print(f"\n[TELEMETRY] {timestamp}")
        print(f"  Data: {payload.get('data', 'N/A')}")
        
        # Save to file
        lines = [f"Data: {payload.get('data', 'N/A')}"]
        write_block(f"[{timestamp}] TELEMETRY DATA", lines)
        
        # Save to JSON
        append_record(payload)

def main():
    print("=" * 100)
    print("WORKING FINAL CAPTURE - Using Discovered Coroutine Classes")
    print("=" * 100)
    print("This script captures unlock/lock requests using the real coroutine classes")
    print("discovered through automatic analysis.")
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
        print("READY TO CAPTURE!")
        print("=" * 100)
        print("Instructions:")
        print("1. Use the spawned app instance (don't switch apps)")
        print("2. Login to your account")
        print("3. Find a scooter")
        print("4. Press UNLOCK - watch for [UNLOCK] messages")
        print("5. Press LOCK - watch for [LOCK] messages")
        print("6. Press Ctrl+C when done")
        print("=" * 100)
        
        # Keep running
        sys.stdin.read()
        
    except KeyboardInterrupt:
        print("\n[OK] Capture stopped")
    except Exception as e:
        print(f"\n[ERROR] {e}")
    finally:
        if 'session' in locals():
            session.detach()
        print(f"\nText log: {OUTPUT_FILE}")
        print(f"JSON export: {OUTPUT_JSON}")
        print(f"Items captured: {len(captured_data)}")

if __name__ == "__main__":
    main()