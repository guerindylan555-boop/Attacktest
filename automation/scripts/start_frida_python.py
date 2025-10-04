#!/usr/bin/env python3
"""Python-based Frida server starter with better error handling."""

import subprocess
import sys
import time
import os

def start_frida_server(device_id="emulator-5554"):
    """Start Frida server on device using Python subprocess."""
    print(f"[INFO] Starting Frida server on device {device_id}")
    
    # Wait for device to be ready
    for i in range(10):
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "get-state"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and "device" in result.stdout:
                print("[INFO] Device is ready")
                break
        except Exception:
            pass
        print(f"[INFO] Waiting for device to be ready... ({i+1}/10)")
        time.sleep(2)
    else:
        print(f"[ERROR] Device {device_id} is not ready")
        return False
    
    # Kill any existing Frida server
    print("[INFO] Killing existing Frida server processes...")
    try:
        subprocess.run(
            ["adb", "-s", device_id, "shell", "su", "0", "pkill", "-f", "frida-server"],
            capture_output=True, timeout=5
        )
        time.sleep(1)
    except Exception:
        pass
    
    # Start Frida server using a different approach
    print("[INFO] Starting Frida server...")
    try:
        # Start Frida server in background using nohup
        result = subprocess.run(
            ["adb", "-s", device_id, "shell", "su", "0", "nohup", "/data/local/tmp/frida-server", ">/dev/null", "2>&1", "&"],
            capture_output=True, text=True, timeout=5
        )
        
        # Wait a moment for it to start
        time.sleep(3)
        
        # Check if it's running
        print("[INFO] Checking if Frida server is running...")
        result = subprocess.run(
            ["adb", "-s", device_id, "shell", "ps -A | grep frida-server"],
            capture_output=True, text=True, timeout=5
        )
        
        if result.returncode == 0 and "frida-server" in result.stdout:
            print("[SUCCESS] Frida server is running")
            return True
        else:
            print("[ERROR] Frida server failed to start")
            print(f"[DEBUG] Process check output: {result.stdout}")
            
            # Try a different approach - start with explicit background
            print("[INFO] Trying alternative startup method...")
            subprocess.run(
                ["adb", "-s", device_id, "shell", "su", "0", "sh", "-c", "'/data/local/tmp/frida-server &'"],
                capture_output=True, timeout=5
            )
            time.sleep(3)
            
            # Check again
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "ps -A | grep frida-server"],
                capture_output=True, text=True, timeout=5
            )
            
            if result.returncode == 0 and "frida-server" in result.stdout:
                print("[SUCCESS] Frida server is running (alternative method)")
                return True
            else:
                print("[ERROR] Frida server still failed to start")
                print(f"[DEBUG] Final process check: {result.stdout}")
                return False
            
    except Exception as e:
        print(f"[ERROR] Exception starting Frida server: {e}")
        return False

def main():
    device_id = sys.argv[1] if len(sys.argv) > 1 else "emulator-5554"
    success = start_frida_server(device_id)
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
