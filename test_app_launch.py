#!/usr/bin/env python3
"""Test script to verify MaynDrive app launches correctly."""

import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from automation.scripts import run_hooks

def test_app_detection():
    """Test if we can detect if the app is running."""
    print("=" * 60)
    print("TEST 1: App Detection")
    print("=" * 60)
    
    is_running = run_hooks.is_app_running()
    print(f"App running status: {is_running}")
    print()
    return is_running

def test_app_launch():
    """Test if we can launch the app."""
    print("=" * 60)
    print("TEST 2: App Launch")
    print("=" * 60)
    
    # First, check if already running
    if run_hooks.is_app_running():
        print("[INFO] App is already running, stopping it first...")
        import subprocess
        subprocess.run(
            ["adb", "shell", "am", "force-stop", run_hooks.PACKAGE_NAME],
            capture_output=True
        )
        import time
        time.sleep(2)
    
    print("[INFO] Attempting to launch app...")
    success = run_hooks.launch_app()
    print(f"Launch result: {'SUCCESS' if success else 'FAILED'}")
    
    if success:
        print("[INFO] Verifying app is running...")
        is_running = run_hooks.is_app_running()
        print(f"App running after launch: {is_running}")
        return is_running
    return False

def test_frida_attach():
    """Test if Frida can attach to the app."""
    print("=" * 60)
    print("TEST 3: Frida Attach")
    print("=" * 60)
    
    try:
        print("[INFO] Starting Frida in attach mode with auto-launch...")
        proc, log_file = run_hooks.run_frida(attach_mode=True, auto_launch=True)
        
        # Wait a moment to see if Frida stays running
        import time
        time.sleep(5)
        
        if proc.poll() is None:
            print(f"[SUCCESS] Frida is running (PID: {proc.pid})")
            print(f"[INFO] Log file: {log_file}")
            print("[INFO] Terminating Frida process...")
            proc.terminate()
            proc.wait(timeout=5)
            return True
        else:
            print(f"[ERROR] Frida exited immediately (return code: {proc.returncode})")
            print(f"[INFO] Check log file: {log_file}")
            # Read last few lines of log
            try:
                with open(log_file, 'r') as f:
                    lines = f.readlines()
                    print("[LOG] Last 10 lines:")
                    for line in lines[-10:]:
                        print(f"  {line.rstrip()}")
            except Exception as e:
                print(f"[ERROR] Could not read log: {e}")
            return False
    except Exception as e:
        print(f"[ERROR] Failed to start Frida: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("MaynDrive App Launch Test Suite")
    print("=" * 60 + "\n")
    
    results = {}
    
    # Test 1: Detection
    try:
        results['detection'] = test_app_detection()
    except Exception as e:
        print(f"[ERROR] Detection test failed: {e}")
        results['detection'] = False
    
    # Test 2: Launch
    try:
        results['launch'] = test_app_launch()
    except Exception as e:
        print(f"[ERROR] Launch test failed: {e}")
        results['launch'] = False
    
    # Test 3: Frida attach
    try:
        results['frida'] = test_frida_attach()
    except Exception as e:
        print(f"[ERROR] Frida test failed: {e}")
        results['frida'] = False
    
    # Summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    for test_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{test_name.upper()}: {status}")
    
    all_passed = all(results.values())
    print("=" * 60)
    if all_passed:
        print("All tests PASSED! ✓")
        return 0
    else:
        print("Some tests FAILED! ✗")
        return 1

if __name__ == "__main__":
    sys.exit(main())

