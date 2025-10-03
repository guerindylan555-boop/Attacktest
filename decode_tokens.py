#!/usr/bin/env python3
"""
Decode JWT tokens from capture files to see user IDs
"""

import base64
import json
import re

def decode_jwt_payload(token):
    """Decode JWT payload to see user information"""
    try:
        # Remove "Bearer " prefix if present
        if token.startswith("Bearer "):
            token = token[7:]
        
        # Split JWT into parts
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        # Decode the payload (second part)
        payload = parts[1]
        # Add padding if needed
        payload += '=' * (4 - len(payload) % 4)
        
        decoded = base64.b64decode(payload).decode('utf-8')
        return json.loads(decoded)
    except Exception as e:
        print(f"Error decoding token: {e}")
        return None

def find_tokens_in_file(filename):
    """Find and decode all JWT tokens in a file"""
    print(f"\n[CHECK] Checking {filename}...")
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Find all Bearer tokens
        bearer_pattern = r'Bearer eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        tokens = re.findall(bearer_pattern, content)
        
        if not tokens:
            print(f"   No Bearer tokens found")
            return []
        
        print(f"   Found {len(tokens)} Bearer tokens")
        
        unique_tokens = list(set(tokens))  # Remove duplicates
        print(f"   {len(unique_tokens)} unique tokens")
        
        for i, token in enumerate(unique_tokens):
            print(f"\n   Token {i+1}: {token[:50]}...")
            payload = decode_jwt_payload(token)
            if payload:
                print(f"   User ID: {payload.get('user_id', 'N/A')}")
                print(f"   Session ID: {payload.get('session_id', 'N/A')}")
                print(f"   Issued At: {payload.get('iat', 'N/A')}")
                print(f"   Expires: {payload.get('exp', 'N/A')}")
            else:
                print(f"   Could not decode token")
        
        return unique_tokens
        
    except FileNotFoundError:
        print(f"   File not found")
        return []
    except Exception as e:
        print(f"   Error: {e}")
        return []

def main():
    print("[SEARCH] JWT Token Decoder - Finding User IDs")
    print("=" * 60)
    
    capture_files = [
        'CAPTURED_NEW_ACCOUNT.txt',
        'CAPTURED_WORKING_FINAL.txt', 
        'CAPTURED_API_DECRYPT.txt',
        'CAPTURED_API.txt'
    ]
    
    all_tokens = []
    
    for filename in capture_files:
        tokens = find_tokens_in_file(filename)
        all_tokens.extend(tokens)
    
    print(f"\n[SUMMARY] Total unique tokens found: {len(set(all_tokens))}")
    
    # Look for user 117953 specifically
    print(f"\n[TARGET] Looking for user 117953...")
    found_117953 = False
    
    for token in set(all_tokens):
        payload = decode_jwt_payload(token)
        if payload and payload.get('user_id') == 117953:
            print(f"[SUCCESS] FOUND USER 117953 TOKEN!")
            print(f"   Token: {token[:50]}...")
            print(f"   Full token: {token}")
            found_117953 = True
            break
    
    if not found_117953:
        print("[ERROR] User 117953 token not found in any capture files")
        print("   This might mean:")
        print("   - The new account capture didn't work properly")
        print("   - The token wasn't saved to the expected file")
        print("   - You need to run the capture again with the new account")

if __name__ == "__main__":
    main()
