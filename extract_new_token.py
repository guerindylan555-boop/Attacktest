#!/usr/bin/env python3
"""
Extract and decode the new token from the provided data
"""

import base64
import json

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

def main():
    print("=" * 60)
    print("EXTRACTING NEW TOKEN FROM PROVIDED DATA")
    print("=" * 60)
    
    # The token from your new capture data
    new_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjox..."
    
    print(f"New token (truncated): {new_token}")
    print("\n[INFO] The token appears to be truncated in your message.")
    print("We need the FULL token to decode it properly.")
    
    print("\n[INSTRUCTIONS]")
    print("1. Look at your capture output again")
    print("2. Find the COMPLETE Bearer token (not truncated)")
    print("3. It should look like: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjox...")
    print("4. Copy the ENTIRE token (it's usually very long)")
    
    print("\n[ALTERNATIVE]")
    print("If you can't find the full token, let's run the cross-account test")
    print("with the truncated token and see what happens:")
    
    # Try to run the cross-account test with what we have
    print("\n" + "=" * 60)
    print("RUNNING CROSS-ACCOUNT TEST WITH AVAILABLE DATA")
    print("=" * 60)
    
    # Use the truncated token for now
    print(f"Using truncated token: {new_token}")
    print("This will likely fail, but we can see the error message.")
    
    return new_token

if __name__ == "__main__":
    main()
