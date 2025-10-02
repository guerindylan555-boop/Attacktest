"""
Test script for MaynDrive API Client
Tests various endpoints and validates responses
"""

import sys
from mayn_drive_api import MaynDriveAPI, print_response


class APITester:
    """Test suite for MaynDrive API"""
    
    def __init__(self, email: str, password: str):
        self.email = email
        self.password = password
        self.api = MaynDriveAPI(environment='production')
        self.test_results = {
            'passed': 0,
            'failed': 0,
            'skipped': 0
        }
    
    def run_test(self, test_name: str, test_func):
        """Run a single test"""
        print(f"\n{'='*70}")
        print(f"TEST: {test_name}")
        print(f"{'='*70}")
        
        try:
            success, message = test_func()
            if success:
                print(f"✓ PASSED: {message}")
                self.test_results['passed'] += 1
            else:
                print(f"✗ FAILED: {message}")
                self.test_results['failed'] += 1
        except Exception as e:
            print(f"✗ ERROR: {str(e)}")
            self.test_results['failed'] += 1
    
    def test_authentication(self):
        """Test login functionality"""
        success, data = self.api.login(self.email, self.password)
        
        if success and self.api.access_token:
            return True, f"Login successful, token: {self.api.access_token[:20]}..."
        else:
            return False, f"Login failed: {data}"
    
    def test_get_profile(self):
        """Test getting user profile"""
        success, data = self.api.get_user_profile()
        
        if success and isinstance(data, dict):
            user_email = data.get('email', 'N/A')
            user_id = data.get('id', 'N/A')
            return True, f"Profile retrieved - ID: {user_id}, Email: {user_email}"
        else:
            return False, f"Failed to get profile: {data}"
    
    def test_get_wallet(self):
        """Test wallet endpoint"""
        success, data = self.api.get_wallet(currency="USD", network_id=1)
        
        if success:
            balance = data.get('balance', 'N/A')
            return True, f"Wallet retrieved - Balance: {balance}"
        else:
            return False, f"Failed to get wallet: {data}"
    
    def test_get_vehicle_models(self):
        """Test getting vehicle models"""
        success, data = self.api.get_vehicle_models()
        
        if success and isinstance(data, dict):
            models_count = len(data.get('models', []))
            return True, f"Retrieved {models_count} vehicle models"
        else:
            return False, f"Failed to get models: {data}"
    
    def test_get_rents(self):
        """Test rent history"""
        success, data = self.api.get_rents()
        
        if success:
            rents_count = len(data.get('rents', []))
            return True, f"Retrieved {rents_count} rent records"
        else:
            return False, f"Failed to get rents: {data}"
    
    def test_token_refresh(self):
        """Test token refresh"""
        if not self.api.refresh_token:
            return False, "No refresh token available"
        
        old_token = self.api.access_token
        success, data = self.api.refresh_access_token()
        
        if success and self.api.access_token != old_token:
            return True, "Token refreshed successfully"
        else:
            return False, f"Token refresh failed: {data}"
    
    def test_vehicle_info_readonly(self):
        """Test read-only vehicle operations (if serial number provided)"""
        serial_number = input("\nEnter vehicle serial number (or 'skip' to skip): ")
        
        if serial_number.lower() == 'skip':
            self.test_results['skipped'] += 1
            return True, "Test skipped by user"
        
        # Try regular endpoint
        success, data = self.api.get_vehicle_info(serial_number, admin=False)
        
        if success:
            battery = data.get('battery_level', 'N/A')
            location = data.get('location', {})
            return True, f"Vehicle info retrieved - Battery: {battery}%, Location: {location}"
        else:
            return False, f"Failed to get vehicle info: {data}"
    
    def test_admin_vehicle_info(self):
        """Test admin vehicle info (if serial number provided)"""
        serial_number = input("\nEnter vehicle serial number for admin test (or 'skip' to skip): ")
        
        if serial_number.lower() == 'skip':
            self.test_results['skipped'] += 1
            return True, "Test skipped by user"
        
        success, data = self.api.get_vehicle_info(serial_number, admin=True)
        
        if success:
            return True, f"Admin vehicle info retrieved successfully"
        elif data.get('status_code') == 403:
            return False, "Access denied - Admin permissions required"
        else:
            return False, f"Failed to get admin vehicle info: {data}"
    
    def test_admin_unlock(self):
        """Test admin unlock (optional, requires confirmation)"""
        print("\n⚠️  WARNING: This will attempt to unlock a vehicle!")
        confirm = input("Do you want to test admin unlock? (yes/no): ")
        
        if confirm.lower() != 'yes':
            self.test_results['skipped'] += 1
            return True, "Test skipped by user"
        
        serial_number = input("Enter vehicle serial number: ")
        latitude = float(input("Enter your latitude: "))
        longitude = float(input("Enter your longitude: "))
        
        success, data = self.api.unlock_vehicle_admin(
            serial_number=serial_number,
            latitude=latitude,
            longitude=longitude,
            force=False
        )
        
        if success:
            return True, "Vehicle unlocked successfully!"
        elif data.get('status_code') == 403:
            return False, "Access denied - Admin permissions required"
        else:
            return False, f"Unlock failed: {data}"
    
    def run_all_tests(self):
        """Run all tests"""
        print("""
        ╔═══════════════════════════════════════════════════════════╗
        ║           MaynDrive API Test Suite                        ║
        ╚═══════════════════════════════════════════════════════════╝
        """)
        
        # Authentication tests
        self.run_test("Authentication - Login", self.test_authentication)
        
        if not self.api.access_token:
            print("\n❌ Cannot continue tests without authentication!")
            return
        
        # User profile tests
        self.run_test("User Profile - Get Profile", self.test_get_profile)
        self.run_test("User Profile - Get Wallet", self.test_get_wallet)
        self.run_test("User Profile - Get Rents", self.test_get_rents)
        
        # Vehicle tests
        self.run_test("Vehicles - Get Models", self.test_get_vehicle_models)
        self.run_test("Vehicles - Get Vehicle Info", self.test_vehicle_info_readonly)
        self.run_test("Vehicles - Get Admin Vehicle Info", self.test_admin_vehicle_info)
        
        # Token tests
        self.run_test("Authentication - Token Refresh", self.test_token_refresh)
        
        # Admin tests (optional)
        self.run_test("Admin - Unlock Vehicle", self.test_admin_unlock)
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        total = self.test_results['passed'] + self.test_results['failed'] + self.test_results['skipped']
        
        print(f"\n{'='*70}")
        print("TEST SUMMARY")
        print(f"{'='*70}")
        print(f"Total Tests:   {total}")
        print(f"✓ Passed:      {self.test_results['passed']}")
        print(f"✗ Failed:      {self.test_results['failed']}")
        print(f"⊘ Skipped:     {self.test_results['skipped']}")
        print(f"{'='*70}")
        
        if self.test_results['failed'] == 0:
            print("🎉 All tests passed!")
        else:
            print("⚠️  Some tests failed. Review output above.")


def main():
    """Main test function"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║         MaynDrive API Client - Test Suite                 ║
    ║                                                            ║
    ║  This will test various API endpoints to ensure           ║
    ║  everything is working correctly.                         ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    # Get credentials
    print("\nEnter your credentials:")
    email = input("Email: ")
    password = input("Password: ")
    
    if not email or not password:
        print("❌ Email and password are required!")
        sys.exit(1)
    
    # Create tester and run tests
    tester = APITester(email, password)
    tester.run_all_tests()


if __name__ == "__main__":
    main()

