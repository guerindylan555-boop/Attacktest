"""
Example usage of MaynDrive API Client

This script demonstrates how to:
1. Login to your account
2. Unlock a scooter (both regular and admin)
3. Get vehicle information
4. Manage vehicle settings
"""

from mayn_drive_api import MaynDriveAPI, print_response


def main():
    """Main example function"""
    
    # Initialize the API client
    print("Initializing MaynDrive API Client...")
    api = MaynDriveAPI(environment='production')
    
    # ========== Step 1: Login ==========
    print("\n" + "="*60)
    print("STEP 1: Login")
    print("="*60)
    
    # Replace with your actual credentials
    EMAIL = "your.email@example.com"
    PASSWORD = "your_password"
    
    success, login_data = api.login(EMAIL, PASSWORD)
    print_response(success, login_data, "Login Response")
    
    if not success:
        print("❌ Login failed! Please check your credentials.")
        return
    
    # ========== Step 2: Get User Profile ==========
    print("\n" + "="*60)
    print("STEP 2: Get User Profile")
    print("="*60)
    
    success, profile = api.get_user_profile()
    print_response(success, profile, "User Profile")
    
    # ========== Step 3: Regular Vehicle Unlock ==========
    print("\n" + "="*60)
    print("STEP 3: Unlock Vehicle (Regular)")
    print("="*60)
    
    # Replace with actual vehicle serial number and your location
    SERIAL_NUMBER = "SN12345"  # Example serial number
    LATITUDE = 48.8566  # Example: Paris coordinates
    LONGITUDE = 2.3522
    
    success, unlock_data = api.unlock_vehicle(
        serial_number=SERIAL_NUMBER,
        latitude=LATITUDE,
        longitude=LONGITUDE
    )
    print_response(success, unlock_data, "Regular Unlock Response")
    
    # ========== Step 4: Admin Vehicle Unlock ==========
    print("\n" + "="*60)
    print("STEP 4: Unlock Vehicle (Admin)")
    print("="*60)
    
    success, admin_unlock = api.unlock_vehicle_admin(
        serial_number=SERIAL_NUMBER,
        latitude=LATITUDE,
        longitude=LONGITUDE,
        force=False  # Set to True to force unlock even if in use
    )
    print_response(success, admin_unlock, "Admin Unlock Response")
    
    # ========== Step 5: Get Vehicle Information ==========
    print("\n" + "="*60)
    print("STEP 5: Get Vehicle Information")
    print("="*60)
    
    # Get basic vehicle info
    success, vehicle_info = api.get_vehicle_info(SERIAL_NUMBER, admin=False)
    print_response(success, vehicle_info, "Vehicle Info (Basic)")
    
    # Get admin vehicle info (more details)
    success, admin_info = api.get_vehicle_info(SERIAL_NUMBER, admin=True)
    print_response(success, admin_info, "Vehicle Info (Admin)")
    
    # ========== Step 6: Refresh Vehicle Data ==========
    print("\n" + "="*60)
    print("STEP 6: Refresh Vehicle Data from IoT")
    print("="*60)
    
    success, refresh_data = api.refresh_vehicle_admin(SERIAL_NUMBER)
    print_response(success, refresh_data, "Refresh Vehicle Data")
    
    # ========== Step 7: Identify Vehicle ==========
    print("\n" + "="*60)
    print("STEP 7: Identify Vehicle (Beep/Flash)")
    print("="*60)
    
    success, identify_data = api.identify_vehicle_admin(SERIAL_NUMBER)
    print_response(success, identify_data, "Identify Vehicle")
    
    # ========== Step 8: Get Vehicle Models ==========
    print("\n" + "="*60)
    print("STEP 8: Get Available Vehicle Models")
    print("="*60)
    
    success, models = api.get_vehicle_models()
    print_response(success, models, "Vehicle Models")
    
    # ========== Step 9: Open Battery Compartment ==========
    print("\n" + "="*60)
    print("STEP 9: Open Battery Compartment")
    print("="*60)
    
    success, battery_data = api.open_battery_compartment(SERIAL_NUMBER)
    print_response(success, battery_data, "Battery Compartment")
    
    # ========== Step 10: Get Wallet Information ==========
    print("\n" + "="*60)
    print("STEP 10: Get Wallet Information")
    print("="*60)
    
    success, wallet = api.get_wallet(currency="USD", network_id=1)
    print_response(success, wallet, "Wallet Information")
    
    # ========== Step 11: Get Rent History ==========
    print("\n" + "="*60)
    print("STEP 11: Get Rent History")
    print("="*60)
    
    success, rents = api.get_rents()
    print_response(success, rents, "Rent History")
    
    # ========== Step 12: Lock Vehicle (Admin) ==========
    print("\n" + "="*60)
    print("STEP 12: Lock Vehicle (Admin)")
    print("="*60)
    
    success, lock_data = api.lock_vehicle_admin(
        serial_number=SERIAL_NUMBER,
        latitude=LATITUDE,
        longitude=LONGITUDE
    )
    print_response(success, lock_data, "Admin Lock Response")
    
    print("\n✓ Example script completed!")


def quick_unlock_example():
    """Quick example for just unlocking a scooter"""
    
    # Initialize API
    api = MaynDriveAPI()
    
    # Login
    success, _ = api.login("your.email@example.com", "your_password")
    if not success:
        print("❌ Login failed!")
        return
    
    # Admin unlock
    success, data = api.unlock_vehicle_admin(
        serial_number="SN12345",
        latitude=48.8566,
        longitude=2.3522,
        force=False
    )
    
    if success:
        print("✓ Scooter unlocked successfully!")
    else:
        print(f"❌ Failed to unlock: {data}")


def update_vehicle_settings_example():
    """Example of updating vehicle settings"""
    
    api = MaynDriveAPI()
    
    # Login
    api.login("your.email@example.com", "your_password")
    
    # Update settings
    settings = {
        "max_speed": 25,
        "eco_mode": True,
        "maintenance_mode": False
    }
    
    success, data = api.update_vehicle_settings("SN12345", settings)
    print_response(success, data, "Update Settings")


if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║         MaynDrive API Client - Example Usage              ║
    ║                                                            ║
    ║  IMPORTANT: Update credentials before running!            ║
    ║  - Edit EMAIL and PASSWORD variables                      ║
    ║  - Update SERIAL_NUMBER with actual scooter serial        ║
    ║  - Set your actual GPS coordinates                        ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    choice = input("\nChoose an option:\n1. Run full example\n2. Quick unlock only\n3. Update settings\n\nChoice (1-3): ")
    
    if choice == "1":
        main()
    elif choice == "2":
        quick_unlock_example()
    elif choice == "3":
        update_vehicle_settings_example()
    else:
        print("Invalid choice!")

