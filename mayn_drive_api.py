"""
MaynDrive API Client
A Python client for interacting with the Knot City MaynDrive scooter API.

Base URL: https://api.knotcity.io/
User-Agent: Knot-mayndrive v1.1.34 (android)
"""

import requests
import json
from typing import Optional, Dict, Any, Tuple
from datetime import datetime
import uuid


class MaynDriveAPI:
    """Client for MaynDrive scooter API"""
    
    # Environment URLs
    ENVIRONMENTS = {
        'production': 'https://api.knotcity.io',
        'staging': 'https://staging-api.knotcity.io',  # Hypothetical
        'local_1': 'http://192.168.10.1:8082',
        'local_2': 'http://10.0.2.2:8082',
    }
    
    def __init__(self, environment: str = 'production', timeout: int = 10):
        """
        Initialize the MaynDrive API client
        
        Args:
            environment: One of 'production', 'staging', 'local_1', 'local_2'
            timeout: Request timeout in seconds (default 10s for faster failure)
        """
        self.base_url = self.ENVIRONMENTS.get(environment, self.ENVIRONMENTS['production'])
        self.timeout = timeout
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        
        # Session with default headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Knot-mayndrive v1.1.34 (android)',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
    def _get_headers(self, auth_required: bool = True) -> Dict[str, str]:
        """Get request headers with optional authentication"""
        headers = {}
        if auth_required and self.access_token:
            headers['Authorization'] = f'Bearer {self.access_token}'
        return headers
    
    def _make_request(self, method: str, endpoint: str, auth_required: bool = True, 
                     json_data: Optional[Dict] = None, params: Optional[Dict] = None) -> Tuple[bool, Any]:
        """
        Make an API request
        
        Returns:
            Tuple of (success: bool, data: dict or error message)
        """
        url = f"{self.base_url}{endpoint}"
        headers = self._get_headers(auth_required)
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                json=json_data,
                params=params,
                timeout=self.timeout
            )
            
            # Try to parse JSON response
            try:
                data = response.json()
            except:
                data = {'raw_response': response.text}
            
            if response.status_code in [200, 201]:
                return True, data
            else:
                return False, {
                    'status_code': response.status_code,
                    'error': data,
                    'message': response.text
                }
                
        except requests.exceptions.RequestException as e:
            return False, {'error': str(e), 'type': type(e).__name__}
    
    # ========== Authentication Methods ==========
    
    def login(self, email: str, password: str, scope: str = "user", 
              app_label: str = "mayndrive") -> Tuple[bool, Dict]:
        """
        Login with email and password
        
        Args:
            email: User email
            password: User password
            scope: Authentication scope (default: "user")
            app_label: App label (default: "mayndrive")
        
        Returns:
            Tuple of (success: bool, response data)
        """
        device_info = {
            "uuid": str(uuid.uuid4()),
            "platform": "android",
            "manufacturer": "Google",
            "model": "Pixel 5",
            "os_version": "13",
            "app_version": "1.1.34"
        }
        
        payload = {
            "email": email,
            "password": password,
            "device": device_info,
            "scope": scope,
            "app_label": app_label
        }
        
        success, data = self._make_request('POST', '/api/application/login', 
                                          auth_required=False, json_data=payload)
        
        if success and 'access_token' in data:
            self.access_token = data['access_token']
            if 'refresh_token' in data:
                self.refresh_token = data['refresh_token']
            print(f"✓ Login successful! Access token: {self.access_token[:20]}...")
        
        return success, data
    
    def refresh_access_token(self) -> Tuple[bool, Dict]:
        """
        Refresh the access token using refresh token
        
        Returns:
            Tuple of (success: bool, response data)
        """
        if not self.refresh_token:
            return False, {'error': 'No refresh token available'}
        
        success, data = self._make_request('POST', '/api/application/login/refresh', 
                                          auth_required=True)
        
        if success and 'access_token' in data:
            self.access_token = data['access_token']
            print(f"✓ Token refreshed! New token: {self.access_token[:20]}...")
        
        return success, data
    
    # ========== Vehicle Unlock Methods ==========
    
    def unlock_vehicle(self, serial_number: str, latitude: float, longitude: float) -> Tuple[bool, Dict]:
        """
        Unlock a vehicle (regular user unlock)
        
        Args:
            serial_number: Vehicle serial number (e.g., "SN12345")
            latitude: User's latitude
            longitude: User's longitude
        
        Returns:
            Tuple of (success: bool, response data)
        """
        payload = {
            "serial_number": serial_number,
            "lat": latitude,
            "lng": longitude
        }
        
        success, data = self._make_request('POST', '/api/application/vehicles/unlock', 
                                          json_data=payload)
        
        if success:
            print(f"✓ Vehicle {serial_number} unlocked successfully!")
        else:
            print(f"✗ Failed to unlock vehicle {serial_number}")
        
        return success, data
    
    def unlock_vehicle_admin(self, serial_number: str, latitude: float, longitude: float, 
                            force: bool = False) -> Tuple[bool, Dict]:
        """
        Admin unlock a vehicle (requires admin permissions)
        
        Args:
            serial_number: Vehicle serial number (e.g., "SN12345")
            latitude: User's latitude
            longitude: User's longitude
            force: Force unlock even if vehicle is in use
        
        Returns:
            Tuple of (success: bool, response data)
        """
        payload = {
            "serialNumber": serial_number,
            "latitude": latitude,
            "longitude": longitude,
            "force": force
        }
        
        success, data = self._make_request('POST', '/api/application/vehicles/unlock/admin', 
                                          json_data=payload)
        
        if success:
            print(f"✓ Vehicle {serial_number} admin unlocked successfully!")
        else:
            print(f"✗ Failed to admin unlock vehicle {serial_number}")
        
        return success, data
    
    # ========== Vehicle Information Methods ==========
    
    def get_vehicle_info(self, serial_number: str, admin: bool = False) -> Tuple[bool, Dict]:
        """
        Get vehicle information by serial number
        
        Args:
            serial_number: Vehicle serial number
            admin: Use admin endpoint (includes more details)
        
        Returns:
            Tuple of (success: bool, vehicle data)
        """
        endpoint = f'/api/application/vehicles/sn/{serial_number}'
        if admin:
            endpoint += '/admin'
        
        success, data = self._make_request('GET', endpoint)
        
        if success:
            print(f"✓ Retrieved info for vehicle {serial_number}")
        
        return success, data
    
    def refresh_vehicle_admin(self, serial_number: str) -> Tuple[bool, Dict]:
        """
        Force refresh vehicle data from IoT device (admin only)
        
        Args:
            serial_number: Vehicle serial number
        
        Returns:
            Tuple of (success: bool, response data)
        """
        endpoint = f'/api/application/vehicles/sn/{serial_number}/admin-refresh'
        success, data = self._make_request('GET', endpoint)
        
        if success:
            print(f"✓ Refreshed vehicle {serial_number} data from IoT")
        
        return success, data
    
    def update_vehicle_settings(self, serial_number: str, settings: Dict) -> Tuple[bool, Dict]:
        """
        Update vehicle settings (admin only)
        
        Args:
            serial_number: Vehicle serial number
            settings: Dictionary of settings to update
        
        Returns:
            Tuple of (success: bool, response data)
        """
        endpoint = f'/api/application/vehicles/sn/{serial_number}'
        success, data = self._make_request('PATCH', endpoint, json_data=settings)
        
        if success:
            print(f"✓ Updated settings for vehicle {serial_number}")
        
        return success, data
    
    # ========== Vehicle Lock Methods ==========
    
    def lock_vehicle_admin(self, serial_number: str, latitude: float, longitude: float) -> Tuple[bool, Dict]:
        """
        Admin lock a vehicle
        
        Args:
            serial_number: Vehicle serial number
            latitude: Vehicle's latitude
            longitude: Vehicle's longitude
        
        Returns:
            Tuple of (success: bool, response data)
        """
        payload = {
            "serial_number": serial_number,
            "latitude": latitude,
            "longitude": longitude
        }
        
        success, data = self._make_request('POST', '/api/application/vehicles/freefloat/lock/admin', 
                                          json_data=payload)
        
        if success:
            print(f"✓ Vehicle {serial_number} locked successfully!")
        
        return success, data
    
    def identify_vehicle_admin(self, serial_number: str) -> Tuple[bool, Dict]:
        """
        Make vehicle beep/flash to identify it (admin only)
        
        Args:
            serial_number: Vehicle serial number
        
        Returns:
            Tuple of (success: bool, response data)
        """
        payload = {
            "serial_number": serial_number
        }
        
        success, data = self._make_request('POST', '/api/application/vehicles/freefloat/identify/admin', 
                                          json_data=payload)
        
        if success:
            print(f"✓ Vehicle {serial_number} identification signal sent!")
        
        return success, data
    
    # ========== User Methods ==========
    
    def get_user_profile(self, network_id: Optional[int] = None) -> Tuple[bool, Dict]:
        """
        Get current user profile
        
        Args:
            network_id: Optional network ID filter
        
        Returns:
            Tuple of (success: bool, user data)
        """
        params = {}
        if network_id:
            params['network_id'] = network_id
        
        success, data = self._make_request('GET', '/api/application/users', params=params)
        return success, data
    
    def get_wallet(self, currency: str = "USD", network_id: int = 1) -> Tuple[bool, Dict]:
        """
        Get user wallet information
        
        Args:
            currency: Currency code (e.g., "USD", "EUR")
            network_id: Network ID
        
        Returns:
            Tuple of (success: bool, wallet data)
        """
        params = {
            'currency': currency,
            'network_id': network_id
        }
        
        success, data = self._make_request('GET', '/api/application/users/wallet', params=params)
        return success, data
    
    def get_rents(self) -> Tuple[bool, Dict]:
        """
        Get user's rent history
        
        Returns:
            Tuple of (success: bool, rent data)
        """
        success, data = self._make_request('GET', '/api/application/users/rents')
        return success, data
    
    # ========== Vehicle Models ==========
    
    def get_vehicle_models(self) -> Tuple[bool, Dict]:
        """
        Get available vehicle models
        
        Returns:
            Tuple of (success: bool, models data)
        """
        success, data = self._make_request('GET', '/api/application/vehicles/models')
        return success, data
    
    # ========== Battery Methods ==========
    
    def open_battery_compartment(self, serial_number: str) -> Tuple[bool, Dict]:
        """
        Open vehicle battery compartment
        
        Args:
            serial_number: Vehicle serial number
        
        Returns:
            Tuple of (success: bool, response data)
        """
        payload = {
            "serial_number": serial_number
        }
        
        success, data = self._make_request('POST', '/api/application/vehicles/battery/open', 
                                          json_data=payload)
        
        if success:
            print(f"✓ Battery compartment opened for vehicle {serial_number}")
        
        return success, data


def print_response(success: bool, data: Dict, title: str = "Response"):
    """Helper function to print API responses"""
    print(f"\n{'='*60}")
    print(f"{title}")
    print(f"{'='*60}")
    print(f"Success: {success}")
    print(f"Data: {json.dumps(data, indent=2, default=str)}")
    print(f"{'='*60}\n")

