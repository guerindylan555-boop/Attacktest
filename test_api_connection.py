"""
Quick test to check if MaynDrive API is reachable
"""
import requests
import sys

def test_api():
    """Test API connection"""
    url = "https://api.knotcity.io/api/application/login"
    
    headers = {
        'User-Agent': 'Knot-mayndrive v1.1.34 (android)',
        'Content-Type': 'application/json'
    }
    
    payload = {
        'email': 'test@test.com',
        'password': 'test123'
    }
    
    print("🔍 Testing MaynDrive API connection...")
    print(f"URL: {url}")
    print(f"Headers: {headers}")
    print()
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        
        print(f"✅ API is REACHABLE!")
        print(f"Status Code: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print()
        print(f"Response Body:")
        print(response.text[:500])
        
        if response.status_code == 200:
            print("\n✅ Login endpoint works (even with fake credentials)")
        elif response.status_code == 401:
            print("\n✅ API is UP! (401 = invalid credentials, which is expected)")
        elif response.status_code == 400:
            print("\n✅ API is UP! (400 = bad request format)")
        elif response.status_code == 502:
            print("\n❌ 502 Bad Gateway - API server is down or unreachable")
        elif response.status_code == 503:
            print("\n❌ 503 Service Unavailable - API is temporarily offline")
        else:
            print(f"\n⚠️ Unexpected status code: {response.status_code}")
            
    except requests.exceptions.Timeout:
        print("❌ TIMEOUT: API did not respond within 10 seconds")
        print("   → Server may be down or very slow")
        
    except requests.exceptions.ConnectionError as e:
        print("❌ CONNECTION ERROR: Cannot reach API server")
        print(f"   → {str(e)}")
        print("   → Server may be down or DNS not resolving")
        
    except Exception as e:
        print(f"❌ ERROR: {type(e).__name__}: {str(e)}")

if __name__ == "__main__":
    test_api()

