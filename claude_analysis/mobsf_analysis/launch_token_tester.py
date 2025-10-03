#!/usr/bin/env python3
"""
MaynDrive Token Tester Launcher
Choose between desktop GUI or web interface
"""

import sys
import subprocess
import os
from pathlib import Path

def check_dependencies():
    """Check if required dependencies are installed"""
    try:
        import tkinter
        tkinter_available = True
    except ImportError:
        tkinter_available = False
    
    try:
        import flask
        flask_available = True
    except ImportError:
        flask_available = False
    
    return tkinter_available, flask_available

def launch_desktop_gui():
    """Launch the desktop GUI application"""
    print("🖥️  Launching Desktop GUI...")
    try:
        subprocess.run([sys.executable, "token_tester_gui.py"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error launching desktop GUI: {e}")
    except FileNotFoundError:
        print("❌ Desktop GUI file not found")

def launch_web_interface():
    """Launch the web interface"""
    print("🌐 Launching Web Interface...")
    print("📱 The web interface will be available at: http://localhost:5000")
    print("⚠️  Press Ctrl+C to stop the web server")
    try:
        subprocess.run([sys.executable, "web_token_tester.py"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"❌ Error launching web interface: {e}")
    except FileNotFoundError:
        print("❌ Web interface file not found")
    except KeyboardInterrupt:
        print("\n👋 Web interface stopped")

def main():
    """Main launcher function"""
    print("=" * 60)
    print("🔍 MaynDrive Token Tester Launcher")
    print("=" * 60)
    
    # Check dependencies
    tkinter_available, flask_available = check_dependencies()
    
    print("📋 Available interfaces:")
    
    options = []
    if tkinter_available:
        print("1. 🖥️  Desktop GUI (tkinter)")
        options.append(("desktop", "Desktop GUI"))
    else:
        print("1. ❌ Desktop GUI (tkinter not available)")
    
    if flask_available:
        print("2. 🌐 Web Interface (Flask)")
        options.append(("web", "Web Interface"))
    else:
        print("2. ❌ Web Interface (Flask not available)")
    
    print("3. 📄 View Documentation")
    print("4. 🚪 Exit")
    
    if not options:
        print("\n❌ No interfaces available. Please install required dependencies:")
        print("   - For Desktop GUI: tkinter (usually included with Python)")
        print("   - For Web Interface: pip install flask")
        return
    
    while True:
        try:
            choice = input(f"\nSelect option (1-{len(options)+2}): ").strip()
            
            if choice == "1" and ("desktop", "Desktop GUI") in options:
                launch_desktop_gui()
                break
            elif choice == "2" and ("web", "Web Interface") in options:
                launch_web_interface()
                break
            elif choice == "3":
                show_documentation()
            elif choice == "4":
                print("👋 Goodbye!")
                break
            else:
                print("❌ Invalid choice. Please select a valid option.")
                
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")

def show_documentation():
    """Show documentation and usage instructions"""
    print("\n" + "=" * 60)
    print("📚 MaynDrive Token Tester Documentation")
    print("=" * 60)
    
    print("""
🎯 Purpose:
   This tool tests extracted tokens from the MaynDrive APK against API endpoints
   to identify security vulnerabilities.

🔧 Configuration:
   - API Base URL: Your test API endpoint (e.g., https://api-test.knotcity.io)
   - Test Scooter Serial: Serial number for testing vehicle operations
   - Latitude/Longitude: Test location coordinates

🧪 Testing Process:
   1. Loads 1,141+ tokens extracted from APK analysis
   2. Tests each token against multiple API endpoints:
      - User profile access
      - Wallet information
      - Vehicle unlock operations
      - Admin operations
   3. Reports which tokens provide unauthorized access

📊 Results:
   - Shows successful/failed API calls
   - Identifies valid tokens that can access the API
   - Confirms security vulnerabilities
   - Generates detailed reports

⚠️  Important Notes:
   - Only test against your own test environment
   - Do not use against production systems
   - This is for security research purposes only

🛡️  Security Implications:
   - Valid tokens indicate hardcoded secrets vulnerability
   - Unauthorized API access possible
   - Potential for scooter manipulation
   - User data exposure risk

📁 Output Files:
   - JSON results with detailed test data
   - Markdown reports with vulnerability assessment
   - Configurable test parameters
""")

if __name__ == "__main__":
    main()
