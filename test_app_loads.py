#!/usr/bin/env python3
"""Test script to verify the Flask app can load without errors"""

import sys

try:
    print("Testing if Flask app can load...")
    from exploit_demo_webapp import app
    print("✅ App loaded successfully!")
    print(f"✅ App name: {app.name}")
    print(f"✅ Routes: {[str(rule) for rule in app.url_map.iter_rules()]}")
    sys.exit(0)
except Exception as e:
    print(f"❌ Failed to load app: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

