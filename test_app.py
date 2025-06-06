#!/usr/bin/env python3
"""Test script to verify app can be imported and started"""

try:
    print("Testing app import...")
    from app import app
    print("✅ Successfully imported app")
    print(f"App name: {app.name}")
    print(f"App instance: {app}")
    
    # Test if we can access the app's routes
    with app.app_context():
        rules = list(app.url_map.iter_rules())
        print(f"\n✅ Found {len(rules)} routes")
        for rule in rules[:5]:  # Show first 5 routes
            print(f"  - {rule.rule}")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()