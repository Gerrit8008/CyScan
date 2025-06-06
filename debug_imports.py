"""
Debug script to test imports step by step
"""
import sys
import traceback

def test_import(module_name, description):
    try:
        print(f"\n🔍 Testing: {description}")
        if module_name == "config":
            from config import get_config
            print("✅ config module imported successfully")
        elif module_name == "models":
            from models import db, User
            print("✅ models imported successfully")
        elif module_name == "app_modules.auth":
            from app_modules.auth.routes import auth_bp
            print("✅ auth blueprint imported successfully")
        elif module_name == "app_modules.admin":
            from app_modules.admin import admin_bp
            print("✅ admin blueprint imported successfully")
        elif module_name == "app_modules.client":
            from app_modules.client import client_bp
            print("✅ client blueprint imported successfully")
        elif module_name == "app_modules.scanner":
            from app_modules.scanner import scanner_bp
            print("✅ scanner blueprint imported successfully")
        elif module_name == "app_modules.billing":
            from app_modules.billing import billing_bp
            print("✅ billing blueprint imported successfully")
        elif module_name == "full_app":
            from app import app
            print("✅ Full app imported successfully")
    except Exception as e:
        print(f"❌ Failed to import {module_name}: {e}")
        print("📋 Full traceback:")
        traceback.print_exc()
        return False
    return True

if __name__ == "__main__":
    print("🚀 Starting import debugging...")
    
    modules_to_test = [
        ("config", "Configuration module"),
        ("models", "Database models"),
        ("app_modules.auth", "Auth blueprint"),
        ("app_modules.admin", "Admin blueprint"), 
        ("app_modules.client", "Client blueprint"),
        ("app_modules.scanner", "Scanner blueprint"),
        ("app_modules.billing", "Billing blueprint"),
        ("full_app", "Complete application")
    ]
    
    for module, description in modules_to_test:
        success = test_import(module, description)
        if not success:
            print(f"\n💥 Import failed at: {module}")
            break
    
    print("\n🏁 Import debugging completed")