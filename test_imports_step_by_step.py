#!/usr/bin/env python3
"""
Test imports step by step to find the config.settings issue
"""
import sys
import traceback

def test_import_step(step, import_statement, description):
    print(f"\n🔍 Step {step}: {description}")
    print(f"   Import: {import_statement}")
    try:
        exec(import_statement)
        print(f"   ✅ SUCCESS")
        return True
    except Exception as e:
        print(f"   ❌ FAILED: {e}")
        print(f"   📋 Traceback:")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🚀 Starting step-by-step import test...")
    
    steps = [
        ("from config import get_config", "Basic config import"),
        ("from models import db", "Models import"),
        ("from subscription_constants import SUBSCRIPTION_LEVELS", "Subscription constants"),
        ("from app_modules.auth.routes import auth_bp", "Auth blueprint"),
        ("from app_modules.admin import admin_bp", "Admin blueprint"),
        ("from app_modules.client import client_bp", "Client blueprint"),
        ("from app_modules.scanner import scanner_bp", "Scanner blueprint"),
        ("from app_modules.billing import billing_bp", "Billing blueprint"),
        ("from app import app", "Full app import")
    ]
    
    for i, (import_stmt, description) in enumerate(steps, 1):
        success = test_import_step(i, import_stmt, description)
        if not success:
            print(f"\n💥 IMPORT CHAIN BREAKS AT STEP {i}")
            print(f"   Failed import: {import_stmt}")
            break
    else:
        print("\n🎉 ALL IMPORTS SUCCESSFUL!")
    
    print("\n🏁 Test completed")