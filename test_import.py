#!/usr/bin/env python3
"""Test if all imports work correctly."""

import sys
import os

print("Testing imports...")

try:
    import flask
    print("✅ Flask imported successfully")
except ImportError as e:
    print(f"❌ Failed to import Flask: {e}")

try:
    import flask_sqlalchemy
    print("✅ Flask-SQLAlchemy imported successfully")
except ImportError as e:
    print(f"❌ Failed to import Flask-SQLAlchemy: {e}")

try:
    import psycopg2
    print("✅ psycopg2 imported successfully")
except ImportError as e:
    print(f"❌ Failed to import psycopg2: {e}")

try:
    import gunicorn
    print("✅ Gunicorn imported successfully")
except ImportError as e:
    print(f"❌ Failed to import Gunicorn: {e}")

try:
    from config import get_config
    print("✅ Config module imported successfully")
except ImportError as e:
    print(f"❌ Failed to import config: {e}")

try:
    from models import db
    print("✅ Models module imported successfully")
except ImportError as e:
    print(f"❌ Failed to import models: {e}")

print("\nAll import tests completed!")