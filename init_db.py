#!/usr/bin/env python3
"""Initialize the database with tables and default data."""
import os
import sys
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, init, migrate, upgrade
from config import get_config

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def init_database():
    """Initialize the database with tables."""
    app = Flask(__name__)
    app.config.from_object(get_config())
    
    db = SQLAlchemy(app)
    migrate_instance = Migrate(app, db)
    
    with app.app_context():
        # Import models to ensure they're registered
        import models
        
        # Create migrations directory if it doesn't exist
        migrations_dir = os.path.join(os.path.dirname(__file__), 'migrations')
        if not os.path.exists(migrations_dir):
            print("Initializing migrations...")
            init()
            print("Creating initial migration...")
            migrate(message='Initial migration')
        
        print("Running migrations...")
        upgrade()
        
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_database()