"""
Standalone WSGI entry point that doesn't import from app_modules
"""
import os
import sys
import logging

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from flask import Flask
    from config import get_config
    from models import db
    
    # Create Flask app
    app = Flask(__name__)
    
    # Load configuration
    config_obj = get_config()
    app.config.from_object(config_obj)
    
    # Initialize database
    db.init_app(app)
    
    # Basic route for testing
    @app.route('/')
    def index():
        return "CybrScan is running!"
    
    @app.route('/health')
    def health():
        return {"status": "healthy"}
    
    # Expose for gunicorn
    application = app
    
    logger.info("✅ Standalone WSGI app initialized successfully")
    
except Exception as e:
    logger.error(f"❌ Failed to initialize app: {e}")
    raise

if __name__ == "__main__":
    app.run(debug=True)