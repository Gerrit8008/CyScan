"""
WSGI entry point for CybrScan application - Debug version
"""
import os
import sys
import logging
import traceback

# Setup detailed logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logger.info("🚀 Starting WSGI with detailed debugging...")

try:
    # Step-by-step import debugging
    logger.info("📦 Testing config import...")
    from config import get_config
    logger.info("✅ Config imported successfully")
    
    logger.info("📦 Testing models import...")
    from models import db
    logger.info("✅ Models imported successfully")
    
    logger.info("📦 Testing main app import...")
    from app import app
    logger.info("✅ Successfully imported full CybrScan app")
    application = app
    
except Exception as e:
    logger.error("❌ DETAILED ERROR ANALYSIS:")
    logger.error(f"Error type: {type(e).__name__}")
    logger.error(f"Error message: {str(e)}")
    
    # Print full traceback with line numbers
    tb_lines = traceback.format_exc().split('\n')
    for i, line in enumerate(tb_lines):
        if line.strip():
            logger.error(f"TRACE[{i:02d}]: {line}")
    
    logger.info("🔄 Trying minimal app fallback...")
    try:
        from app_minimal import app
        logger.info("✅ Minimal app imported successfully")
        application = app
    except Exception as e2:
        logger.error(f"❌ Minimal app also failed: {e2}")
        logger.info("🔄 Using basic Flask fallback")
    
    # Fallback to a simple working app
    try:
        from flask import Flask, jsonify
        
        app = Flask(__name__)
        app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-key')
        
        @app.route('/')
        def index():
            return """
            <h1>🚀 CybrScan Loading...</h1>
            <p>Main application is initializing. If you see this page, the deployment is working.</p>
            <p><a href="/health">Health Check</a></p>
            <p><strong>Error:</strong> Main app failed to load - check logs</p>
            """
        
        @app.route('/health')
        def health():
            return jsonify({
                "status": "partial", 
                "message": "Fallback app running - main app failed to load",
                "error": str(e)
            })
        
        application = app
        
    except Exception as fallback_error:
        logger.error(f"❌ Even fallback failed: {fallback_error}")
        raise

if __name__ == '__main__':
    if app:
        app.run(debug=True)