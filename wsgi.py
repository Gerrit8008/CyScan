"""
WSGI entry point for CybrScan application
"""
import os
import sys
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Import the fresh CybrScan application
    from cybrscan_fresh import app
    logger.info("✅ Successfully imported fresh CybrScan app")
    application = app
    
except Exception as e:
    logger.error(f"❌ Failed to import fresh app: {e}")
    logger.info("🔄 Falling back to super minimal test app")
    
    try:
        from app_super_minimal import app
        logger.info("✅ Super minimal test app loaded as fallback")
        application = app
    except Exception as e2:
        logger.error(f"❌ Even super minimal app failed: {e2}")
        raise
    
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