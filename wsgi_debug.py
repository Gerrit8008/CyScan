"""
Debug version of wsgi.py to capture exact error
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

logger.info("🚀 Starting WSGI debug session...")
logger.info(f"📁 Current directory: {os.getcwd()}")
logger.info(f"🐍 Python path: {sys.path[:3]}...")

try:
    logger.info("📦 Testing basic imports...")
    import flask
    logger.info("✅ Flask available")
    
    from config import get_config
    logger.info("✅ Config module imported")
    
    from models import db
    logger.info("✅ Models imported")
    
    logger.info("🔍 Now trying to import app.py...")
    from app import app
    logger.info("✅ Successfully imported full CybrScan app!")
    
    # Test app functionality
    with app.app_context():
        logger.info("✅ App context works")
    
    application = app
    
except Exception as e:
    logger.error(f"❌ Detailed error information:")
    logger.error(f"Error type: {type(e).__name__}")
    logger.error(f"Error message: {str(e)}")
    logger.error("📋 Full traceback:")
    
    # Print detailed traceback
    tb_lines = traceback.format_exc().split('\n')
    for i, line in enumerate(tb_lines):
        logger.error(f"TB[{i:02d}]: {line}")
    
    # Try to identify specific problem
    if "config.settings" in str(e):
        logger.error("🔍 This is the config.settings error!")
        logger.error("📁 Checking if config directory exists...")
        if os.path.exists("config"):
            logger.error("❌ config directory still exists!")
            logger.error(f"Contents: {os.listdir('config')}")
        else:
            logger.error("✅ config directory doesn't exist")
    
    logger.info("🔄 Falling back to minimal app...")
    try:
        from app_minimal import app
        logger.info("✅ Minimal app imported successfully")
        application = app
    except Exception as e2:
        logger.error(f"❌ Even minimal app failed: {e2}")
        raise

logger.info("🎯 WSGI application ready!")

if __name__ == '__main__':
    logger.info("🧪 Running debug tests...")
    try:
        if 'application' in locals():
            logger.info("✅ Application variable exists")
            logger.info(f"App type: {type(application)}")
        else:
            logger.error("❌ No application variable found")
    except Exception as e:
        logger.error(f"❌ Debug test failed: {e}")