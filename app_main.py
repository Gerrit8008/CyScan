"""
Main application entry point - renamed to avoid conflicts
"""
import os
import sys
import logging
from flask import Flask

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_app():
    """Create and configure Flask application"""
    app = Flask(__name__)
    
    # Basic configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback-secret-key')
    app.config['DEBUG'] = False
    
    @app.route('/')
    def index():
        return """
        <h1>CybrScan is Running!</h1>
        <p>Deployment successful on Render.com</p>
        <p><a href="/health">Health Check</a></p>
        """
    
    @app.route('/health')
    def health():
        return {
            "status": "healthy",
            "message": "CybrScan is running successfully",
            "environment": os.environ.get('FLASK_ENV', 'production')
        }
    
    return app

# Create the app instance
app = create_app()

# Alias for different WSGI servers
application = app

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)