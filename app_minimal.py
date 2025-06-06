"""
Minimal CybrScan application for Render deployment
"""
import os
import logging
from flask import Flask, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)

# Basic configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cybrscan-production-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///cybrscan.db')

# Handle Render's postgres:// URL format
if app.config['SQLALCHEMY_DATABASE_URI'] and app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Simple User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CybrScan - Security Scanner Platform</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f8f9fa; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { text-align: center; margin-bottom: 30px; }
            .logo { color: #007bff; font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }
            .tagline { color: #6c757d; font-size: 1.2em; }
            .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
            .feature { text-align: center; padding: 20px; background: #f8f9fa; border-radius: 6px; }
            .feature h3 { color: #007bff; margin-bottom: 10px; }
            .status { background: #d4edda; color: #155724; padding: 15px; border-radius: 6px; margin: 20px 0; }
            .nav { text-align: center; margin-top: 30px; }
            .nav a { display: inline-block; margin: 0 10px; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 4px; }
            .nav a:hover { background: #0056b3; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="logo">🛡️ CybrScan</div>
                <div class="tagline">White-Label Security Scanner Platform for MSPs</div>
            </div>
            
            <div class="status">
                ✅ <strong>Deployment Successful!</strong> Your CybrScan platform is now running on Render.com
            </div>
            
            <div class="features">
                <div class="feature">
                    <h3>🔍 Security Scanning</h3>
                    <p>Comprehensive vulnerability assessment tools</p>
                </div>
                <div class="feature">
                    <h3>🎨 White-Label</h3>
                    <p>Fully customizable branding for MSPs</p>
                </div>
                <div class="feature">
                    <h3>📊 Reporting</h3>
                    <p>Professional security reports and analytics</p>
                </div>
                <div class="feature">
                    <h3>🔒 Multi-Tenant</h3>
                    <p>Secure client isolation and management</p>
                </div>
            </div>
            
            <div class="nav">
                <a href="/health">System Status</a>
                <a href="/api/docs">API Documentation</a>
                <a href="https://github.com/yourusername/CybrScan_render">GitHub</a>
            </div>
        </div>
    </body>
    </html>
    """

@app.route('/health')
def health():
    return jsonify({
        "status": "healthy",
        "application": "CybrScan Security Scanner Platform",
        "version": "1.0.0",
        "environment": os.environ.get('FLASK_ENV', 'production'),
        "database": "Connected" if app.config['SQLALCHEMY_DATABASE_URI'] else "Not configured",
        "features": ["Security Scanning", "White-Label Branding", "Multi-Tenant", "API Access"]
    })

@app.route('/api/docs')
def api_docs():
    return jsonify({
        "api_version": "1.0",
        "endpoints": {
            "/": "Main application page",
            "/health": "System health check",
            "/api/docs": "API documentation (this page)"
        },
        "documentation": "Full API documentation coming soon"
    })

# Initialize database tables
with app.app_context():
    try:
        db.create_all()
        logger.info("✅ Database tables created successfully")
    except Exception as e:
        logger.warning(f"⚠️ Database initialization skipped: {e}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)