#!/usr/bin/env python3
"""
CybrScan - White-Label Security Scanning Platform for MSPs
Main application entry point
"""

import logging
import os
import sqlite3
import platform
import socket
import re
import uuid
import urllib.parse
import time
from datetime import datetime, timedelta
import json
import sys
import traceback
from flask import send_file
from werkzeug.utils import secure_filename

# Setup basic logging first
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
logger.info("Starting CybrScan application initialization...")

try:
    from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
    logger.info("✅ Flask imported successfully")
except ImportError as e:
    logger.error(f"❌ Failed to import Flask: {e}")
    raise

try:
    from flask_cors import CORS
    logger.info("✅ Flask-CORS imported successfully")
except ImportError as e:
    logger.warning(f"⚠️ Flask-CORS not available: {e}")
    CORS = None

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    logger.info("✅ Flask-Limiter imported successfully")
except ImportError as e:
    logger.warning(f"⚠️ Flask-Limiter not available: {e}")
    Limiter = None

try:
    from flask_login import LoginManager, current_user, login_required, login_user, logout_user
    logger.info("✅ Flask-Login imported successfully")
except ImportError as e:
    logger.warning(f"⚠️ Flask-Login not available: {e}")
    LoginManager = None
    current_user = None
    def login_required(f):
        return f

try:
    from dotenv import load_dotenv
    load_dotenv()
    logger.info("✅ Environment variables loaded")
except ImportError as e:
    logger.warning(f"⚠️ python-dotenv not available: {e}")

# Import our custom modules
from config import get_config
from models import db, User, Scanner, Scan, ScannerCustomization, SubscriptionHistory, AdminSettings
from scanner import SecurityScanner
from subscription_constants import SUBSCRIPTION_LEVELS, get_subscription_features, get_client_subscription_level

# Create Flask app
app = Flask(__name__)

# Load configuration
config_obj = get_config()
app.config.from_object(config_obj)

# Set up database path
if not hasattr(app.config, 'DATABASE_URL'):
    app.config['DATABASE_URL'] = 'sqlite:///cybrscan.db'

# Initialize extensions
db.init_app(app)

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize limiter if available
if Limiter:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"]
    )

# CORS for API endpoints
if CORS:
    CORS(app, resources={r"/api/*": {"origins": "*"}})

# Import and register blueprints
from app_modules.auth.routes import auth_bp
from app_modules.admin import admin_bp
from app_modules.client import client_bp
from app_modules.scanner import scanner_bp
from app_modules.billing import billing_bp

app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(client_bp, url_prefix='/client')
app.register_blueprint(scanner_bp, url_prefix='/scanner')
app.register_blueprint(billing_bp, url_prefix='/billing')

# Main routes
@app.route('/')
def index():
    """Landing page"""
    return render_template('index.html', subscription_levels=SUBSCRIPTION_LEVELS)

@app.route('/pricing')
def pricing():
    """Pricing page"""
    return render_template('pricing.html', subscription_levels=SUBSCRIPTION_LEVELS)

@app.route('/dashboard')
@login_required
def dashboard():
    """Redirect to appropriate dashboard based on user role"""
    if current_user.role == 'admin':
        return redirect(url_for('admin.dashboard'))
    else:
        return redirect(url_for('client.dashboard'))

# API Routes
@app.route('/api/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '2.0.0'
    })

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for running scans"""
    try:
        data = request.get_json()
        scanner_id = data.get('scanner_id')
        target_url = data.get('target_url')
        scan_type = data.get('scan_type', 'basic')
        
        if not scanner_id or not target_url:
            return jsonify({'error': 'Missing required parameters'}), 400
        
        # Get scanner configuration
        scanner = Scanner.query.filter_by(id=scanner_id).first()
        if not scanner:
            return jsonify({'error': 'Scanner not found'}), 404
        
        # Check subscription limits
        user = User.query.get(scanner.user_id)
        subscription_level = get_client_subscription_level({'subscription_level': user.subscription_level})
        features = get_subscription_features(subscription_level)
        
        # Count monthly scans
        start_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        monthly_scans = Scan.query.filter(
            Scan.user_id == user.id,
            Scan.created_at >= start_of_month
        ).count()
        
        if monthly_scans >= features['features']['scans_per_month']:
            return jsonify({'error': 'Monthly scan limit exceeded'}), 429
        
        # Run the scan
        security_scanner = SecurityScanner()
        scan_result = security_scanner.scan_website(target_url, scan_type)
        
        # Save scan to database
        scan = Scan(
            user_id=user.id,
            scanner_id=scanner.id,
            target_url=target_url,
            scan_type=scan_type,
            results=json.dumps(scan_result),
            status='completed'
        )
        db.session.add(scan)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'scan_id': scan.id,
            'results': scan_result
        })
        
    except Exception as e:
        logger.error(f"API scan error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

@app.errorhandler(403)
def forbidden(error):
    return render_template('error.html', error_code=403, error_message="Access forbidden"), 403

# Template filters
@app.template_filter('datetime')
def datetime_filter(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.strftime('%Y-%m-%d %H:%M:%S')

@app.template_filter('date')
def date_filter(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value.strftime('%Y-%m-%d')

# Context processors
@app.context_processor
def inject_subscription_levels():
    return dict(subscription_levels=SUBSCRIPTION_LEVELS)

@app.context_processor
def inject_current_user():
    return dict(current_user=current_user if current_user.is_authenticated else None)

# Initialize database
def init_db():
    """Initialize the database"""
    with app.app_context():
        db.create_all()
        logger.info("Database initialized successfully")

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Run the application
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    port = int(os.environ.get('PORT', 5000))
    
    logger.info(f"Starting CybrScan on port {port}, debug={debug_mode}")
    app.run(host='0.0.0.0', port=port, debug=debug_mode)