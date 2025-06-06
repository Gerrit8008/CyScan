"""
CybrScan - Advanced Security Scanning Platform
Professional Grade Security Assessment Tools
"""

from flask import Flask
from flask_login import LoginManager
from flask_cors import CORS
from config.settings import Config
import os
import logging
from datetime import datetime

def create_app(config_class=Config):
    """Application factory pattern"""
    app = Flask(__name__)
    app.config.from_object(config_class)
    
    # Initialize extensions
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # Initialize CORS
    CORS(app, origins=['*'])
    
    # Setup logging
    if not os.path.exists('logs'):
        os.makedirs('logs')
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
        handlers=[
            logging.FileHandler('logs/cybrscan.log'),
            logging.StreamHandler()
        ]
    )
    
    # User loader for Flask-Login
    from app.models import User
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.get_by_id(int(user_id))
    
    # Register blueprints
    from app.routes import main_bp
    from app.auth import auth_bp
    from app.admin import admin_bp
    from app.client import client_bp
    from app.scanner import scanner_bp
    from app.api import api_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(client_bp, url_prefix='/client')
    app.register_blueprint(scanner_bp, url_prefix='/scanner')
    app.register_blueprint(api_bp, url_prefix='/api')
    
    # Initialize database
    from database.db_manager import init_db
    with app.app_context():
        init_db()
    
    app.logger.info('CybrScan application initialized successfully')
    
    return app