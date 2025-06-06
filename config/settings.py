import os
import logging
from dotenv import load_dotenv
from datetime import timedelta

# Load environment variables from .env file if it exists
load_dotenv()

class Config:
    """Base configuration class"""
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cybrscan_secret_key_change_in_production')
    
    # Database configuration
    DB_PATH = os.environ.get('DB_PATH', os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'cybrscan.db'))
    
    # Session configuration
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    
    # Email configuration
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'mail.privateemail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    SMTP_USER = os.environ.get('SMTP_USER', '')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@cybrscan.com')
    
    # Subscription tiers (MSP-focused pricing)
    SUBSCRIPTION_TIERS = {
        'basic': {
            'name': 'Basic',
            'price': 0,
            'scanners_limit': 1,
            'scans_per_month': 25,
            'features': ['Basic scanning', 'Email reports', 'Basic support'],
            'requires_payment': False
        },
        'professional': {
            'name': 'Professional',
            'price': 39,
            'scanners_limit': 3,
            'scans_per_month': 150,
            'features': ['Advanced scanning', 'White-label branding', 'API access', 'Priority support', 'Custom domains'],
            'requires_payment': True
        },
        'business': {
            'name': 'Business',
            'price': 99,
            'scanners_limit': 10,
            'scans_per_month': 750,
            'features': ['All Professional features', 'Advanced analytics', 'Integration support', 'Custom reporting'],
            'requires_payment': True
        },
        'enterprise': {
            'name': 'Enterprise',
            'price': 249,
            'scanners_limit': -1,  # Unlimited
            'scans_per_month': -1,  # Unlimited
            'features': ['All Business features', 'Unlimited scanners', 'Unlimited scans', 'Dedicated support', 'Custom development'],
            'requires_payment': True
        }
    }
    
    # Payment configuration
    STRIPE_PUBLISHABLE_KEY = os.environ.get('STRIPE_PUBLISHABLE_KEY', '')
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', '')
    
    # Feature flags
    ENABLE_AUTO_EMAIL = os.environ.get('ENABLE_AUTO_EMAIL', 'True') == 'True'
    FULL_SCAN_ENABLED = os.environ.get('FULL_SCAN_ENABLED', 'True') == 'True'
    ENABLE_CSS_EXTRACTION = os.environ.get('ENABLE_CSS_EXTRACTION', 'True') == 'True'
    
    # Rate limiting
    RATE_LIMIT_PER_DAY = int(os.environ.get('RATE_LIMIT_PER_DAY', 200))
    RATE_LIMIT_PER_HOUR = int(os.environ.get('RATE_LIMIT_PER_HOUR', 50))
    
    # Upload configuration
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'ico'}
    
    @staticmethod
    def init_app(app):
        """Initialize the application with this configuration"""
        app.config.from_object(Config)
        
        # Ensure data directory exists
        os.makedirs(os.path.dirname(Config.DB_PATH), exist_ok=True)
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        
        # Check essential config
        if not Config.SMTP_USER or not Config.SMTP_PASSWORD:
            logging.warning("Email credentials not configured. Email functionality will not work.")
            
        return app

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    
class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    
class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DATABASE_URL = 'sqlite:///test.db'