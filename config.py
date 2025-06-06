import os
from datetime import timedelta

# Import subscription levels for compatibility with app_modules
try:
    from subscription_constants import SUBSCRIPTION_LEVELS
except ImportError:
    SUBSCRIPTION_LEVELS = {}

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database
    DATABASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'databases')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or f'sqlite:///{os.path.join(DATABASE_DIR, "cybrscan.db")}'
    # Handle Render's postgres:// URL format
    if SQLALCHEMY_DATABASE_URI and SQLALCHEMY_DATABASE_URI.startswith('postgres://'):
        SQLALCHEMY_DATABASE_URI = SQLALCHEMY_DATABASE_URI.replace('postgres://', 'postgresql://', 1)
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # File uploads
    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg'}
    
    # Email configuration
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@cybrscan.com')
    
    # Rate limiting
    RATELIMIT_STORAGE_URL = "memory://"
    RATELIMIT_DEFAULT = "100 per hour"
    RATELIMIT_HEADERS_ENABLED = True
    
    # Scanner defaults
    DEFAULT_SCAN_TIMEOUT = 30
    MAX_SCAN_TIMEOUT = 120
    
    # Subscription settings
    STRIPE_PUBLIC_KEY = os.environ.get('STRIPE_PUBLIC_KEY')
    STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY')
    STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET')
    
    # Application settings
    APP_NAME = "CybrScan"
    APP_URL = os.environ.get('APP_URL', 'http://localhost:5000')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@cybrscan.com')
    SUPPORT_EMAIL = os.environ.get('SUPPORT_EMAIL', 'support@cybrscan.com')
    
    # Feature flags
    ENABLE_REGISTRATION = True
    ENABLE_API = True
    ENABLE_CUSTOM_DOMAINS = True
    ENABLE_EMAIL_NOTIFICATIONS = True
    ENABLE_AUTO_COLOR_DETECTION = True
    
    # Security
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None
    
    # Subscription levels for app_modules compatibility
    SUBSCRIPTION_LEVELS = SUBSCRIPTION_LEVELS

class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

# Get the current configuration
def get_config():
    """Get the current configuration based on environment"""
    env = os.environ.get('FLASK_ENV', 'development')
    return config.get(env, config['default'])