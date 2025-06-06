"""
CybrScan Data Models
"""

from flask_login import UserMixin
from database.db_manager import get_user_by_id, get_user_by_email, verify_password
from datetime import datetime, timedelta
import json

class User(UserMixin):
    """User model for Flask-Login"""
    
    def __init__(self, user_data):
        self.id = user_data['id']
        self.username = user_data['username']
        self.email = user_data['email']
        self.password_hash = user_data['password_hash']
        self.salt = user_data['salt']
        self.role = user_data['role']
        self.subscription_level = user_data['subscription_level']
        self.full_name = user_data.get('full_name')
        self.company = user_data.get('company')
        self.phone = user_data.get('phone')
        self.created_at = user_data['created_at']
        self.last_login = user_data.get('last_login')
        self.is_active = bool(user_data['is_active'])
        self.email_verified = bool(user_data.get('email_verified', 0))
        self.subscription_expires = user_data.get('subscription_expires')
        self.monthly_scans_used = user_data.get('monthly_scans_used', 0)
        self.monthly_scans_reset = user_data.get('monthly_scans_reset')
        self.payment_method_id = user_data.get('payment_method_id')
    
    def get_id(self):
        """Return user ID as string for Flask-Login"""
        return str(self.id)
    
    def is_admin(self):
        """Check if user is admin"""
        return self.role == 'admin'
    
    def check_password(self, password):
        """Verify password"""
        return verify_password(password, self.password_hash, self.salt)
    
    def can_scan(self):
        """Check if user can perform scans based on subscription"""
        from config import Config
        
        subscription_info = Config.SUBSCRIPTION_LEVELS.get(self.subscription_level, {})
        monthly_limit = subscription_info.get('monthly_scans', 0)
        
        if monthly_limit == -1:  # Unlimited
            return True
        
        # Check if monthly reset is needed
        if self.monthly_scans_reset:
            reset_date = datetime.fromisoformat(self.monthly_scans_reset)
            if datetime.now() > reset_date:
                # Reset monthly usage
                self.reset_monthly_scans()
                return True
        
        return self.monthly_scans_used < monthly_limit
    
    def reset_monthly_scans(self):
        """Reset monthly scan count"""
        from database.db_manager import get_db_connection
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            next_reset = datetime.now() + timedelta(days=30)
            cursor.execute('''
                UPDATE users 
                SET monthly_scans_used = 0, monthly_scans_reset = ?
                WHERE id = ?
            ''', (next_reset.isoformat(), self.id))
            conn.commit()
            
            self.monthly_scans_used = 0
            self.monthly_scans_reset = next_reset.isoformat()
            
        finally:
            conn.close()
    
    def increment_scan_count(self):
        """Increment monthly scan count"""
        from database.db_manager import get_db_connection
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE users 
                SET monthly_scans_used = monthly_scans_used + 1
                WHERE id = ?
            ''', (self.id,))
            conn.commit()
            
            self.monthly_scans_used += 1
            
        finally:
            conn.close()
    
    def get_subscription_info(self):
        """Get subscription information"""
        from config import Config
        return Config.SUBSCRIPTION_LEVELS.get(self.subscription_level, {})
    
    def get_remaining_scans(self):
        """Get remaining scans for this month"""
        subscription_info = self.get_subscription_info()
        monthly_limit = subscription_info.get('monthly_scans', 0)
        
        if monthly_limit == -1:
            return -1  # Unlimited
        
        return max(0, monthly_limit - self.monthly_scans_used)
    
    @staticmethod
    def get_by_id(user_id):
        """Get user by ID"""
        user_data = get_user_by_id(user_id)
        return User(user_data) if user_data else None
    
    @staticmethod
    def get_by_email(email):
        """Get user by email"""
        user_data = get_user_by_email(email)
        return User(user_data) if user_data else None
    
    def to_dict(self):
        """Convert user to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'subscription_level': self.subscription_level,
            'full_name': self.full_name,
            'company': self.company,
            'phone': self.phone,
            'created_at': self.created_at,
            'last_login': self.last_login,
            'is_active': self.is_active,
            'email_verified': self.email_verified,
            'subscription_expires': self.subscription_expires,
            'monthly_scans_used': self.monthly_scans_used,
            'remaining_scans': self.get_remaining_scans()
        }


class Scanner:
    """Scanner model"""
    
    def __init__(self, scanner_data):
        self.id = scanner_data['id']
        self.user_id = scanner_data['user_id']
        self.name = scanner_data['name']
        self.description = scanner_data.get('description')
        self.api_key = scanner_data['api_key']
        
        # Customization
        self.logo_url = scanner_data.get('logo_url')
        self.favicon_url = scanner_data.get('favicon_url')
        self.primary_color = scanner_data.get('primary_color', '#007bff')
        self.secondary_color = scanner_data.get('secondary_color', '#6c757d')
        self.accent_color = scanner_data.get('accent_color', '#28a745')
        self.background_color = scanner_data.get('background_color', '#ffffff')
        self.text_color = scanner_data.get('text_color', '#212529')
        
        self.title = scanner_data.get('title', 'Security Scanner')
        self.subtitle = scanner_data.get('subtitle', 'Powered by CybrScan')
        self.footer_text = scanner_data.get('footer_text', 'Professional Security Assessment')
        
        # Advanced customization
        self.css_overrides = scanner_data.get('css_overrides')
        self.custom_domain = scanner_data.get('custom_domain')
        self.auto_color_detection = bool(scanner_data.get('auto_color_detection', 1))
        
        # Scanner settings
        try:
            self.scan_types = json.loads(scanner_data.get('scan_types', '["basic", "ssl", "ports"]'))
        except:
            self.scan_types = ["basic", "ssl", "ports"]
        
        self.max_targets = scanner_data.get('max_targets', 1)
        self.timeout_seconds = scanner_data.get('timeout_seconds', 30)
        
        self.created_at = scanner_data['created_at']
        self.updated_at = scanner_data.get('updated_at')
        self.is_active = bool(scanner_data.get('is_active', 1))
    
    def get_css_variables(self):
        """Generate CSS variables for customization"""
        return {
            '--primary-color': self.primary_color,
            '--secondary-color': self.secondary_color,
            '--accent-color': self.accent_color,
            '--background-color': self.background_color,
            '--text-color': self.text_color,
        }
    
    def to_dict(self):
        """Convert scanner to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'description': self.description,
            'api_key': self.api_key,
            'logo_url': self.logo_url,
            'favicon_url': self.favicon_url,
            'primary_color': self.primary_color,
            'secondary_color': self.secondary_color,
            'accent_color': self.accent_color,
            'background_color': self.background_color,
            'text_color': self.text_color,
            'title': self.title,
            'subtitle': self.subtitle,
            'footer_text': self.footer_text,
            'css_overrides': self.css_overrides,
            'custom_domain': self.custom_domain,
            'auto_color_detection': self.auto_color_detection,
            'scan_types': self.scan_types,
            'max_targets': self.max_targets,
            'timeout_seconds': self.timeout_seconds,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'is_active': self.is_active
        }