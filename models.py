from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import string

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    company_name = db.Column(db.String(200))
    phone = db.Column(db.String(20))
    role = db.Column(db.String(20), default='client')  # admin or client
    subscription_level = db.Column(db.String(20), default='basic')  # basic, starter, professional, enterprise
    subscription_tier = db.Column(db.String(20), default='basic')  # Legacy support
    subscription_status = db.Column(db.String(20), default='active')  # active, cancelled, expired, past_due
    subscription_start_date = db.Column(db.DateTime)
    next_billing_date = db.Column(db.DateTime)
    stripe_customer_id = db.Column(db.String(100))
    stripe_subscription_id = db.Column(db.String(100))
    api_key = db.Column(db.String(64), unique=True)
    scanners_used = db.Column(db.Integer, default=0)
    scans_this_month = db.Column(db.Integer, default=0)
    last_scan_reset = db.Column(db.DateTime, default=datetime.utcnow)
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    scanners = db.relationship('Scanner', backref='owner', lazy='dynamic', cascade='all, delete-orphan')
    scans = db.relationship('Scan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    subscription_history = db.relationship('SubscriptionHistory', backref='user', lazy='dynamic')
    billing_transactions = db.relationship('BillingTransaction', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_api_key(self):
        alphabet = string.ascii_letters + string.digits
        self.api_key = ''.join(secrets.choice(alphabet) for _ in range(64))
        return self.api_key
    
    def reset_monthly_usage(self):
        self.scans_this_month = 0
        self.last_scan_reset = datetime.utcnow()
    
    def increment_scan_count(self):
        self.scans_this_month += 1
    
    def can_create_scanner(self):
        from subscription_constants import get_scanner_limit, is_unlimited
        if is_unlimited(self.subscription_tier, 'scanner_limit'):
            return True
        limit = get_scanner_limit(self.subscription_tier)
        return self.scanners_used < limit
    
    def can_perform_scan(self):
        from subscription_constants import get_scan_limit, is_unlimited
        if is_unlimited(self.subscription_tier, 'scans_per_month'):
            return True
        limit = get_scan_limit(self.subscription_tier)
        return self.scans_this_month < limit

class Scanner(db.Model):
    __tablename__ = 'scanners'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    api_key = db.Column(db.String(64), unique=True, nullable=False)
    
    # Customization
    logo_url = db.Column(db.String(500))
    favicon_url = db.Column(db.String(500))
    primary_color = db.Column(db.String(7), default='#2563eb')
    secondary_color = db.Column(db.String(7), default='#1e40af')
    accent_color = db.Column(db.String(7), default='#3b82f6')
    background_color = db.Column(db.String(7), default='#ffffff')
    text_color = db.Column(db.String(7), default='#1f2937')
    button_color = db.Column(db.String(7), default='#2563eb')
    button_text_color = db.Column(db.String(7), default='#ffffff')
    
    # Branding
    title = db.Column(db.String(200), default='Security Scanner')
    subtitle = db.Column(db.String(500))
    footer_text = db.Column(db.String(500))
    custom_css = db.Column(db.Text)
    auto_detect_colors = db.Column(db.Boolean, default=True)
    
    # Settings
    is_active = db.Column(db.Boolean, default=True)
    custom_domain = db.Column(db.String(200))
    webhook_url = db.Column(db.String(500))
    notification_email = db.Column(db.String(120))
    scan_timeout = db.Column(db.Integer, default=30)
    
    # Features
    enable_ssl_scan = db.Column(db.Boolean, default=True)
    enable_port_scan = db.Column(db.Boolean, default=True)
    enable_dns_scan = db.Column(db.Boolean, default=True)
    enable_header_scan = db.Column(db.Boolean, default=True)
    enable_vulnerability_scan = db.Column(db.Boolean, default=True)
    
    # Statistics
    total_scans = db.Column(db.Integer, default=0)
    unique_domains_scanned = db.Column(db.Integer, default=0)
    last_scan_at = db.Column(db.DateTime)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scans = db.relationship('Scan', backref='scanner', lazy='dynamic', cascade='all, delete-orphan')
    customizations = db.relationship('ScannerCustomization', backref='scanner', lazy='dynamic')
    
    def generate_api_key(self):
        alphabet = string.ascii_letters + string.digits
        self.api_key = ''.join(secrets.choice(alphabet) for _ in range(64))
        return self.api_key
    
    def increment_scan_count(self):
        self.total_scans += 1
        self.last_scan_at = datetime.utcnow()

class Scan(db.Model):
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    scanner_id = db.Column(db.Integer, db.ForeignKey('scanners.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    domain = db.Column(db.String(255), nullable=False, index=True)
    scan_id = db.Column(db.String(100), unique=True, nullable=False)
    
    # Contact info (for lead generation)
    contact_name = db.Column(db.String(200))
    contact_email = db.Column(db.String(120))
    contact_phone = db.Column(db.String(20))
    contact_company = db.Column(db.String(200))
    
    # Scan results
    status = db.Column(db.String(20), default='pending')  # pending, scanning, completed, failed
    risk_score = db.Column(db.Integer, default=0)
    vulnerabilities_found = db.Column(db.Integer, default=0)
    
    # Detailed results (JSON)
    ssl_results = db.Column(db.JSON)
    port_results = db.Column(db.JSON)
    dns_results = db.Column(db.JSON)
    header_results = db.Column(db.JSON)
    vulnerability_results = db.Column(db.JSON)
    
    # Metadata
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    referer = db.Column(db.String(500))
    scan_duration = db.Column(db.Float)
    error_message = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    completed_at = db.Column(db.DateTime)
    
    def calculate_risk_score(self):
        score = 100
        vulnerabilities = 0
        
        # SSL scoring
        if self.ssl_results:
            if not self.ssl_results.get('valid', False):
                score -= 20
                vulnerabilities += 1
            if self.ssl_results.get('expired', False):
                score -= 15
                vulnerabilities += 1
        
        # Port scoring
        if self.port_results:
            open_ports = self.port_results.get('open_ports', [])
            risky_ports = [21, 23, 135, 139, 445, 3389]  # FTP, Telnet, RPC, SMB, RDP
            for port in open_ports:
                if port in risky_ports:
                    score -= 10
                    vulnerabilities += 1
        
        # Header scoring
        if self.header_results:
            missing_headers = self.header_results.get('missing', [])
            critical_headers = ['X-Frame-Options', 'Content-Security-Policy', 'Strict-Transport-Security']
            for header in critical_headers:
                if header in missing_headers:
                    score -= 5
                    vulnerabilities += 1
        
        self.risk_score = max(0, score)
        self.vulnerabilities_found = vulnerabilities

class ScannerCustomization(db.Model):
    __tablename__ = 'scanner_customizations'
    
    id = db.Column(db.Integer, primary_key=True)
    scanner_id = db.Column(db.Integer, db.ForeignKey('scanners.id'), nullable=False)
    domain = db.Column(db.String(255), nullable=False)
    
    # Auto-detected colors
    detected_primary_color = db.Column(db.String(7))
    detected_secondary_color = db.Column(db.String(7))
    detected_accent_color = db.Column(db.String(7))
    detected_logo_url = db.Column(db.String(500))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SubscriptionHistory(db.Model):
    __tablename__ = 'subscription_history'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    old_tier = db.Column(db.String(20))
    new_tier = db.Column(db.String(20), nullable=False)
    action = db.Column(db.String(50))  # upgrade, downgrade, cancel, reactivate
    stripe_event_id = db.Column(db.String(100))
    amount = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AdminSettings(db.Model):
    __tablename__ = 'admin_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text)
    description = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @staticmethod
    def get(key, default=None):
        setting = AdminSettings.query.filter_by(key=key).first()
        return setting.value if setting else default
    
    @staticmethod
    def set(key, value, description=None):
        setting = AdminSettings.query.filter_by(key=key).first()
        if setting:
            setting.value = value
            if description:
                setting.description = description
        else:
            setting = AdminSettings(key=key, value=value, description=description)
            db.session.add(setting)
        db.session.commit()

class BillingTransaction(db.Model):
    __tablename__ = 'billing_transactions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Transaction details
    amount = db.Column(db.Float, nullable=False)
    currency = db.Column(db.String(3), default='USD')
    subscription_level = db.Column(db.String(20))
    transaction_type = db.Column(db.String(20), default='subscription')  # subscription, commission, refund
    
    # Stripe information
    stripe_session_id = db.Column(db.String(100))
    stripe_payment_intent_id = db.Column(db.String(100))
    stripe_invoice_id = db.Column(db.String(100))
    
    # Status tracking
    status = db.Column(db.String(20), default='pending')  # pending, completed, failed, refunded
    
    # Metadata
    description = db.Column(db.Text)
    transaction_metadata = db.Column(db.JSON)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    processed_at = db.Column(db.DateTime)
    
    def __repr__(self):
        return f'<BillingTransaction {self.id}: {self.amount} {self.currency} - {self.status}>'

class Lead(db.Model):
    __tablename__ = 'leads'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # MSP owner
    scanner_id = db.Column(db.Integer, db.ForeignKey('scanners.id'), nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'))
    
    # Lead information
    name = db.Column(db.String(200))
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20))
    company = db.Column(db.String(200))
    website = db.Column(db.String(255))
    
    # Lead scoring
    lead_score = db.Column(db.Integer, default=0)
    lead_source = db.Column(db.String(100), default='scanner')  # scanner, referral, organic
    lead_status = db.Column(db.String(20), default='new')  # new, contacted, qualified, converted, lost
    
    # Interaction tracking
    first_scan_date = db.Column(db.DateTime)
    last_interaction = db.Column(db.DateTime)
    total_scans = db.Column(db.Integer, default=1)
    
    # Conversion tracking
    converted_to_client = db.Column(db.Boolean, default=False)
    conversion_date = db.Column(db.DateTime)
    estimated_value = db.Column(db.Float)
    
    # Metadata
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    referer = db.Column(db.String(500))
    utm_source = db.Column(db.String(100))
    utm_medium = db.Column(db.String(100))
    utm_campaign = db.Column(db.String(100))
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='leads')
    scanner = db.relationship('Scanner', backref='leads')
    scan = db.relationship('Scan', backref='lead', uselist=False)
    
    def calculate_lead_score(self):
        """Calculate lead score based on various factors"""
        score = 0
        
        # Company website provided
        if self.website:
            score += 20
            
        # Phone number provided
        if self.phone:
            score += 15
            
        # Company name provided
        if self.company:
            score += 25
            
        # Multiple scans (shows interest)
        if self.total_scans > 1:
            score += (self.total_scans - 1) * 10
            
        # Recent activity
        if self.last_interaction:
            days_since_interaction = (datetime.utcnow() - self.last_interaction).days
            if days_since_interaction <= 7:
                score += 20
            elif days_since_interaction <= 30:
                score += 10
        
        self.lead_score = min(100, score)
        return self.lead_score