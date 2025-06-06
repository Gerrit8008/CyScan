"""
Completely fresh CybrScan app with original functionality
Using a new filename to avoid any caching issues
"""
import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from scanner import SecurityScanner
import secrets
import re
from datetime import datetime

# Complete subscription tiers matching your pricing
SUBSCRIPTION_TIERS = {
    'basic': {
        'name': 'Basic',
        'price': 0.00,
        'period': 'forever',
        'description': 'Perfect for trying out our platform',
        'requires_payment': False,
        'features': {
            'scanners': 1,
            'scans_per_month': 10,
            'white_label': False,
            'branding': 'Basic branding',
            'reports': 'Email reports',
            'support': 'Community support',
            'api_access': False,
            'client_portal': False
        }
    },
    'starter': {
        'name': 'Starter',
        'price': 29.99,
        'period': 'month',
        'description': 'Great for small MSPs',
        'requires_payment': True,
        'features': {
            'scanners': 5,
            'scans_per_month': 100,
            'white_label': True,
            'branding': 'Custom branding',
            'reports': 'PDF & Email reports',
            'support': 'Email support',
            'api_access': True,
            'client_portal': True
        }
    },
    'professional': {
        'name': 'Professional',
        'price': 99.99,
        'period': 'month',
        'description': 'Perfect for growing MSPs',
        'requires_payment': True,
        'features': {
            'scanners': 25,
            'scans_per_month': 500,
            'white_label': True,
            'branding': 'Full custom branding',
            'reports': 'Advanced reporting',
            'support': 'Priority support',
            'api_access': True,
            'client_portal': True
        }
    },
    'enterprise': {
        'name': 'Enterprise',
        'price': 299.99,
        'period': 'month',
        'description': 'For large MSPs and agencies',
        'requires_payment': True,
        'features': {
            'scanners': 'unlimited',
            'scans_per_month': 'unlimited',
            'white_label': True,
            'branding': 'Complete white-label',
            'reports': 'Custom reporting & analytics',
            'support': '24/7 dedicated support',
            'api_access': True,
            'client_portal': True,
            'custom_integrations': True
        }
    }
}

# Create Flask app
app = Flask(__name__)

# Basic configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cybrscan-fresh-key')

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Simple User class for testing
class User(UserMixin):
    def __init__(self, id, username, email, password_hash):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = 'client'
        self.subscription_level = 'basic'
        self.company_name = 'Demo Company'
        self.next_billing_date = 'End of month'

# In-memory user storage for testing
users = {}
user_counter = 1

# Create demo accounts
def create_demo_accounts():
    global user_counter
    
    # Demo admin account
    admin_user = User('admin', 'admin', 'admin@cybrscan.com', generate_password_hash('admin123'))
    admin_user.role = 'admin'
    admin_user.subscription_level = 'enterprise'
    admin_user.company_name = 'CybrScan Admin'
    users['admin'] = admin_user
    
    # Demo client account  
    demo_user = User('demo', 'demo', 'demo@cybrscan.com', generate_password_hash('demo123'))
    demo_user.role = 'client'
    demo_user.subscription_level = 'professional'
    demo_user.company_name = 'Demo Company'
    users['demo'] = demo_user
    
    user_counter = 3

# Initialize demo accounts
create_demo_accounts()

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

# Routes using original templates
@app.route('/')
def index():
    """Landing page with original CybrScan design"""
    return render_template('index.html', subscription_levels=SUBSCRIPTION_TIERS)

@app.route('/pricing')
def pricing():
    """Pricing page"""
    return render_template('pricing.html', subscription_levels=SUBSCRIPTION_TIERS)

@app.route('/health')
def health():
    return {
        "status": "healthy",
        "app": "CybrScan Fresh",
        "templates": "Using original templates",
        "scanner": "Available"
    }

# Scanner API endpoint
@app.route('/api/scan', methods=['POST'])
def scan_website():
    """Perform a security scan on a website"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url']
        
        # Initialize scanner
        scanner = SecurityScanner()
        
        # Perform scan
        scan_results = scanner.comprehensive_scan(url)
        
        return jsonify({
            'success': True,
            'url': url,
            'results': scan_results,
            'timestamp': scan_results.get('timestamp')
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Demo scanner page
@app.route('/demo')
def demo_scanner():
    """Demo scanner page"""
    return render_template('scanner/demo.html') if os.path.exists('templates/scanner/demo.html') else jsonify({'error': 'Demo template not found'})

# Authentication routes
@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        company_name = request.form.get('company_name', '').strip()
        
        # Basic validation
        if not email or not username or not password:
            flash('All fields are required', 'error')
            return render_template('auth/register.html', subscription_tiers=SUBSCRIPTION_TIERS)
        
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('Invalid email address', 'error')
            return render_template('auth/register.html', subscription_tiers=SUBSCRIPTION_TIERS)
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return render_template('auth/register.html', subscription_tiers=SUBSCRIPTION_TIERS)
        
        # Check if user already exists
        for user in users.values():
            if user.email == email:
                flash('Email already registered', 'error')
                return render_template('auth/register.html', subscription_tiers=SUBSCRIPTION_TIERS)
        
        # Create new user
        global user_counter
        user_id = str(user_counter)
        password_hash = generate_password_hash(password)
        
        new_user = User(user_id, username, email, password_hash)
        users[user_id] = new_user
        user_counter += 1
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('auth/register.html', subscription_tiers=SUBSCRIPTION_TIERS)

@app.route('/auth/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        if not email or not password:
            flash('Email and password are required', 'error')
            return render_template('auth/login.html')
        
        # Find user by email
        user = None
        for u in users.values():
            if u.email == email:
                user = u
                break
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('auth/login.html')

@app.route('/auth/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    return render_template('client/client-dashboard.html', 
                         user=current_user,
                         scans_used=5,
                         scans_limit=100,
                         scanners_count=2,
                         recent_scans=[],
                         subscription_levels=SUBSCRIPTION_TIERS)

@app.route('/client/dashboard')
@login_required
def client_dashboard():
    """Client dashboard (alternative route)"""
    return render_template('client/client-dashboard.html', user=current_user)

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    """Admin dashboard"""
    if current_user.role != 'admin':
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    return render_template('admin/admin-dashboard.html', user=current_user)

# Login info route
@app.route('/login-info')
def login_info():
    """Show demo login credentials"""
    return jsonify({
        'demo_accounts': {
            'admin': {
                'email': 'admin@cybrscan.com',
                'password': 'admin123',
                'role': 'admin',
                'access': 'Full admin dashboard and settings'
            },
            'demo': {
                'email': 'demo@cybrscan.com', 
                'password': 'demo123',
                'role': 'client',
                'access': 'Client dashboard and scanner management'
            }
        },
        'note': 'These are demo accounts for testing purposes'
    })

if __name__ == '__main__':
    app.run(debug=True)