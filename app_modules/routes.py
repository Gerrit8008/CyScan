"""
Main Application Routes
"""

from flask import Blueprint, render_template, request, jsonify, redirect, url_for
from flask_login import current_user
from config import Config
import logging

logger = logging.getLogger(__name__)

main_bp = Blueprint('main', __name__, template_folder='../templates')

@main_bp.route('/')
def index():
    """Landing page"""
    return render_template('index.html', 
                         subscription_levels=Config.SUBSCRIPTION_LEVELS)

@main_bp.route('/pricing')
def pricing():
    """Pricing page"""
    return render_template('pricing.html', 
                         subscription_levels=Config.SUBSCRIPTION_LEVELS)

@main_bp.route('/features')
def features():
    """Features page"""
    return render_template('features.html')

@main_bp.route('/about')
def about():
    """About page"""
    return render_template('about.html')

@main_bp.route('/contact')
def contact():
    """Contact page"""
    return render_template('contact.html')

@main_bp.route('/demo')
def demo():
    """Demo scanner page"""
    demo_config = {
        'title': 'CybrScan Demo Scanner',
        'subtitle': 'Try our security scanning technology',
        'primary_color': '#007bff',
        'secondary_color': '#6c757d',
        'accent_color': '#28a745',
        'background_color': '#ffffff',
        'text_color': '#212529',
        'footer_text': 'Demo - Powered by CybrScan'
    }
    
    return render_template('scanner/demo.html', config=demo_config)

@main_bp.route('/demo/scan', methods=['POST'])
def demo_scan():
    """Demo scan endpoint"""
    target_url = request.json.get('url', '').strip()
    
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Basic URL validation
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
    
    # Demo scan results (simulated)
    demo_results = {
        'target': target_url,
        'scan_id': 'demo-scan-001',
        'status': 'completed',
        'timestamp': '2024-01-01T12:00:00Z',
        'vulnerabilities': [
            {
                'type': 'SSL Configuration',
                'severity': 'Medium',
                'description': 'SSL certificate expires in 30 days',
                'recommendation': 'Renew SSL certificate before expiration'
            },
            {
                'type': 'HTTP Headers',
                'severity': 'Low', 
                'description': 'Missing security headers detected',
                'recommendation': 'Add X-Frame-Options and Content-Security-Policy headers'
            }
        ],
        'open_ports': [80, 443],
        'server_info': {
            'server': 'nginx/1.18.0',
            'powered_by': 'Unknown'
        },
        'ssl_info': {
            'valid': True,
            'expires': '2024-12-31',
            'issuer': 'Let\'s Encrypt'
        },
        'risk_score': 25,
        'grade': 'B+'
    }
    
    return jsonify(demo_results)

@main_bp.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': '2024-01-01T12:00:00Z',
        'version': '1.0.0'
    })

@main_bp.route('/dashboard')
def dashboard_redirect():
    """Redirect to appropriate dashboard based on user role"""
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    
    if current_user.is_admin():
        return redirect(url_for('admin.dashboard'))
    else:
        return redirect(url_for('client.dashboard'))

@main_bp.app_errorhandler(404)
def not_found(error):
    """404 error handler"""
    return render_template('errors/404.html'), 404

@main_bp.app_errorhandler(500)
def internal_error(error):
    """500 error handler"""
    logger.error(f'Internal error: {error}')
    return render_template('errors/500.html'), 500

@main_bp.app_errorhandler(403)
def forbidden(error):
    """403 error handler"""
    return render_template('errors/403.html'), 403