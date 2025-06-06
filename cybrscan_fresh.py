"""
Completely fresh CybrScan app with original functionality
Using a new filename to avoid any caching issues
"""
import os
from flask import Flask, render_template, request, jsonify
from flask_login import LoginManager
from scanner import SecurityScanner

# Create Flask app
app = Flask(__name__)

# Basic configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cybrscan-fresh-key')

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

@login_manager.user_loader
def load_user(user_id):
    return None

# Routes using original templates
@app.route('/')
def index():
    """Landing page with original CybrScan design"""
    return render_template('index.html', subscription_levels={})

@app.route('/pricing')
def pricing():
    """Pricing page"""
    return render_template('pricing.html', subscription_levels={})

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

if __name__ == '__main__':
    app.run(debug=True)