"""
Completely fresh CybrScan app with original functionality
Using a new filename to avoid any caching issues
"""
import os
from flask import Flask, render_template
from flask_login import LoginManager

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
        "templates": "Using original templates"
    }

if __name__ == '__main__':
    app.run(debug=True)