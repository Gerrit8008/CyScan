"""
Super minimal test app to isolate the config.settings issue
"""
import os
from flask import Flask

# Create a minimal Flask app with just the basics
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'test-key')

@app.route('/')
def index():
    return """
    <h1>🧪 CybrScan - Super Minimal Test</h1>
    <p>This is a test to isolate the config.settings import issue.</p>
    <p>If you see this, Flask is working correctly.</p>
    """

@app.route('/health')
def health():
    return {"status": "working", "test": "super minimal app"}

if __name__ == '__main__':
    app.run(debug=True)