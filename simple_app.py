#!/usr/bin/env python3
"""
Ultra-simple Flask app for Render deployment testing
"""

def application(environ, start_response):
    """Simple WSGI application"""
    status = '200 OK'
    headers = [('Content-type', 'text/html')]
    start_response(status, headers)
    
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>CybrScan - Deployment Test</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            .success { color: #28a745; }
            .info { color: #17a2b8; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1 class="success">✅ CybrScan Deployment Successful!</h1>
            <p>Your application is running on Render.com</p>
            <div class="info">
                <h3>Environment Information:</h3>
                <ul>
                    <li>Status: Healthy</li>
                    <li>Platform: Render.com</li>
                    <li>Runtime: Python 3.11</li>
                    <li>Server: Gunicorn</li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """
    
    return [html.encode('utf-8')]

# Also provide Flask-style import for compatibility
try:
    from flask import Flask
    app = Flask(__name__)
    
    @app.route('/')
    def index():
        return """
        <h1 style="color: green;">✅ CybrScan is Running!</h1>
        <p>Deployment successful on Render.com</p>
        <p><a href="/health">Health Check</a></p>
        """
    
    @app.route('/health')
    def health():
        return {"status": "healthy", "message": "CybrScan deployment successful"}
        
except ImportError:
    # Fallback if Flask is not available
    app = None

if __name__ == '__main__':
    # For testing
    if app:
        app.run(host='0.0.0.0', port=5000)
    else:
        print("Flask not available, using WSGI application")