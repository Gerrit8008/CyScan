#!/usr/bin/env python3
"""
Simple startup script for CybrScan - Development Mode
"""

import os
import sys
from flask import Flask, render_template, request, jsonify

# Basic Flask app setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'
app.config['DEBUG'] = True

# Basic routes for testing
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({'status': 'healthy', 'message': 'CybrScan is running!'})

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/auth/register')
def register():
    return render_template('auth/register.html')

@app.route('/auth/login')
def login():
    return render_template('auth/login.html')

if __name__ == '__main__':
    print("🚀 Starting CybrScan Development Server...")
    print("📍 Access the application at: http://localhost:5000")
    print("📍 Health check: http://localhost:5000/health")
    print("📍 Pricing page: http://localhost:5000/pricing")
    print("📍 Press Ctrl+C to stop the server")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        use_reloader=True
    )