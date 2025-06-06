"""
WSGI entry point for production deployment
"""
from app import app

# Expose app at module level for gunicorn
application = app

if __name__ == "__main__":
    app.run()