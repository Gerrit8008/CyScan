#!/bin/bash
# Start script for Render deployment
exec gunicorn wsgi:app --bind 0.0.0.0:${PORT:-10000}