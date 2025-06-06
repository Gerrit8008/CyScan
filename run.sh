#!/bin/bash
# Force the correct gunicorn command
echo "🚀 Starting CybrScan with correct configuration..."
exec gunicorn simple_app:application --bind 0.0.0.0:${PORT:-10000}