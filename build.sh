#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create necessary directories
mkdir -p databases
mkdir -p uploads
mkdir -p logs

# Initialize database migrations if needed
if [ "$DATABASE_URL" ]; then
    echo "Initializing database..."
    python init_db.py
fi

echo "Build completed successfully!"