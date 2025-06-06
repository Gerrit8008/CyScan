#!/bin/bash
echo "Verifying project structure..."

# Check for problematic directories
if [ -d "app" ]; then
    echo "ERROR: 'app' directory exists! This will conflict with app.py"
    exit 1
fi

# Check for required files
for file in "app.py" "wsgi.py" "config.py" "models.py" "requirements.txt" "render.yaml"; do
    if [ ! -f "$file" ]; then
        echo "ERROR: Required file '$file' is missing!"
        exit 1
    fi
done

echo "✓ Project structure looks good!"
echo "✓ No 'app' directory found (good!)"
echo "✓ All required files present"

# List main files
echo -e "\nMain application files:"
ls -la *.py | grep -E "(app|wsgi|config|models)\.py"