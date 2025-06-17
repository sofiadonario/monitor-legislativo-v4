#!/bin/bash
# Universal Railway startup script
echo "🚀 Starting Monitor Legislativo v4..."

# Try to find Python in various locations
PYTHON_CMD=""

# Check common Python locations
for py_path in "/opt/venv/bin/python" "/usr/local/bin/python3" "/usr/bin/python3" "python3" "python"; do
    if command -v "$py_path" &> /dev/null; then
        PYTHON_CMD="$py_path"
        echo "✅ Found Python at: $PYTHON_CMD"
        break
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    echo "❌ Python not found! Checking PATH..."
    echo "PATH: $PATH"
    which python3 || which python || echo "No python found in PATH"
    exit 1
fi

# Show Python version
echo "🐍 Python version: $($PYTHON_CMD --version)"

# Show working directory and files
echo "📁 Working directory: $(pwd)"
echo "📄 Files present:"
ls -la

# Try to run uvicorn with the found Python
echo "🌟 Starting uvicorn..."
exec "$PYTHON_CMD" -m uvicorn minimal_app:app --host 0.0.0.0 --port ${PORT:-8000} --log-level info