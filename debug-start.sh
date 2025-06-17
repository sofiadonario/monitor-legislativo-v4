#!/bin/bash
echo "🔍 Railway Environment Debug"
echo "=========================="

echo "🌍 Environment Variables:"
env | sort

echo "🐍 Python Search:"
find / -name "python*" -type f 2>/dev/null | head -20

echo "📦 Package Search:"
find / -name "uvicorn*" -type f 2>/dev/null | head -10

echo "💻 System Info:"
uname -a
cat /etc/os-release 2>/dev/null || echo "No OS release info"

echo "📁 Current Directory:"
pwd
ls -la

echo "🔗 PATH:"
echo $PATH

echo "🛠️ Available Commands:"
which python3 2>/dev/null || echo "python3 not in PATH"
which python 2>/dev/null || echo "python not in PATH"
which pip3 2>/dev/null || echo "pip3 not in PATH"
which uvicorn 2>/dev/null || echo "uvicorn not in PATH"

# Try manual uvicorn installation
echo "📥 Trying pip install uvicorn..."
python3 -m pip install uvicorn 2>&1 || echo "pip install failed"

# Try running uvicorn
echo "🚀 Attempting to start uvicorn..."
python3 -m uvicorn minimal_app:app --host 0.0.0.0 --port ${PORT:-8000}