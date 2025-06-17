#!/usr/bin/env python3
"""
Verify Railway deployment setup
"""

import sys
import os

print("🔍 Railway Deployment Verification")
print("=" * 50)

# Check Python version
print(f"Python version: {sys.version}")
print(f"Python executable: {sys.executable}")

# Check working directory
print(f"Working directory: {os.getcwd()}")

# Check environment variables
port = os.getenv("PORT", "NOT_SET")
print(f"PORT environment variable: {port}")

# Check required files exist
required_files = ["minimal_app.py", "Procfile", "railway.json", "requirements.txt"]
for file in required_files:
    if os.path.exists(file):
        print(f"✅ {file} exists")
    else:
        print(f"❌ {file} missing")

# Check if we can import required packages
try:
    import fastapi
    print(f"✅ FastAPI version: {fastapi.__version__}")
except ImportError:
    print("❌ FastAPI not installed")

try:
    import uvicorn
    print(f"✅ Uvicorn version: {uvicorn.__version__}")
except ImportError:
    print("❌ Uvicorn not installed")

# Check if minimal app can be imported
try:
    from minimal_app import app
    print("✅ minimal_app.py imports successfully")
except Exception as e:
    print(f"❌ minimal_app.py import failed: {e}")

print("=" * 50)
print("✅ Verification complete")