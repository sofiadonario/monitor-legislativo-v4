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
def verify_deployment_files():
    """Verify essential files for Railway deployment exist"""
    print("🔍 Verifying essential deployment files...")
    required_files = ["minimal_app.py", "railway.json", "deps.txt"]
    
    missing_files = []
    for f in required_files:
        if os.path.exists(f):
            print(f"✅ {f} exists")
        else:
            print(f"❌ {f} missing")
            missing_files.append(f)

    if missing_files:
        print(f"❌ The following files are missing: {', '.join(missing_files)}")
    else:
        print("✅ All required files exist")

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