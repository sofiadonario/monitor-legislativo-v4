#!/usr/bin/env python3
"""
Railway deployment start script for Monitor Legislativo v4
Ultra-Budget Academic Deployment
"""

import os
import sys
import subprocess
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def main():
    port = os.getenv("PORT", "8000")
    
    print(f"Starting Monitor Legislativo v4 API on port {port}...")
    print(f"Python: {sys.executable}")
    print(f"Python version: {sys.version}")
    print(f"Working directory: {os.getcwd()}")
    
    # Try gunicorn first (preferred for production)
    try:
        import gunicorn
        print("✅ Gunicorn found - using gunicorn with uvicorn workers")
        
        cmd = [
            sys.executable, "-m", "gunicorn",
            "wsgi:application",
            "--bind", f"0.0.0.0:{port}",
            "--worker-class", "uvicorn.workers.UvicornWorker",
            "--workers", "1",
            "--timeout", "120",
            "--max-requests", "1000",
            "--log-level", "info",
            "--preload"
        ]
        
        print(f"Command: {' '.join(cmd)}")
        subprocess.run(cmd, check=True)
        
    except ImportError:
        print("❌ Gunicorn not found - falling back to uvicorn")
        
        try:
            import uvicorn
            print("✅ Uvicorn found - using uvicorn directly")
            
            # Import the app
            from web.main import app
            
            uvicorn.run(
                app,
                host="0.0.0.0",
                port=int(port),
                log_level="info"
            )
            
        except ImportError:
            print("❌ Neither gunicorn nor uvicorn found!")
            print("📦 Installed packages:")
            subprocess.run([sys.executable, "-m", "pip", "list"], check=False)
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        print("📦 Installed packages:")
        subprocess.run([sys.executable, "-m", "pip", "list"], check=False)
        sys.exit(1)

if __name__ == "__main__":
    main()