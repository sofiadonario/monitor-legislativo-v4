#!/usr/bin/env python3
"""
Railway deployment start script for Monitor Legislativo v4
Ultra-Budget Academic Deployment
"""

import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def main():
    port = int(os.getenv("PORT", "8000"))
    
    print(f"🚀 Starting Monitor Legislativo v4 API on port {port}...")
    print(f"📍 Working directory: {os.getcwd()}")
    print(f"🐍 Python: {sys.executable}")
    
    try:
        # Simple uvicorn approach - most reliable for Railway
        import uvicorn
        print("✅ Using uvicorn server")
        
        # Try importing the main app first, fall back to minimal
        try:
            from web.main import app
            print("✅ Main FastAPI app imported successfully")
        except Exception as e:
            print(f"⚠️ Main app import failed: {e}")
            print("🔄 Using minimal app as fallback")
            from minimal_app import app
        
        # Start the server
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=port,
            log_level="info",
            access_log=True
        )
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("📦 Available packages:")
        import subprocess
        subprocess.run([sys.executable, "-m", "pip", "list"], check=False)
        sys.exit(1)
        
    except Exception as e:
        print(f"❌ Startup error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()