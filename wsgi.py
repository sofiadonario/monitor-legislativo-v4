"""
WSGI/ASGI entry point for Railway deployment
Ultra-Budget Academic Deployment - Monitor Legislativo v4
"""

import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import the FastAPI app
from web.main import app

# Expose the app for gunicorn (this is what Railway calls)
application = app

if __name__ == "__main__":
    # Fallback for direct execution
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)