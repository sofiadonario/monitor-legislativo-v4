"""
ASGI entry point for uvicorn deployment
Railway Ultra-Budget Academic Deployment
"""

import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import the FastAPI app
from web.main import app

# Expose the app for uvicorn/asgi servers
application = app