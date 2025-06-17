"""
WSGI entry point for gunicorn deployment
Railway Ultra-Budget Academic Deployment
"""

import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import the FastAPI app
from web.main import app

# Expose the app for gunicorn
application = app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)