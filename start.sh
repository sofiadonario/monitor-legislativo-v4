#!/bin/bash
# Railway deployment start script
# Ultra-Budget Academic Deployment

echo "Starting Monitor Legislativo v4 API..."
echo "PORT: $PORT"
echo "Environment: Production"

# Start with uvicorn (preferred)
exec python -m uvicorn web.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1 --log-level info