#!/bin/bash
# Railway deployment start script
# Ultra-Budget Academic Deployment

echo "Starting Monitor Legislativo v4 API..."
echo "PORT: $PORT"
echo "Environment: Production"

# Check if gunicorn is available
if command -v gunicorn &> /dev/null; then
    echo "Using gunicorn with uvicorn workers..."
    exec gunicorn wsgi:application \
        --bind 0.0.0.0:${PORT:-8000} \
        --worker-class uvicorn.workers.UvicornWorker \
        --workers 1 \
        --timeout 120 \
        --log-level info
else
    echo "Fallback to uvicorn..."
    exec python -m uvicorn web.main:app \
        --host 0.0.0.0 \
        --port ${PORT:-8000} \
        --workers 1 \
        --log-level info
fi