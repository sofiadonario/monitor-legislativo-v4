#!/bin/bash
# Railway deployment start script
# Ultra-Budget Academic Deployment

echo "Starting Monitor Legislativo v4 API..."
echo "PORT: $PORT"
echo "Environment: Production"
echo "Python path: $(which python)"
echo "Python version: $(python --version)"

# Check if gunicorn module is available
if python -c "import gunicorn" 2>/dev/null; then
    echo "Using gunicorn with uvicorn workers..."
    exec python -m gunicorn wsgi:application \
        --bind 0.0.0.0:${PORT:-8000} \
        --worker-class uvicorn.workers.UvicornWorker \
        --workers 1 \
        --timeout 120 \
        --log-level info
else
    echo "Gunicorn not found, fallback to uvicorn..."
    exec python -m uvicorn web.main:app \
        --host 0.0.0.0 \
        --port ${PORT:-8000} \
        --workers 1 \
        --log-level info
fi