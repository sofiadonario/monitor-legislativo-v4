FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements from parent directory
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy core modules
COPY core/ ./core/

# Copy main app
COPY main_app/ ./main_app/

# Copy src data directory with legislative data
COPY src/ ./src/

# Copy public directory with CSV data files
COPY public/ ./public/

# Set Python path to include core, main_app, and src
ENV PYTHONPATH=/app:/app/core:/app/main_app:/app/src
ENV PYTHONUNBUFFERED=1

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

# Start the application - use PORT env var from Railway
CMD uvicorn main_app.main:app --host 0.0.0.0 --port ${PORT:-8000}