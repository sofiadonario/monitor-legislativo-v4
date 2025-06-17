# Multi-stage Dockerfile for Desktop Service
# Optimized for small image size and build caching

# Stage 1: Python base
FROM python:3.11-slim-bullseye as python-base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DISPLAY=:99

# Install system dependencies for GUI applications
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    build-essential \
    curl \
    git \
    xvfb \
    x11-apps \
    python3-tk \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1001 appuser && \
    useradd --uid 1001 --gid appuser --shell /bin/bash --create-home appuser

# Stage 2: Dependencies
FROM python-base as deps

# Copy requirements from project root and desktop
COPY requirements*.txt ./
COPY desktop/requirements*.txt ./desktop/ 2>/dev/null || true

# Install Python dependencies
COPY deps.txt .
RUN pip install --user -r deps.txt && \
    ([ -f desktop/requirements.txt ] && pip install --user -r desktop/requirements.txt || true)

# Stage 3: Production
FROM python-base as production

# Copy dependencies
COPY --from=deps /root/.local /home/appuser/.local

# Make sure scripts in .local are usable
ENV PATH=/home/appuser/.local/bin:$PATH

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=appuser:appuser core/ ./core/
COPY --chown=appuser:appuser desktop/ ./desktop/

# Create necessary directories
RUN mkdir -p logs data cache tmp && \
    chown -R appuser:appuser logs data cache tmp

# Switch to non-root user
USER appuser

# Health check (for CLI applications)
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python desktop/main.py --version || exit 1

# Set default environment variables
ENV LOG_LEVEL=INFO \
    LOG_FORMAT=json \
    CACHE_DIR=/app/cache \
    DATA_DIR=/app/data \
    PYTHONPATH=/app

# Create startup script for X11 forwarding
COPY --chown=appuser:appuser <<EOF /home/appuser/start.sh
#!/bin/bash
# Start X virtual framebuffer if no display available
if [ -z "\$DISPLAY" ]; then
    export DISPLAY=:99
    Xvfb :99 -screen 0 1024x768x24 &
    sleep 2
fi

# Run the desktop application
exec python desktop/main.py "\$@"
EOF

RUN chmod +x /home/appuser/start.sh

# Default command
CMD ["/home/appuser/start.sh"]