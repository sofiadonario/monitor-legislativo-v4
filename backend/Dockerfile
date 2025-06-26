# Multi-stage Dockerfile for Monitor Legislativo v4 Backend
# Optimized for production deployment with Brazilian legislative research capabilities

# ========================================
# STAGE 1: Python Base with Brazilian Dependencies
# ========================================
FROM python:3.11-slim as python-base

# Set environment variables for Python optimization
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    POETRY_VERSION=1.7.1

# Install system dependencies for Brazilian legislative processing
RUN apt-get update && apt-get install -y \
    # Essential build tools
    build-essential \
    gcc \
    g++ \
    # Database dependencies
    libpq-dev \
    postgresql-client \
    # Network tools
    curl \
    wget \
    # Text processing for Portuguese
    libicu-dev \
    # Image processing
    libjpeg-dev \
    libpng-dev \
    # Compression libraries
    zlib1g-dev \
    # XML processing for government APIs
    libxml2-dev \
    libxslt1-dev \
    # SSL/TLS support
    libssl-dev \
    libffi-dev \
    # Locale support for Brazilian Portuguese
    locales \
    locales-all \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set Brazilian Portuguese locale
ENV LC_ALL=pt_BR.UTF-8 \
    LANG=pt_BR.UTF-8 \
    LANGUAGE=pt_BR:pt:en

# Generate Brazilian locale
RUN locale-gen pt_BR.UTF-8

# Install Poetry for dependency management
RUN pip install poetry==$POETRY_VERSION

# Configure Poetry
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VENV_IN_PROJECT=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

# ========================================
# STAGE 2: Development Dependencies
# ========================================
FROM python-base as deps

# Set working directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml poetry.lock ./

# Install Python dependencies
RUN poetry install --only=main --no-root && rm -rf $POETRY_CACHE_DIR

# ========================================
# STAGE 3: Application Code
# ========================================
FROM python-base as runtime

# Create application user for security
RUN groupadd -r monitor && useradd -r -g monitor monitor

# Set working directory
WORKDIR /app

# Copy virtual environment from deps stage
COPY --from=deps /app/.venv /app/.venv

# Make sure to use virtual environment
ENV PATH="/app/.venv/bin:$PATH"

# Copy application code
COPY . .

# Create necessary directories with proper permissions
RUN mkdir -p /app/logs /app/uploads /app/static /app/media \
    && chown -R monitor:monitor /app

# Install additional Brazilian NLP dependencies
RUN python -m pip install \
    # Portuguese language processing
    spacy-legacy \
    https://github.com/explosion/spacy-models/releases/download/pt_core_news_sm-3.7.0/pt_core_news_sm-3.7.0-py3-none-any.whl \
    # Brazilian legal text processing
    unidecode \
    # Government API libraries
    xmltodict \
    # Performance monitoring
    psutil \
    # Brazilian date/time handling
    python-dateutil \
    # Currency formatting for Brazilian Real
    babel

# Download Portuguese language model for spaCy
RUN python -m spacy download pt_core_news_sm

# Set up Brazilian legislative text processing
# COPY ./nlp/portuguese_legal_processor.py /app/nlp/
COPY ./data/brazilian_legal_vocabularies.json /app/data/

# Expose port
EXPOSE 8000

# Health check for Brazilian legislative APIs
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Switch to non-root user
USER monitor

# Set environment variables for production
ENV ENVIRONMENT=production \
    PYTHONPATH=/app \
    PORTUGUESE_NLP_ENABLED=true \
    BRAZILIAN_LEGAL_PROCESSING=true

# FINAL DEPENDENCY CHECK: Ensure correct asyncpg version is installed
# This is a failsafe to prevent version conflicts.
RUN poetry run pip install --no-cache-dir --upgrade "asyncpg==0.29.0"

# ========================================
# PRODUCTION ENTRYPOINT
# ========================================

# Copy entrypoint script
COPY ./scripts/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Default command for production
CMD ["/app/entrypoint.sh"]