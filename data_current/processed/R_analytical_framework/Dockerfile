# Brazilian Legislative Analytics Framework - Docker Container
# Multi-stage build for optimized container size

# Stage 1: Base R environment with system dependencies
FROM rocker/verse:4.3.0 as base

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV RENV_VERSION=1.0.0

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Geospatial libraries
    libgdal-dev \
    libgeos-dev \
    libproj-dev \
    libudunits2-dev \
    # Text processing
    libicu-dev \
    libxml2-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    # Database support
    libsqlite3-dev \
    # Python for NLP
    python3 \
    python3-pip \
    python3-dev \
    # Additional utilities
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies for NLP
RUN pip3 install --no-cache-dir \
    spacy \
    pandas \
    numpy \
    && python3 -m spacy download pt_core_news_sm

# Stage 2: R package installation
FROM base as packages

# Install renv
RUN R -e "install.packages('renv', repos = c(CRAN = 'https://cloud.r-project.org'))"

# Copy renv lock file
COPY renv.lock renv.lock

# Install R packages using renv
RUN R -e "renv::consent(provided = TRUE)" \
    && R -e "renv::restore()"

# Install additional packages not in renv.lock
RUN R -e "install.packages(c( \
    'sentimentr', \
    'udpipe', \
    'spacyr', \
    'ldatuning', \
    'rollinglda', \
    'lexiconPT', \
    'textclean', \
    'changepoint', \
    'bcp', \
    'prophet', \
    'tidygraph', \
    'ggraph', \
    'networkD3', \
    'visNetwork', \
    'tmap', \
    'tmaptools', \
    'mapview', \
    'spdep', \
    'spatstat', \
    'VIM', \
    'validate', \
    'checkmate', \
    'janitor', \
    'skimr', \
    'corrplot', \
    'wordcloud', \
    'survminer' \
), repos = 'https://cloud.r-project.org', dependencies = TRUE)"

# Stage 3: Final application stage
FROM packages as app

# Set working directory
WORKDIR /app

# Copy framework files
COPY . .

# Create required directories
RUN mkdir -p /app/data /app/output /app/logs

# Set permissions
RUN chmod +x *.R

# Create non-root user for security
RUN useradd -m -u 1000 analyst && \
    chown -R analyst:analyst /app
USER analyst

# Environment variables for the application
ENV R_LIBS_USER=/usr/local/lib/R/site-library
ENV FRAMEWORK_HOME=/app
ENV DATA_DIR=/app/data
ENV OUTPUT_DIR=/app/output

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD R -e "cat('Brazilian Legislative Analytics Framework is ready\n')" || exit 1

# Default command
CMD ["R", "--vanilla", "-f", "09_master_execution_script.R"]

# Metadata
LABEL org.opencontainers.image.title="Brazilian Legislative Analytics Framework"
LABEL org.opencontainers.image.description="Comprehensive R framework for Brazilian legislative data analysis"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.authors="Brazilian Legislative Analytics Framework Team"
LABEL org.opencontainers.image.source="https://github.com/brazilian-legislative-analytics/framework"
LABEL org.opencontainers.image.licenses="MIT"

# Usage instructions in the image
RUN echo "# Brazilian Legislative Analytics Framework Docker Container" > /app/DOCKER_USAGE.md && \
    echo "" >> /app/DOCKER_USAGE.md && \
    echo "## Quick Start" >> /app/DOCKER_USAGE.md && \
    echo "" >> /app/DOCKER_USAGE.md && \
    echo "1. Build the container:" >> /app/DOCKER_USAGE.md && \
    echo "   docker build -t brazilian-legislative-analytics ." >> /app/DOCKER_USAGE.md && \
    echo "" >> /app/DOCKER_USAGE.md && \
    echo "2. Run with data volume:" >> /app/DOCKER_USAGE.md && \
    echo "   docker run -v /path/to/data:/app/data -v /path/to/output:/app/output brazilian-legislative-analytics" >> /app/DOCKER_USAGE.md && \
    echo "" >> /app/DOCKER_USAGE.md && \
    echo "3. Interactive session:" >> /app/DOCKER_USAGE.md && \
    echo "   docker run -it -v /path/to/data:/app/data brazilian-legislative-analytics R" >> /app/DOCKER_USAGE.md && \
    echo "" >> /app/DOCKER_USAGE.md && \
    echo "## Volume Mounts" >> /app/DOCKER_USAGE.md && \
    echo "- /app/data: Input CSV files" >> /app/DOCKER_USAGE.md && \
    echo "- /app/output: Analysis results" >> /app/DOCKER_USAGE.md && \
    echo "- /app/logs: Application logs" >> /app/DOCKER_USAGE.md