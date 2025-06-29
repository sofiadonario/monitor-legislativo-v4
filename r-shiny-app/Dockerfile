# Multi-stage Docker build for R Shiny Academic Legislative Monitor
FROM rocker/shiny:latest

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    libcurl4-openssl-dev \
    libssl-dev \
    libxml2-dev \
    libgdal-dev \
    libudunits2-dev \
    libproj-dev \
    libgeos-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY . /app/

# Install R packages from .Rprofile
RUN cd /app && R -e "source('.Rprofile')"

# Additional packages for enhanced functionality
RUN R -e "install.packages(c( \
    'plotly', \
    'highcharter', \
    'dygraphs', \
    'ggiraph', \
    'tmap', \
    'sf', \
    'htmlwidgets', \
    'reactR', \
    'crosstalk', \
    'promises', \
    'future', \
    'ipc' \
), repos='https://cran.rstudio.com/')"

# Create necessary directories
RUN mkdir -p /app/data/cache /app/data/geographic /app/www /app/logs

# Set permissions
RUN chmod -R 755 /app
RUN chown -R shiny:shiny /app

# Expose port 3838
EXPOSE 3838

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:3838/health || exit 1

# Start Shiny server
CMD ["R", "-e", "shiny::runApp('/app', host='0.0.0.0', port=3838)"]