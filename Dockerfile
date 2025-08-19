# Secure Railway Dockerfile for R Shiny Application
FROM rocker/shiny:4.3.1

# Create non-root user for security
RUN groupadd -r shinyapp && useradd -r -g shinyapp -u 1001 shinyapp

# Install system dependencies with security updates
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    libpq-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    libxml2-dev \
    libgdal-dev \
    libudunits2-dev \
    libproj-dev \
    libgeos-dev \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install required R packages
RUN R -e "install.packages(c('DBI','RPostgres','pool','shiny','shinydashboard','DT','plotly','dplyr','RColorBrewer','stringr','scales','lubridate','tidyr','jsonlite','magrittr','sf','geobr','geojsonio','R.utils','yaml'), repos='https://cran.rstudio.com/')"

# Set working directory
WORKDIR /app

# Copy application files (secure connection system)
COPY app.R ./
COPY railway_migrate.sh ./
COPY db/ ./db/
COPY auth/ ./auth/
COPY monitoring/ ./monitoring/

# Copy modules directory with maps
COPY modules/ ./modules/

# Copy configuration and data directories
COPY data/ ./data/
COPY fixes/ ./fixes/
COPY scripts/ ./scripts/
COPY config/ ./config/
COPY health_check.R ./

# Create required directories
RUN mkdir -p analytics_output logs cache

# Set secure permissions
RUN chown -R shinyapp:shinyapp /app && \
    chmod -R 755 /app && \
    chmod +x /app/railway_migrate.sh

# Remove any potentially dangerous files that might have been copied
RUN find /app -name "*.R" -path "*/RAILWAY_PRODUCTION_DB_FIX.R" -delete || true && \
    find /app -name "*password*" -delete || true && \
    find /app -name "*secret*" -delete || true

# Switch to non-root user
USER shinyapp

# Expose port
EXPOSE 3838

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3838/health || exit 1

# Start with migration and application
CMD ["bash", "-c", "./railway_migrate.sh && R -e \"shiny::runApp(host='0.0.0.0', port=3838)\""]
