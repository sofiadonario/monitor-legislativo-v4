# OPTIMIZED RAILWAY DOCKERFILE FOR R SHINY APPLICATION
# ====================================================
# Production-ready, memory-optimized for Railway deployment
FROM rocker/shiny:4.5.1

# Set memory and CPU limits for Railway
ENV R_MAX_VSIZE=2G \
    R_NSIZE=1000000 \
    R_VSIZE=1000000000

# Create non-root user for security
RUN groupadd -r shinyapp && useradd -r -g shinyapp -u 1001 shinyapp

# Install system dependencies with security updates and memory optimization
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
    libfontconfig1-dev \
    libfreetype6-dev \
    libfribidi-dev \
    libharfbuzz-dev \
    libjpeg-dev \
    libpng-dev \
    libtiff5-dev \
    ca-certificates \
    curl \
    htop \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Install R packages in stages to avoid memory issues
# Stage 1: Core packages (required for basic functionality)
RUN R -e "options(repos = c(CRAN = 'https://cran.rstudio.com/')); \
    install.packages(c('shiny', 'shinydashboard', 'DT', 'plotly', 'dplyr', 'RColorBrewer'), \
    dependencies = TRUE, Ncpus = 2)" && \
    rm -rf /tmp/R* && \
    R -e "gc()"

# Stage 2: Database and connection packages
RUN R -e "options(repos = c(CRAN = 'https://cran.rstudio.com/')); \
    install.packages(c('DBI', 'RPostgres', 'pool', 'jsonlite'), \
    dependencies = TRUE, Ncpus = 2)" && \
    rm -rf /tmp/R* && \
    R -e "gc()"

# Stage 3: Data manipulation packages
RUN R -e "options(repos = c(CRAN = 'https://cran.rstudio.com/')); \
    install.packages(c('stringr', 'scales', 'lubridate', 'tidyr', 'magrittr'), \
    dependencies = TRUE, Ncpus = 2)" && \
    rm -rf /tmp/R* && \
    R -e "gc()"

# Stage 4: Geospatial packages (memory intensive)
RUN R -e "options(repos = c(CRAN = 'https://cran.rstudio.com/')); \
    install.packages(c('sf', 'geobr'), \
    dependencies = TRUE, Ncpus = 1)" && \
    rm -rf /tmp/R* && \
    R -e "gc()"

# Stage 5: Additional visualization and utility packages
RUN R -e "options(repos = c(CRAN = 'https://cran.rstudio.com/')); \
    install.packages(c('geojsonio', 'R.utils', 'yaml', 'shinyjs', 'htmltools', 'leaflet'), \
    dependencies = TRUE, Ncpus = 2)" && \
    rm -rf /tmp/R* && \
    R -e "gc()"

# Stage 6: Optional packages (can fail without breaking deployment)
RUN R -e "options(repos = c(CRAN = 'https://cran.rstudio.com/')); \
    tryCatch({ \
      install.packages(c('echarts4r', 'digest'), dependencies = TRUE, Ncpus = 2) \
    }, error = function(e) { \
      cat('Optional packages installation failed, continuing...\\n') \
    })" && \
    rm -rf /tmp/R* && \
    R -e "gc()"

# Set working directory
WORKDIR /app

# Copy Railway deployment fixes first
COPY railway_deployment_fix.R ./
COPY app_railway.R ./
COPY railway_startup.sh ./
COPY start.R ./
COPY railway_health_startup.R ./
COPY railway_start_production.R ./

# Copy original application (fallback)
COPY app.R ./

# Copy essential system files
COPY railway_migrate.sh ./
COPY health_check.R ./

# Copy core directories (with error handling)
COPY --chown=shinyapp:shinyapp db/ ./db/
COPY --chown=shinyapp:shinyapp auth/ ./auth/
COPY --chown=shinyapp:shinyapp monitoring/ ./monitoring/

# Copy modules directory with maps (optional)
COPY --chown=shinyapp:shinyapp modules/ ./modules/

# Copy configuration and data directories (optional)
COPY --chown=shinyapp:shinyapp data/ ./data/
COPY --chown=shinyapp:shinyapp fixes/ ./fixes/
COPY --chown=shinyapp:shinyapp scripts/ ./scripts/
COPY --chown=shinyapp:shinyapp config/ ./config/

# Create required directories with proper ownership
RUN mkdir -p analytics_output logs cache tmp && \
    chown -R shinyapp:shinyapp /app && \
    chmod -R 755 /app && \
    chmod +x /app/railway_migrate.sh && \
    chmod +x /app/railway_startup.sh

# Remove any potentially dangerous files that might have been copied
RUN find /app -name "*.R" -path "*/RAILWAY_PRODUCTION_DB_FIX.R" -delete 2>/dev/null || true && \
    find /app -name "*password*" -delete 2>/dev/null || true && \
    find /app -name "*secret*" -delete 2>/dev/null || true && \
    find /app -name ".env*" -delete 2>/dev/null || true

# Set Railway-specific environment variables
ENV SHINY_HOST=0.0.0.0 \
    SHINY_PORT=3838 \
    RAILWAY_DEPLOYMENT=true \
    R_LIBS_USER=/usr/local/lib/R/site-library \
    LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8

# Switch to non-root user
USER shinyapp

# Expose port
EXPOSE 3838

# Health check for Railway monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:3838/health || exit 1

# Use health check startup script
CMD ["Rscript", "railway_health_startup.R"]
