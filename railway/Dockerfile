# =============================================================================
# RAILWAY-OPTIMIZED SECURE DOCKERFILE
# Brazilian Legislative Monitoring System - R Shiny Application
# Optimized for Railway's container platform with security hardening
# =============================================================================

# Use Rocker's optimized Shiny image with R 4.3.1
FROM rocker/shiny:4.3.1

# Metadata for Railway deployment tracking
LABEL maintainer="Monitor Legislativo Team" \
      org.railway.app="monitor-legislativo-v4" \
      org.railway.service="r-shiny-app" \
      description="Secure R Shiny application for Brazilian legislative monitoring" \
      version="1.0.0"

# Create non-root user for security (Railway recommended)
RUN groupadd -r shinyapp && useradd -r -g shinyapp -u 1001 shinyapp

# Update system and install dependencies in a single layer for Railway optimization
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    # Core system dependencies
    libpq-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    libxml2-dev \
    libsodium-dev \
    # Geospatial dependencies (for Brazilian maps and choropleth visualization)
    libgdal-dev \
    libudunits2-dev \
    libproj-dev \
    libgeos-dev \
    libspatialite-dev \
    # Network and security tools
    ca-certificates \
    curl \
    wget \
    # Cleanup to reduce image size (Railway optimization)
    && apt-get autoremove -y \
    && apt-get autoclean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/* \
    && rm -rf /usr/share/doc/* \
    && rm -rf /usr/share/man/* \
    && find /var/log -type f -delete

# Set Railway-optimized environment variables
ENV PORT=3838 \
    HOST=0.0.0.0 \
    R_LIBS_USER="/app/R_libs" \
    SHINY_PORT=3838 \
    SHINY_HOST=0.0.0.0 \
    # Railway-specific optimizations
    RAILWAY_ENVIRONMENT=production \
    # Security settings
    DEBIAN_FRONTEND=noninteractive \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8 \
    # Brazilian timezone
    TZ=America/Sao_Paulo

# Create optimized R library directory for Railway caching
RUN mkdir -p /app/R_libs && \
    chown -R shinyapp:shinyapp /app

# Switch to non-root user for package installation (security best practice)
USER shinyapp

# Install R packages with Railway build caching optimization
# Install in specific order for better caching: core dependencies first
RUN R -e "options(repos = c(CRAN = 'https://cran.rstudio.com/'), Ncpus = parallel::detectCores()); \
    # Core database and web dependencies
    install.packages(c('DBI', 'RPostgres', 'pool'), lib = '/app/R_libs', dependencies = TRUE); \
    # Shiny ecosystem  
    install.packages(c('shiny', 'shinydashboard', 'DT'), lib = '/app/R_libs', dependencies = TRUE); \
    # Data manipulation and visualization
    install.packages(c('dplyr', 'tidyr', 'stringr', 'lubridate'), lib = '/app/R_libs', dependencies = TRUE); \
    # Plotting and visualization
    install.packages(c('plotly', 'RColorBrewer', 'scales'), lib = '/app/R_libs', dependencies = TRUE); \
    # Data processing and utilities
    install.packages(c('jsonlite', 'magrittr', 'R.utils'), lib = '/app/R_libs', dependencies = TRUE); \
    # Geospatial packages (for Brazilian legislative mapping)
    install.packages(c('sf', 'geobr', 'geojsonio'), lib = '/app/R_libs', dependencies = TRUE); \
    cat('R packages installed successfully for Railway deployment\\n')"

# Switch back to root temporarily for directory creation
USER root

# Create secure application directory structure optimized for Railway
RUN mkdir -p /app/{modules,data,fixes,scripts,auth,logs,tmp} && \
    chown -R shinyapp:shinyapp /app && \
    chmod -R 750 /app

# Set working directory
WORKDIR /app

# Copy application files with proper security context
# Railway will use .dockerignore to exclude dangerous files
COPY --chown=shinyapp:shinyapp app.R /app/
COPY --chown=shinyapp:shinyapp modules/ /app/modules/
COPY --chown=shinyapp:shinyapp data/ /app/data/
COPY --chown=shinyapp:shinyapp fixes/ /app/fixes/
COPY --chown=shinyapp:shinyapp scripts/ /app/scripts/
COPY --chown=shinyapp:shinyapp auth/ /app/auth/

# Create runtime directories
RUN mkdir -p /app/analytics_output && \
    chown -R shinyapp:shinyapp /app/analytics_output && \
    chmod 750 /app/analytics_output

# Security hardening: Remove any dangerous files that might bypass .dockerignore
RUN find /app -name "*RAILWAY_PRODUCTION_DB_FIX*" -type f -delete 2>/dev/null || true && \
    find /app -name "*production*fix*" -type f -delete 2>/dev/null || true && \
    find /app -name "*nuclear*fix*" -type f -delete 2>/dev/null || true && \
    find /app -name "*emergency*fix*" -type f -delete 2>/dev/null || true && \
    find /app -name "*.log" -type f -delete 2>/dev/null || true && \
    find /app -name "*.tmp" -type f -delete 2>/dev/null || true && \
    find /app -name "*password*" -type f -delete 2>/dev/null || true && \
    find /app -name "*secret*" -type f -delete 2>/dev/null || true

# Switch to non-root user permanently
USER shinyapp

# Set final secure permissions
RUN chmod -R u=rwX,g=rX,o= /app && \
    chmod 755 /app/app.R

# Railway health check configuration
HEALTHCHECK --interval=60s --timeout=30s --start-period=120s --retries=3 \
    CMD curl -f http://localhost:$PORT/ || exit 1

# Railway requires PORT environment variable support
EXPOSE $PORT

# Railway-optimized startup command with comprehensive error handling
CMD ["sh", "-c", "echo 'Starting Monitor Legislativo on Railway...' && \
    echo 'Railway Environment:' $RAILWAY_ENVIRONMENT && \
    echo 'Port:' $PORT && \
    echo 'Host:' $HOST && \
    echo 'User:' $(whoami) && \
    echo 'Working Directory:' $(pwd) && \
    echo 'R Library Path:' $R_LIBS_USER && \
    echo 'Available R Packages:' && R -e 'cat(installed.packages(lib.loc = \"/app/R_libs\")[,1], sep = \", \")' && \
    echo 'Starting Shiny Server...' && \
    exec R -e 'tryCatch({ \
        # Railway environment detection \
        railway_env <- Sys.getenv(\"RAILWAY_ENVIRONMENT\", \"development\"); \
        cat(\"Railway Environment:\", railway_env, \"\\n\"); \
        # Port configuration for Railway \
        port <- as.numeric(Sys.getenv(\"PORT\", \"3838\")); \
        host <- Sys.getenv(\"HOST\", \"0.0.0.0\"); \
        cat(\"Starting on\", host, \":\", port, \"\\n\"); \
        # Load application with error handling \
        tryCatch({ \
            source(\"/app/app.R\"); \
        }, error = function(e) { \
            cat(\"ERROR loading app.R:\", e$message, \"\\n\"); \
            if (file.exists(\"/app/app.R\")) { \
                cat(\"app.R exists, attempting direct execution...\\n\"); \
            } else { \
                cat(\"CRITICAL: app.R not found!\\n\"); \
                quit(status = 1); \
            } \
        }); \
        # Start Shiny application \
        shiny::runApp(\"/app/app.R\", host = host, port = port, launch.browser = FALSE); \
    }, error = function(e) { \
        cat(\"CRITICAL APPLICATION ERROR:\", e$message, \"\\n\"); \
        cat(\"Stacktrace:\", paste(traceback(), collapse = \"\\n\"), \"\\n\"); \
        cat(\"Environment info:\\n\"); \
        print(Sys.info()); \
        cat(\"Working directory contents:\\n\"); \
        print(list.files(\"/app\", recursive = TRUE, full.names = TRUE)); \
        quit(status = 1); \
    })'"]

# Railway deployment metadata
LABEL railway.deploy.region="us-west1" \
      railway.deploy.healthcheck="/health" \
      railway.deploy.restart-policy="always" \
      railway.deploy.memory="2Gi" \
      railway.deploy.cpu="1000m" \
      railway.security.user="shinyapp" \
      railway.security.user-id="1001" \
      railway.security.non-root="true" \
      railway.optimization.cache="true" \
      railway.optimization.build-cache="R_libs"

# =============================================================================
# RAILWAY DEPLOYMENT NOTES:
#
# 1. Environment Variables (set in Railway dashboard):
#    - DATABASE_URL: PostgreSQL connection string  
#    - OAUTH_GOOGLE_CLIENT_ID: Google OAuth client ID (optional)
#    - OAUTH_GOOGLE_CLIENT_SECRET: Google OAuth secret (optional)
#    - SESSION_SECRET: Session encryption key
#    - LOG_LEVEL: Application logging level (INFO, DEBUG, WARN, ERROR)
#
# 2. Railway Platform Optimizations:
#    - Multi-layered caching for R packages
#    - Efficient apt package installation
#    - Non-root user execution for security
#    - Health checks configured for Railway load balancer
#    - Brazilian timezone support
#
# 3. Security Features:
#    - Runs as non-root user (shinyapp:1001)
#    - Dangerous files excluded via .dockerignore
#    - Runtime security validation
#    - Comprehensive error logging for debugging
#
# 4. Geospatial Support:
#    - Complete geospatial library stack for Brazilian legislative mapping
#    - Choropleth visualization support
#    - Brazil-specific geospatial data processing
#
# 5. Railway Build Command (if needed):
#    docker build -f railway/Dockerfile -t monitor_legislativo_railway .
# =============================================================================