# Multi-stage Docker build for R Shiny Academic Legislative Monitor
FROM rocker/shiny:latest

# Use persistent cache for R packages
ARG R_LIBS_USER=/usr/local/lib/R/site-library
ENV R_LIBS_USER=${R_LIBS_USER}

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

# Install R packages from .Rprofile (cached between builds)
RUN --mount=type=cache,target=${R_LIBS_USER} \
    Rscript -e "source('/app/.Rprofile')"

# Additional packages for enhanced functionality (also cached)
RUN --mount=type=cache,target=${R_LIBS_USER} \
    Rscript -e "install.packages(c( \"plotly\", \"highcharter\", \"dygraphs\", \"ggiraph\", \"tmap\", \"sf\", \"htmlwidgets\", \"reactR\", \"crosstalk\", \"promises\", \"future\", \"ipc\" ), repos='https://cran.rstudio.com/')"

# Create necessary directories
RUN mkdir -p /app/data/cache /app/data/geographic /app/www /app/logs

# Set permissions
RUN chmod -R 755 /app
RUN chown -R shiny:shiny /app

# Expose default Shiny port (Railway sets $PORT, default 8080)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Start Shiny server with health endpoint support
CMD ["Rscript", "/app/run_app.R"]