# Multi-stage build for Railway deployment with geospatial support
FROM rocker/geospatial:4.3.1 AS builder

# Install system dependencies for database and analytics
RUN apt-get update && apt-get install -y \
    libpq-dev \
    libudunits2-dev \
    && rm -rf /var/lib/apt/lists/*

# Install packages in optimized order to prevent memory issues
# Core packages first
RUN R -e "install.packages(c('shiny', 'shinydashboard', 'DBI', 'RPostgres'), repos='https://cran.rstudio.com/', dependencies=FALSE)"

# Data packages
RUN R -e "install.packages(c('dplyr', 'DT', 'plotly', 'ggplot2'), repos='https://cran.rstudio.com/', dependencies=FALSE)"

# Geospatial packages (already included in rocker/geospatial base)
RUN R -e "install.packages('leaflet', repos='https://cran.rstudio.com/', dependencies=FALSE)"

# Optional packages with error handling
RUN R -e "tryCatch({install.packages(c('htmlwidgets', 'RColorBrewer', 'stringr', 'scales', 'lubridate'), repos='https://cran.rstudio.com/', dependencies=FALSE)}, error=function(e){cat('Optional packages installation failed, continuing...\n')})"

# Final runtime stage
FROM rocker/geospatial:4.3.1

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/R/site-library /usr/local/lib/R/site-library

# Install only runtime system dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /srv/shiny-server

# Copy application files
COPY app.R .
COPY RAILWAY_DATABASE_FINAL_FIX.R .
COPY startup_diagnostics.R .
COPY test_railway_connection.R .

# Copy analytics systems (if they exist)
COPY geospatial_analytics_system.R . 
COPY temporal_analysis_system.R .
COPY legislative_ml_system.R .
COPY advanced_text_mining_pipeline.R .

# Copy optional files if they exist
COPY railway_analytics_lightweight.R . 2>/dev/null || true
COPY railway_error_handler.R . 2>/dev/null || true

# Verify core packages are working
RUN R -e "library(shiny); library(shinydashboard); library(leaflet); cat('✅ Core packages verified\n')"

# Set proper permissions
RUN chmod -R 755 /srv/shiny-server

# Expose port
EXPOSE 3838

# Run startup diagnostics then the app
CMD ["R", "-e", "source('startup_diagnostics.R'); shiny::runApp('/srv/shiny-server/app.R', host='0.0.0.0', port=as.numeric(Sys.getenv('PORT', 3838)))"]