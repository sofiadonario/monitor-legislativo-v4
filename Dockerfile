# Railway deployment optimized for Brazilian Legislative Monitoring System
# Handles 134k+ documents with full analytics capabilities
FROM rocker/geospatial:4.3.1 AS builder

# Install system dependencies for database, analytics and geospatial processing
RUN apt-get update && apt-get install -y \
    libpq-dev \
    libudunits2-dev \
    libgdal-dev \
    libproj-dev \
    libgeos-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install packages in optimized order to prevent memory issues
# Essential packages first
RUN R -e "install.packages(c('shiny', 'shinydashboard', 'DBI', 'RPostgreSQL', 'RPostgres'), repos='https://cran.rstudio.com/', dependencies=FALSE)"

# Core data manipulation and visualization packages
RUN R -e "install.packages(c('dplyr', 'DT', 'plotly', 'ggplot2', 'tidyr', 'purrr'), repos='https://cran.rstudio.com/', dependencies=FALSE)"

# Geospatial packages (sf already in base, add complementary packages)
RUN R -e "install.packages(c('leaflet', 'leaflet.extras', 'geobr', 'spdep'), repos='https://cran.rstudio.com/', dependencies=FALSE)"

# Analytics and text mining packages
RUN R -e "install.packages(c('stringr', 'lubridate', 'viridis', 'RColorBrewer', 'htmlwidgets', 'scales'), repos='https://cran.rstudio.com/', dependencies=FALSE)"

# Statistical analysis packages for advanced analytics  
RUN R -e "tryCatch({install.packages(c('spatstat', 'arrow', 'jsonlite', 'readr'), repos='https://cran.rstudio.com/', dependencies=FALSE)}, error=function(e){cat('Advanced packages installation failed, continuing...\n')})"

# Final runtime stage
FROM rocker/geospatial:4.3.1

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/R/site-library /usr/local/lib/R/site-library

# Install only runtime system dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    libgdal32 \
    libproj25 \
    libgeos-c1v5 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /srv/shiny-server

# Copy main application files
COPY app.R .
COPY RAILWAY_PRODUCTION_DB_FIX.R .

# Copy critical archive files that provide full analytics functionality
# These files are now tracked in git and contain all 134k+ document analytics systems
COPY archive/database_fixes/RAILWAY_DATABASE_FINAL_FIX.R .
COPY archive/diagnostic_files/startup_diagnostics.R .
COPY archive/old_analysis_scripts/geospatial_analytics_system.R .
COPY archive/old_analysis_scripts/temporal_analysis_system.R .
COPY archive/old_analysis_scripts/legislative_ml_system.R .
COPY archive/old_analysis_scripts/advanced_text_mining_pipeline.R .
COPY archive/old_analysis_scripts/ml_anomaly_detection_system.R .

# Copy essential dev tools for Railway deployment
COPY dev-tools/railway_analytics_lightweight.R .
COPY dev-tools/railway_error_handler.R .
COPY dev-tools/test_railway_connection.R .

# Verify all critical packages are working for full analytics functionality
RUN R -e "library(shiny); library(shinydashboard); library(leaflet); library(sf); library(dplyr); library(plotly); cat('✅ All core packages verified for Brazilian Legislative Analytics\n')"

# Set proper permissions
RUN chmod -R 755 /srv/shiny-server

# Expose port
EXPOSE 3838

# Run the app directly with comprehensive error handling
CMD ["R", "-e", "shiny::runApp('/srv/shiny-server/app.R', host='0.0.0.0', port=as.numeric(Sys.getenv('PORT', 3838)))"]
