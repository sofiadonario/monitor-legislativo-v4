# Optimized Production Dockerfile for Monitor Legislativo v4
FROM rocker/shiny:4.3.1

# Install system dependencies in single layer
RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    libssl-dev \
    libxml2-dev \
    libgdal-dev \
    libudunits2-dev \
    libproj-dev \
    libgeos-dev \
    libsqlite3-dev \
    libpq-dev \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables early for better caching
ENV R_CONFIG_ACTIVE=production
ENV SHINY_LOG_LEVEL=INFO

# Install R packages efficiently using RStudio Package Manager
RUN R -e "options(repos = c(CRAN = 'https://packagemanager.rstudio.com/all/latest'), timeout = 300); \
    packages <- c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite', \
                  'DBI', 'RPostgres', 'pool', 'dbplyr', 'config', 'httr', 'yaml', \
                  'lubridate', 'plotly', 'ggplot2', 'futile.logger', 'htmltools', \
                  'htmlwidgets', 'crosstalk', 'magrittr', 'openxlsx', 'readr', \
                  'digest', 'shinyjs', 'shinycssloaders', 'RColorBrewer', 'viridis', \
                  'scales', 'base64enc', 'png', 'leaflet'); \
    install.packages(packages, dependencies = TRUE); \
    cat('✅ All packages installed successfully\\n')"

# Verify essential packages are installed
RUN R -e "required <- c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite', \
                       'DBI', 'RPostgres', 'pool', 'plotly', 'ggplot2', 'leaflet'); \
          installed <- installed.packages()[,'Package']; \
          missing <- required[!required %in% installed]; \
          if(length(missing) > 0) { \
            cat('❌ MISSING PACKAGES:', missing, '\\n'); \
            quit(status=1) \
          } else { \
            cat('✅ ALL REQUIRED PACKAGES VERIFIED\\n') \
          }"

# Set working directory and create necessary directories
WORKDIR /app
RUN mkdir -p data/cache data/geographic www logs exports temp

# Copy application files
COPY app.R ./
COPY R/ ./R/
COPY config.yml ./
COPY dev-tools/startup_diagnostics.R ./

# Expose port
EXPOSE ${PORT:-3838}

# Start the application
CMD ["R", "-e", "source('app.R')"]