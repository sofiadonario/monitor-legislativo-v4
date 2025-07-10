# Ultra-Simple Leaflet Installation for Railway
FROM rocker/shiny:4.3.1

# Essential system dependencies only
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

# BULLETPROOF LEAFLET INSTALLATION
# Using RStudio Package Manager for binary packages to avoid compilation
ARG CACHE_BUST=9
RUN echo "Installing packages with binary from RStudio Package Manager..." && \
    R -e "options(repos = c(CRAN = 'https://packagemanager.rstudio.com/all/latest'), timeout = 300); \
          packages <- c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite', \
                       'DBI', 'RPostgres', 'pool', 'dbplyr', \
                       'config', 'httr', 'yaml', 'lubridate', \
                       'plotly', 'ggplot2', 'futile.logger', \
                       'htmltools', 'htmlwidgets', 'crosstalk', 'magrittr', \
                       'openxlsx', 'readr', 'digest', 'shinyjs', 'shinycssloaders', \
                       'RColorBrewer', 'viridis', 'scales', \
                       'base64enc', 'png'); \
          install.packages(packages, type = 'binary', dependencies = FALSE); \
          cat('Core packages installed\\n')"

# Install leaflet specifically with multiple fallbacks
RUN echo "Installing leaflet with fallback strategies..." && \
    R -e "success <- FALSE; \
          # Strategy 1: Binary from RStudio Package Manager \
          tryCatch({ \
            options(repos = c(CRAN = 'https://packagemanager.rstudio.com/all/latest')); \
            install.packages('leaflet', type = 'binary', dependencies = FALSE); \
            library(leaflet); \
            success <- TRUE; \
            cat('SUCCESS: Leaflet installed via binary packages\\n') \
          }, error = function(e) cat('Binary install failed:', conditionMessage(e), '\\n')); \
          \
          # Strategy 2: Regular CRAN if binary failed \
          if(!success) { \
            tryCatch({ \
              options(repos = c(CRAN = 'https://cran.rstudio.com/')); \
              install.packages('leaflet', dependencies = TRUE); \
              library(leaflet); \
              success <- TRUE; \
              cat('SUCCESS: Leaflet installed via CRAN\\n') \
            }, error = function(e) cat('CRAN install failed:', conditionMessage(e), '\\n')) \
          }; \
          \
          # Strategy 3: Cloud R-Project \
          if(!success) { \
            tryCatch({ \
              options(repos = c(CRAN = 'https://cloud.r-project.org/')); \
              install.packages('leaflet', dependencies = TRUE); \
              library(leaflet); \
              success <- TRUE; \
              cat('SUCCESS: Leaflet installed via cloud.r-project.org\\n') \
            }, error = function(e) cat('Cloud install failed:', conditionMessage(e), '\\n')) \
          }; \
          \
          if(!success) stop('CRITICAL ERROR: All leaflet installation strategies failed')"

# Test leaflet functionality
RUN echo "Testing leaflet functionality..." && \
    R -e "library(leaflet); \
          m <- leaflet() %>% addTiles(); \
          cat('✅ Leaflet test successful - map object created\\n'); \
          cat('Leaflet version:', as.character(packageVersion('leaflet')), '\\n')"

# Set working directory
WORKDIR /app

# Create directories
RUN mkdir -p data/cache data/geographic www logs exports temp

# Copy application files
COPY app.R ./
COPY R/ ./R/
COPY config.yml ./

# Copy optional files if they exist
COPY test_version.R* ./
COPY www* ./www/

# Final verification
RUN echo "Final package verification..." && \
    R -e "required <- c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite', \
                       'DBI', 'RPostgres', 'pool', 'plotly', 'ggplot2', 'leaflet'); \
          missing <- required[!required %in% installed.packages()[,'Package']]; \
          if(length(missing) > 0) { \
            cat('MISSING:', missing, '\\n'); \
            quit(status=1) \
          } else { \
            cat('✅ All required packages verified\\n') \
          }"

# Environment
ENV R_CONFIG_ACTIVE=production
ENV SHINY_LOG_LEVEL=INFO

# Port
EXPOSE ${PORT:-3838}

# Start
CMD ["R", "-e", "if(file.exists('test_version.R')) source('test_version.R'); source('app.R')"]