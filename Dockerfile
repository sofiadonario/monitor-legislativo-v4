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
ARG CACHE_BUST=10
RUN echo "Installing ALL packages with binary from RStudio Package Manager..." && \
    R -e "options(repos = c(CRAN = 'https://packagemanager.rstudio.com/all/latest'), timeout = 600); \
          packages <- c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite', \
                       'DBI', 'RPostgres', 'pool', 'dbplyr', \
                       'config', 'httr', 'yaml', 'lubridate', \
                       'plotly', 'ggplot2', 'futile.logger', \
                       'htmltools', 'htmlwidgets', 'crosstalk', 'magrittr', \
                       'openxlsx', 'readr', 'digest', 'shinyjs', 'shinycssloaders', \
                       'RColorBrewer', 'viridis', 'scales', \
                       'base64enc', 'png', 'leaflet'); \
          for(pkg in packages) { \
            tryCatch({ \
              install.packages(pkg, type = 'binary', dependencies = FALSE); \
              cat('✓', pkg, 'installed\\n') \
            }, error = function(e) { \
              cat('Binary failed for', pkg, '- trying with dependencies\\n'); \
              install.packages(pkg, dependencies = TRUE) \
            }) \
          }; \
          cat('ALL packages installation completed\\n')"

# Verify all packages were installed successfully
RUN echo "Verifying package installation..." && \
    R -e "required <- c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite', \
                       'DBI', 'RPostgres', 'pool', 'plotly', 'ggplot2', 'leaflet'); \
          installed <- installed.packages()[,'Package']; \
          missing <- required[!required %in% installed]; \
          if(length(missing) > 0) { \
            cat('Installing missing packages via CRAN:', missing, '\\n'); \
            options(repos = 'https://cran.rstudio.com/'); \
            install.packages(missing, dependencies = TRUE) \
          }; \
          cat('Package verification completed\\n')"

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