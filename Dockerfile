# Production Dockerfile for Monitor Legislativo v4 - Comprehensive Leaflet Fix
FROM rocker/shiny:4.3.1

# Install system dependencies (minimal but comprehensive set)
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

# COMPREHENSIVE LEAFLET INSTALLATION STRATEGY
# Using multiple approaches to ensure leaflet installs successfully

# Strategy 1: Install ALL packages using binary packages from RStudio Package Manager
ARG CACHE_BUST=9
RUN echo "=== STRATEGY 1: Binary packages from RStudio Package Manager ===" && \
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
              cat('✓ Installed:', pkg, '\\n') \
            }, error = function(e) { \
              cat('✗ Failed:', pkg, '-', conditionMessage(e), '\\n'); \
              install.packages(pkg, dependencies = TRUE) \
            }) \
          }; \
          cat('Strategy 1 completed - installed:', length(intersect(packages, installed.packages()[,\"Package\"])), 'of', length(packages), '\\n')" || echo "Strategy 1 failed, continuing..."

# Strategy 2: Install any missing packages from Strategy 1
RUN echo "=== STRATEGY 2: Install missing packages ===" && \
    R -e "required <- c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite', \
                       'DBI', 'RPostgres', 'pool', 'plotly', 'ggplot2', 'leaflet'); \
          installed <- installed.packages()[,'Package']; \
          missing <- required[!required %in% installed]; \
          if(length(missing) > 0) { \
            cat('Installing missing packages:', missing, '\\n'); \
            options(repos = c(CRAN = 'https://cran.rstudio.com/')); \
            for(pkg in missing) { \
              tryCatch({ \
                install.packages(pkg, dependencies = TRUE); \
                cat('✓ Installed missing:', pkg, '\\n') \
              }, error = function(e) cat('✗ Failed to install:', pkg, '\\n')) \
            } \
          } else { \
            cat('All required packages already installed\\n') \
          }"

# Strategy 3: If still not installed, try different CRAN mirrors
RUN echo "=== STRATEGY 3: Different CRAN mirrors ===" && \
    R -e "if(!'leaflet' %in% installed.packages()[,'Package']) { \
            mirrors <- c('https://cloud.r-project.org/', \
                        'https://cran.microsoft.com/', \
                        'https://cran.case.edu/'); \
            for(mirror in mirrors) { \
              cat('Trying mirror:', mirror, '\\n'); \
              tryCatch({ \
                options(repos = mirror); \
                install.packages('leaflet', dependencies = TRUE); \
                if('leaflet' %in% installed.packages()[,'Package']) { \
                  cat('Success with mirror:', mirror, '\\n'); \
                  break \
                } \
              }, error = function(e) cat('Failed with:', mirror, '\\n')) \
            } \
          } else { \
            cat('Leaflet already installed\\n') \
          }"

# Strategy 4: Install from GitHub as last resort
RUN echo "=== STRATEGY 4: GitHub installation (last resort) ===" && \
    R -e "if(!'leaflet' %in% installed.packages()[,'Package']) { \
            if(!'remotes' %in% installed.packages()[,'Package']) { \
              install.packages('remotes') \
            }; \
            remotes::install_github('rstudio/leaflet'); \
            cat('Strategy 4 completed\\n') \
          } else { \
            cat('Leaflet already installed\\n') \
          }" || echo "All strategies attempted"

# Verification and testing
RUN echo "=== LEAFLET VERIFICATION ===" && \
    R -e "packages <- installed.packages()[,'Package']; \
          cat('Total packages installed:', length(packages), '\\n'); \
          cat('Leaflet installed:', 'leaflet' %in% packages, '\\n'); \
          if('leaflet' %in% packages) { \
            library(leaflet); \
            cat('Leaflet version:', as.character(packageVersion('leaflet')), '\\n'); \
            m <- leaflet() %>% addTiles(); \
            cat('✅ Leaflet functionality test PASSED\\n') \
          } else { \
            cat('❌ LEAFLET INSTALLATION FAILED\\n'); \
            cat('Available packages:', head(sort(packages), 20), '\\n'); \
            stop('CRITICAL: Leaflet installation failed after all strategies') \
          }"

# Set working directory
WORKDIR /app

# Create necessary directories
RUN mkdir -p data/cache data/geographic www logs exports temp

# Copy application files
COPY app.R ./
COPY R/ ./R/
COPY config.yml ./
COPY startup_diagnostics.R ./

# Final package verification
RUN echo "=== FINAL VERIFICATION ===" && \
    R -e "required <- c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite', \
                       'DBI', 'RPostgres', 'pool', 'plotly', 'ggplot2', 'leaflet'); \
          installed <- installed.packages()[,'Package']; \
          missing <- required[!required %in% installed]; \
          if(length(missing) > 0) { \
            cat('❌ MISSING PACKAGES:', missing, '\\n'); \
            quit(status=1) \
          } else { \
            cat('✅ ALL REQUIRED PACKAGES VERIFIED\\n'); \
            for(pkg in required) { \
              tryCatch({ \
                library(pkg, character.only=TRUE); \
                cat('✓', pkg, 'loads successfully\\n') \
              }, error = function(e) { \
                cat('✗', pkg, 'FAILED to load:', conditionMessage(e), '\\n'); \
                quit(status=1) \
              }) \
            } \
          }"

# Set environment variables
ENV R_CONFIG_ACTIVE=production
ENV SHINY_LOG_LEVEL=INFO

# Expose port
EXPOSE ${PORT:-3838}

# Start the application
CMD ["R", "-e", "source('app.R')"]