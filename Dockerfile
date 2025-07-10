# Production Dockerfile for Monitor Legislativo v4
FROM rocker/shiny:4.3.1

# Install system dependencies
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
    libsodium-dev \
    postgresql-client \
    redis-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install R packages using binary packages to avoid compilation issues
ARG CACHE_BUST=5
RUN echo "Installing R packages at $(date)" && \
    R -e "options(repos = c(CRAN = 'https://packagemanager.rstudio.com/all/latest')); \
          install.packages(c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite', \
                           'DBI', 'RPostgres', 'pool', 'dbplyr', \
                           'config', 'httr', 'yaml', 'lubridate', \
                           'plotly', 'ggplot2', 'futile.logger', \
                           'htmltools', 'htmlwidgets', 'crosstalk', \
                           'openxlsx', 'readr', 'digest', 'shinyjs', 'shinycssloaders', \
                           'leaflet'), \
                         type = 'binary')" && \
    R -e "cat('Installed packages:\n'); print(installed.packages()[,c('Package', 'Version')])"

# Set working directory
WORKDIR /app

# Create necessary directories first
RUN mkdir -p data/cache data/geographic www logs exports temp

# Copy application files
COPY app.R ./
COPY R/ ./R/
COPY config.yml ./

# Copy test_version.R if it exists
COPY test_version.R* ./

# Copy www directory if it exists
COPY www* ./www/

# Verify required packages are installed
RUN R -e "required_packages <- c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite', \
                                'DBI', 'RPostgres', 'pool', 'plotly', 'ggplot2', 'leaflet'); \
         missing <- required_packages[!required_packages %in% installed.packages()[,'Package']]; \
         if(length(missing) > 0) { \
           cat('Missing packages:', missing, '\n'); \
           quit(status=1) \
         } else { \
           cat('All required packages installed successfully\n'); \
           library(leaflet); \
           cat('Leaflet version:', as.character(packageVersion('leaflet')), '\n') \
         }"

# Set environment variables
ENV R_CONFIG_ACTIVE=production
ENV SHINY_LOG_LEVEL=INFO

# Expose port
EXPOSE ${PORT:-3838}

# Start the application
CMD ["R", "-e", "if(file.exists('test_version.R')) source('test_version.R'); source('app.R')"]