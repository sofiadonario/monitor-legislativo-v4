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

# Install R packages - force cache bust with timestamp
ARG CACHE_BUST=4
RUN echo "Installing R packages at $(date)" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite'))" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('DBI', 'RPostgres', 'pool', 'dbplyr'))" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('config', 'httr', 'yaml', 'lubridate'))" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('plotly', 'ggplot2', 'futile.logger'))" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('leaflet', 'sf', 'geobr'))" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('openxlsx', 'readr', 'digest'))" && \
    R -e "cat('Installed packages:\n'); print(installed.packages()[,c('Package', 'Version')])"

# Set working directory
WORKDIR /app

# Create necessary directories first
RUN mkdir -p data/cache data/geographic www logs exports temp

# Copy application files
COPY app.R ./
COPY R/ ./R/
COPY config.yml ./

# Verify required packages are installed
RUN R -e "required_packages <- c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite', 'DBI', 'RPostgres', 'pool', 'plotly', 'ggplot2', 'leaflet'); missing <- required_packages[!required_packages %in% installed.packages()[,'Package']]; if(length(missing) > 0) { cat('Missing packages:', missing, '\n'); quit(status=1) } else { cat('All required packages installed\n') }"

# Set environment variables
ENV R_CONFIG_ACTIVE=production
ENV SHINY_LOG_LEVEL=INFO

# Expose port
EXPOSE ${PORT:-3838}

# Start the application
CMD ["R", "-e", "source('app.R')"]