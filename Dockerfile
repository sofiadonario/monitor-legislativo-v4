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
ARG CACHE_BUST=1
RUN echo "Installing R packages at $(date)" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite'))" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('leaflet', 'plotly'))" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('RSQLite', 'DBI', 'config', 'httr', 'yaml'))" && \
    R -e "cat('Installed packages:\n'); print(installed.packages()[,c('Package', 'Version')])"

# Set working directory
WORKDIR /app

# Create necessary directories first
RUN mkdir -p data/cache data/geographic www logs exports temp

# Copy application files
COPY app_minimal.R ./app.R
COPY R/ ./R/
COPY www/ ./www/
COPY config.yml ./

# Verify minimal required packages are installed
RUN R -e "required_packages <- c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite'); missing <- required_packages[!required_packages %in% installed.packages()[,'Package']]; if(length(missing) > 0) { cat('Missing packages:', missing, '\n'); quit(status=1) } else { cat('All required packages installed\n') }"

# Set environment variables
ENV R_CONFIG_ACTIVE=production
ENV SHINY_LOG_LEVEL=INFO

# Expose port
EXPOSE ${PORT:-3838}

# Create health check
RUN echo 'OK' > /tmp/health

# Start the application
CMD ["R", "-e", "options(shiny.port = as.integer(Sys.getenv('PORT', '3838')), shiny.host = '0.0.0.0', shiny.maxRequestSize = 100*1024^2); source('app.R')"]