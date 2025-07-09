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

# Install R packages with proper dependencies
RUN R -e "install.packages(c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite'), repos='https://cran.rstudio.com/')" && \
    R -e "install.packages(c('leaflet', 'plotly'), repos='https://cran.rstudio.com/')" && \
    R -e "install.packages(c('RSQLite', 'DBI', 'config', 'httr', 'yaml'), repos='https://cran.rstudio.com/')"

# Set working directory
WORKDIR /app

# Create necessary directories first
RUN mkdir -p data/cache data/geographic www logs exports temp

# Copy application files
COPY app.R ./
COPY R/ ./R/
COPY www/ ./www/
COPY config.yml ./

# Set environment variables
ENV R_CONFIG_ACTIVE=production
ENV SHINY_LOG_LEVEL=INFO

# Expose port
EXPOSE ${PORT:-3838}

# Start the application
CMD ["R", "-e", "options(shiny.port = as.integer(Sys.getenv('PORT', '3838')), shiny.host = '0.0.0.0', shiny.maxRequestSize = 100*1024^2); shiny::runApp('app.R', launch.browser = FALSE)"]