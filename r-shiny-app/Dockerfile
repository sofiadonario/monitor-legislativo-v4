# Production Dockerfile for Monitor Legislativo v4
FROM rocker/shiny:4.3.1

# Install system dependencies including additional leaflet dependencies
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
    gdal-bin \
    libgeos++-dev \
    libgeos-c1v5 \
    libproj-dev \
    proj-data \
    proj-bin \
    libgdal-dev \
    libpng-dev \
    libjpeg-dev \
    libmagick++-dev \
    librsvg2-dev \
    libwebp-dev \
    libtiff5-dev \
    libfontconfig1-dev \
    libfreetype6-dev \
    libfribidi-dev \
    libharfbuzz-dev \
    # Additional dependencies for terra and s2
    g++ \
    gcc \
    libc6-dev \
    make \
    libglpk-dev \
    libgmp3-dev \
    libicu-dev \
    libnetcdf-dev \
    libopenblas-dev \
    && rm -rf /var/lib/apt/lists/*

# Install core R packages first
ARG CACHE_BUST=7
RUN echo "Installing core R packages at $(date)" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite'))" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('DBI', 'RPostgres', 'pool', 'dbplyr'))" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('config', 'httr', 'yaml', 'lubridate'))" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('plotly', 'ggplot2', 'futile.logger'))" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('openxlsx', 'readr', 'digest', 'shinyjs', 'shinycssloaders'))"

# Install spatial dependencies first (required by leaflet)
RUN echo "Installing spatial dependencies..." && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages('sp', dependencies=TRUE)" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages('units', dependencies=TRUE)" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages('classInt', dependencies=TRUE)" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages('s2', dependencies=TRUE)" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages('sf', dependencies=TRUE)" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages('terra', dependencies=TRUE)" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages('raster', dependencies=TRUE)" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('png', 'base64enc'), dependencies=TRUE)"

# Install htmlwidgets ecosystem (required by leaflet)
RUN echo "Installing htmlwidgets dependencies..." && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('htmltools', 'htmlwidgets'), dependencies=TRUE)" && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('crosstalk', 'magrittr'), dependencies=TRUE)"

# Install additional visualization dependencies
RUN echo "Installing visualization dependencies..." && \
    R -e "options(repos='https://cran.rstudio.com/'); install.packages(c('RColorBrewer', 'viridis', 'scales'), dependencies=TRUE)"

# Install leaflet with retries and verbose output
RUN echo "Installing leaflet package..." && \
    R -e "options(repos='https://cran.rstudio.com/', download.file.method='libcurl'); \
          for(i in 1:3) { \
            tryCatch({ \
              install.packages('leaflet', dependencies=TRUE, verbose=TRUE); \
              library(leaflet); \
              cat('Leaflet installed successfully\n'); \
              break \
            }, error = function(e) { \
              cat('Attempt', i, 'failed:', conditionMessage(e), '\n'); \
              if(i == 3) stop('Failed to install leaflet after 3 attempts') \
            }) \
          }" && \
    R -e "cat('Installed packages:\n'); print(installed.packages()[,c('Package', 'Version')])"

# Set working directory
WORKDIR /app

# Create necessary directories first
RUN mkdir -p data/cache data/geographic www logs exports temp

# Copy application files
COPY app.R ./
COPY R/ ./R/
COPY config.yml ./

# Verify all required packages are installed (including leaflet)
RUN R -e "required_packages <- c('shiny', 'shinydashboard', 'DT', 'dplyr', 'jsonlite', 'DBI', 'RPostgres', 'pool', 'plotly', 'ggplot2', 'leaflet'); \
         installed <- installed.packages()[,'Package']; \
         missing <- required_packages[!required_packages %in% installed]; \
         if(length(missing) > 0) { \
           cat('ERROR: Missing required packages:', missing, '\n'); \
           cat('Installed packages:', sort(installed), '\n'); \
           quit(status=1) \
         } else { \
           cat('✅ All required packages installed successfully\n'); \
           cat('Total packages installed:', length(installed), '\n') \
         }"
# Verify leaflet functionality
RUN R -e "library(leaflet); cat('✅ Leaflet library loaded successfully - map functionality enabled\n')"

# Set environment variables
ENV R_CONFIG_ACTIVE=production
ENV SHINY_LOG_LEVEL=INFO

# Expose port
EXPOSE ${PORT:-3838}

# Start the application
CMD ["R", "-e", "source('app.R')"]