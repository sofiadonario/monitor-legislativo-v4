# Minimal Dockerfile for Monitor Legislativo v4 - Railway Deployment
FROM rocker/r-base:4.3.1

# Install system dependencies for PostgreSQL and R packages
RUN apt-get update && apt-get install -y \
    libpq-dev \
    libcurl4-openssl-dev \
    libssl-dev \
    libxml2-dev \
    libudunits2-dev \
    libgdal-dev \
    libgeos-dev \
    libproj-dev \
    build-essential \
    cmake \
    libevent-dev \
    && rm -rf /var/lib/apt/lists/*

# Install core packages first
RUN R -e "install.packages(c('config', 'DBI', 'RPostgres', 'pool', 'dplyr', 'digest', 'jsonlite', 'stringr', 'markdown'), repos='https://cloud.r-project.org/')"

# Install shiny and UI packages
RUN R -e "install.packages(c('shiny', 'shinydashboard', 'DT'), repos='https://cloud.r-project.org/')"

# Install visualization packages
RUN R -e "install.packages(c('plotly', 'ggplot2', 'leaflet'), repos='https://cloud.r-project.org/')"

WORKDIR /app

# Copy ALL the essential files
COPY app.R ./
COPY database.R ./
COPY utils.R ./
COPY diagnostic_check.R ./
COPY start_app.R ./
COPY config.yml ./

# List files to verify they were copied (diagnostic)
RUN ls -la

# Run diagnostic check at build time
RUN R -e "source('diagnostic_check.R')"

# Expose port and run
EXPOSE 3838

# Use the startup script
CMD ["R", "-e", "source('start_app.R')"]