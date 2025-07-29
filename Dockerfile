# Monitor Legislativo v4 - Optimized Railway Deployment
# Using rocker/shiny for pre-installed shiny packages
FROM rocker/shiny:4.3.1

# Install only essential system dependencies
RUN apt-get update && apt-get install -y \
    libpq-dev \
    libgdal-dev \
    libudunits2-dev \
    && rm -rf /var/lib/apt/lists/*

# Install all required packages in one command using binary packages where possible
RUN install2.r --error --skipinstalled \
    config \
    DBI \
    RPostgres \
    pool \
    dplyr \
    shinydashboard \
    DT \
    jsonlite \
    plotly \
    ggplot2 \
    leaflet \
    stringr \
    markdown \
    readr

# Quick verification that key packages are installed
RUN R -e "if(!require(shiny)) stop('shiny not installed'); if(!require(shinydashboard)) stop('shinydashboard not installed'); cat('✓ All packages verified\n')"

WORKDIR /app

# Copy ALL the essential files
COPY app.R ./
COPY database.R ./
COPY utils.R ./
COPY missing_functions.R ./
COPY diagnostic_check.R ./
COPY start_app.R ./
COPY config.yml ./
COPY railway_debug.R ./
COPY scripts/ ./scripts/

# List files to verify they were copied (diagnostic)
RUN ls -la

# Skip diagnostic check to speed up build
# RUN R -e "source('diagnostic_check.R')"

# Expose port and run
EXPOSE 3838

# Use the startup script
CMD ["R", "-e", "source('start_app.R')"]