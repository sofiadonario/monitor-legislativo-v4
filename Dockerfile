# Railway Dockerfile for R Shiny Application with Bulletproof PostgreSQL Connection
FROM rocker/shiny:4.3.1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libpq-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    libxml2-dev \
    libgdal-dev \
    libudunits2-dev \
    && rm -rf /var/lib/apt/lists/*

# Install required R packages
RUN R -e "install.packages(c('DBI','RPostgres','pool','shiny','shinydashboard','DT','plotly','dplyr','RColorBrewer','stringr','scales','lubridate','tidyr','jsonlite','magrittr','sf','geobr','geojsonio','R.utils'), repos='https://cran.rstudio.com/')"

# Set working directory
WORKDIR /srv/shiny-server

# Copy application files
COPY app.R ./
COPY RAILWAY_PRODUCTION_DB_FIX.R ./

# Copy modules directory with maps
COPY modules/ ./modules/

# Copy data directory (for brazil_states.R)
COPY data/ ./data/

# Copy fixes directory (for map_data_fix.R)
COPY fixes/ ./fixes/

# Copy scripts directory (for geospatial_utils.R and choropleth_generator.R)
COPY scripts/ ./scripts/

# Create directories for data files
RUN mkdir -p analytics_output

# Note: CSV files are loaded from the database or generated at runtime
# No need to copy them during build

# Make sure shiny server can read the files
RUN chmod -R 755 /srv/shiny-server

# Expose port for Railway
EXPOSE 3838

# Start the application
CMD ["R", "-e", "shiny::runApp('/srv/shiny-server/app.R', host='0.0.0.0', port=3838)"]
