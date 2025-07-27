# Optimized Dockerfile with Leaflet Support for Monitor Legislativo v4
FROM rocker/geospatial:4.3.1

# Install additional required system dependencies including Python
RUN apt-get update && apt-get install -y \
    libpq-dev \
    postgresql-client \
    libcurl4-openssl-dev \
    libssl-dev \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV R_CONFIG_ACTIVE=production
ENV SHINY_LOG_LEVEL=INFO
ENV DEPLOYMENT_TIMESTAMP=2025-07-18T10:40:00Z

# Install R packages in logical groups for better caching and faster builds

# Group 1: Core Shiny packages
RUN R -e "install.packages(c('shiny', 'shinydashboard', 'DT'), \
    repos='https://cloud.r-project.org/')"

# Group 2: Data manipulation and database packages
RUN R -e "install.packages(c('dplyr', 'jsonlite', 'DBI', 'RPostgres', 'pool', 'dbplyr'), \
    repos='https://cloud.r-project.org/')"

# Group 3: Spatial and visualization packages (including leaflet)
RUN R -e "install.packages(c('leaflet', 'plotly', 'ggplot2'), \
    repos='https://cloud.r-project.org/')"

# Group 4: Utility packages
RUN R -e "install.packages(c('config', 'httr', 'yaml', 'lubridate', 'futile.logger'), \
    repos='https://cloud.r-project.org/')"

# Group 5: Additional packages
RUN R -e "install.packages(c('htmltools', 'htmlwidgets', 'magrittr', 'readr', 'digest', \
    'crosstalk', 'viridis', 'scales', 'base64enc', 'png'), \
    repos='https://cloud.r-project.org/')"

# Group 6: UI enhancement and export packages
RUN R -e "install.packages(c('shinyjs', 'shinycssloaders', 'openxlsx', 'xml2', \
    'knitr', 'rmarkdown', 'markdown'), \
    repos='https://cloud.r-project.org/')"

# Group 7: Spatial and text processing packages
RUN R -e "install.packages(c('sf', 'geobr', 'RColorBrewer', 'stringr', 'textclean'), \
    repos='https://cloud.r-project.org/')"

# Group 8: Additional database packages
RUN R -e "install.packages(c('RSQLite', 'RPostgreSQL'), \
    repos='https://cloud.r-project.org/')"

# Group 9: Advanced analytics packages (reticulate for Python integration)
RUN R -e "install.packages(c('reticulate', 'wordcloud2'), \
    repos='https://cloud.r-project.org/')"

# Install Python dependencies for advanced analytics
COPY lexml_overview/use_version/requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Set working directory and create necessary directories
WORKDIR /app
RUN mkdir -p data/cache data/geographic www logs exports temp

# Copy application files
COPY app.R ./
COPY scripts/R/ ./scripts/R/
COPY config.yml ./
COPY dev-tools/startup_diagnostics.R ./
# Copy LexML data directory with CSV file
COPY lexml_overview/ ./lexml_overview/
# Copy data_current directory with processed data
COPY data_current/ ./data_current/

# Expose port
EXPOSE ${PORT:-3838}

# Start the application
CMD ["R", "-e", "source('app.R')"]