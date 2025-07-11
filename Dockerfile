# Optimized Dockerfile with Leaflet Support for Monitor Legislativo v4
FROM rocker/geospatial:4.3.1

# Install additional required system dependencies
RUN apt-get update && apt-get install -y \
    libpq-dev \
    postgresql-client \
    libcurl4-openssl-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV R_CONFIG_ACTIVE=production
ENV SHINY_LOG_LEVEL=INFO

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
    'knitr', 'rmarkdown'), \
    repos='https://cloud.r-project.org/')"

# Group 7: Spatial and text processing packages
RUN R -e "install.packages(c('sf', 'geobr', 'RColorBrewer', 'stringr', 'textclean'), \
    repos='https://cloud.r-project.org/')"

# Group 8: Additional database packages
RUN R -e "install.packages(c('RSQLite', 'RPostgreSQL'), \
    repos='https://cloud.r-project.org/')"

# Set working directory and create necessary directories
WORKDIR /app
RUN mkdir -p data/cache data/geographic www logs exports temp

# Copy application files
COPY app.R ./
COPY R/ ./R/
COPY config.yml ./
COPY dev-tools/startup_diagnostics.R ./

# Expose port
EXPOSE ${PORT:-3838}

# Start the application
CMD ["R", "-e", "source('app.R')"]