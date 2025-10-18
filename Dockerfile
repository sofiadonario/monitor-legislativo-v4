# Base with Shiny Server preinstalled
FROM rocker/shiny:4.5.1

# 1) System libs (Postgres, curl/ssl, XML; plus GIS libs for sf/leaflet)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev libssl-dev libcurl4-openssl-dev libxml2-dev \
    libfontconfig1-dev \
    libgdal-dev libgeos-dev libproj-dev libudunits2-dev \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 2) Install R packages in stages for better error handling
# Core shiny packages first
RUN R -e "install.packages(c('shiny', 'shinydashboard', 'DT'), \
    repos='https://cloud.r-project.org', dependencies=TRUE)"

# Database packages
RUN R -e "install.packages(c('DBI', 'RPostgres', 'pool'), \
    repos='https://cloud.r-project.org', dependencies=TRUE)"

# Data manipulation
RUN R -e "install.packages(c('dplyr', 'data.table', 'lubridate', 'tidyr', 'magrittr'), \
    repos='https://cloud.r-project.org', dependencies=TRUE)"

# Visualization packages
RUN R -e "install.packages(c('ggplot2', 'scales', 'RColorBrewer', 'plotly'), \
    repos='https://cloud.r-project.org', dependencies=TRUE)"

# Web/UI packages
RUN R -e "install.packages(c('htmltools', 'httpuv', 'fastmap', 'promises', 'jsonlite', 'glue', 'digest'), \
    repos='https://cloud.r-project.org', dependencies=TRUE)"

# Shiny extensions
RUN R -e "install.packages(c('shinythemes', 'shinycssloaders', 'shinyjs', 'shinydashboardPlus', 'shinyWidgets'), \
    repos='https://cloud.r-project.org', dependencies=TRUE)"

# Optional packages (won't fail build if they don't install)
RUN R -e "tryCatch({ \
    install.packages(c('leaflet', 'sf', 'geobr', 'yaml', 'R.utils', 'geojsonio'), \
    repos='https://cloud.r-project.org', dependencies=TRUE) \
}, error=function(e) cat('Optional packages skipped:', e$message, '\n'))"

# 3) Copy your app into /app directory
WORKDIR /app
COPY . /app/

# 4) Environment + port
ENV PORT=3838
EXPOSE 3838

# 5) Health check for Railway
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:3838/health || exit 1

# 6) Start app directly with R (not through shiny-server)
CMD ["R", "-e", "shiny::runApp('app.R', host='0.0.0.0', port=as.numeric(Sys.getenv('PORT', '3838')))"]
