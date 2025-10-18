# Base with Shiny Server preinstalled
FROM rocker/shiny:4.5.1

# 1) System libs (Postgres, curl/ssl, XML; plus GIS libs for sf/leaflet)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev libssl-dev libcurl4-openssl-dev libxml2-dev \
    libfontconfig1-dev libharfbuzz-dev libfribidi-dev libfreetype6-dev libpng-dev libtiff5-dev libjpeg-dev \
    libgdal-dev libgeos-dev libproj-dev libudunits2-dev libsqlite3-dev \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 2) Install R packages in explicit order with error handling
# CRITICAL: Core shiny packages must succeed
RUN R -e "options(timeout = 600); \
    pkgs <- c('shiny', 'shinydashboard', 'DT'); \
    for (pkg in pkgs) { \
      cat('Installing', pkg, '...\n'); \
      install.packages(pkg, repos='https://cloud.r-project.org', dependencies=TRUE); \
      if (!requireNamespace(pkg, quietly=TRUE)) stop(paste('FAILED:', pkg)); \
      cat('SUCCESS:', pkg, '\n'); \
    }"

# Database packages - CRITICAL
RUN R -e "options(timeout = 600); \
    pkgs <- c('DBI', 'RPostgres', 'pool'); \
    for (pkg in pkgs) { \
      cat('Installing', pkg, '...\n'); \
      install.packages(pkg, repos='https://cloud.r-project.org', dependencies=TRUE); \
      if (!requireNamespace(pkg, quietly=TRUE)) stop(paste('FAILED:', pkg)); \
      cat('SUCCESS:', pkg, '\n'); \
    }"

# Data manipulation - CRITICAL
RUN R -e "options(timeout = 600); \
    pkgs <- c('dplyr', 'data.table', 'lubridate', 'tidyr', 'magrittr', 'stringr', 'readr'); \
    for (pkg in pkgs) { \
      cat('Installing', pkg, '...\n'); \
      install.packages(pkg, repos='https://cloud.r-project.org', dependencies=TRUE); \
      if (!requireNamespace(pkg, quietly=TRUE)) stop(paste('FAILED:', pkg)); \
      cat('SUCCESS:', pkg, '\n'); \
    }"

# Visualization packages - CRITICAL
RUN R -e "options(timeout = 600); \
    pkgs <- c('ggplot2', 'scales', 'RColorBrewer', 'plotly'); \
    for (pkg in pkgs) { \
      cat('Installing', pkg, '...\n'); \
      install.packages(pkg, repos='https://cloud.r-project.org', dependencies=TRUE); \
      if (!requireNamespace(pkg, quietly=TRUE)) stop(paste('FAILED:', pkg)); \
      cat('SUCCESS:', pkg, '\n'); \
    }"

# Web/utility packages
RUN R -e "options(timeout = 600); \
    install.packages(c('htmltools', 'httpuv', 'fastmap', 'promises', 'future', 'jsonlite', 'glue', 'digest', 'httr', 'memoise'), \
    repos='https://cloud.r-project.org', dependencies=TRUE)"

# Shiny extensions
RUN R -e "options(timeout = 600); \
    install.packages(c('shinythemes', 'shinycssloaders', 'shinyjs', 'shinydashboardPlus', 'shinyWidgets'), \
    repos='https://cloud.r-project.org', dependencies=TRUE)"

# Spatial packages (may take longer, but required for maps)
RUN R -e "options(timeout = 900); \
    install.packages(c('sf', 'lwgeom', 'units'), repos='https://cloud.r-project.org', dependencies=TRUE)"

RUN R -e "options(timeout = 900); \
    install.packages('leaflet', repos='https://cloud.r-project.org', dependencies=TRUE); \
    if (!requireNamespace('leaflet', quietly=TRUE)) stop('FAILED: leaflet is required for maps')"

# Spatial data helpers (optional but useful)
RUN R -e "options(timeout = 900); \
    tryCatch({ \
      install.packages(c('geobr', 'rmapshaper', 'geojsonio'), repos='https://cloud.r-project.org', dependencies=TRUE); \
      cat('Spatial helpers installed successfully\n') \
    }, error=function(e) { \
      cat('WARNING: Some spatial helpers failed (non-critical):', e$message, '\n') \
    })"

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
