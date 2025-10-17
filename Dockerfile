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

# 2) Install R packages needed at runtime
#    Use littler's install2.r (comes with rocker images) for faster, parallel installs
RUN install2.r --error --skipinstalled -n $(getconf _NPROCESSORS_ONLN) \
    shiny shinydashboard DT leaflet plotly \
    jsonlite dplyr data.table \
    DBI RPostgres pool \
    glue digest \
    htmltools httpuv fastmap promises \
    shinythemes shinycssloaders shinyjs \
    sf geobr \
    ggplot2 scales \
    lubridate tidyr magrittr \
    RColorBrewer \
    yaml R.utils geojsonio \
    shinydashboardPlus shinyWidgets

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
