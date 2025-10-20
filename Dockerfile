# Railway cache bust - $(date)
# Last rebuild: Sun Oct 19 21:30:00 -03 2025
# FORCE COMPLETE CACHE INVALIDATION
FROM rocker/shiny:4.5.1

# 1) System libs - CRITICAL: cmake + libabsl-dev needed for s2 (dependency of sf/leaflet)
# NOTE: liblwgeom-dev doesn't exist in Ubuntu 24.04 (noble) - removed
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential g++ make cmake pkg-config \
    libabsl-dev \
    libpq-dev libssl-dev libcurl4-openssl-dev libxml2-dev \
    libfontconfig1-dev libharfbuzz-dev libfribidi-dev libfreetype6-dev libpng-dev libtiff5-dev libjpeg-dev \
    libgdal-dev libgeos-dev libproj-dev libudunits2-dev libsqlite3-dev \
    protobuf-compiler libprotobuf-dev \
    postgresql-client \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 2) CRITICAL: Disable renv and all user profiles in production
# This prevents any auto-activation or profile hijacking of library paths
ENV RENV_CONFIG_AUTO_ACTIVATE=FALSE
ENV RENV_CONFIG_ACTIVATE_ON_LOAD=FALSE
ENV R_PROFILE_USER=/dev/null
ENV R_ENVIRON_USER=/dev/null

# 3) Install pak for better dependency management
RUN R -q -e "install.packages('pak', repos='https://r-lib.github.io/p/pak/stable/')"

# 4) Install R packages explicitly (no Suggests avalanche)
RUN R -q -e "options(timeout=900, Ncpus=parallel::detectCores()); \
  install.packages(c( \
    'shinydashboard','shiny','DT', \
    'DBI','RPostgres','pool', \
    'dplyr','data.table','lubridate','tidyr','magrittr','stringr','readr', \
    'ggplot2','scales','RColorBrewer','plotly', \
    'htmltools','httpuv','fastmap','promises','future','jsonlite','glue','digest','httr','memoise', \
    'shinythemes','shinycssloaders','shinyjs','shinydashboardPlus','shinyWidgets', \
    'units','s2','sf','leaflet','openxlsx' \
  ), repos='https://cloud.r-project.org')"

# 5) Spatial data helpers (optional - geobr can be heavy)
RUN R -q -e "tryCatch({ \
  pak::pkg_install(c('geobr', 'rmapshaper', 'geojsonio')); \
  cat('Spatial helpers installed successfully\\n') \
}, error = function(e) { \
  cat('WARNING: Some spatial helpers failed (non-critical):', e\$message, '\\n') \
})"

# 6) VERIFICATION: Fail build if must-haves aren't truly there
RUN R -q -e "stopifnot( \
  requireNamespace('shinydashboard', quietly=TRUE), \
  requireNamespace('shiny', quietly=TRUE), \
  requireNamespace('DT', quietly=TRUE), \
  requireNamespace('leaflet', quietly=TRUE), \
  requireNamespace('DBI', quietly=TRUE), \
  requireNamespace('RPostgres', quietly=TRUE), \
  requireNamespace('pool', quietly=TRUE) \
); cat('✅ All critical packages verified at build time\\n')"

# 7) Copy application into /app directory (simple setup)
ARG CACHEBUST=$(date +%Y%m%d%H%M%S)
WORKDIR /app
COPY . /app/

# 8) Environment + port
ENV PORT=3838
EXPOSE 3838

# 9) Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:3838/health || exit 1

# 10) Start app directly with R (bypass shiny-server)
CMD ["R", "-e", "shiny::runApp('app.R', host='0.0.0.0', port=as.numeric(Sys.getenv('PORT', '3838')))" ]
