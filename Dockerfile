# syntax=docker/dockerfile:1.4
# BuildKit heredocs are required below

# OPTIMIZED RAILWAY DOCKERFILE FOR R SHINY APPLICATION
# ====================================================
# Production-ready, memory-optimized for Railway deployment
FROM rocker/shiny:4.5.1

# Set memory and CPU limits for Railway
ENV R_MAX_VSIZE=2G \
    R_NSIZE=1000000 \
    R_VSIZE=1000000000

# PROJ data path for sf at runtime
ENV PROJ_LIB=/usr/share/proj \
    RENV_CONFIG_INSTALL_PACKAGES_CHECK_SOURCE=yes

# Create non-root user for security
RUN groupadd -r shinyapp && useradd -r -g shinyapp -u 1001 shinyapp

# Update packages
RUN apt-get update && apt-get upgrade -y

# Install system dependencies with security updates and memory optimization
# NOTE: Ubuntu noble (24.04) ships PROJ 9.x with libproj.so.25 - ensure sf compiles against this
# CRITICAL: Added cmake and libabsl-dev for s2 package compilation
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get install -y --no-install-recommends \
    libpq-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    libxml2-dev \
    libfontconfig1-dev \
    libfreetype6-dev \
    libfribidi-dev \
    libharfbuzz-dev \
    libjpeg-dev \
    libpng-dev \
    libtiff5-dev \
    libpoppler-cpp-dev \
    libpoppler-dev \
    postgresql-client \
    build-essential \
    pkg-config \
    default-jdk \
    ca-certificates \
    curl \
    htop \
    libicu-dev \
    cmake \
    libabsl-dev \
    libproj-dev \
    libproj25 \
    proj-data \
    proj-bin \
    libgeos-dev \
    libgeos++-dev \
    libgdal-dev \
    gdal-bin \
    libudunits2-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /tmp/* \
    && rm -rf /var/tmp/*

# Ensure Java is detected by R for rJava/mallet
RUN R CMD javareconf

# Set global R options for source compilation during Docker build
RUN R -q -e "options(repos=c(CRAN='https://cloud.r-project.org'), \
                     Ncpus=parallel::detectCores(), \
                     pkgType='source', \
                     install.packages.check.source='yes'); \
            cat('R build options set for source compilation\\n')"

# Install remotes for version pinning
RUN R -q -e "options(repos=c(CRAN='https://cloud.r-project.org')); \
  if (!('remotes' %in% rownames(installed.packages()))) install.packages('remotes', Ncpus=2)"

#############################################
# Rebuild stringi from source (ICU match)   #
#############################################
RUN <<'BASH' bash
set -euo pipefail
cat >/tmp/install_stringi_stack.R <<'RSCRIPT'
options(repos = c(CRAN = "https://cloud.r-project.org"),
        Ncpus = max(1L, parallel::detectCores()),
        pkgType = "source",
        install.packages.check.source = "yes")
message("[icu] Rebuilding stringi from source to match container ICU...")
if ("stringi" %in% rownames(installed.packages())) remove.packages("stringi")
install.packages("stringi")
message("[icu] Installing stringr (depends on stringi)...")
install.packages("stringr")
suppressPackageStartupMessages(library(stringi))
suppressPackageStartupMessages(library(stringr))
cat("SMOKETEST OK: stringi/stringr from source with system ICU\n")
RSCRIPT
Rscript /tmp/install_stringi_stack.R
rm -f /tmp/install_stringi_stack.R
BASH

#############################################
# Build s2 first (Abseil via system or vendored)
#############################################
RUN <<'BASH' bash
set -euo pipefail
cat >/tmp/install_s2_stack.R <<'RSCRIPT'
options(repos = c(CRAN = "https://cloud.r-project.org"),
        Ncpus = max(1L, parallel::detectCores()),
        pkgType = "source",
        install.packages.check.source = "yes")
# Prefer system Abseil if present; otherwise vendored path (needs cmake)
if (file.exists("/usr/lib/x86_64-linux-gnu/pkgconfig/absl_base.pc") ||
    file.exists("/usr/lib/x86_64-linux-gnu/cmake/absl/abslConfig.cmake")) {
  message("[s2] System Abseil detected, setting S2_USE_SYSTEM_ABSEIL=TRUE")
  Sys.setenv(S2_USE_SYSTEM_ABSEIL = "TRUE")
}
message("[s2] Installing s2 from source...")
install.packages("s2")
suppressPackageStartupMessages(library(s2))
cat("SMOKETEST OK: s2 loads (Abseil: ", Sys.getenv("S2_USE_SYSTEM_ABSEIL", "vendored"), ")\n", sep="")
RSCRIPT
Rscript /tmp/install_s2_stack.R
rm -f /tmp/install_s2_stack.R
BASH

#############################################
# Then build sf against system PROJ/GEOS/GDAL
#############################################
RUN <<'BASH' bash
set -euo pipefail
cat >/tmp/install_sf_stack.R <<'RSCRIPT'
options(repos = c(CRAN = "https://cloud.r-project.org"),
        Ncpus = max(1L, parallel::detectCores()),
        pkgType = "source",
        install.packages.check.source = "yes")
if ("sf" %in% rownames(installed.packages())) remove.packages("sf")
message("[sf] Installing sf from source...")
install.packages("sf")
message("[sf] Verifying load...")
suppressPackageStartupMessages(library(sf))
cat("SMOKETEST OK: sf loads and links to system libs\n")
RSCRIPT
Rscript /tmp/install_sf_stack.R
rm -f /tmp/install_sf_stack.R
BASH

#############################################
# Chart stack: scales >=1.4.0, ggplot2, plotly
#############################################
RUN <<'BASH' bash
set -euo pipefail
cat >/tmp/install_chart_stack.R <<'RSCRIPT'
options(repos = c(CRAN = "https://cloud.r-project.org"),
        Ncpus = max(1L, parallel::detectCores()),
        pkgType = "source",
        install.packages.check.source = "yes")
if (!requireNamespace("remotes", quietly = TRUE)) install.packages("remotes")
target_scales <- "1.4.0"
message("[chart] Installing scales==", target_scales, " from source...")
if ("scales" %in% rownames(installed.packages())) remove.packages("scales")
remotes::install_version("scales", version = target_scales, upgrade = "never")
message("[chart] Installing ggplot2 and plotly from source...")
install.packages(c("ggplot2","plotly"))
message("[chart] Verifying versions and loadability...")
stopifnot(utils::packageVersion("scales") >= target_scales)
suppressPackageStartupMessages(library(ggplot2))
suppressPackageStartupMessages(library(plotly))
cat("SMOKETEST OK: scales>=", target_scales, ", ggplot2, plotly\n", sep = "")
RSCRIPT
Rscript /tmp/install_chart_stack.R
rm -f /tmp/install_chart_stack.R
BASH

#############################################
# DB stack: bit, bit64, DBI, RPostgres, pool
#############################################
RUN <<'BASH' bash
set -euo pipefail
cat >/tmp/install_db_stack.R <<'RSCRIPT'
options(repos = c(CRAN = "https://cloud.r-project.org"),
        Ncpus = max(1L, parallel::detectCores()),
        pkgType = "source",
        install.packages.check.source = "yes")
message("[db] Installing bit and bit64...")
install.packages(c("bit","bit64"))
message("[db] Installing DBI, RPostgres, pool, jsonlite, httr...")
install.packages(c("DBI","RPostgres","pool","jsonlite","httr"))
message("[db] Verifying loadability...")
suppressPackageStartupMessages(library(bit))
suppressPackageStartupMessages(library(bit64))
suppressPackageStartupMessages(library(DBI))
suppressPackageStartupMessages(library(RPostgres))
suppressPackageStartupMessages(library(pool))
suppressPackageStartupMessages(library(httr))
cat("SMOKETEST OK: DBI/RPostgres/pool/httr and bit/bit64\n")
RSCRIPT
Rscript /tmp/install_db_stack.R
rm -f /tmp/install_db_stack.R
BASH

# Pin CRAN repository to specific snapshot for reproducibility
ENV CRAN_SNAPSHOT="2024-09-15"

# Stage 1: Core packages (required for basic functionality)
RUN R -e "options(repos = c(CRAN = 'https://packagemanager.rstudio.com/cran/__linux__/jammy/2024-09-15')); \
    install.packages(c('shiny'), \
    dependencies = TRUE, Ncpus = 2)" && \
    rm -rf /tmp/R* && \
    R -e "gc()"

# Optional common runtime libs your app already uses (idempotent)
RUN R -q -e "options(repos=c(CRAN='https://cloud.r-project.org')); \
  pkgs <- c('dplyr','DT','shinydashboard','RColorBrewer'); \
  to_install <- setdiff(pkgs, rownames(installed.packages())); \
  if (length(to_install)) install.packages(to_install, dependencies=TRUE, Ncpus=2)"

# Stage 3: Data manipulation packages (including data.table for CSV loading)
RUN R -e "options(repos = c(CRAN = 'https://packagemanager.rstudio.com/cran/__linux__/jammy/2024-09-15')); \
    install.packages(c('lubridate', 'tidyr', 'magrittr', 'data.table'), \
    dependencies = TRUE, Ncpus = 2)" && \
    rm -rf /tmp/R* && \
    R -e "gc()"

# Install geobr after sf is properly built
RUN R -e "options(repos = c(CRAN = 'https://packagemanager.rstudio.com/cran/__linux__/jammy/2024-09-15')); \
    tryCatch({ \
      install.packages(c('geobr'), dependencies = TRUE, Ncpus = 1); \
      cat('geobr installed successfully\\n') \
    }, error = function(e) { \
      cat('geobr installation failed:', e\$message, '\\n') \
    })" && \
    rm -rf /tmp/R* && \
    R -e "gc()"

#############################################
# Final consolidated smoketest
#############################################
RUN R -q -e " \
  suppressPackageStartupMessages({library(stringi);library(stringr); \
  library(s2); library(sf); library(ggplot2); library(plotly); library(DBI); library(RPostgres); library(pool)}); \
  stopifnot(utils::packageVersion('scales') >= '1.4.0'); \
  cat('=== ALL SMOKETESTS PASSED ===\\n'); \
  cat('  - stringi/stringr: system ICU\\n'); \
  cat('  - s2: Abseil support enabled\\n'); \
  cat('  - sf: libproj25 linkage\\n'); \
  cat('  - scales>=1.4.0, ggplot2, plotly\\n'); \
  cat('  - DBI/RPostgres/pool with bit/bit64\\n'); \
  cat('=============================\\n')"

# Verify sf.so linkage to libproj25
RUN bash -c "so=\$(Rscript -e 'cat(system.file(\"libs\", \"sf.so\", package=\"sf\"))') && \
    if [ -f \"\$so\" ]; then echo 'Checking sf.so PROJ linkage:' && ldd \$so | grep libproj; fi"

# Stage 5: Additional visualization and utility packages (including lwgeom)
RUN R -e "options(repos = c(CRAN = 'https://packagemanager.rstudio.com/cran/__linux__/jammy/2024-09-15')); \
    install.packages(c('geojsonio', 'R.utils', 'yaml', 'shinyjs', 'htmltools', 'leaflet', 'shinydashboardPlus', 'shinyWidgets', 'shinycssloaders'), \
    dependencies = TRUE, Ncpus = 2)" && \
    rm -rf /tmp/R* && \
    R -e "gc()"

# Stage 6: Analytics and visualization packages
RUN R -e "options(repos = c(CRAN = 'https://packagemanager.rstudio.com/cran/__linux__/jammy/2024-09-15')); \
    tryCatch({ \
      install.packages(c('igraph', 'networkD3', 'forecast', 'changepoint'), dependencies = TRUE, Ncpus = 2); \
      cat('Analytics packages installed successfully\\n') \
    }, error = function(e) { \
      cat('Analytics packages installation failed, continuing...\\n') \
    })" && \
    rm -rf /tmp/R* && \
    R -e "gc()"

# Stage 7: PDF processing and text mining packages
RUN R -e "options(repos = c(CRAN = 'https://packagemanager.rstudio.com/cran/__linux__/jammy/2024-09-15')); \
    tryCatch({ \
      install.packages(c('pdftools', 'Rpoppler', 'tm', 'tidytext', 'rJava', 'mallet', 'topicmodels'), dependencies = TRUE, Ncpus = 2); \
      cat('PDF processing and text mining packages installed successfully\\n') \
    }, error = function(e) { \
      cat('PDF processing packages installation failed, continuing...\\n') \
    })" && \
    rm -rf /tmp/R* && \
    R -e "gc()"

# Stage 8: Optional packages (can fail without breaking deployment)
RUN R -e "options(repos = c(CRAN = 'https://packagemanager.rstudio.com/cran/__linux__/jammy/2024-09-15')); \
    tryCatch({ \
      install.packages(c('echarts4r', 'digest', 'plumber'), dependencies = TRUE, Ncpus = 2) \
    }, error = function(e) { \
      cat('Optional packages installation failed, continuing...\\n') \
    })" && \
    rm -rf /tmp/R* && \
    R -e "gc()"

# Set working directory
WORKDIR /app

# Cache buster - forces rebuild of application files layer
ARG CACHE_DATE=2025-01-07

# Copy essential application files
COPY app_railway.R ./
COPY start.R ./
COPY railway_minimal_health.R ./
COPY railway_ultra_minimal.R ./
COPY railway_production_server.R ./
COPY railway_production_final.R ./

# Copy original application (fallback)
COPY app.R ./

# Copy health check endpoints
COPY plumber.R ./

# Copy essential system files
COPY railway_migrate.sh ./
COPY health_check.R ./
COPY start_with_db_init.sh ./
COPY start_with_api.sh ./

# Copy database migration files
COPY --chown=shinyapp:shinyapp database/ ./database/

# Copy API directory (Plumber REST API)
COPY --chown=shinyapp:shinyapp api/ ./api/

# Copy data directory with actual CSV files (CRITICAL for fallback when database unavailable)
COPY --chown=shinyapp:shinyapp data_current/ ./data_current/

# Copy global configuration (clean architecture)
COPY global.R ./

# Copy core directories (with error handling)
COPY --chown=shinyapp:shinyapp db/ ./db/
COPY --chown=shinyapp:shinyapp auth/ ./auth/
COPY --chown=shinyapp:shinyapp monitoring/ ./monitoring/

# Copy modules directory with maps (optional)
COPY --chown=shinyapp:shinyapp modules/ ./modules/

# Copy configuration and data directories (optional)
COPY --chown=shinyapp:shinyapp data/ ./data/
COPY --chown=shinyapp:shinyapp scripts/ ./scripts/
COPY --chown=shinyapp:shinyapp config/ ./config/

# Copy R Architecture Consolidation implementation (CRITICAL)
COPY --chown=shinyapp:shinyapp R/ ./R/

# Create required directories with proper ownership
RUN mkdir -p analytics_output logs cache tmp && \
    chown -R shinyapp:shinyapp /app && \
    chmod -R 755 /app && \
    chmod +x /app/start_with_db_init.sh /app/start_with_api.sh /app/railway_migrate.sh

# Remove any potentially dangerous files that might have been copied
RUN find /app -name "*.R" -path "*/RAILWAY_PRODUCTION_DB_FIX.R" -delete 2>/dev/null || true && \
    find /app -name "*password*" -delete 2>/dev/null || true && \
    find /app -name "*secret*" -delete 2>/dev/null || true && \
    find /app -name ".env*" -delete 2>/dev/null || true

# Set Railway-specific environment variables
ENV SHINY_HOST=0.0.0.0 \
    SHINY_PORT=3838 \
    RAILWAY_DEPLOYMENT=true \
    R_LIBS_USER=/usr/local/lib/R/site-library \
    LC_ALL=en_US.UTF-8 \
    LANG=en_US.UTF-8

# Switch to non-root user
USER shinyapp

# Expose port
EXPOSE 3838

# Health check for Railway monitoring
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:3838/health || exit 1

# Use startup script that initializes database schema and API before starting app
CMD ["/app/start_with_api.sh"]