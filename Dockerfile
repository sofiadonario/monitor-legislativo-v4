# Monitor Legislativo v4 - Railway Deployment (Fixed package installation)
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

# Force fresh shiny installation - install dependencies first
RUN R -e "install.packages(c('httpuv', 'mime', 'htmltools', 'xtable', 'sourcetools', 'later', 'promises', 'crayon', 'rlang'), repos='https://cloud.r-project.org/')"

# Install shiny and UI packages with verbose output
RUN R -e "install.packages(c('shiny', 'shinydashboard', 'DT'), repos='https://cloud.r-project.org/', verbose=TRUE)"

# Install visualization packages
RUN R -e "install.packages(c('plotly', 'ggplot2', 'leaflet'), repos='https://cloud.r-project.org/')"

# Check individual package installation
RUN R -e "packages <- c('shiny', 'shinydashboard', 'DT'); for(pkg in packages) { if(requireNamespace(pkg, quietly=TRUE)) { cat('✓', pkg, 'OK\n') } else { cat('✗', pkg, 'MISSING\n') } }"

# Test loading shiny package specifically during build
RUN R -e "library(shiny); cat('✓ Shiny package loads successfully during build\n'); cat('Shiny version:', as.character(packageVersion('shiny')), '\n')"

# Check and fix library paths for Railway compatibility
RUN R -e "cat('Library paths during build:\n'); print(.libPaths()); cat('R_LIBS_USER:\n'); cat(Sys.getenv('R_LIBS_USER'), '\n')"

# Ensure packages are accessible in standard locations
RUN R -e "if(!dir.exists('/usr/local/lib/R/site-library')) { dir.create('/usr/local/lib/R/site-library', recursive=TRUE) }; cat('Created standard library directory\n')"

# Set environment variable for consistent library path
ENV R_LIBS_USER=/usr/local/lib/R/site-library

# Railway-specific fix: Ensure packages are accessible at runtime
# Create links from build-time library to runtime library paths
RUN mkdir -p /usr/local/lib/R/site-library && \
    R -e "build_libs <- .libPaths()[1]; runtime_lib <- '/usr/local/lib/R/site-library'; if(build_libs != runtime_lib && dir.exists(build_libs)) { system(paste('cp -r', file.path(build_libs, '*'), runtime_lib, '2>/dev/null || true')) }"

# Final verification that shiny is accessible in the target location
RUN R -e "cat('Final shiny check in target location:\n'); .libPaths('/usr/local/lib/R/site-library'); if(requireNamespace('shiny', quietly=TRUE)) { cat('✓ SHINY ACCESSIBLE\n') } else { cat('✗ SHINY NOT ACCESSIBLE\n'); quit(status=1) }"

WORKDIR /app

# Copy ALL the essential files
COPY app.R ./
COPY database.R ./
COPY utils.R ./
COPY diagnostic_check.R ./
COPY start_app.R ./
COPY config.yml ./
COPY railway_debug.R ./

# List files to verify they were copied (diagnostic)
RUN ls -la

# Run diagnostic check at build time
RUN R -e "source('diagnostic_check.R')"

# Expose port and run
EXPOSE 3838

# Use the startup script
CMD ["R", "-e", "source('start_app.R')"]