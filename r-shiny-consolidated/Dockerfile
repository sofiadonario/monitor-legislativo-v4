# Monitor Legislativo v4 - R Architecture Consolidation
# Production Docker container for unified R Shiny application

FROM rocker/shiny-verse:4.3.2

# Set working directory
WORKDIR /srv/shiny-server/

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    libssl-dev \
    libxml2-dev \
    libpq-dev \
    libsodium-dev \
    libudunits2-dev \
    libgdal-dev \
    libgeos-dev \
    libproj-dev \
    libv8-dev \
    libjq-dev \
    libprotobuf-dev \
    protobuf-compiler \
    libjpeg-dev \
    libpng-dev \
    libtiff-dev \
    libfribidi-dev \
    libharfbuzz-dev \
    libfontconfig1-dev \
    libfreetype6-dev \
    libmagick++-dev \
    redis-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy package management files
COPY DESCRIPTION renv.lock ./

# Install renv and restore packages
RUN R -e "install.packages('renv', repos='https://cloud.r-project.org')"
RUN R -e "renv::consent(provided = TRUE)"
RUN R -e "renv::restore()"

# Install additional R packages not in renv.lock
RUN R -e "install.packages(c('geobr', 'redux', 'openxlsx', 'digest'), repos='https://cloud.r-project.org')"

# Copy application files
COPY app.R ./
COPY config.yml ./
COPY R/ ./R/
COPY data/ ./data/

# Create directories for logs and exports
RUN mkdir -p logs exports

# Set proper permissions
RUN chown -R shiny:shiny /srv/shiny-server/
RUN chmod -R 755 /srv/shiny-server/

# Configure Shiny Server
RUN echo "run_as shiny;" > /etc/shiny-server/shiny-server.conf && \
    echo "server {" >> /etc/shiny-server/shiny-server.conf && \
    echo "  listen 3838;" >> /etc/shiny-server/shiny-server.conf && \
    echo "  location / {" >> /etc/shiny-server/shiny-server.conf && \
    echo "    site_dir /srv/shiny-server;" >> /etc/shiny-server/shiny-server.conf && \
    echo "    log_dir /var/log/shiny-server;" >> /etc/shiny-server/shiny-server.conf && \
    echo "    directory_index on;" >> /etc/shiny-server/shiny-server.conf && \
    echo "    app_init_timeout 60;" >> /etc/shiny-server/shiny-server.conf && \
    echo "    app_idle_timeout 300;" >> /etc/shiny-server/shiny-server.conf && \
    echo "  }" >> /etc/shiny-server/shiny-server.conf && \
    echo "}" >> /etc/shiny-server/shiny-server.conf

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:3838/ || exit 1

# Expose port
EXPOSE 3838

# Set environment
ENV R_CONFIG_ACTIVE=production
ENV SHINY_PORT=3838

# Start command
CMD ["/usr/bin/shiny-server"]