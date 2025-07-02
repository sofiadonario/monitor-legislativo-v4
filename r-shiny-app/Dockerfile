# Optimized Dockerfile for Railway R Shiny deployment
FROM rocker/shiny:4.3.1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
    libssl-dev \
    libxml2-dev \
    libgdal-dev \
    libudunits2-dev \
    libproj-dev \
    libgeos-dev \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy R application files (paths relative to build context)
COPY app-minimal.R ./app.R
COPY .Rprofile ./

# Install R packages
RUN R -e "source('.Rprofile')"

# Create necessary directories
RUN mkdir -p data/cache data/geographic www logs exports

# Set permissions
RUN chown -R shiny:shiny /app

# Expose port
EXPOSE 3838

# Run the Shiny app with proper signal handling
CMD ["R", "-e", "shiny::runApp('/app/app.R', host='0.0.0.0', port=as.integer(Sys.getenv('PORT', '3838')))"]