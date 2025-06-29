# Minimal R Shiny Dockerfile for Railway
FROM rocker/shiny:4.3.2

WORKDIR /app

# Install curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copy app
COPY app.R /app/

# Install required R packages
RUN R -e "install.packages(c('shiny', 'jsonlite'), repos='https://cran.rstudio.com/')"

# Expose port
EXPOSE 3838

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:3838/ || exit 1

# Run app
CMD ["R", "-e", "shiny::runApp('/app/app.R', host='0.0.0.0', port=3838)"]