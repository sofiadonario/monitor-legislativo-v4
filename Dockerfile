# Minimal Dockerfile for Monitor Legislativo v4 - Railway Deployment
FROM rocker/r-base:4.3.1

# Install system dependencies for PostgreSQL
RUN apt-get update && apt-get install -y \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install essential packages needed by database.R and app.R
RUN R -e "install.packages(c('shiny', 'shinydashboard', 'DT', 'config', 'DBI', 'RPostgres', 'pool', 'dplyr', 'digest'), repos='https://cloud.r-project.org/')"

WORKDIR /app

# Copy ALL the essential files
COPY app.R ./
COPY database.R ./
COPY utils.R ./
COPY diagnostic_check.R ./
COPY start_app.R ./
COPY config.yml ./

# List files to verify they were copied (diagnostic)
RUN ls -la

# Run diagnostic check at build time
RUN R -e "source('diagnostic_check.R')"

# Expose port and run
EXPOSE 3838

# Use the startup script
CMD ["R", "-e", "source('start_app.R')"]