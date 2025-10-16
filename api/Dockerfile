FROM rocker/r-base:4.3.2

# Install system dependencies for R packages
RUN apt-get update && apt-get install -y \
    libpq-dev \
    libssl-dev \
    libcurl4-openssl-dev \
    libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

# Install R packages
RUN R -e "install.packages(c('plumber', 'DBI', 'RPostgres', 'redux', 'glue', 'jsonlite', 'digest'), repos='https://cloud.r-project.org/')"

# Set working directory
WORKDIR /app

# Copy API files
COPY . .

# Expose API port
EXPOSE 8000

# Start the API
CMD ["Rscript", "start_api.R"]
