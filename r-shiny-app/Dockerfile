# R Shiny Dockerfile for Railway
FROM rocker/shiny:4.3.2

WORKDIR /app

# Copy the minimal R Shiny app files
COPY app-minimal.R ./app.R
COPY run_app_minimal.R ./run_app.R

# Make run script executable
RUN chmod +x ./run_app.R

# Expose port (Railway will override with $PORT)
EXPOSE 3838

# Start R Shiny app using PORT from Railway
CMD ["sh", "-c", "PORT=${PORT:-3838} Rscript ./run_app.R"]