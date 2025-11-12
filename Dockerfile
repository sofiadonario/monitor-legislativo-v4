# Fast deployment using pre-built base image
FROM southamerica-east1-docker.pkg.dev/mackmonitor/monitor-legislativo-v4/base-image:latest

# Copy application files
WORKDIR /app
COPY . /app/

# Environment + port
ENV PORT=3838
EXPOSE 3838

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:3838/health || exit 1

# Start app
CMD ["R", "-e", "shiny::runApp('app_phoenix.R', host='0.0.0.0', port=as.numeric(Sys.getenv('PORT', '3838')))"]
