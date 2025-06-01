#!/usr/bin/env Rscript
# Railway Health Check Startup Script
# ====================================
# Minimal server with health check endpoint for Railway deployment

cat("========================================\n")
cat("Railway Health Server Starting...\n")
cat("========================================\n")

# Load only essential libraries
suppressWarnings(suppressMessages({
  library(shiny)
  library(httpuv)
  library(jsonlite)
}))

# Get port from environment
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Configuration: host=%s, port=%d\n", host, port))
cat(sprintf("Environment: %s\n", Sys.getenv("RAILWAY_ENVIRONMENT", "production")))

# Create a simple HTTP server with health check
server <- startServer(host, port, list(
  call = function(req) {
    # Handle health check endpoints
    if (req$PATH_INFO %in% c("/health", "/health/", "/healthz", "/")) {
      return(list(
        status = 200L,
        headers = list(
          "Content-Type" = "application/json",
          "Cache-Control" = "no-cache"
        ),
        body = toJSON(list(
          status = "healthy",
          timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ"),
          service = "monitor-legislativo-v4",
          port = port,
          message = "Service is running"
        ), auto_unbox = TRUE)
      ))
    }
    
    # For any other path, load the Shiny app if available
    if (file.exists("app.R")) {
      # Return a basic HTML response directing to the app
      return(list(
        status = 200L,
        headers = list("Content-Type" = "text/html"),
        body = paste0(
          "<html><body>",
          "<h1>Monitor Legislativo v4</h1>",
          "<p>Shiny application is available on this port.</p>",
          "<p>Health check: <a href='/health'>/health</a></p>",
          "</body></html>"
        )
      ))
    }
    
    # Fallback response
    return(list(
      status = 404L,
      headers = list("Content-Type" = "text/plain"),
      body = "Not Found"
    ))
  }
))

cat("========================================\n")
cat(sprintf("Health server running on %s:%d\n", host, port))
cat("Health endpoint available at: /health\n")
cat("========================================\n")

# Keep the server running
while (TRUE) {
  Sys.sleep(1)
  service()
}