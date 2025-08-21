#!/usr/bin/env Rscript
# Railway Health Check Server with Shiny App
# ===========================================
# This script runs a simple HTTP server for health checks
# and then starts the main Shiny application

cat("Starting Railway Health Check Server...\n")

# Get port from environment
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Configuration: host=%s, port=%d\n", host, port))

# Try to use httpuv for a simple health check server
# httpuv is already a dependency of Shiny
library(httpuv)
library(shiny)

# Create a simple health check response
health_response <- function() {
  list(
    status = 200,
    headers = list(
      "Content-Type" = "application/json",
      "Cache-Control" = "no-cache"
    ),
    body = jsonlite::toJSON(list(
      status = "healthy",
      timestamp = Sys.time(),
      service = "monitor-legislativo-v4",
      port = port
    ), auto_unbox = TRUE)
  )
}

# Create HTTP request handler
app_handler <- function(req) {
  # Handle health check endpoints
  if (req$PATH_INFO == "/health" || 
      req$PATH_INFO == "/health/" ||
      req$PATH_INFO == "/healthz" ||
      req$PATH_INFO == "/") {
    return(health_response())
  }
  
  # For all other paths, return 404
  # The Shiny app will handle its own routes
  return(list(
    status = 404,
    headers = list("Content-Type" = "text/plain"),
    body = "Not Found - Use Shiny app URL"
  ))
}

# Start health check server in background
health_server <- NULL
start_health_server <- function() {
  tryCatch({
    cat("Starting health check server on port", port, "...\n")
    health_server <<- startServer(host, port, app_handler)
    cat("Health check server started successfully\n")
    TRUE
  }, error = function(e) {
    cat("Failed to start health check server:", e$message, "\n")
    FALSE
  })
}

# Try to start the health server
if (start_health_server()) {
  cat("Health endpoint available at: http://", host, ":", port, "/health\n", sep = "")
  
  # Keep the server running
  # In production, this would be handled by the process manager
  while(TRUE) {
    Sys.sleep(1)
    service()  # Process httpuv events
  }
} else {
  cat("ERROR: Could not start health check server\n")
  quit(status = 1)
}