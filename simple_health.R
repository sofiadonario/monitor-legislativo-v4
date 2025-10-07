#!/usr/bin/env Rscript
# Simple health check script that runs quickly for Railway deployment
# This creates a simple HTTP server just for health checks

library(httpuv)

# Simple health check function
simple_health_check <- function() {
  list(
    status = "healthy",
    timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC"),
    service = "monitor-legislativo-v4",
    version = "1.0.0"
  )
}

# HTTP request handler
handle_request <- function(req) {
  if (grepl("^/health", req$PATH_INFO)) {
    health_status <- simple_health_check()
    return(list(
      status = 200,
      headers = list("Content-Type" = "application/json"),
      body = jsonlite::toJSON(health_status, auto_unbox = TRUE)
    ))
  }
  
  # For all other requests, return a basic response
  return(list(
    status = 200,
    headers = list("Content-Type" = "text/plain"),
    body = "OK"
  ))
}

# Get port from environment (Railway sets this)
port <- as.numeric(Sys.getenv("PORT", "3838"))

cat("Starting simple health check server on port", port, "\n")

# Start the server
server <- startServer("0.0.0.0", port, list(
  call = handle_request
))

# Keep the server running
while(TRUE) {
  Sys.sleep(1)
}