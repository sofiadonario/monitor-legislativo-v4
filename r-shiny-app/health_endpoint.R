#!/usr/bin/env Rscript

# Simple health endpoint for Railway
# This creates a basic HTTP server on the same port for health checks

library(httpuv)
library(jsonlite)

# Health check handler
health_handler <- function(req) {
  if (req$PATH_INFO == "/health") {
    health_data <- list(
      status = "healthy",
      service = "rshiny",
      version = R.version.string,
      timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S"),
      port = Sys.getenv("PORT", "3838")
    )
    
    list(
      status = 200L,
      headers = list('Content-Type' = 'application/json'),
      body = toJSON(health_data, auto_unbox = TRUE)
    )
  } else {
    list(
      status = 404L,
      headers = list('Content-Type' = 'text/plain'),
      body = "Not Found"
    )
  }
}

# Start health server on port 3839 (Railway can check this)
cat("Starting health endpoint on port 3839...\n")
health_server <- startServer(
  host = "0.0.0.0",
  port = 3839,
  app = list(call = health_handler)
)

# Keep the script running
cat("Health endpoint running. Use Ctrl+C to stop.\n")
while(TRUE) {
  Sys.sleep(1)
} 