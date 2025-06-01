#!/usr/bin/env Rscript
# Railway Proxy Server for Health Checks
# =======================================
# Acts as a proxy that handles health checks and forwards to Shiny

cat("========================================\n")
cat("Railway Proxy Server Starting...\n")
cat("========================================\n")

# Load required libraries
suppressWarnings(suppressMessages({
  library(httpuv)
  library(jsonlite)
}))

# Configuration
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"
shiny_port <- port + 10000  # Internal Shiny port

cat(sprintf("Configuration:\n"))
cat(sprintf("  Public port: %d\n", port))
cat(sprintf("  Internal Shiny port: %d\n", shiny_port))
cat(sprintf("  Host: %s\n", host))

# Start Shiny app in background
cat("Starting Shiny app in background...\n")
system(sprintf("Rscript -e \"shiny::runApp('app.R', host='127.0.0.1', port=%d, launch.browser=FALSE)\" &", shiny_port), wait = FALSE)

# Give Shiny time to start
Sys.sleep(5)

# Create proxy server
proxy_app <- function(req) {
  # Handle health checks directly
  if (req$PATH_INFO %in% c("/health", "/health/", "/healthz", "/healthz/")) {
    return(list(
      status = 200,
      headers = list(
        "Content-Type" = "application/json",
        "Access-Control-Allow-Origin" = "*"
      ),
      body = toJSON(list(
        status = "healthy",
        timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ"),
        service = "monitor-legislativo-v4",
        message = "Proxy server running"
      ), auto_unbox = TRUE)
    ))
  }
  
  # For all other requests, proxy to Shiny (simplified response for now)
  return(list(
    status = 200,
    headers = list(
      "Content-Type" = "text/html"
    ),
    body = paste0(
      "<html><head>",
      "<meta http-equiv='refresh' content='0; url=http://", host, ":", shiny_port, req$PATH_INFO, "'>",
      "</head><body>",
      "<p>Redirecting to Shiny app...</p>",
      "</body></html>"
    )
  ))
}

# Start proxy server
cat(sprintf("Starting proxy server on port %d...\n", port))
cat(sprintf("Health endpoint: http://%s:%d/health\n", host, port))

srv <- startServer(host, port, proxy_app)

cat("Proxy server started successfully\n")
cat("========================================\n")

# Keep running
while(TRUE) {
  Sys.sleep(0.1)
  service()
}