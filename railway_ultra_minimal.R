#!/usr/bin/env Rscript
# Ultra Minimal Railway Server - Bypasses version checks
# ======================================================

cat("Starting ultra-minimal server...\n")

# Get port from environment
port <- as.numeric(Sys.getenv("PORT", "3838"))

# Load httpuv directly to create a simple HTTP server
library(httpuv)

# Create HTTP server with health check
cat(sprintf("Creating HTTP server on port %d\n", port))

s <- startServer(
  host = "0.0.0.0",
  port = port,
  app = list(
    call = function(req) {
      path <- req$PATH_INFO
      
      # Health check endpoint
      if (!is.null(path) && grepl("^/health", path)) {
        return(list(
          status = 200L,
          headers = list("Content-Type" = "text/plain"),
          body = "OK"
        ))
      }
      
      # Default response
      list(
        status = 200L,
        headers = list("Content-Type" = "text/html; charset=utf-8"),
        body = paste0(
          "<html><body>",
          "<h1>Monitor Legislativo</h1>",
          "<p>Server is running on port ", port, "</p>",
          "<p>Health check: <a href='/health'>/health</a></p>",
          "<p>Status: OK</p>",
          "</body></html>"
        )
      )
    }
  )
)

cat("Server started successfully\n")
cat(sprintf("Health check available at: http://0.0.0.0:%d/health\n", port))

# Keep the server running
while(TRUE) {
  Sys.sleep(1)
  service()
}