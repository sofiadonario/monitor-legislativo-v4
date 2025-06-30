#!/usr/bin/env Rscript

# Run script for Railway deployment
# This adds a health endpoint handler

library(shiny)

# Get port from environment or use default
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat("Starting R Shiny app on", host, ":", port, "\n")

# Create a simple health check handler
options(shiny.http.response.filter = function(req, res) {
  if (req$PATH_INFO == "/health") {
    res$status <- 200
    res$headers[["Content-Type"]] <- "application/json"
    res$body <- '{"status":"healthy","app":"monitor-legislativo-rshiny"}'
    return(res)
  }
  return(res)
})

# Run the main app
runApp(".", host = host, port = port)