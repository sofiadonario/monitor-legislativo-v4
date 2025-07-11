#!/usr/bin/env Rscript

# --- TRACING WRAPPER START ---
# This code is for debugging the 'writeImpl' warning.
# It wraps cat() and writeLines() to print a stack trace when they
# are called with multi-element character vectors.

message(">>>> EXECUTING CUSTOM run_app.R - TRACING ENABLED <<<<")

old_cat <- base::cat
cat <- function(..., file = "", sep = " ", fill = FALSE, labels = NULL, append = FALSE) {
  if (is.character(list(...)[[1]]) && length(list(...)[[1]]) > 1) {
    message("--- CAT TRACEBACK ---")
    try(print(traceback(1)))
    message("--- END TRACEBACK ---")
  }
  old_cat(..., file = file, sep = sep, fill = fill, labels = labels, append = append)
}

old_writeLines <- base::writeLines
writeLines <- function(text, ...) {
  if (is.character(text) && length(text) > 1) {
    message("--- WRITELINES TRACEBACK ---")
    try(print(traceback(1)))
    message("--- END TRACEBACK ---")
  }
  old_writeLines(text, ...)
}
# --- TRACING WRAPPER END ---

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