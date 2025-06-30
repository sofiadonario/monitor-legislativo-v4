#!/usr/bin/env Rscript

# Debug: Wrap cat to find multi-line vectors
old_cat <- base::cat
cat <- function(..., file = "", sep = " ", fill = FALSE, labels = NULL, append = FALSE) {
  # The warning is about the first argument being a character vector of length > 1
  if (length(list(...)) > 0) {
    arg1 <- list(...)[[1]]
    if (is.character(arg1) && length(arg1) > 1) {
        message("--- CAT TRACEBACK ---")
        try(print(traceback(1)))
        message("--- END TRACEBACK ---")
    }
  }
  old_cat(..., file = file, sep = sep, fill = fill, labels = labels, append = append)
}

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