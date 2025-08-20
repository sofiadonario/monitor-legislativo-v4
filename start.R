#!/usr/bin/env Rscript
# Simple Railway startup script for R Shiny

cat("Starting R Shiny application for Railway...\n")

# Get PORT from environment
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Configuration: host=%s, port=%d\n", host, port))

# Try to load the app
tryCatch({
  # Check if app.R exists
  if (!file.exists("app.R")) {
    stop("app.R file not found!")
  }
  
  cat("Loading Shiny application from app.R...\n")
  
  # Run the Shiny app directly
  shiny::runApp(
    appDir = ".",
    host = host,
    port = port,
    launch.browser = FALSE
  )
}, error = function(e) {
  cat("ERROR starting application:\n")
  cat(e$message, "\n")
  
  # Try a minimal fallback
  cat("Attempting minimal fallback server...\n")
  library(shiny)
  
  ui <- fluidPage(
    h1("Monitor Legislativo v4"),
    p("Application is starting up. Please refresh in a moment.")
  )
  
  server <- function(input, output, session) {}
  
  shinyApp(ui, server, options = list(host = host, port = port))
})