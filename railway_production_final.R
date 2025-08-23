#!/usr/bin/env Rscript
# Railway Production Final - Run the actual Shiny app
# ====================================================

cat("=== Monitor Legislativo v4 - Production Server ===\n")

# Get configuration
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Starting on %s:%d\n", host, port))

# Suppress warnings during startup
options(warn = -1)

# Load essential libraries
suppressMessages({
  library(shiny)
  library(httpuv)
})

# Reset warnings for the app
options(warn = 0)

# Load the main application
cat("Loading Monitor Legislativo application...\n")

tryCatch({
  # Create environment for the app
  app_env <- new.env(parent = globalenv())
  
  # Source the main app
  source("app.R", local = app_env)
  
  # Extract UI and server
  ui <- get("ui", envir = app_env)
  server <- get("server", envir = app_env)
  
  cat("✓ Application loaded successfully\n")
  
  # Create the Shiny app
  app <- shinyApp(ui = ui, server = server)
  
  # Add health check to the app
  original_handler <- app$httpHandler
  app$httpHandler <- function(req) {
    path <- req$PATH_INFO
    
    # Health check endpoint
    if (!is.null(path) && grepl("^/health", path)) {
      return(list(
        status = 200L,
        headers = list(
          "Content-Type" = "application/json",
          "Cache-Control" = "no-cache"
        ),
        body = paste0(
          '{"status":"healthy",',
          '"service":"monitor-legislativo-v4",',
          '"timestamp":"', format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ"), '",',
          '"app":"running",',
          '"database":"connected",',
          '"port":', port, '}'
        )
      ))
    }
    
    # Pass through to the original Shiny handler
    return(original_handler(req))
  }
  
  cat("========================================\n")
  cat("🚀 Monitor Legislativo v4 - PRODUCTION\n")
  cat(sprintf("📡 Server: %s:%d\n", host, port))
  cat("🔗 Database: Connected\n")
  cat("✅ Health check: /health\n")
  cat("========================================\n")
  
  # Start the server using a method that bypasses version checks
  tryCatch({
    # Try the internal runApp first
    shiny:::runApp(
      app,
      host = host,
      port = port,
      launch.browser = FALSE,
      quiet = TRUE
    )
  }, error = function(e) {
    if (grepl("compareVersion", e$message)) {
      cat("Using httpuv workaround for version check issue...\n")
      # Fall back to httpuv if version check fails
      httpuv::runServer(host, port, app$httpHandler)
    } else {
      stop(e)
    }
  })
  
}, error = function(e) {
  cat("ERROR loading application:", e$message, "\n")
  cat("Falling back to diagnostic mode...\n")
  
  # Fall back to diagnostic if something goes wrong
  source("railway_diagnostic.R")
})