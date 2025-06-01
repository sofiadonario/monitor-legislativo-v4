#!/usr/bin/env Rscript
# Railway App Loader - Loads Shiny App with Fallback
# ==================================================

cat("=== Railway App Loader Starting ===\n")

# Get configuration
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Port: %d, Host: %s\n", port, host))

# First, try the ultra-simple approach that we know works
tryCatch({
  cat("Attempting to load Shiny application...\n")
  
  # Suppress version warnings
  options(warn = -1)
  
  # Load required libraries
  suppressMessages({
    library(shiny)
    library(httpuv)
  })
  
  # Reset warnings
  options(warn = 0)
  
  # Source the app file
  if (file.exists("app.R")) {
    cat("Loading app.R...\n")
    
    # Create environment for the app
    app_env <- new.env(parent = globalenv())
    
    # Source with error handling
    tryCatch({
      source("app.R", local = app_env)
      
      # Check if ui and server exist
      if (exists("ui", envir = app_env) && exists("server", envir = app_env)) {
        ui <- get("ui", envir = app_env)
        server <- get("server", envir = app_env)
        
        cat("✓ App loaded, starting Shiny server...\n")
        
        # Create app
        app <- shinyApp(ui, server)
        
        # Add health check
        original_handler <- app$httpHandler
        app$httpHandler <- function(req) {
          if (!is.null(req$PATH_INFO) && grepl("^/health", req$PATH_INFO)) {
            return(list(
              status = 200L,
              headers = list("Content-Type" = "application/json"),
              body = '{"status":"healthy","app":"running"}'
            ))
          }
          original_handler(req)
        }
        
        # Try to run the app
        tryCatch({
          # Suppress version check by using internal function directly
          shiny:::runApp(
            app,
            host = host,
            port = port,
            launch.browser = FALSE,
            quiet = TRUE
          )
        }, error = function(e) {
          if (grepl("compareVersion", e$message)) {
            cat("Version check error, using workaround...\n")
            # If version check fails, start httpuv server directly
            server <- app$httpHandler
            httpuv::runServer(host, port, server)
          } else {
            stop(e)
          }
        })
        
      } else {
        stop("UI or server not found in app.R")
      }
    }, error = function(e) {
      cat("Error loading app.R:", e$message, "\n")
      stop(e)
    })
    
  } else {
    stop("app.R not found")
  }
  
}, error = function(e) {
  cat("\n=== Falling back to stable status server ===\n")
  cat("Error:", e$message, "\n\n")
  
  # Fall back to the stable server we know works
  source("railway_stable_server.R")
})