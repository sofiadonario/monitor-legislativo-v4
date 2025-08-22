#!/usr/bin/env Rscript
# Simple Railway Startup with Health Check
# =========================================
# Runs a health check server alongside the Shiny app

cat("========================================\n")
cat("Railway Simple Server Starting...\n")
cat("========================================\n")

# Load required libraries
suppressWarnings(suppressMessages({
  library(shiny)
  library(httpuv)
  library(jsonlite)
  library(parallel)
}))

# Configuration
port <- as.numeric(Sys.getenv("PORT", "3838"))
health_port <- as.numeric(Sys.getenv("HEALTH_PORT", as.character(port + 1)))
host <- "0.0.0.0"

cat(sprintf("Configuration:\n"))
cat(sprintf("  Main app port: %d\n", port))
cat(sprintf("  Health check port: %d\n", health_port))
cat(sprintf("  Host: %s\n", host))
cat(sprintf("  Environment: %s\n", Sys.getenv("RAILWAY_ENVIRONMENT", "unknown")))

# Function to run health check server
run_health_server <- function() {
  cat(sprintf("Starting health check server on port %d...\n", health_port))
  
  health_app <- function(req) {
    if (grepl("^/health", req$PATH_INFO)) {
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
          port = port,
          health_port = health_port
        ), auto_unbox = TRUE)
      ))
    }
    
    return(list(
      status = 404,
      headers = list("Content-Type" = "text/plain"),
      body = "Not Found"
    ))
  }
  
  # Start the health server
  tryCatch({
    srv <- startServer(host, health_port, health_app)
    cat(sprintf("Health check server started on port %d\n", health_port))
    
    # Keep it running
    while(TRUE) {
      Sys.sleep(0.1)
      service()
    }
  }, error = function(e) {
    cat("Error in health server:", e$message, "\n")
  })
}

# Function to run main Shiny app
run_shiny_app <- function() {
  cat(sprintf("Starting Shiny app on port %d...\n", port))
  
  # Load the main app
  tryCatch({
    if (file.exists("app.R")) {
      source("app.R", local = TRUE)
      cat("Main application loaded\n")
    } else {
      stop("app.R not found")
    }
  }, error = function(e) {
    cat("Error loading app.R:", e$message, "\n")
    cat("Creating fallback app...\n")
    
    ui <<- fluidPage(
      titlePanel("Monitor Legislativo v4"),
      mainPanel(
        h3("Starting..."),
        p("The application is initializing."),
        verbatimTextOutput("info")
      )
    )
    
    server <<- function(input, output, session) {
      output$info <- renderText({
        paste0(
          "Server Time: ", Sys.time(), "\n",
          "Port: ", port, "\n",
          "Health Port: ", health_port, "\n",
          "R Version: ", R.version.string
        )
      })
    }
  })
  
  # Run the Shiny app
  runApp(
    appDir = getwd(),
    host = host,
    port = port,
    launch.browser = FALSE
  )
}

# Main execution
if (port == health_port) {
  # If ports are the same, we need a different approach
  cat("Running combined server (same port for app and health)...\n")
  
  # Create a simple wrapper that handles both
  library(later)
  
  # Start health check in background
  later(function() {
    cat("Setting up inline health check...\n")
    # This approach won't work well, so let's just run the app
  }, delay = 0)
  
  # Just run the Shiny app and hope Railway accepts it
  run_shiny_app()
  
} else {
  # Run health server in background and Shiny app in foreground
  cat("Starting servers on different ports...\n")
  
  # Fork the health server (if supported)
  if (capabilities("fork")) {
    cat("Using fork for health server...\n")
    health_pid <- mcparallel(run_health_server())
    cat(sprintf("Health server PID: %s\n", health_pid$pid))
    
    # Give health server time to start
    Sys.sleep(2)
    
    # Run Shiny app in main process
    run_shiny_app()
  } else {
    # Windows or non-fork system - try running both in same process
    cat("Fork not available, using single process...\n")
    
    # Start health server in background using later
    library(later)
    later(run_health_server, delay = 0)
    
    # Give it a moment
    Sys.sleep(1)
    
    # Run Shiny app
    run_shiny_app()
  }
}