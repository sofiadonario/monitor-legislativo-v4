#!/usr/bin/env Rscript
# Railway Production Startup with Health Check Support
# =====================================================
# This script provides health check endpoints for Railway
# while running the main Shiny application

cat("========================================\n")
cat("Railway Production Server Starting...\n")
cat("========================================\n")

# Load required libraries
suppressWarnings(suppressMessages({
  library(shiny)
  library(httpuv)
  library(jsonlite)
}))

# Configuration
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Configuration: host=%s, port=%d\n", host, port))
cat(sprintf("Environment: %s\n", Sys.getenv("RAILWAY_ENVIRONMENT", "unknown")))

# Health check data
health_data <- list(
  status = "starting",
  start_time = Sys.time(),
  checks_passed = 0,
  last_check = NULL
)

# Simple health check handler
handle_health <- function(req, res) {
  # Update health data
  health_data$checks_passed <<- health_data$checks_passed + 1
  health_data$last_check <<- Sys.time()
  uptime <- as.numeric(difftime(Sys.time(), health_data$start_time, units = "secs"))
  
  # Create response
  response <- list(
    status = "healthy",
    timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC"),
    service = "monitor-legislativo-v4",
    uptime_seconds = round(uptime, 2),
    checks_passed = health_data$checks_passed,
    environment = list(
      railway_service = Sys.getenv("RAILWAY_SERVICE_NAME", "unknown"),
      railway_environment = Sys.getenv("RAILWAY_ENVIRONMENT_NAME", "unknown"),
      port = port,
      r_version = R.version.string
    )
  )
  
  res$status <- 200
  res$headers[["Content-Type"]] <- "application/json"
  res$body <- toJSON(response, auto_unbox = TRUE)
  
  cat(sprintf("[%s] Health check #%d - OK\n", 
              format(Sys.time(), "%H:%M:%S"), 
              health_data$checks_passed))
  
  return(res)
}

# Root handler (for basic connectivity test)
handle_root <- function(req, res) {
  res$status <- 200
  res$headers[["Content-Type"]] <- "text/html"
  res$body <- paste0(
    "<html><body>",
    "<h1>Monitor Legislativo v4</h1>",
    "<p>Brazilian Legislative Monitor is running</p>",
    "<p>Health check: <a href='/health'>/health</a></p>",
    "<p>Shiny app should be available on this port</p>",
    "</body></html>"
  )
  return(res)
}

# Create a minimal Shiny app that includes health check handling
cat("Loading Shiny application...\n")

# Try to load the main app
app_loaded <- FALSE
tryCatch({
  if (file.exists("app.R")) {
    source("app.R", local = TRUE)
    app_loaded <- TRUE
    cat("Main application loaded successfully\n")
  }
}, error = function(e) {
  cat("Warning: Could not load main app.R:", e$message, "\n")
})

# If main app didn't load, create a minimal fallback
if (!app_loaded) {
  cat("Creating fallback application...\n")
  
  ui <- fluidPage(
    tags$head(
      tags$script(HTML("
        // Handle health check requests in the browser
        if (window.location.pathname === '/health') {
          document.write(JSON.stringify({
            status: 'healthy',
            message: 'Shiny app responding',
            timestamp: new Date().toISOString()
          }));
        }
      "))
    ),
    titlePanel("Monitor Legislativo v4 - Starting"),
    mainPanel(
      h3("System Status"),
      p("The application is starting up..."),
      verbatimTextOutput("status")
    )
  )
  
  server <- function(input, output, session) {
    # Handle health check via Shiny custom message
    observe({
      query <- parseQueryString(session$clientData$url_search)
      if (!is.null(query$health)) {
        session$sendCustomMessage("health_check", list(status = "ok"))
      }
    })
    
    output$status <- renderText({
      paste0(
        "Server Time: ", Sys.time(), "\n",
        "Port: ", port, "\n",
        "R Version: ", R.version.string, "\n",
        "Status: Starting..."
      )
    })
  }
}

# Custom Shiny server with health check support
cat("Starting hybrid server with health check support...\n")

# Override shiny's httpHandler to add health check
original_handler <- shiny:::handlerManager$createHttpuvApp
shiny:::handlerManager$createHttpuvApp <- function(handler) {
  app <- original_handler(handler)
  
  # Wrap the original call function
  original_call <- app$call
  app$call <- function(req) {
    # Check if this is a health check request
    if (req$PATH_INFO %in% c("/health", "/health/", "/healthz", "/healthz/")) {
      # Return health check response
      return(list(
        status = 200,
        headers = list(
          "Content-Type" = "application/json",
          "Cache-Control" = "no-cache"
        ),
        body = toJSON(list(
          status = "healthy",
          timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ"),
          service = "monitor-legislativo-v4",
          message = "Shiny application running"
        ), auto_unbox = TRUE)
      ))
    }
    
    # Otherwise, use original handler
    return(original_call(req))
  }
  
  return(app)
}

# Update health status
health_data$status <- "running"

cat("========================================\n")
cat(sprintf("Server starting on %s:%d\n", host, port))
cat("Health check endpoint: /health\n")
cat("========================================\n")

# Run the Shiny app
runApp(
  appDir = getwd(),
  host = host,
  port = port,
  launch.browser = FALSE
)