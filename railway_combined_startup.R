#!/usr/bin/env Rscript
# Railway Combined Startup - Health Check + Shiny App
# ====================================================
# Runs both health check server AND the actual Shiny application

cat("========================================\n")
cat("Railway Combined Server Starting...\n")
cat("========================================\n")

# Load required libraries
suppressWarnings(suppressMessages({
  library(shiny)
  library(httpuv)
  library(jsonlite)
  library(parallel)
}))

# Get port from environment
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Configuration: host=%s, port=%d\n", host, port))

# First, start a simple health check server in the background
health_server <- NULL
tryCatch({
  health_server <- startServer("127.0.0.1", 8080, list(
    call = function(req) {
      if (req$PATH_INFO %in% c("/health", "/health/", "/healthz", "/")) {
        return(list(
          status = 200L,
          headers = list(
            "Content-Type" = "application/json",
            "Cache-Control" = "no-cache"
          ),
          body = toJSON(list(
            status = "healthy",
            timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ"),
            service = "monitor-legislativo-v4",
            port = port,
            message = "Service is running"
          ), auto_unbox = TRUE)
        ))
      }
      return(list(status = 404L, headers = list(), body = "Not Found"))
    }
  ))
  cat("Health check server started on port 8080\n")
}, error = function(e) {
  cat("Warning: Could not start separate health server:", e$message, "\n")
})

# Now load and run the actual Shiny application
cat("Loading main Shiny application...\n")

# Source the app.R file
app_loaded <- FALSE
tryCatch({
  if (file.exists("app.R")) {
    # Clear any existing ui/server objects
    if (exists("ui")) rm(ui, envir = .GlobalEnv)
    if (exists("server")) rm(server, envir = .GlobalEnv)
    
    # Source the app
    source("app.R", local = FALSE)
    
    # Check if ui and server were created
    if (exists("ui") && exists("server")) {
      app_loaded <- TRUE
      cat("Main application loaded successfully\n")
    } else {
      cat("Warning: app.R did not create ui and server objects\n")
    }
  } else {
    cat("ERROR: app.R file not found!\n")
  }
}, error = function(e) {
  cat("ERROR loading app.R:", e$message, "\n")
})

# If app didn't load, create a minimal fallback
if (!app_loaded) {
  cat("Creating minimal fallback application...\n")
  
  ui <- fluidPage(
    titlePanel("Monitor Legislativo v4 - Loading Error"),
    mainPanel(
      h3("Application failed to load"),
      p("The main application could not be loaded. Please check the logs."),
      verbatimTextOutput("error_info")
    )
  )
  
  server <- function(input, output, session) {
    output$error_info <- renderText({
      paste0(
        "Server Time: ", Sys.time(), "\n",
        "Port: ", port, "\n",
        "Working Directory: ", getwd(), "\n",
        "Files in directory: ", paste(list.files(), collapse = ", ")
      )
    })
  }
}

# Create a custom handler that adds health check to Shiny
cat("Creating Shiny app with integrated health check...\n")

# Store original runApp function
original_runApp <- runApp

# Create wrapper that adds health check
runApp <- function(...) {
  # Get the Shiny app object
  app_obj <- shinyApp(ui = ui, server = server)
  
  # Wrap the app's httpHandler to add health check
  original_handler <- app_obj$httpHandler
  
  app_obj$httpHandler <- function(req) {
    # Check if this is a health check request
    if (req$PATH_INFO %in% c("/health", "/health/", "/healthz")) {
      return(list(
        status = 200L,
        headers = list(
          "Content-Type" = "application/json",
          "Cache-Control" = "no-cache"
        ),
        body = toJSON(list(
          status = "healthy",
          timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ"),
          service = "monitor-legislativo-v4",
          app_loaded = app_loaded,
          message = "Shiny app is running"
        ), auto_unbox = TRUE)
      ))
    }
    
    # Otherwise, use the original handler
    return(original_handler(req))
  }
  
  # Run with modified handler
  return(original_runApp(app_obj, ...))
}

cat("========================================\n")
cat(sprintf("Starting Shiny application on %s:%d\n", host, port))
cat("Health endpoint: /health\n")
cat("========================================\n")

# Run the Shiny app with all features
runApp(
  appDir = getwd(),
  host = host,
  port = port,
  launch.browser = FALSE
)