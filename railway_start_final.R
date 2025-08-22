#!/usr/bin/env Rscript
# Railway Final Startup Script
# =============================
# Simplified approach: Run Shiny with a health endpoint

cat("========================================\n")
cat("Railway Production Server Starting...\n")
cat("========================================\n")

# Load libraries
suppressWarnings(suppressMessages({
  library(shiny)
  library(jsonlite)
}))

# Configuration
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Starting server on %s:%d\n", host, port))

# Load the main app
app_loaded <- FALSE
tryCatch({
  if (file.exists("app.R")) {
    source("app.R", local = TRUE)
    app_loaded <- TRUE
    cat("Main application loaded successfully\n")
  }
}, error = function(e) {
  cat("Warning: Could not load app.R:", e$message, "\n")
})

# If app didn't load, create minimal one
if (!app_loaded) {
  cat("Creating minimal application...\n")
  
  ui <- fluidPage(
    tags$head(
      tags$script(HTML("
        // Intercept health check requests
        if (window.location.pathname === '/health') {
          document.body.innerHTML = JSON.stringify({
            status: 'healthy',
            timestamp: new Date().toISOString()
          });
        }
      "))
    ),
    titlePanel("Monitor Legislativo v4"),
    mainPanel(
      h3("Application Status"),
      verbatimTextOutput("status")
    )
  )
  
  server <- function(input, output, session) {
    # Check if this is a health check request
    observe({
      query <- parseQueryString(session$clientData$url_search)
      path <- session$clientData$url_pathname
      
      # If health check path, send custom response
      if (!is.null(path) && grepl("/health", path)) {
        session$sendCustomMessage("health_response", list(
          status = "healthy",
          timestamp = Sys.time()
        ))
      }
    })
    
    output$status <- renderText({
      paste0(
        "Server Time: ", Sys.time(), "\n",
        "Port: ", port, "\n",
        "R Version: ", R.version.string, "\n",
        "Status: Running"
      )
    })
  }
}

# Create a custom httpuv app that wraps the Shiny app
cat("Creating server with health check support...\n")

# Store the original shinyApp function
original_shinyApp <- shinyApp

# Override shinyApp to add health check
shinyApp <- function(ui, server, ...) {
  app <- original_shinyApp(ui, server, ...)
  
  # Store original appObj
  original_appObj <- app$appObj
  
  # Create wrapper
  app$appObj <- function(req) {
    # Check if this is a health check
    if (req$PATH_INFO %in% c("/health", "/health/", "/healthz")) {
      # Return health check response
      return(list(
        status = 200L,
        headers = list(
          "Content-Type" = "application/json",
          "Cache-Control" = "no-cache"
        ),
        body = toJSON(list(
          status = "healthy",
          timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ"),
          service = "monitor-legislativo-v4"
        ), auto_unbox = TRUE)
      ))
    }
    
    # Otherwise, call original handler
    return(original_appObj(req))
  }
  
  return(app)
}

cat("========================================\n")
cat("Starting Shiny application...\n")
cat("Health endpoint: /health\n")
cat("========================================\n")

# Run the app
runApp(
  appDir = getwd(),
  host = host,
  port = port,
  launch.browser = FALSE
)