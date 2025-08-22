#!/usr/bin/env Rscript
# Railway Basic Startup - Based on working start.R with health check
# ===================================================================

cat("Starting R Shiny application for Railway...\n")

# Load required libraries
suppressWarnings(suppressMessages({
  library(shiny, warn.conflicts = FALSE)
}))

# Get PORT from environment
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Configuration: host=%s, port=%d\n", host, port))

# Suppress version warnings and run app directly
options(warn = -1)  # Suppress warnings temporarily

# Global variables to hold ui and server
ui <- NULL
server <- NULL
app_loaded <- FALSE

# Try to load the main application
tryCatch({
  if (!file.exists("app.R")) {
    stop("app.R file not found!")
  }
  
  cat("Loading main application...\n")
  source("app.R", local = TRUE)
  
  # Check if ui and server exist in local environment or global
  if (exists("ui", envir = environment()) && exists("server", envir = environment())) {
    app_loaded <- TRUE
    cat("Main application loaded successfully (local)\n")
  } else if (exists("ui", envir = .GlobalEnv) && exists("server", envir = .GlobalEnv)) {
    ui <<- get("ui", envir = .GlobalEnv)
    server <<- get("server", envir = .GlobalEnv)
    app_loaded <- TRUE
    cat("Main application loaded successfully (global)\n")
  } else {
    stop("ui and server objects not found after loading app.R")
  }
  
}, error = function(e) {
  cat("ERROR loading main app:", e$message, "\n")
  cat("Creating minimal fallback server...\n")
  
  # Simple fallback UI with health check support
  ui <<- fluidPage(
    tags$head(
      tags$script(HTML("
        // Simple health check responder for client-side
        if (window.location.pathname === '/health') {
          document.body.innerHTML = JSON.stringify({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            service: 'monitor-legislativo-v4'
          });
        }
      "))
    ),
    titlePanel("Monitor Legislativo v4"),
    mainPanel(
      h3("System Status: Fallback Mode"),
      p("The main application could not be loaded."),
      p("Running in fallback mode for health checks."),
      br(),
      verbatimTextOutput("status")
    )
  )
  
  server <<- function(input, output, session) {
    output$status <- renderText({
      paste0("Server Time: ", Sys.time(), 
             "\nHost: ", host,
             "\nPort: ", port,
             "\nR Version: ", R.version.string,
             "\nApp Loaded: ", app_loaded)
    })
  }
})

cat("Creating Shiny app with health check support...\n")

# Create the app object
app <- shinyApp(ui = ui, server = server)

# Store original httpHandler
original_handler <- app$httpHandler

# Create new handler with health check
app$httpHandler <- function(req) {
  # Handle health check requests
  if (!is.null(req$PATH_INFO) && req$PATH_INFO %in% c("/health", "/health/", "/healthz")) {
    return(list(
      status = 200L,
      headers = list(
        "Content-Type" = "application/json",
        "Cache-Control" = "no-cache"
      ),
      body = paste0(
        '{"status":"healthy",',
        '"timestamp":"', format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ"), '",',
        '"service":"monitor-legislativo-v4",',
        '"port":', port, ',',
        '"app_loaded":', tolower(app_loaded), ',',
        '"message":"Basic startup server is running"}'
      )
    ))
  }
  
  # Otherwise use original handler
  return(original_handler(req))
}

# Start the server
cat("Starting server on", host, "port", port, "\n")
cat("Access your dashboard at: Railway deployment URL\n")
cat("Health endpoint: /health\n")

# Run the app with modified handler
runApp(
  app,
  host = host,
  port = port,
  launch.browser = FALSE
)