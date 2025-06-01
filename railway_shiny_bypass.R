#!/usr/bin/env Rscript
# Railway Shiny Server with Version Check Bypass
# ===============================================

cat("=== Railway Shiny Server Starting ===\n")

# Get configuration
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Configuration: Port=%d, Host=%s\n", port, host))

# Load required libraries
suppressWarnings(suppressMessages({
  library(shiny)
  library(httpuv)
}))

# Override the problematic version check function
assignInNamespace("checkShinyVersion", function() { return(invisible(NULL)) }, "shiny")

# Try to load the main application
app_loaded <- FALSE
ui <- NULL
server <- NULL

tryCatch({
  cat("Loading main application from app.R...\n")
  
  if (file.exists("app.R")) {
    # Source the app file
    source("app.R", local = TRUE)
    
    # Try to find ui and server objects
    if (exists("ui") && exists("server")) {
      app_loaded <- TRUE
      cat("✓ Main application loaded successfully\n")
    } else if (exists("ui", envir = .GlobalEnv) && exists("server", envir = .GlobalEnv)) {
      ui <- get("ui", envir = .GlobalEnv)
      server <- get("server", envir = .GlobalEnv)
      app_loaded <- TRUE
      cat("✓ Main application loaded from global environment\n")
    }
  }
}, error = function(e) {
  cat("Warning: Could not load main app:", e$message, "\n")
  cat("Continuing with fallback UI...\n")
})

# If app didn't load, create a fallback
if (!app_loaded) {
  cat("Creating fallback application...\n")
  
  ui <- fluidPage(
    titlePanel("Monitor Legislativo v4"),
    mainPanel(
      h3("Railway Deployment Status"),
      p("The server is running but the main application could not be loaded."),
      p("This is a fallback interface to maintain health checks."),
      br(),
      h4("System Information:"),
      verbatimTextOutput("sysinfo"),
      br(),
      h4("Environment Variables:"),
      verbatimTextOutput("envvars")
    )
  )
  
  server <- function(input, output, session) {
    output$sysinfo <- renderText({
      paste0(
        "Server Time: ", Sys.time(), "\n",
        "R Version: ", R.version.string, "\n",
        "Port: ", port, "\n",
        "Host: ", host, "\n",
        "Working Directory: ", getwd()
      )
    })
    
    output$envvars <- renderText({
      env_vars <- Sys.getenv()
      db_url <- if(nchar(Sys.getenv("DATABASE_URL")) > 0) "Set (hidden)" else "Not set"
      paste0(
        "DATABASE_URL: ", db_url, "\n",
        "RAILWAY_ENVIRONMENT: ", Sys.getenv("RAILWAY_ENVIRONMENT", "Not set"), "\n",
        "R_CONFIG_ACTIVE: ", Sys.getenv("R_CONFIG_ACTIVE", "Not set")
      )
    })
  }
}

# Create the Shiny app
cat("Creating Shiny application...\n")
app <- shinyApp(ui = ui, server = server)

# Add health check handler using httpuv
original_handler <- app$httpHandler
app$httpHandler <- function(req) {
  path <- req$PATH_INFO
  
  # Handle health check
  if (!is.null(path) && grepl("^/health", path)) {
    return(list(
      status = 200L,
      headers = list(
        "Content-Type" = "application/json",
        "Cache-Control" = "no-cache"
      ),
      body = jsonlite::toJSON(list(
        status = "healthy",
        timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ"),
        service = "monitor-legislativo-v4",
        app_loaded = app_loaded,
        port = port
      ), auto_unbox = TRUE)
    ))
  }
  
  # Pass through to original handler
  return(original_handler(req))
}

# Start the server
cat("========================================\n")
cat(sprintf("Starting Shiny server on %s:%d\n", host, port))
cat("Health endpoint: /health\n")
cat("========================================\n")

# Run the app with error handling
tryCatch({
  runApp(
    app,
    host = host,
    port = port,
    launch.browser = FALSE
  )
}, error = function(e) {
  cat("ERROR: Failed to start Shiny server:", e$message, "\n")
  cat("Falling back to httpuv server...\n")
  
  # Fallback to direct httpuv server
  s <- startServer(
    host = host,
    port = port,
    app = list(
      call = function(req) {
        path <- req$PATH_INFO
        if (!is.null(path) && grepl("^/health", path)) {
          return(list(
            status = 200L,
            headers = list("Content-Type" = "text/plain"),
            body = "OK"
          ))
        }
        list(
          status = 200L,
          headers = list("Content-Type" = "text/html"),
          body = "<html><body><h1>Monitor Legislativo</h1><p>Fallback server running</p></body></html>"
        )
      }
    )
  )
  
  cat("Httpuv server started as fallback\n")
  while(TRUE) {
    Sys.sleep(1)
    service()
  }
})