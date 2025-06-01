#!/usr/bin/env Rscript
# Railway Simple Startup - Direct Shiny Launch with Health Check
# ===============================================================

cat("========================================\n")
cat("Railway Simple Server Starting...\n")
cat("========================================\n")

# Load only essential libraries
suppressWarnings(suppressMessages({
  library(shiny)
}))

# Get port from environment
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Configuration: host=%s, port=%d\n", host, port))
cat(sprintf("Environment: %s\n", Sys.getenv("RAILWAY_ENVIRONMENT", "production")))

# Load the main application
cat("Loading main Shiny application...\n")

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
  cat("Stack trace:\n")
  print(traceback())
})

# If app didn't load, create a minimal fallback
if (!app_loaded) {
  cat("Creating minimal fallback application...\n")
  
  ui <- fluidPage(
    tags$head(
      tags$script(HTML("
        // Simple health check responder
        if (window.location.pathname === '/health') {
          document.body.innerHTML = JSON.stringify({
            status: 'healthy',
            timestamp: new Date().toISOString()
          });
        }
      "))
    ),
    titlePanel("Monitor Legislativo v4 - Loading Error"),
    mainPanel(
      h3("Application failed to load"),
      p("Please check deployment logs for details."),
      verbatimTextOutput("error_info")
    )
  )
  
  server <- function(input, output, session) {
    output$error_info <- renderText({
      paste0(
        "Server Time: ", Sys.time(), "\n",
        "Port: ", port, "\n",
        "Working Directory: ", getwd(), "\n",
        "R Version: ", R.version.string
      )
    })
  }
}

# Override the httpHandler to add health check WITHOUT version comparison
cat("Adding health check handler...\n")

.GlobalEnv$.original_shinyAppHttpHandler <- NULL

addResourcePath("__health__", tempdir())

shinyOptions(
  port = port,
  host = host,
  launch.browser = FALSE
)

# Create app with modified handler
app <- shinyApp(ui = ui, server = server)

# Get the original httpHandler
original_handler <- app$httpHandler

# Create wrapper that adds health check
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
        '"message":"Shiny app is running"}'
      )
    ))
  }
  
  # Otherwise use original handler
  return(original_handler(req))
}

cat("========================================\n")
cat(sprintf("Starting Shiny application on %s:%d\n", host, port))
cat("Health endpoint: /health\n")
cat("========================================\n")

# Run the app directly
runApp(
  app,
  host = host,
  port = port,
  launch.browser = FALSE
)