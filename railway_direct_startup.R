#!/usr/bin/env Rscript
# Railway Direct Startup - Bypass runApp completely
# ===================================================

cat("========================================\n")
cat("Railway Direct Server Starting...\n")
cat("========================================\n")

# Load only essential libraries
suppressWarnings(suppressMessages({
  library(shiny)
  library(httpuv)
}))

# Get port from environment
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Configuration: host=%s, port=%d\n", host, port))

# Load the main application first
cat("Loading main Shiny application...\n")

app_loaded <- FALSE
ui <- NULL
server <- NULL

tryCatch({
  if (file.exists("app.R")) {
    # Clear any existing ui/server objects
    if (exists("ui", envir = .GlobalEnv)) rm(ui, envir = .GlobalEnv)
    if (exists("server", envir = .GlobalEnv)) rm(server, envir = .GlobalEnv)
    
    # Source the app
    source("app.R", local = FALSE)
    
    # Get ui and server from global environment
    if (exists("ui", envir = .GlobalEnv) && exists("server", envir = .GlobalEnv)) {
      ui <- get("ui", envir = .GlobalEnv)
      server <- get("server", envir = .GlobalEnv)
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

# If app didn't load, create minimal fallback
if (!app_loaded || is.null(ui) || is.null(server)) {
  cat("Creating minimal fallback application...\n")
  
  ui <- fluidPage(
    titlePanel("Monitor Legislativo v4"),
    mainPanel(
      h3("Application Status"),
      p("The system is running but the main app failed to load."),
      verbatimTextOutput("status")
    )
  )
  
  server <- function(input, output, session) {
    output$status <- renderText({
      paste0(
        "Server Time: ", Sys.time(), "\n",
        "Port: ", port, "\n",
        "R Version: ", R.version.string, "\n",
        "App Loaded: ", app_loaded
      )
    })
  }
}

# Create httpuv server directly (bypass shinyApp and runApp)
cat("Creating httpuv server directly...\n")

# Create the Shiny app object manually
app_obj <- list(ui = ui, server = server)
class(app_obj) <- "shiny.appobj"

# Create httpHandler manually
httpHandler <- function(req) {
  # Handle health check first
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
        '"message":"Direct httpuv server is running"}'
      )
    ))
  }
  
  # Handle regular Shiny requests
  tryCatch({
    # Create a basic Shiny session for this request
    session <- shiny:::createAppHandlers(app_obj$server, app_obj$ui)
    return(session$httpHandler(req))
  }, error = function(e) {
    # Fallback response
    return(list(
      status = 500L,
      headers = list("Content-Type" = "text/html"),
      body = paste0(
        "<html><body>",
        "<h1>Monitor Legislativo v4</h1>",
        "<p>Service is running but encountered an error: ", e$message, "</p>",
        "<p>Health check: <a href='/health'>/health</a></p>",
        "</body></html>"
      )
    ))
  })
}

# Start httpuv server directly
cat("========================================\n")
cat(sprintf("Starting direct httpuv server on %s:%d\n", host, port))
cat("Health endpoint: /health\n")
cat("========================================\n")

server_obj <- startServer(host, port, list(call = httpHandler))

# Keep server running
cat("Server started successfully. Waiting for requests...\n")

while (TRUE) {
  later::later(function() {}, delay = 1)
  later::run_now(timeoutSecs = 1)
  Sys.sleep(0.1)
}