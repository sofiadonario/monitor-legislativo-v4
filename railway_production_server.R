#!/usr/bin/env Rscript
# Railway Production Server - Robust Shiny Deployment
# ===================================================

cat("=== Railway Production Server Starting ===\n")

# Get configuration
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Configuration: Port=%d, Host=%s\n", port, host))

# Suppress all warnings during startup
options(warn = -1)

# Load required libraries quietly
suppressWarnings(suppressMessages({
  library(shiny)
  library(httpuv)
}))

# Reset warnings to normal
options(warn = 0)

# Initialize variables
app_loaded <- FALSE
ui <- NULL
server <- NULL

# Try to load the main application
tryCatch({
  cat("Loading main application...\n")
  
  if (file.exists("app.R")) {
    # Create a new environment for the app
    app_env <- new.env(parent = globalenv())
    
    # Source the app in the new environment
    source("app.R", local = app_env)
    
    # Look for ui and server in the app environment
    if (exists("ui", envir = app_env) && exists("server", envir = app_env)) {
      ui <- get("ui", envir = app_env)
      server <- get("server", envir = app_env)
      app_loaded <- TRUE
      cat("✓ Main application loaded successfully\n")
    }
  }
}, error = function(e) {
  cat("Note: Main app not loaded, using fallback. Error:", e$message, "\n")
})

# Create fallback if needed
if (!app_loaded) {
  cat("Using fallback interface...\n")
  
  ui <- fluidPage(
    tags$head(tags$style(HTML("
      body { font-family: 'Segoe UI', Arial, sans-serif; }
      .container-fluid { padding: 20px; }
      .status-ok { color: green; font-weight: bold; }
    "))),
    
    titlePanel("Monitor Legislativo v4 - Railway"),
    
    sidebarLayout(
      sidebarPanel(
        h4("Deployment Status"),
        tags$p(class = "status-ok", "✓ Server Running"),
        hr(),
        h5("Quick Links"),
        tags$ul(
          tags$li(tags$a(href = "/health", "Health Check")),
          tags$li(tags$a(href = "https://railway.app", target = "_blank", "Railway Dashboard"))
        )
      ),
      
      mainPanel(
        h3("System Information"),
        verbatimTextOutput("sysinfo"),
        
        h3("Configuration"),
        verbatimTextOutput("config"),
        
        h3("Database Status"),
        verbatimTextOutput("dbstatus")
      )
    )
  )
  
  server <- function(input, output, session) {
    output$sysinfo <- renderText({
      paste0(
        "Server Time: ", format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z"), "\n",
        "R Version: ", R.version.string, "\n",
        "Shiny Version: ", packageVersion("shiny"), "\n",
        "Working Directory: ", getwd()
      )
    })
    
    output$config <- renderText({
      paste0(
        "Port: ", port, "\n",
        "Host: ", host, "\n",
        "Environment: ", Sys.getenv("RAILWAY_ENVIRONMENT", "development"), "\n",
        "Config Active: ", Sys.getenv("R_CONFIG_ACTIVE", "default")
      )
    })
    
    output$dbstatus <- renderText({
      db_url <- Sys.getenv("DATABASE_URL")
      if (nchar(db_url) > 0) {
        # Parse database URL to show connection info (without password)
        if (grepl("postgresql://", db_url)) {
          parts <- strsplit(gsub("postgresql://", "", db_url), "[@:/]")[[1]]
          paste0(
            "Database: PostgreSQL\n",
            "Status: Configured\n",
            "Host: ", if(length(parts) > 2) parts[3] else "Unknown", "\n",
            "Port: ", if(length(parts) > 3) parts[4] else "5432", "\n",
            "Database: ", if(length(parts) > 4) parts[5] else "Unknown"
          )
        } else {
          "Database URL is set (non-PostgreSQL)"
        }
      } else {
        "Database: Not configured\nSet DATABASE_URL environment variable"
      }
    })
  }
}

# Create Shiny app with specific options to avoid version checks
cat("Creating Shiny application with health check...\n")

# Create the app without version checks
app <- shinyApp(
  ui = ui,
  server = server,
  options = list(
    launch.browser = FALSE,
    host = host,
    port = port
  )
)

# Add health check handler
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
        '"timestamp":"', format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ"), '",',
        '"service":"monitor-legislativo-v4",',
        '"app_loaded":', tolower(app_loaded), ',',
        '"uptime":', as.numeric(Sys.time() - .GlobalEnv$start_time, units="secs"), '}'
      )
    ))
  }
  
  # Default handler
  return(original_handler(req))
}

# Record start time
.GlobalEnv$start_time <- Sys.time()

# Start the server
cat("========================================\n")
cat(sprintf("Starting server on %s:%d\n", host, port))
cat("Access at: Railway deployment URL\n")
cat("Health check: /health\n")
cat("========================================\n")

# Run with specific httpuv options
runApp(
  app,
  host = host,
  port = port,
  launch.browser = FALSE,
  quiet = TRUE
)