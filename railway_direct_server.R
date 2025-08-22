#!/usr/bin/env Rscript
# Railway Direct Server - Using httpuv directly with Shiny UI
# ===========================================================

cat("=== Railway Direct Server Starting ===\n")

# Get configuration
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Port: %d, Host: %s\n", port, host))

# Load libraries
suppressWarnings(suppressMessages({
  library(httpuv)
  library(shiny)
  library(jsonlite)
}))

# Try to load the main app
app_loaded <- FALSE
main_app <- NULL

tryCatch({
  cat("Attempting to load main application...\n")
  
  # Source the app file
  if (file.exists("app.R")) {
    app_env <- new.env()
    source("app.R", local = app_env)
    
    # Check if ui and server exist
    if (exists("ui", envir = app_env) && exists("server", envir = app_env)) {
      ui <- get("ui", envir = app_env)
      server <- get("server", envir = app_env)
      
      # Create the Shiny app without running it
      main_app <- shiny::shinyApp(ui, server)
      app_loaded <- TRUE
      cat("✓ Main application loaded successfully\n")
    }
  }
}, error = function(e) {
  cat("Note: Main app not loaded:", e$message, "\n")
})

# Create HTTP server using httpuv
cat("Creating HTTP server...\n")

s <- startServer(
  host = host,
  port = port,
  app = list(
    call = function(req) {
      path <- req$PATH_INFO
      
      # Health check endpoint
      if (!is.null(path) && grepl("^/health", path)) {
        return(list(
          status = 200L,
          headers = list(
            "Content-Type" = "application/json",
            "Cache-Control" = "no-cache"
          ),
          body = toJSON(list(
            status = "healthy",
            timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ"),
            service = "monitor-legislativo-v4",
            app_loaded = app_loaded,
            port = port,
            message = "Server is running"
          ), auto_unbox = TRUE)
        ))
      }
      
      # Try to serve the Shiny app if loaded
      if (app_loaded && !is.null(main_app)) {
        # Use the Shiny app's HTTP handler if available
        if (!is.null(main_app$httpHandler)) {
          return(main_app$httpHandler(req))
        }
      }
      
      # Fallback HTML response
      html_content <- paste0(
        '<!DOCTYPE html>',
        '<html>',
        '<head>',
        '<title>Monitor Legislativo v4</title>',
        '<style>',
        'body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; ',
        'margin: 0; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); ',
        'min-height: 100vh; display: flex; align-items: center; justify-content: center; }',
        '.container { background: white; border-radius: 10px; padding: 40px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); max-width: 600px; width: 100%; }',
        'h1 { color: #333; margin-top: 0; }',
        '.status { padding: 10px 20px; background: #10b981; color: white; border-radius: 5px; display: inline-block; font-weight: bold; }',
        '.info { margin: 20px 0; padding: 20px; background: #f3f4f6; border-radius: 5px; }',
        '.info p { margin: 5px 0; color: #4b5563; }',
        '.links { margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb; }',
        '.links a { color: #6366f1; text-decoration: none; margin-right: 20px; }',
        '.links a:hover { text-decoration: underline; }',
        '</style>',
        '</head>',
        '<body>',
        '<div class="container">',
        '<h1>Monitor Legislativo v4</h1>',
        '<div class="status">✓ Server Running</div>',
        '<div class="info">',
        '<p><strong>Status:</strong> ', if(app_loaded) 'Application Loaded' else 'Fallback Mode', '</p>',
        '<p><strong>Port:</strong> ', port, '</p>',
        '<p><strong>Time:</strong> ', format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z"), '</p>',
        '<p><strong>Environment:</strong> ', Sys.getenv("RAILWAY_ENVIRONMENT", "development"), '</p>',
        '</div>',
        '<div class="links">',
        '<a href="/health">Health Check</a>',
        '<a href="https://railway.app" target="_blank">Railway Dashboard</a>',
        '</div>',
        '</div>',
        '</body>',
        '</html>'
      )
      
      list(
        status = 200L,
        headers = list("Content-Type" = "text/html; charset=utf-8"),
        body = html_content
      )
    }
  )
)

cat("========================================\n")
cat(sprintf("Server started on %s:%d\n", host, port))
cat("Health check: /health\n")
cat("========================================\n")

# Keep the server running
while(TRUE) {
  Sys.sleep(0.1)
  service()
}