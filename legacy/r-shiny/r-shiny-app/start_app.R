# Monitor Legislativo v4 - Railway Startup Script
# Ensure proper network binding for Railway deployment

# Get port from environment
port <- as.integer(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

# Print startup information for debugging
cat("=== Monitor Legislativo v4 Startup ===\n")
cat("Host:", host, "\n")
cat("Port:", port, "\n")
cat("Working directory:", getwd(), "\n")
cat("R version:", R.version.string, "\n")
cat("========================================\n")

# Set global options
options(
  shiny.host = host,
  shiny.port = port,
  shiny.launch.browser = FALSE,
  shiny.autoreload = FALSE,
  shiny.sanitize.errors = FALSE
)

# Source the main application
cat("Loading application...\n")
source("app.R")

# Keep the session alive
cat("Application should be running on http://", host, ":", port, "\n")