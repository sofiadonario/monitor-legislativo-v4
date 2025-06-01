#!/usr/bin/env Rscript
# Simple Railway startup script for R Shiny

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

# Try to load the main application
tryCatch({
  if (!file.exists("app.R")) {
    stop("app.R file not found!")
  }
  
  cat("Loading main application...\n")
  source("app.R", local = TRUE)
  
}, error = function(e) {
  cat("ERROR loading main app:", e$message, "\n")
  cat("Starting minimal fallback server...\n")
  
  # Simple fallback UI
  ui <- fluidPage(
    titlePanel("Monitor Legislativo v4"),
    mainPanel(
      h3("System Status: Starting Up"),
      p("The Brazilian Legislative Monitor is initializing..."),
      p("If this message persists, please contact the administrator."),
      br(),
      verbatimTextOutput("status")
    )
  )
  
  server <- function(input, output, session) {
    output$status <- renderText({
      paste0("Server Time: ", Sys.time(), 
             "\nHost: ", host,
             "\nPort: ", port,
             "\nR Version: ", R.version.string)
    })
  }
  
  # Run fallback app
  shinyApp(ui, server, options = list(host = host, port = port))
})

# If we get here, the main app loaded successfully
cat("Starting server on", host, "port", port, "\n")
cat("Access your dashboard at: http://localhost or Railway deployment URL\n")

# Start the main Shiny application
shinyApp(ui = ui, server = server, options = list(
  host = host,
  port = port,
  launch.browser = FALSE
))