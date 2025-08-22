#!/usr/bin/env Rscript
# Minimal Railway Health Check Server
# ===================================
# This script creates the simplest possible Shiny app with health check support

cat("=== Railway Minimal Health Server Starting ===\n")

# Load only essential library
library(shiny)

# Get configuration
port <- as.numeric(Sys.getenv("PORT", "3838"))
host <- "0.0.0.0"

cat(sprintf("Port: %d, Host: %s\n", port, host))

# Create minimal UI
ui <- fluidPage(
  titlePanel("Monitor Legislativo - Health Check Mode"),
  mainPanel(
    h3("Server Status: Running"),
    verbatimTextOutput("info")
  )
)

# Create minimal server
server <- function(input, output, session) {
  output$info <- renderText({
    paste0(
      "Time: ", Sys.time(), "\n",
      "Port: ", port, "\n",
      "Status: Healthy"
    )
  })
}

# Create app with health check
app <- shinyApp(ui, server)

# Add health check handler
app$httpHandler <- local({
  original <- app$httpHandler
  function(req) {
    # Check if this is a health check request
    path <- req$PATH_INFO
    if (!is.null(path) && grepl("^/health", path)) {
      return(list(
        status = 200L,
        headers = list("Content-Type" = "text/plain"),
        body = "OK"
      ))
    }
    # Pass through to original handler
    original(req)
  }
})

cat("Starting minimal server...\n")

# Run the app
runApp(
  app,
  host = host,
  port = port,
  launch.browser = FALSE
)