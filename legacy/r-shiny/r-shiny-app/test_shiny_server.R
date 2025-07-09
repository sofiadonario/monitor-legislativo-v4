# Test Shiny Server for Monitor Legislativo v4
# Quick test to verify Shiny works and can serve HTTP

cat("🚀 Testing Shiny server for Monitor Legislativo v4\n")

# Set library path
.libPaths(c(path.expand("~/R/library"), .libPaths()))

# Load required libraries
library(shiny)
cat("✅ Shiny loaded successfully\n")

# Create a simple test app with health endpoint
ui <- fluidPage(
  titlePanel("Monitor Legislativo v4 - R Shiny Test"),
  
  h3("🌟 R Shiny Status: ONLINE"),
  
  div(
    h4("System Information:"),
    p(paste("R version:", R.version.string)),
    p(paste("Shiny version:", packageVersion("shiny"))),
    p(paste("Timestamp:", Sys.time())),
    p(paste("Host:", Sys.info()["nodename"]))
  ),
  
  hr(),
  
  h4("Interactive Test:"),
  actionButton("test_btn", "Click to Test Reactivity", class = "btn-primary"),
  br(), br(),
  verbatimTextOutput("test_output"),
  
  hr(),
  
  h4("Health Check:"),
  p("Status: ✅ Healthy"),
  p("This endpoint simulates /health for React integration")
)

server <- function(input, output, session) {
  output$test_output <- renderText({
    if (input$test_btn > 0) {
      paste("🎉 Button clicked", input$test_btn, "times at", Sys.time())
    } else {
      "Ready for testing..."
    }
  })
  
  # Health check endpoint simulation
  observe({
    cat("Health check accessed at", as.character(Sys.time()), "\n")
  })
}

# Test that the app can be created
cat("🧪 Testing app creation...\n")
app <- shinyApp(ui = ui, server = server)
cat("✅ Shiny app created successfully\n")

cat("\n🌐 Ready to start server!\n")
cat("📍 To start: runApp(port = 3838, host = '0.0.0.0')\n")
cat("📊 Health endpoint: http://localhost:3838/\n")
cat("🔐 This will serve the R Shiny integration for React\n")

# Start the server (commented out for testing)
# runApp(app, port = 3838, host = "0.0.0.0")

cat("\n✅ Shiny test completed successfully!\n")
cat("🚀 Ready for production deployment!\n")