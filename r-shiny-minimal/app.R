# Monitor Legislativo v4 - Minimal R Shiny Service
library(shiny)
library(jsonlite)

# Define UI
ui <- fluidPage(
  titlePanel("Monitor Legislativo v4 - R Analytics"),
  
  h3("🌟 R Shiny Service: ONLINE"),
  
  div(
    h4("System Information:"),
    p(paste("R version:", R.version.string)),
    p(paste("Shiny version:", packageVersion("shiny"))),
    p(paste("Timestamp:", Sys.time())),
    p("Service: Railway Production")
  ),
  
  hr(),
  
  h4("Health Check:"),
  p("Status: ✅ Healthy"),
  p("This service provides R analytics for Monitor Legislativo v4"),
  
  hr(),
  
  actionButton("test_btn", "Test Reactivity", class = "btn-primary"),
  br(), br(),
  verbatimTextOutput("test_output")
)

# Define server
server <- function(input, output, session) {
  output$test_output <- renderText({
    if (input$test_btn > 0) {
      paste("Button clicked", input$test_btn, "times at", Sys.time())
    } else {
      "Ready for testing..."
    }
  })
}

# Run app
shinyApp(ui = ui, server = server)