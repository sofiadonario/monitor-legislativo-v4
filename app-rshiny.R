# Monitor Legislativo v4 - Standalone R Shiny for Railway
library(shiny)

ui <- fluidPage(
  titlePanel("Monitor Legislativo v4 - R Analytics Service"),
  
  h2("R Shiny Service: ONLINE"),
  
  div(class = "well",
    h3("System Information:"),
    p(strong("Service:"), "Railway R Shiny"),
    p(strong("R Version:"), R.version.string),
    p(strong("Shiny Version:"), packageVersion("shiny")),
    p(strong("Status:"), "Healthy"),
    p(strong("Timestamp:"), textOutput("timestamp", inline = TRUE))
  ),
  
  hr(),
  
  h3("Health Check Endpoint"),
  p("This service provides R analytics integration for Monitor Legislativo v4"),
  p("React Frontend: https://sofiadonario.github.io/monitor-legislativo-v4/"),
  
  hr(),
  
  h3("Interactive Test"),
  actionButton("test_btn", "Test Reactivity", class = "btn-primary"),
  br(), br(),
  verbatimTextOutput("test_output")
)

server <- function(input, output, session) {
  output$timestamp <- renderText({
    invalidateLater(1000)
    as.character(Sys.time())
  })
  
  output$test_output <- renderText({
    if (input$test_btn > 0) {
      paste("Button clicked", input$test_btn, "times at", Sys.time())
    } else {
      "Ready for testing..."
    }
  })
}

# Run the application
shinyApp(ui = ui, server = server)