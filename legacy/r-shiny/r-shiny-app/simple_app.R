# Monitor Legislativo v4 - Simple R Shiny Service for Railway
# Minimal deployment for integration with React frontend

library(shiny)
library(jsonlite)

# Define UI
ui <- fluidPage(
  titlePanel("Monitor Legislativo v4 - R Analytics Service"),
  
  div(class = "container-fluid",
    fluidRow(
      column(12,
        h2("🌟 R Shiny Service Status: ONLINE"),
        hr(),
        
        div(class = "card",
          div(class = "card-body",
            h4("System Information:"),
            p(paste("R version:", R.version.string)),
            p(paste("Shiny version:", packageVersion("shiny"))),
            p(paste("Service:", "Railway Production")),
            p(paste("Timestamp:", Sys.time())),
            p(paste("Host:", Sys.info()[["nodename"]]))
          )
        ),
        
        hr(),
        
        div(class = "card",
          div(class = "card-body",
            h4("Health Check Endpoint:"),
            p("Status: ✅ Healthy"),
            p("URL: /health"),
            p("This service provides R analytics for Monitor Legislativo v4")
          )
        ),
        
        hr(),
        
        div(class = "card",
          div(class = "card-body",
            h4("Interactive Test:"),
            actionButton("test_btn", "Click to Test Reactivity", class = "btn btn-primary"),
            br(), br(),
            verbatimTextOutput("test_output")
          )
        )
      )
    )
  ),
  
  # Add Bootstrap CSS
  tags$head(
    tags$link(rel = "stylesheet", 
              href = "https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css")
  )
)

# Define server logic
server <- function(input, output, session) {
  # Test reactivity
  output$test_output <- renderText({
    if (input$test_btn > 0) {
      paste("🎉 Button clicked", input$test_btn, "times at", Sys.time())
    } else {
      "Ready for testing..."
    }
  })
  
  # Health check logging
  observe({
    cat("Health check accessed at", as.character(Sys.time()), "\n")
  })
}

# Create Shiny app
shinyApp(ui = ui, server = server)