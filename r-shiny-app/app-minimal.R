library(shiny)

ui <- fluidPage(
  titlePanel("Monitor Legislativo - R Shiny"),
  
  sidebarLayout(
    sidebarPanel(
      h3("Status"),
      p("R Shiny service is running successfully on Railway!"),
      br(),
      p("This demonstrates the R analytics component of Monitor Legislativo v4.")
    ),
    
    mainPanel(
      h3("System Information"),
      verbatimTextOutput("sysinfo")
    )
  )
)

server <- function(input, output, session) {
  output$sysinfo <- renderPrint({
    list(
      Status = "✅ R Shiny Running",
      R_Version = R.version.string,
      Platform = Sys.info()["sysname"],
      Port = Sys.getenv("PORT", "3838"),
      Working_Directory = getwd()
    )
  })
  
  # Simple health check route
  observeEvent(session$clientData, {
    if (!is.null(session$clientData$url_pathname) && 
        session$clientData$url_pathname == "/health") {
      session$sendCustomMessage("health", "OK")
    }
  })
}

options(shiny.host = "0.0.0.0")
options(shiny.port = as.integer(Sys.getenv("PORT", "3838")))

shinyApp(ui = ui, server = server)