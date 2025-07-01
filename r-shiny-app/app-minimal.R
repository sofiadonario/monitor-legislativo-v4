library(shiny)

ui <- fluidPage(
  titlePanel("Monitor Legislativo - Minimal Test"),
  
  sidebarLayout(
    sidebarPanel(
      h3("Status"),
      p("This is a minimal R Shiny app for Railway deployment testing."),
      p("If you can see this, R Shiny is working on Railway!")
    ),
    
    mainPanel(
      h3("System Information"),
      verbatimTextOutput("sysinfo"),
      
      h3("Environment Variables"),
      verbatimTextOutput("envvars")
    )
  )
)

server <- function(input, output, session) {
  output$sysinfo <- renderPrint({
    list(
      R_Version = R.version.string,
      Platform = Sys.info()["sysname"],
      Working_Directory = getwd(),
      Port = Sys.getenv("PORT", "3838")
    )
  })
  
  output$envvars <- renderPrint({
    env_vars <- Sys.getenv()
    env_vars[grep("RAILWAY|PORT|SHINY", names(env_vars))]
  })
}

options(shiny.host = "0.0.0.0")
options(shiny.port = as.integer(Sys.getenv("PORT", "3838")))

message("Starting minimal Shiny app on port ", getOption("shiny.port"))

shinyApp(ui = ui, server = server)