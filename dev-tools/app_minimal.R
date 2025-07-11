# Monitor Legislativo v4 - Minimal R Shiny Application
# Railway Production Deployment - Minimal Version without complex dependencies

library(shiny)
library(shinydashboard)
library(DT)
library(dplyr)
library(jsonlite)

# Simple sample data
sample_documents <- data.frame(
  id = 1:10,
  titulo = paste("Documento", 1:10),
  tipo = sample(c("lei", "decreto", "portaria"), 10, replace = TRUE),
  estado = sample(c("SP", "RJ", "MG", "RS"), 10, replace = TRUE),
  data = Sys.Date() - sample(1:365, 10),
  stringsAsFactors = FALSE
)

# Simple UI
ui <- dashboardPage(
  dashboardHeader(title = "Monitor Legislativo v4"),
  dashboardSidebar(
    sidebarMenu(
      menuItem("Dashboard", tabName = "dashboard", icon = icon("dashboard")),
      menuItem("Documents", tabName = "documents", icon = icon("file-text"))
    )
  ),
  dashboardBody(
    tabItems(
      tabItem(tabName = "dashboard",
        fluidRow(
          box(
            title = "Statistics", 
            status = "primary", 
            solidHeader = TRUE, 
            width = 12,
            h3("Monitor Legislativo v4 - Production Deployment"),
            p("Application is running successfully on Railway!"),
            p("Database connection will be implemented in next version.")
          )
        )
      ),
      tabItem(tabName = "documents",
        fluidRow(
          box(
            title = "Sample Documents", 
            status = "primary", 
            solidHeader = TRUE, 
            width = 12,
            DT::dataTableOutput("documentsTable")
          )
        )
      )
    )
  )
)

# Server
server <- function(input, output) {
  output$documentsTable <- DT::renderDataTable({
    DT::datatable(sample_documents, options = list(pageLength = 10))
  })
}

# Print startup information
cat("Starting Monitor Legislativo v4 Shiny application...\n")
cat("PORT env var:", Sys.getenv("PORT"), "\n")
cat("Using port:", as.integer(Sys.getenv("PORT", "3838")), "\n")
cat("Host: 0.0.0.0\n")
cat("All env vars with PORT:\n")
envs <- Sys.getenv()
for(name in names(envs)) {
  if(grepl("PORT", name, ignore.case = TRUE)) {
    cat("  ", name, "=", envs[name], "\n")
  }
}

# Set options before running app
options(
  shiny.host = "0.0.0.0",
  shiny.port = as.integer(Sys.getenv("PORT", "3838")),
  shiny.launch.browser = FALSE,
  shiny.autoreload = FALSE
)

# Run the application with explicit options
cat("Starting Shiny app...\n")
app <- shinyApp(ui = ui, server = server)

# Add a print when server starts
runApp(app, host = "0.0.0.0", port = as.integer(Sys.getenv("PORT", "3838")), launch.browser = FALSE)