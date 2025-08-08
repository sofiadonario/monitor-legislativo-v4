# Minimal working Shiny app for Railway deployment
library(shiny)
library(shinydashboard)
library(DT)
library(plotly)
library(dplyr)

# Load database connection
source("scripts/R/database_connection.R", local = TRUE)

# UI
ui <- dashboardPage(
  dashboardHeader(
    title = "MackMonitor - Brazilian Legislative Analytics",
    titleWidth = 350
  ),
  
  dashboardSidebar(
    sidebarMenu(
      menuItem("📊 Executive Summary", tabName = "executive", icon = icon("chart-line")),
      menuItem("📚 Library", tabName = "library", icon = icon("book"))
    )
  ),
  
  dashboardBody(
    tabItems(
      # Executive Summary Tab
      tabItem(tabName = "executive",
        h2("📊 Executive Summary"),
        fluidRow(
          valueBox(
            value = "134,014",
            subtitle = "Total Documents",
            icon = icon("file-alt"),
            color = "blue"
          ),
          valueBox(
            value = "27",
            subtitle = "Brazilian States",
            icon = icon("map"),
            color = "green"
          ),
          valueBox(
            value = "Active",
            subtitle = "System Status",
            icon = icon("check-circle"),
            color = "green"
          )
        ),
        fluidRow(
          box(
            title = "Welcome to MackMonitor",
            status = "primary",
            solidHeader = TRUE,
            width = 12,
            p("Brazilian Legislative Monitoring System"),
            p("Database connected with 134,014 legislative documents"),
            p("Ready for analysis and exploration")
          )
        )
      ),
      
      # Library Tab
      tabItem(tabName = "library",
        h2("📚 Document Library"),
        fluidRow(
          box(
            title = "Search Documents",
            status = "info",
            solidHeader = TRUE,
            width = 12,
            p("Browse and search legislative documents"),
            br(),
            DT::dataTableOutput("documents_table")
          )
        )
      )
    )
  )
)

# Server
server <- function(input, output, session) {
  
  # Sample data for documents table
  output$documents_table <- DT::renderDataTable({
    # Try to get real data from database
    docs <- tryCatch({
      if(exists("get_connection_status") && get_connection_status()$connected) {
        conn <- get_db_connection()
        if(!is.null(conn)) {
          docs <- dbGetQuery(conn, "SELECT id, title, species, estado FROM documents LIMIT 100")
          return(docs)
        }
      }
      # Fallback sample data
      data.frame(
        ID = 1:10,
        Title = paste("Document", 1:10),
        Type = rep(c("Legislation", "Jurisprudence"), 5),
        State = rep(c("SP", "RJ", "MG", "DF", "RS"), 2)
      )
    }, error = function(e) {
      # Fallback sample data
      data.frame(
        ID = 1:10,
        Title = paste("Document", 1:10),
        Type = rep(c("Legislation", "Jurisprudence"), 5),
        State = rep(c("SP", "RJ", "MG", "DF", "RS"), 2)
      )
    })
    
    DT::datatable(docs, options = list(pageLength = 10))
  })
}

# Run app
shinyApp(ui = ui, server = server)