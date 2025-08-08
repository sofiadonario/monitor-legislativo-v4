# MINIMAL SHINY DASHBOARD - BASELINE FOR TESTING
# ============================================================================
# This minimal version includes only essential packages and the executive tab
# to establish a working baseline for identifying tabItem issues

# Load only essential packages
library(shiny)
library(shinydashboard)

# Simple fallback function
get_total_documents <- function(filters = list()) { 
  return(134014)
}

get_lexml_dashboard_metrics <- function() {
  list(
    total_documents = 134014,
    states_covered = 26,
    municipalities_covered = 1000,
    states_coverage_percentage = 96.3,
    municipalities_coverage_percentage = 18.0,
    date_range = "2019-2024"
  )
}

# UI
ui <- dashboardPage(
  dashboardHeader(title = "Legislative Monitor - Minimal Test"),
  
  # Sidebar with just one menu item
  dashboardSidebar(
    sidebarMenu(
      menuItem("📊 Executive Summary", tabName = "executive", icon = icon("chart-line"))
    )
  ),
  
  # Body with just one tabItem
  dashboardBody(
    tabItems(
      # Executive Summary Tab - Minimal Version
      tabItem(tabName = "executive",
        fluidRow(
          valueBoxOutput("exec_total_docs"),
          valueBoxOutput("exec_states_coverage"),
          valueBoxOutput("exec_date_range")
        ),
        fluidRow(
          box(
            title = "System Status", status = "success", solidHeader = TRUE, width = 12,
            h4("✅ Minimal Dashboard Running"),
            p("This is a minimal working version with only the Executive Summary tab."),
            p("If this works, we can incrementally add other tabs to identify the issue.")
          )
        )
      )
    )
  )
)

# Server
server <- function(input, output, session) {
  
  # Get metrics once at startup
  metrics <- get_lexml_dashboard_metrics()
  
  # Executive Summary Outputs
  output$exec_total_docs <- renderValueBox({
    valueBox(
      value = format(metrics$total_documents, big.mark = ","),
      subtitle = "Total Documents",
      icon = icon("file-alt"),
      color = "blue"
    )
  })
  
  output$exec_states_coverage <- renderValueBox({
    valueBox(
      value = paste0(metrics$states_covered, "/27"),
      subtitle = "States Covered",
      icon = icon("map-marker-alt"),
      color = "green"
    )
  })
  
  output$exec_date_range <- renderValueBox({
    valueBox(
      value = metrics$date_range,
      subtitle = "Date Range",
      icon = icon("calendar"),
      color = "yellow"
    )
  })
}

# Run the app
shinyApp(ui = ui, server = server)