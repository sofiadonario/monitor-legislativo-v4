# MACKMONITOR - UNIFIED ANALYTICS DASHBOARD (No Leaflet Version)
# ==============================================================
# Simplified version without heavy geospatial dependencies for Railway
# 134,014+ Documents | 26 States | Railway Deployment Optimized

cat("🚀 MACKMONITOR - Analytics Dashboard Loading (No Leaflet)...\n")

# Load essential packages
library(shiny)
library(shinydashboard)
library(DT)
library(plotly)
library(dplyr)
library(ggplot2)

# Optional packages with fallback
tryCatch({
  library(RColorBrewer)
  library(htmlwidgets)
}, error = function(e) {
  cat("⚠️ Optional packages not available\n")
})

# Load database connection
tryCatch({
  source("RAILWAY_DATABASE_FINAL_FIX.R")
  cat("✅ Database connection loaded\n")
}, error = function(e) {
  cat("⚠️ Database connection failed, using fallbacks\n")
  
  # Fallback functions
  get_total_documents <<- function(filters = list()) { return(134014) }
  get_lexml_dashboard_metrics <<- function() {
    return(list(
      total_documents = 134014,
      states_with_docs = 21,
      municipalities_with_docs = 315,
      states_percentage = 77.8,
      municipalities_percentage = 5.7,
      date_range_years = 50,
      last_updated = Sys.time(),
      data_source = "fallback"
    ))
  }
  get_documents_by_state <<- function(limit = 100) {
    return(data.frame(
      estado = c("SP", "MG", "DF", "SC", "RS"),
      count = c(15000, 12000, 8000, 5000, 4000)
    ))
  }
  get_documents_by_type <<- function(limit = 100) {
    return(data.frame(
      tipo = c("Jurisprudência", "Legislação", "Outros", "Doutrina", "Proposições"),
      count = c(54617, 51086, 13850, 12809, 1651)
    ))
  }
})

# Simple UI without leaflet
ui <- dashboardPage(
  dashboardHeader(title = "MackMonitor - Analytics Dashboard"),
  
  dashboardSidebar(
    sidebarMenu(
      menuItem("📊 Dashboard", tabName = "dashboard", icon = icon("dashboard")),
      menuItem("📈 Statistics", tabName = "stats", icon = icon("chart-bar")),
      menuItem("ℹ️ About", tabName = "about", icon = icon("info"))
    )
  ),
  
  dashboardBody(
    tabItems(
      # Dashboard tab
      tabItem(tabName = "dashboard",
        fluidRow(
          valueBoxOutput("total_docs"),
          valueBoxOutput("states_coverage"),
          valueBoxOutput("municipalities_coverage")
        ),
        
        fluidRow(
          box(
            title = "Documents by State", status = "primary", solidHeader = TRUE,
            width = 6, height = 400,
            plotlyOutput("state_chart")
          ),
          box(
            title = "Documents by Type", status = "success", solidHeader = TRUE,
            width = 6, height = 400,
            plotlyOutput("type_chart")
          )
        )
      ),
      
      # Statistics tab
      tabItem(tabName = "stats",
        fluidRow(
          box(
            title = "System Health Status", status = "primary", solidHeader = TRUE,
            width = 12,
            verbatimTextOutput("system_health")
          )
        )
      ),
      
      # About tab
      tabItem(tabName = "about",
        fluidRow(
          box(
            title = "About MackMonitor", status = "primary", solidHeader = TRUE,
            width = 12,
            h3("Brazilian Legislative Monitoring Dashboard"),
            p("📊 Total Documents: 134,014"),
            p("🗺️ Geographic Coverage: 21 states, 315+ municipalities"),
            p("📅 Time Range: 50+ years of legislative data"),
            p("🚀 Deployed on Railway with PostgreSQL backend")
          )
        )
      )
    )
  )
)

# Server logic
server <- function(input, output, session) {
  
  # Get metrics reactively
  metrics <- reactive({
    get_lexml_dashboard_metrics()
  })
  
  # Value boxes
  output$total_docs <- renderValueBox({
    m <- metrics()
    valueBox(
      value = format(m$total_documents, big.mark = ","),
      subtitle = "Total Documents",
      icon = icon("file-text"),
      color = "blue"
    )
  })
  
  output$states_coverage <- renderValueBox({
    m <- metrics()
    valueBox(
      value = paste0(m$states_with_docs, " (", m$states_percentage, "%)"),
      subtitle = "States with Documents",
      icon = icon("map"),
      color = "green"
    )
  })
  
  output$municipalities_coverage <- renderValueBox({
    m <- metrics()
    valueBox(
      value = paste0(m$municipalities_with_docs, " (", m$municipalities_percentage, "%)"),
      subtitle = "Municipalities with Documents", 
      icon = icon("city"),
      color = "yellow"
    )
  })
  
  # State chart
  output$state_chart <- renderPlotly({
    state_data <- get_documents_by_state(10)
    
    p <- plot_ly(
      data = state_data,
      x = ~reorder(estado, count),
      y = ~count,
      type = "bar",
      text = ~paste("State:", estado, "<br>Documents:", format(count, big.mark = ",")),
      textposition = "none",
      hovertemplate = "%{text}<extra></extra>"
    ) %>%
    layout(
      title = "Documents by State",
      xaxis = list(title = "State"),
      yaxis = list(title = "Number of Documents"),
      showlegend = FALSE
    )
    
    p
  })
  
  # Type chart
  output$type_chart <- renderPlotly({
    type_data <- get_documents_by_type(10)
    
    p <- plot_ly(
      data = type_data,
      labels = ~tipo,
      values = ~count,
      type = "pie",
      textinfo = "label+percent",
      hovertemplate = "%{label}<br>Documents: %{value:,}<br>Percentage: %{percent}<extra></extra>"
    ) %>%
    layout(title = "Documents by Type")
    
    p
  })
  
  # System health
  output$system_health <- renderText({
    # Check connection status
    conn_status <- if (exists("get_connection_status")) {
      get_connection_status()
    } else {
      list(status = "unknown", message = "Status function not available")
    }
    
    paste(
      "=== SYSTEM HEALTH STATUS ===\n",
      sprintf("Database: %s", 
        ifelse(conn_status$status == "connected", 
               paste0("✅ Connected (", format(conn_status$document_count, big.mark = ","), " documents)"),
               "❌ Disconnected - Using fallback")),
      sprintf("Data Source: %s", metrics()$data_source),
      "",
      "=== PERFORMANCE METRICS ===",
      sprintf("Environment: %s", ifelse(Sys.getenv("RAILWAY_ENVIRONMENT") != "", "Railway Production", "Development")),
      sprintf("Port: %s", Sys.getenv("PORT", "3838")),
      sprintf("Last Updated: %s", format(metrics()$last_updated, "%Y-%m-%d %H:%M:%S")),
      "",
      "=== DEPLOYMENT INFO ===",
      "Platform: Railway",
      "Version: No-Leaflet Minimal",
      sprintf("R Version: %s", R.version.string),
      sep = "\n"
    )
  })
}

cat("✅ MackMonitor Dashboard ready (No Leaflet version)\n")

# Create the Shiny app
shinyApp(ui = ui, server = server)