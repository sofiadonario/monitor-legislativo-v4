# MONITOR LEGISLATIVO V4 - MONITORING DASHBOARD
# ==============================================
# Real-time monitoring dashboard for production metrics
# Optimized for Railway deployment and Brazilian academic context

library(shiny)
library(shinydashboard)
library(plotly)
library(DT)
library(dplyr)
library(lubridate)

# =============================================================================
# MONITORING DASHBOARD UI
# =============================================================================

#' Create monitoring dashboard UI
#' @return Shiny UI for monitoring dashboard
monitoring_dashboard_ui <- function() {
  dashboardPage(
    dashboardHeader(title = "Monitor Legislativo v4 - Production Metrics"),
    
    dashboardSidebar(
      sidebarMenu(
        menuItem("System Health", tabName = "health", icon = icon("heartbeat")),
        menuItem("Performance", tabName = "performance", icon = icon("tachometer-alt")),
        menuItem("Database", tabName = "database", icon = icon("database")),
        menuItem("Application", tabName = "application", icon = icon("cogs")),
        menuItem("Alerts", tabName = "alerts", icon = icon("exclamation-triangle")),
        menuItem("Logs", tabName = "logs", icon = icon("file-text"))
      )
    ),
    
    dashboardBody(
      tags$head(
        tags$style(HTML("
          .content-wrapper, .right-side {
            background-color: #f4f4f4;
          }
          .small-box .inner {
            padding: 10px;
          }
          .monitoring-card {
            background: white;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.12);
          }
        "))
      ),
      
      tabItems(
        # System Health Tab
        tabItem(tabName = "health",
          fluidRow(
            valueBoxOutput("overall_status"),
            valueBoxOutput("uptime"),
            valueBoxOutput("memory_usage")
          ),
          
          fluidRow(
            box(
              title = "Health Check Status",
              status = "primary",
              solidHeader = TRUE,
              width = 6,
              height = 400,
              tableOutput("health_checks")
            ),
            
            box(
              title = "System Resources",
              status = "primary", 
              solidHeader = TRUE,
              width = 6,
              height = 400,
              plotlyOutput("resource_chart")
            )
          ),
          
          fluidRow(
            box(
              title = "Real-time Metrics",
              status = "info",
              solidHeader = TRUE,
              width = 12,
              height = 300,
              plotlyOutput("realtime_metrics")
            )
          )
        ),
        
        # Performance Tab
        tabItem(tabName = "performance",
          fluidRow(
            valueBoxOutput("cpu_usage"),
            valueBoxOutput("response_time"),
            valueBoxOutput("active_sessions")
          ),
          
          fluidRow(
            box(
              title = "Performance Trends",
              status = "primary",
              solidHeader = TRUE,
              width = 12,
              height = 500,
              plotlyOutput("performance_trends")
            )
          ),
          
          fluidRow(
            box(
              title = "Memory Usage Over Time",
              status = "info",
              solidHeader = TRUE,
              width = 6,
              height = 400,
              plotlyOutput("memory_trend")
            ),
            
            box(
              title = "CPU Usage Over Time",
              status = "info",
              solidHeader = TRUE,
              width = 6,
              height = 400,
              plotlyOutput("cpu_trend")
            )
          )
        ),
        
        # Database Tab
        tabItem(tabName = "database",
          fluidRow(
            valueBoxOutput("db_connections"),
            valueBoxOutput("db_response_time"),
            valueBoxOutput("cache_hit_rate")
          ),
          
          fluidRow(
            box(
              title = "Database Performance",
              status = "primary",
              solidHeader = TRUE,
              width = 12,
              height = 400,
              plotlyOutput("database_metrics")
            )
          ),
          
          fluidRow(
            box(
              title = "Connection Pool Status",
              status = "info",
              solidHeader = TRUE,
              width = 6,
              height = 300,
              tableOutput("connection_pool")
            ),
            
            box(
              title = "Query Performance",
              status = "info",
              solidHeader = TRUE,
              width = 6,
              height = 300,
              tableOutput("query_performance")
            )
          )
        ),
        
        # Application Tab
        tabItem(tabName = "application",
          fluidRow(
            valueBoxOutput("total_users"),
            valueBoxOutput("documents_processed"),
            valueBoxOutput("search_queries")
          ),
          
          fluidRow(
            box(
              title = "Application Usage",
              status = "primary",
              solidHeader = TRUE,
              width = 12,
              height = 400,
              plotlyOutput("application_usage")
            )
          ),
          
          fluidRow(
            box(
              title = "Feature Usage",
              status = "info",
              solidHeader = TRUE,
              width = 6,
              height = 300,
              plotlyOutput("feature_usage")
            ),
            
            box(
              title = "Error Rates",
              status = "info",
              solidHeader = TRUE,
              width = 6,
              height = 300,
              plotlyOutput("error_rates")
            )
          )
        ),
        
        # Alerts Tab
        tabItem(tabName = "alerts",
          fluidRow(
            valueBoxOutput("active_alerts"),
            valueBoxOutput("alert_rate"),
            valueBoxOutput("last_alert")
          ),
          
          fluidRow(
            box(
              title = "Recent Alerts",
              status = "warning",
              solidHeader = TRUE,
              width = 12,
              height = 500,
              DT::dataTableOutput("alerts_table")
            )
          )
        ),
        
        # Logs Tab
        tabItem(tabName = "logs",
          fluidRow(
            box(
              title = "Application Logs",
              status = "primary",
              solidHeader = TRUE,
              width = 6,
              height = 600,
              verbatimTextOutput("app_logs")
            ),
            
            box(
              title = "Error Logs", 
              status = "danger",
              solidHeader = TRUE,
              width = 6,
              height = 600,
              verbatimTextOutput("error_logs")
            )
          )
        )
      )
    )
  )
}

# =============================================================================
# MONITORING DASHBOARD SERVER
# =============================================================================

#' Create monitoring dashboard server logic
#' @param input Shiny input
#' @param output Shiny output
#' @param session Shiny session
monitoring_dashboard_server <- function(input, output, session) {
  
  # Reactive values for real-time data
  values <- reactiveValues(
    metrics_history = data.frame(),
    last_update = Sys.time(),
    health_status = list()
  )
  
  # Auto-refresh every 30 seconds
  observe({
    invalidateLater(30000, session)
    
    # Collect current metrics
    current_metrics <- collect_system_metrics()
    
    # Update reactive values
    values$last_update <- Sys.time()
    values$health_status <- health_check()
    
    # Add to metrics history (keep last 100 records)
    if (nrow(values$metrics_history) >= 100) {
      values$metrics_history <- tail(values$metrics_history, 99)
    }
    
    new_row <- data.frame(
      timestamp = current_metrics$timestamp,
      memory_percent = current_metrics$memory$usage_percent %||% 0,
      cpu_percent = current_metrics$cpu_usage_percent %||% 0,
      disk_percent = current_metrics$disk$usage_percent %||% 0,
      active_sessions = current_metrics$app_metrics$active_sessions %||% 0,
      db_connections = current_metrics$app_metrics$database_connections %||% 0
    )
    
    values$metrics_history <- rbind(values$metrics_history, new_row)
  })
  
  # Overall Status Value Box
  output$overall_status <- renderValueBox({
    status <- values$health_status$status %||% "unknown"
    color <- switch(status,
                   "healthy" = "green",
                   "degraded" = "yellow", 
                   "unhealthy" = "red",
                   "gray")
    
    valueBox(
      value = toupper(status),
      subtitle = "System Status",
      icon = icon("heartbeat"),
      color = color
    )
  })
  
  # Uptime Value Box
  output$uptime <- renderValueBox({
    start_time <- as.POSIXct(Sys.getenv("APP_START_TIME", Sys.time()))
    uptime_duration <- difftime(Sys.time(), start_time, units = "hours")
    uptime_text <- if (uptime_duration < 1) {
      paste(round(as.numeric(uptime_duration) * 60), "min")
    } else if (uptime_duration < 24) {
      paste(round(as.numeric(uptime_duration)), "hours")
    } else {
      paste(round(as.numeric(uptime_duration) / 24), "days")
    }
    
    valueBox(
      value = uptime_text,
      subtitle = "Uptime",
      icon = icon("clock"),
      color = "blue"
    )
  })
  
  # Memory Usage Value Box
  output$memory_usage <- renderValueBox({
    current_metrics <- collect_system_metrics()
    memory_percent <- current_metrics$memory$usage_percent %||% 0
    color <- if (memory_percent > 90) "red" else if (memory_percent > 75) "yellow" else "green"
    
    valueBox(
      value = paste0(round(memory_percent), "%"),
      subtitle = "Memory Usage",
      icon = icon("memory"),
      color = color
    )
  })
  
  # Health Checks Table
  output$health_checks <- renderTable({
    health <- values$health_status
    if (length(health$checks) > 0) {
      data.frame(
        Component = names(health$checks),
        Status = unlist(health$checks),
        stringsAsFactors = FALSE
      )
    } else {
      data.frame(Component = "No data", Status = "Loading...")
    }
  }, striped = TRUE, hover = TRUE)
  
  # Resource Chart
  output$resource_chart <- renderPlotly({
    current_metrics <- collect_system_metrics()
    
    resources <- data.frame(
      Resource = c("Memory", "CPU", "Disk"),
      Usage = c(
        current_metrics$memory$usage_percent %||% 0,
        current_metrics$cpu_usage_percent %||% 0,
        current_metrics$disk$usage_percent %||% 0
      )
    )
    
    p <- plot_ly(resources, x = ~Resource, y = ~Usage, type = 'bar',
                 marker = list(color = c('#3498db', '#e74c3c', '#f39c12'))) %>%
      layout(title = "Current Resource Usage",
             yaxis = list(title = "Usage (%)", range = c(0, 100)),
             xaxis = list(title = ""))
    p
  })
  
  # Real-time Metrics
  output$realtime_metrics <- renderPlotly({
    if (nrow(values$metrics_history) > 0) {
      p <- plot_ly(values$metrics_history, x = ~timestamp) %>%
        add_lines(y = ~memory_percent, name = "Memory %", line = list(color = '#3498db')) %>%
        add_lines(y = ~cpu_percent, name = "CPU %", line = list(color = '#e74c3c')) %>%
        layout(title = "Real-time System Metrics",
               yaxis = list(title = "Usage (%)"),
               xaxis = list(title = "Time"))
      p
    } else {
      plotly_empty()
    }
  })
  
  # Additional outputs would be implemented similarly...
  # For brevity, showing key examples above
  
  # Alerts Table
  output$alerts_table <- DT::renderDataTable({
    # Load alerts from log file
    alert_file <- "monitoring/logs/alerts.log"
    if (file.exists(alert_file)) {
      tryCatch({
        alert_lines <- readLines(alert_file, n = 100)
        alert_data <- lapply(alert_lines, function(x) {
          tryCatch(fromJSON(x), error = function(e) NULL)
        })
        alert_data <- Filter(Negate(is.null), alert_data)
        
        if (length(alert_data) > 0) {
          alerts_df <- do.call(rbind, lapply(alert_data, function(x) {
            data.frame(
              timestamp = x$timestamp,
              level = x$level,
              message = x$message,
              stringsAsFactors = FALSE
            )
          }))
          alerts_df$timestamp <- as.POSIXct(alerts_df$timestamp)
          alerts_df[order(alerts_df$timestamp, decreasing = TRUE), ]
        } else {
          data.frame(timestamp = character(), level = character(), message = character())
        }
      }, error = function(e) {
        data.frame(timestamp = character(), level = character(), message = character())
      })
    } else {
      data.frame(timestamp = character(), level = character(), message = character())
    }
  }, options = list(pageLength = 20, order = list(list(0, 'desc'))))
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Helper function for null coalescing
`%||%` <- function(x, y) if (is.null(x)) y else x

#' Launch monitoring dashboard
#' @param port Port to run dashboard on (default: 3839)
launch_monitoring_dashboard <- function(port = 3839) {
  if (!is_production()) {
    cat("ℹ️ Monitoring dashboard available in production mode only\n")
    return(FALSE)
  }
  
  shinyApp(
    ui = monitoring_dashboard_ui(),
    server = monitoring_dashboard_server,
    options = list(port = port, host = "0.0.0.0")
  )
}