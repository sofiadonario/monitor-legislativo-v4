# MONITORING DASHBOARD UI FOR R SHINY RAILWAY DEPLOYMENT
# ======================================================
# Real-time monitoring dashboard with health metrics, logs, and analytics

library(shiny)
library(shinydashboard)
library(DT)
library(plotly)
library(dplyr)

# Source monitoring components
source("monitoring/logger.R")
source("monitoring/app_monitor.R")
source("monitoring/telemetry.R")

# Monitoring Dashboard UI Module
monitoring_ui <- function(id) {
  ns <- NS(id)
  
  tagList(
    # CSS for monitoring dashboard
    tags$head(
      tags$style(HTML("
        .monitoring-card {
          background: #f8f9fa;
          border-radius: 8px;
          padding: 15px;
          margin-bottom: 15px;
          border-left: 4px solid #007bff;
        }
        
        .metric-card {
          text-align: center;
          padding: 20px;
          border-radius: 8px;
          margin-bottom: 15px;
        }
        
        .metric-value {
          font-size: 2.5em;
          font-weight: bold;
          margin-bottom: 5px;
        }
        
        .metric-label {
          font-size: 0.9em;
          color: #6c757d;
        }
        
        .status-healthy { 
          background: #d4edda; 
          border-color: #c3e6cb; 
          color: #155724; 
        }
        
        .status-warning { 
          background: #fff3cd; 
          border-color: #ffeaa7; 
          color: #856404; 
        }
        
        .status-error { 
          background: #f8d7da; 
          border-color: #f5c6cb; 
          color: #721c24; 
        }
        
        .alert-item {
          padding: 10px;
          margin-bottom: 10px;
          border-radius: 5px;
          border-left: 4px solid #dc3545;
        }
        
        .log-viewer {
          background: #1e1e1e;
          color: #d4d4d4;
          font-family: 'Courier New', monospace;
          padding: 15px;
          border-radius: 5px;
          max-height: 500px;
          overflow-y: auto;
        }
        
        .log-entry {
          margin-bottom: 5px;
          word-wrap: break-word;
        }
        
        .log-debug { color: #608b4e; }
        .log-info { color: #9cdcfe; }
        .log-warn { color: #dcdcaa; }
        .log-error { color: #f48771; }
        .log-critical { color: #ff6b6b; }
      "))
    ),
    
    fluidRow(
      # System Health Overview
      box(
        title = "System Health", 
        status = "primary", 
        solidHeader = TRUE,
        width = 12,
        
        fluidRow(
          column(3,
            div(class = "metric-card",
                id = ns("health_status_card"),
                div(class = "metric-value", textOutput(ns("health_status"))),
                div(class = "metric-label", "Overall Status")
            )
          ),
          column(3,
            div(class = "metric-card status-healthy",
                div(class = "metric-value", textOutput(ns("active_sessions"))),
                div(class = "metric-label", "Active Sessions")
            )
          ),
          column(3,
            div(class = "metric-card status-healthy",
                div(class = "metric-value", textOutput(ns("total_requests"))),
                div(class = "metric-label", "Total Requests")
            )
          ),
          column(3,
            div(class = "metric-value", textOutput(ns("uptime"))),
            div(class = "metric-label", "Uptime")
          )
        ),
        
        br(),
        
        fluidRow(
          column(4,
            h5("Memory Usage"),
            div(
              progressBar(
                id = ns("memory_progress"),
                value = 0,
                total = 100,
                title = "",
                display_pct = TRUE
              )
            ),
            textOutput(ns("memory_details"))
          ),
          column(4,
            h5("CPU Usage"),
            div(
              progressBar(
                id = ns("cpu_progress"),
                value = 0,
                total = 100,
                title = "",
                display_pct = TRUE
              )
            ),
            textOutput(ns("cpu_details"))
          ),
          column(4,
            h5("Database Status"),
            div(
              id = ns("db_status_indicator"),
              textOutput(ns("db_status"))
            )
          )
        )
      )
    ),
    
    fluidRow(
      # Performance Metrics
      box(
        title = "Performance Metrics",
        status = "info",
        solidHeader = TRUE,
        width = 8,
        
        tabsetPanel(
          tabPanel("Real-time Charts",
            plotlyOutput(ns("performance_chart"), height = "400px")
          ),
          tabPanel("Response Times",
            plotlyOutput(ns("response_time_chart"), height = "400px")
          ),
          tabPanel("Error Rates",
            plotlyOutput(ns("error_rate_chart"), height = "400px")
          )
        )
      ),
      
      # Active Alerts
      box(
        title = "Active Alerts",
        status = "warning",
        solidHeader = TRUE,
        width = 4,
        
        div(
          id = ns("alerts_container"),
          uiOutput(ns("alerts_display"))
        ),
        
        br(),
        actionButton(
          ns("clear_alerts"),
          "Clear All Alerts",
          class = "btn-warning btn-sm"
        )
      )
    ),
    
    fluidRow(
      # Feature Usage Analytics
      box(
        title = "Feature Usage Analytics",
        status = "success",
        solidHeader = TRUE,
        width = 6,
        
        fluidRow(
          column(6,
            h5("Top Features (7 days)"),
            DT::dataTableOutput(ns("top_features_table"))
          ),
          column(6,
            h5("Usage Patterns"),
            plotlyOutput(ns("usage_patterns_chart"), height = "300px")
          )
        ),
        
        br(),
        
        fluidRow(
          column(4,
            div(class = "metric-card status-healthy",
                div(class = "metric-value", textOutput(ns("total_interactions"))),
                div(class = "metric-label", "Total Interactions")
            )
          ),
          column(4,
            div(class = "metric-card status-healthy",
                div(class = "metric-value", textOutput(ns("unique_features"))),
                div(class = "metric-label", "Features Used")
            )
          ),
          column(4,
            div(class = "metric-card status-healthy",
                div(class = "metric-value", textOutput(ns("success_rate"))),
                div(class = "metric-label", "Success Rate")
            )
          )
        )
      ),
      
      # Session Analytics
      box(
        title = "Session Analytics",
        status = "info",
        solidHeader = TRUE,
        width = 6,
        
        fluidRow(
          column(6,
            h5("Session Overview"),
            div(class = "metric-card status-healthy",
                div(class = "metric-value", textOutput(ns("peak_sessions"))),
                div(class = "metric-label", "Peak Sessions")
            ),
            div(class = "metric-card status-healthy",
                div(class = "metric-value", textOutput(ns("avg_session_duration"))),
                div(class = "metric-label", "Avg Duration")
            )
          ),
          column(6,
            h5("Error Statistics"),
            div(class = "metric-card status-warning",
                div(class = "metric-value", textOutput(ns("error_count"))),
                div(class = "metric-label", "Total Errors")
            ),
            div(class = "metric-card", 
                id = ns("error_rate_card"),
                div(class = "metric-value", textOutput(ns("error_rate"))),
                div(class = "metric-label", "Error Rate")
            )
          )
        )
      )
    ),
    
    fluidRow(
      # Log Viewer
      box(
        title = "Application Logs",
        status = "primary",
        solidHeader = TRUE,
        width = 12,
        collapsible = TRUE,
        collapsed = TRUE,
        
        fluidRow(
          column(3,
            selectInput(
              ns("log_level_filter"),
              "Log Level:",
              choices = c("All" = "all", "DEBUG" = "debug", "INFO" = "info", 
                         "WARN" = "warn", "ERROR" = "error", "CRITICAL" = "critical"),
              selected = "info"
            )
          ),
          column(3,
            dateRangeInput(
              ns("log_date_filter"),
              "Date Range:",
              start = Sys.Date() - 1,
              end = Sys.Date(),
              max = Sys.Date()
            )
          ),
          column(3,
            textInput(
              ns("log_search"),
              "Search Logs:",
              placeholder = "Enter search term..."
            )
          ),
          column(3,
            br(),
            actionButton(
              ns("refresh_logs"),
              "Refresh",
              class = "btn-primary btn-sm"
            ),
            actionButton(
              ns("export_logs"),
              "Export",
              class = "btn-secondary btn-sm"
            )
          )
        ),
        
        br(),
        
        div(
          class = "log-viewer",
          id = ns("log_display"),
          verbatimTextOutput(ns("logs_content"))
        )
      )
    )
  )
}

# Monitoring Dashboard Server Module
monitoring_server <- function(id) {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns
    
    # Reactive values for monitoring data
    monitoring_data <- reactiveValues(
      last_update = Sys.time(),
      health_check = list(),
      metrics = list(),
      alerts = list(),
      logs = character(0)
    )
    
    # Auto-refresh monitoring data
    observe({
      invalidateLater(5000) # Refresh every 5 seconds
      
      # Update health check
      health_check <- perform_health_check()
      monitoring_data$health_check <- health_check
      
      # Update metrics
      monitoring_data$metrics <- get_current_metrics()
      
      # Update alerts
      monitoring_data$alerts <- get_active_alerts()
      
      monitoring_data$last_update <- Sys.time()
    })
    
    # Health Status Outputs
    output$health_status <- renderText({
      health <- monitoring_data$health_check
      if (isTRUE(length(health) > 0) && !is.null(health$status)) {
        switch(health$status,
               "healthy" = "🟢 HEALTHY",
               "degraded" = "🟡 DEGRADED", 
               "unhealthy" = "🔴 UNHEALTHY",
               "error" = "❌ ERROR",
               "⚪ UNKNOWN")
      } else {
        "⚪ UNKNOWN"
      }
    })
    
    # Update health status card color
    observe({
      health <- monitoring_data$health_check
      if (isTRUE(length(health) > 0) && !is.null(health$status)) {
        class <- switch(health$status,
                       "healthy" = "status-healthy",
                       "degraded" = "status-warning",
                       "unhealthy" = "status-error",
                       "error" = "status-error",
                       "")
        
        runjs(paste0("$('#", ns("health_status_card"), "').removeClass('status-healthy status-warning status-error').addClass('", class, "')"))
      }
    })
    
    # System Metrics Outputs
    output$active_sessions <- renderText({
      metrics <- monitoring_data$metrics
      if (length(metrics) > 0) {
        format(metrics$active_sessions, big.mark = ",")
      } else {
        "0"
      }
    })
    
    output$total_requests <- renderText({
      metrics <- monitoring_data$metrics
      if (length(metrics) > 0) {
        format(metrics$total_requests, big.mark = ",")
      } else {
        "0"
      }
    })
    
    output$uptime <- renderText({
      metrics <- monitoring_data$metrics
      if (length(metrics) > 0) {
        format_duration(metrics$uptime_seconds)
      } else {
        "Unknown"
      }
    })
    
    output$memory_details <- renderText({
      metrics <- monitoring_data$metrics
      if (length(metrics) > 0) {
        paste(round(metrics$memory_usage_mb, 1), "MB")
      } else {
        "Unknown"
      }
    })
    
    output$cpu_details <- renderText({
      metrics <- monitoring_data$metrics
      if (length(metrics) > 0) {
        paste(round(metrics$cpu_usage_percent, 1), "%")
      } else {
        "Unknown"
      }
    })
    
    output$db_status <- renderText({
      metrics <- monitoring_data$metrics
      if (length(metrics) > 0) {
        if (metrics$db_connections > 0) {
          "🟢 Connected"
        } else {
          "🔴 Disconnected"
        }
      } else {
        "⚪ Unknown"
      }
    })
    
    # Performance Charts
    output$performance_chart <- renderPlotly({
      metrics <- monitoring_data$metrics
      if (isTRUE(length(metrics) > 0) && nrow(metrics$performance_history) > 0) {
        data <- metrics$performance_history
        
        p <- plot_ly(data, x = ~timestamp) %>%
          add_trace(y = ~memory_mb, name = "Memory (MB)", type = "scatter", mode = "lines") %>%
          add_trace(y = ~cpu_percent, name = "CPU (%)", type = "scatter", mode = "lines", yaxis = "y2") %>%
          layout(
            title = "System Performance Over Time",
            xaxis = list(title = "Time"),
            yaxis = list(title = "Memory (MB)", side = "left"),
            yaxis2 = list(title = "CPU (%)", side = "right", overlaying = "y"),
            hovermode = "x"
          )
        
        return(p)
      } else {
        # Empty chart
        plot_ly() %>%
          layout(
            title = "No performance data available",
            xaxis = list(title = "Time"),
            yaxis = list(title = "Value")
          )
      }
    })
    
    # Feature Usage Analytics
    observe({
      analytics <- get_feature_usage_analytics(7)
      
      output$total_interactions <- renderText({
        format(analytics$total_interactions, big.mark = ",")
      })
      
      output$unique_features <- renderText({
        format(analytics$unique_features, big.mark = ",")
      })
      
      output$success_rate <- renderText({
        paste(round(analytics$success_rate * 100, 1), "%")
      })
      
      output$top_features_table <- DT::renderDataTable({
        if (!isTRUE(is.null(analytics$top_features)) && is.data.frame(analytics$top_features) && nrow(analytics$top_features) > 0) {
          analytics$top_features[1:min(10, nrow(analytics$top_features)),]
        } else {
          data.frame(feature = character(0), usage_count = numeric(0))
        }
      }, options = list(pageLength = 10, searching = FALSE, dom = 't'))
    })
    
    # Session Analytics
    output$peak_sessions <- renderText({
      metrics <- monitoring_data$metrics
      if (length(metrics) > 0) {
        format(metrics$peak_sessions, big.mark = ",")
      } else {
        "0"
      }
    })
    
    output$error_count <- renderText({
      metrics <- monitoring_data$metrics
      if (length(metrics) > 0) {
        format(metrics$error_count, big.mark = ",")
      } else {
        "0"
      }
    })
    
    output$error_rate <- renderText({
      metrics <- monitoring_data$metrics
      if (length(metrics) > 0) {
        rate <- metrics$error_count / max(1, metrics$total_requests)
        paste(round(rate * 100, 2), "%")
      } else {
        "0.00%"
      }
    })
    
    # Alerts Display
    output$alerts_display <- renderUI({
      alerts <- monitoring_data$alerts
      
      if (length(alerts) == 0) {
        return(div(
          class = "text-muted text-center",
          style = "padding: 20px;",
          "No active alerts"
        ))
      }
      
      alert_items <- lapply(alerts, function(alert) {
        severity_class <- switch(alert$severity,
                                "ERROR" = "status-error",
                                "WARN" = "status-warning", 
                                "status-healthy")
        
        div(
          class = paste("alert-item", severity_class),
          div(
            strong(paste(alert$severity, "-", alert$type)),
            br(),
            alert$message,
            br(),
            tags$small(format(alert$timestamp, "%Y-%m-%d %H:%M:%S"))
          )
        )
      })
      
      do.call(tagList, alert_items)
    })
    
    # Clear Alerts
    observeEvent(input$clear_alerts, {
      clear_alerts()
      showNotification("All alerts cleared", type = "message")
    })
    
    # Log Viewer (simplified implementation)
    output$logs_content <- renderText({
      # This would connect to actual log storage in production
      "Real-time logs would be displayed here.\nIntegration with Railway logs pending...\n\n[2024-08-18 10:30:15] INFO: Application started\n[2024-08-18 10:30:16] INFO: Database connection established\n[2024-08-18 10:30:17] DEBUG: Loading user interface\n[2024-08-18 10:30:18] INFO: Application ready"
    })
    
    # Refresh logs
    observeEvent(input$refresh_logs, {
      showNotification("Logs refreshed", type = "message")
    })
    
    # Export logs
    observeEvent(input$export_logs, {
      showNotification("Log export functionality would be implemented here", type = "message")
    })
  })
}

# Utility function for duration formatting (also used in app_monitor.R)
if (!exists("format_duration")) {
  format_duration <- function(seconds) {
    if (seconds < 60) {
      return(paste(round(seconds, 1), "seconds"))
    } else if (seconds < 3600) {
      return(paste(round(seconds / 60, 1), "minutes"))
    } else if (seconds < 86400) {
      return(paste(round(seconds / 3600, 1), "hours"))
    } else {
      return(paste(round(seconds / 86400, 1), "days"))
    }
  }
}

# Custom progress bar function
progressBar <- function(id, value, total = 100, title = "", display_pct = FALSE) {
  percentage <- round((value / total) * 100, 1)
  
  color_class <- if (percentage > 80) "progress-bar-danger" else if (percentage > 60) "progress-bar-warning" else "progress-bar-success"
  
  div(
    class = "progress",
    div(
      id = id,
      class = paste("progress-bar", color_class),
      role = "progressbar",
      style = paste0("width: ", percentage, "%"),
      `aria-valuenow` = value,
      `aria-valuemin` = 0,
      `aria-valuemax` = total,
      if (display_pct) paste0(percentage, "%") else ""
    )
  )
}

# Export UI and server functions
list(
  ui = monitoring_ui,
  server = monitoring_server
)