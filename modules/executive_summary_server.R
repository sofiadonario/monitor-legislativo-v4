# ============================================================================
# ENHANCED EXECUTIVE SUMMARY SERVER FUNCTIONS
# ============================================================================
# 
# Server-side functions for the Enhanced Executive Summary with advanced analytics
# Integrates with the analytics engine to provide real-time insights
# 
# Features:
# - Real-time data processing with caching
# - Interactive visualization rendering
# - Dynamic KPI calculations
# - Smart alert generation and monitoring
# - Performance-optimized reactive functions
# 
# Author: Data Science Consultant
# Date: 2025-08-29
# Version: 1.0 Production-Ready
# ============================================================================

# Source the analytics engine
if (!exists("generate_executive_summary_analytics")) {
  source("modules/executive_summary_analytics.R", local = TRUE)
}

cat("✅ Executive Summary Server Functions loaded\n")

# ============================================================================
# 1. REACTIVE DATA PROCESSING
# ============================================================================

#' Initialize Executive Summary Server Functions
#' 
#' @param input Shiny input object
#' @param output Shiny output object
#' @param session Shiny session object
#' @param get_document_data Function to retrieve document data
init_executive_summary_server <- function(input, output, session, get_document_data) {
  
  # Reactive values for caching
  values <- reactiveValues(
    analytics_results = NULL,
    last_updated = NULL,
    cache_valid = FALSE
  )
  
  # ============================================================================
  # 2. MAIN ANALYTICS REACTIVE
  # ============================================================================
  
  # Main analytics computation with caching
  analytics_data <- reactive({
    
    # Check if we need to refresh data
    current_time <- Sys.time()
    cache_duration <- 300  # 5 minutes
    
    if (is.null(values$last_updated) || 
        difftime(current_time, values$last_updated, units = "secs") > cache_duration ||
        !values$cache_valid) {
      
      cat("🔄 Refreshing Executive Summary analytics...\n")
      
      # Get fresh data
      tryCatch({
        doc_data <- get_document_data()

        if (!is.null(doc_data) && is.data.frame(doc_data) && nrow(doc_data) > 0) {
          # Generate comprehensive analytics
          analytics_results <- generate_executive_summary_analytics(doc_data, cache_enabled = TRUE)
          
          # Update cache
          values$analytics_results <- analytics_results
          values$last_updated <- current_time
          values$cache_valid <- TRUE
          
          cat("✅ Analytics refreshed successfully\n")
          return(analytics_results)
        } else {
          # Fallback data structure
          return(create_fallback_analytics())
        }
        
      }, error = function(e) {
        cat("❌ Error refreshing analytics:", e$message, "\n")
        if (!is.null(values$analytics_results)) {
          return(values$analytics_results)  # Return cached data if available
        } else {
          return(create_fallback_analytics())
        }
      })
      
    } else {
      # Return cached data
      return(values$analytics_results)
    }
  })
  
  # ============================================================================
  # 3. ENHANCED VALUE BOX OUTPUTS
  # ============================================================================
  
  # Total Documents with trend
  output$exec_enhanced_total_docs <- shinydashboard::renderValueBox({
    cat("[RENDER] exec_enhanced_total_docs: START\n", file = stderr())
    analytics <- analytics_data()
    cat("[RENDER] exec_enhanced_total_docs: Got analytics\n", file = stderr())
    
    tryCatch({
      total_docs <- scalar_num(analytics$dashboard_summary$total_documents, 0)
      trend_data <- scalar_num(analytics$temporal_analysis$statistical_insights$year_over_year_growth, 0)
      
      trend_text <- if (!is.null(trend_data) && length(trend_data) > 0 && !is.na(trend_data)) {
        sprintf("%.1f%% YoY", trend_data)
      } else {
        "No trend data"
      }
      
      trend_direction <- if (!is.null(trend_data) && length(trend_data) > 0 && !is.na(trend_data)) {
        if (trend_data > 0) "increasing" else if (trend_data < 0) "decreasing" else "stable"
      } else {
        "stable"
      }
      
      # Safe color and icon selection
      trend_color <- if (isTRUE(trend_direction == "increasing")) "#28a745" else if (isTRUE(trend_direction == "decreasing")) "#dc3545" else "#6c757d"
      trend_icon <- if (isTRUE(trend_direction == "increasing")) "arrow-up" else if (isTRUE(trend_direction == "decreasing")) "arrow-down" else "minus"

      cat(sprintf("[RENDER] exec_enhanced_total_docs: Creating valueBox with total_docs=%s (class=%s, length=%d)\n",
                  total_docs, class(total_docs), length(total_docs)), file = stderr())

      safe_valueBox(
        value = value_box_scalar(total_docs, format_fn = function(x) format(x, big.mark = ",")),
        subtitle = HTML(paste0("Total Documents<br><small style='color: ", trend_color,
                              ";'><i class='fa fa-", trend_icon, "'></i> ", trend_text, "</small>")),
        icon = icon("file-text"),
        color = "blue"
      )
      
    }, error = function(e) {
      safe_valueBox(
        value = "Error",
        subtitle = "Total Documents",
        icon = icon("exclamation-triangle"),
        color = "red"
      )
    })
  })
  
  # States Coverage with performance indicator
  output$exec_enhanced_states_coverage <- shinydashboard::renderValueBox({
    cat("[EXEC DEBUG] exec_enhanced_states_coverage starting...\n", file = stderr())
    analytics <- analytics_data()
    cat("[EXEC DEBUG] exec_enhanced_states_coverage got analytics data\n", file = stderr())
    
    tryCatch({
      # Safe nested access
      states_covered <- tryCatch(analytics$dashboard_summary$states_covered, error = function(e) 0)
      if (is.null(states_covered) || length(states_covered) == 0 || !is.numeric(states_covered)) states_covered <- 0
      
      coverage_pct <- (states_covered / 27) * 100
      
      # Safe comparison with scalar value
      performance_color <- if (isTRUE(coverage_pct >= 90)) "green" 
                          else if (isTRUE(coverage_pct >= 70)) "yellow" 
                          else "red"
      
      safe_valueBox(
        value = value_box_scalar(paste0(scalar_num(states_covered, 0), "/27")),
        subtitle = HTML(paste0("States Covered<br><small style='color: #6c757d;'>",
                              sprintf("%.1f%% Coverage", scalar_num(coverage_pct, 0)), "</small>")),
        icon = icon("map"),
        color = performance_color
      )
      
    }, error = function(e) {
      safe_valueBox(
        value = "Error",
        subtitle = "States Coverage",
        icon = icon("exclamation-triangle"),
        color = "red"
      )
    })
  })
  
  # Monthly Activity with moving average
  output$exec_enhanced_monthly_activity <- renderValueBox({
    cat("[EXEC DEBUG] exec_enhanced_monthly_activity starting...\n", file = stderr())
    analytics <- analytics_data()
    cat("[EXEC DEBUG] exec_enhanced_monthly_activity got analytics data\n", file = stderr())
    
    tryCatch({
      # Safe nested access
      monthly_avg <- tryCatch(analytics$temporal_analysis$summary$recent_monthly_avg, error = function(e) NULL)
      
      if (!is.null(monthly_avg) && length(monthly_avg) > 0 && !is.na(monthly_avg) && is.numeric(monthly_avg)) {
        # Safe comparisons with isTRUE
        activity_level <- if (isTRUE(monthly_avg > 1000)) "High" 
                         else if (isTRUE(monthly_avg > 500)) "Medium" 
                         else "Low"
        
        color <- if (isTRUE(activity_level == "High")) "green"
                else if (isTRUE(activity_level == "Medium")) "yellow"
                else "orange"
        
        safe_valueBox(
          value = value_box_scalar(round(scalar_num(monthly_avg, 0)), format_fn = function(x) format(x, big.mark = ",")),
          subtitle = HTML(paste0("Monthly Average<br><small style='color: #6c757d;'>",
                                activity_level, " Activity</small>")),
          icon = icon("chart-line"),
          color = color
        )
      } else {
        safe_valueBox(
          value = "N/A",
          subtitle = "Monthly Average",
          icon = icon("chart-line"),
          color = "light-blue"
        )
      }
      
    }, error = function(e) {
      safe_valueBox(
        value = "Error",
        subtitle = "Monthly Activity",
        icon = icon("exclamation-triangle"),
        color = "red"
      )
    })
  })
  
  # Data Freshness with quality score
  output$exec_enhanced_data_freshness <- renderValueBox({
    cat("[EXEC DEBUG] exec_enhanced_data_freshness starting...\n", file = stderr())
    analytics <- analytics_data()
    cat("[EXEC DEBUG] exec_enhanced_data_freshness got analytics data\n", file = stderr())
    
    tryCatch({
      quality_score <- tryCatch(analytics$kpi_analysis$core_kpis$complete_metadata_pct, error = function(e) NULL)
      if (is.null(quality_score) || length(quality_score) == 0 || !is.numeric(quality_score)) quality_score <- NULL

      if (!is.null(quality_score) && length(quality_score) > 0 && !is.na(quality_score)) {
        quality_level <- if (quality_score >= 95) "Excellent"
                        else if (quality_score >= 90) "Good"
                        else if (quality_score >= 80) "Fair"
                        else "Poor"
        
        color <- if (quality_level == "Excellent") "green"
                else if (quality_level == "Good") "blue"
                else if (quality_level == "Fair") "yellow"
                else "red"
        
        safe_valueBox(
          value = value_box_scalar(sprintf("%.1f%%", scalar_num(quality_score, 0))),
          subtitle = HTML(paste0("Data Quality<br><small style='color: #6c757d;'>",
                                quality_level, "</small>")),
          icon = icon("check-circle"),
          color = color
        )
      } else {
        safe_valueBox(
          value = "N/A",
          subtitle = "Data Quality",
          icon = icon("check-circle"),
          color = "light-blue"
        )
      }
      
    }, error = function(e) {
      safe_valueBox(
        value = "Error",
        subtitle = "Data Quality",
        icon = icon("exclamation-triangle"),
        color = "red"
      )
    })
  })
  
  # ============================================================================
  # 4. STRATEGIC INSIGHTS OUTPUTS
  # ============================================================================
  
  # KPI Container
  output$exec_kpi_total_documents <- renderUI({
    analytics <- analytics_data()
    
    # Safe nested access
    total_docs <- tryCatch(analytics$dashboard_summary$total_documents, error = function(e) 0)
    if (is.null(total_docs) || !is.numeric(total_docs)) total_docs <- 0
    
    growth <- tryCatch(analytics$temporal_analysis$statistical_insights$year_over_year_growth, error = function(e) NULL)
    
    div(class = "insight-item",
      div(class = "insight-icon", icon("file-text")),
      div(class = "insight-text",
        span(class = "kpi-number", format(total_docs, big.mark = ",")),
        span("Total Documents"),
        if (!is.null(growth) && length(growth) > 0 && !is.na(growth) && is.numeric(growth)) {
          trend_class <- if (isTRUE(growth > 0)) "trend-indicator trend-up" else if (isTRUE(growth < 0)) "trend-indicator trend-down" else "trend-indicator trend-stable"
          span(class = trend_class, sprintf("%.1f%% YoY", growth))
        }
      )
    )
  })
  
  output$exec_kpi_monthly_growth <- renderUI({
    analytics <- analytics_data()
    
    # Safe nested access
    monthly_avg <- tryCatch(analytics$temporal_analysis$summary$recent_monthly_avg, error = function(e) 0)
    if (is.null(monthly_avg) || !is.numeric(monthly_avg)) monthly_avg <- 0
    
    div(class = "insight-item",
      div(class = "insight-icon", icon("chart-line")),
      div(class = "insight-text",
        span(class = "kpi-number", format(round(monthly_avg), big.mark = ",")),
        span("Monthly Average"),
        span(class = "performance-badge badge-good", "Active")
      )
    )
  })
  
  output$exec_kpi_data_quality <- renderUI({
    analytics <- analytics_data()
    
    # Safe nested access
    quality_score <- tryCatch(analytics$kpi_analysis$core_kpis$complete_metadata_pct, error = function(e) 0)
    if (is.null(quality_score) || !is.numeric(quality_score)) quality_score <- 0
    
    # Safe comparisons
    quality_level <- if (isTRUE(quality_score >= 95)) "EXCELLENT"
                    else if (isTRUE(quality_score >= 90)) "GOOD" 
                    else "NEEDS_IMPROVEMENT"
    
    div(class = "insight-item",
      div(class = "insight-icon", icon("check-circle")),
      div(class = "insight-text",
        span(class = "kpi-number", sprintf("%.1f%%", quality_score)),
        span("Data Quality"),
        span(class = paste0("performance-badge badge-", tolower(gsub("_", "-", quality_level))), quality_level)
      )
    )
  })
  
  # ============================================================================
  # 5. VISUALIZATION OUTPUTS
  # ============================================================================
  
  # Advanced Trends Chart
  output$exec_advanced_trends <- renderPlotly({
    # Suppress stderr during initial render to prevent "Expecting a single value" errors
    tryCatch({
      cat("[EXEC DEBUG] exec_advanced_trends starting...\n", file = stderr())

      # Safely get analytics data with error suppression
      analytics <- tryCatch({
        analytics_data()
      }, error = function(e) {
        cat("[EXEC DEBUG] Error in analytics_data():", conditionMessage(e), "\n", file = stderr())
        return(NULL)
      })

      if (is.null(analytics)) {
        cat("[EXEC GUARD] exec_advanced_trends analytics NULL – placeholder will be returned\n", file = stderr())
      } else {
        cat("[EXEC DEBUG] exec_advanced_trends got analytics data\n", file = stderr())
      }

      # Validate analytics structure before accessing nested data
      if (is.null(analytics) || !is.list(analytics) ||
          is.null(analytics$temporal_analysis) ||
          !is.list(analytics$temporal_analysis)) {
        cat("[EXEC GUARD] exec_advanced_trends temporal_analysis not ready – placeholder plot\n", file = stderr())
        return(plot_ly() %>%
          add_annotations(
            text = "Loading analytics data...",
            x = 0.5, y = 0.5,
            showarrow = FALSE,
            font = list(size = 14, color = "#6c757d")
          ) %>%
          layout(xaxis = list(showgrid = FALSE, showticklabels = FALSE, zeroline = FALSE),
                 yaxis = list(showgrid = FALSE, showticklabels = FALSE, zeroline = FALSE)))
      }

      trends_data <- analytics$temporal_analysis$monthly_trends
      if (is.null(trends_data)) {
        cat("[EXEC GUARD] exec_advanced_trends monthly_trends NULL – placeholder plot\n", file = stderr())
      }

      if (!is.null(trends_data) && is.data.frame(trends_data) && nrow(trends_data) > 0) {
        
        cat("[EXEC DEBUG] exec_advanced_trends rendering trends chart\n", file = stderr())
        
        # Create base plot
        p <- plot_ly(trends_data, x = ~year_month) %>%
          add_trace(
            y = ~document_count,
            type = 'scatter',
            mode = 'lines+markers',
            name = 'Document Count',
            line = list(color = '#3498db', width = 2),
            marker = list(size = 6)
          )
        
        # Add moving average if available
        if ("moving_avg_3m" %in% names(trends_data)) {
          p <- p %>%
            add_trace(
              y = ~moving_avg_3m,
              type = 'scatter',
              mode = 'lines',
              name = '3-Month Average',
              line = list(color = '#e74c3c', width = 2, dash = 'dash')
            )
        }
        
        # Add forecast if available and enabled (safe Boolean guard)
        forecast_data <- analytics$temporal_analysis$forecast_results$next_6_months
        if (!is.null(forecast_data) && is.data.frame(forecast_data) && nrow(forecast_data) > 0 && isTRUE(input$exec_show_forecast)) {
          p <- p %>%
            add_trace(
              data = forecast_data,
              x = ~month,
              y = ~predicted_count,
              type = 'scatter',
              mode = 'lines+markers',
              name = 'Forecast',
              line = list(color = '#f39c12', width = 2, dash = 'dot'),
              marker = list(size = 5)
            ) %>%
            add_ribbons(
              data = forecast_data,
              x = ~month,
              ymin = ~lower_bound,
              ymax = ~upper_bound,
              name = 'Confidence Interval',
              fillcolor = 'rgba(243, 156, 18, 0.2)',
              line = list(color = 'transparent')
            )
        }
        
        # Customize layout
        p %>%
          layout(
            title = list(text = "Legislative Activity Trends", font = list(size = 16)),
            xaxis = list(title = "Time Period", showgrid = TRUE),
            yaxis = list(title = "Document Count", showgrid = TRUE),
            hovermode = 'x unified',
            showlegend = TRUE,
            margin = list(t = 50, b = 50, l = 60, r = 20)
          )
        
      } else {
        cat("[EXEC GUARD] exec_advanced_trends insufficient data – placeholder plot\n", file = stderr())
        # Fallback empty plot
        plot_ly() %>%
          add_annotations(
            text = "No temporal data available",
            x = 0.5, y = 0.5,
            showarrow = FALSE,
            font = list(size = 14, color = "#6c757d")
          ) %>%
          layout(
            xaxis = list(visible = FALSE),
            yaxis = list(visible = FALSE)
          )
      }
      
    }, error = function(e) {
      # Silently handle "Expecting a single value" errors during startup
      if (!grepl("Expecting a single value", e$message, fixed = TRUE)) {
        cat("❌ Error in exec_advanced_trends:", e$message, "\n", file = stderr())
      } else {
        cat("[EXEC SUPPRESS] exec_advanced_trends captured extent error\n", file = stderr())
      }
      plot_ly() %>%
        add_annotations(
          text = "Loading chart...",
          x = 0.5, y = 0.5,
          showarrow = FALSE,
          font = list(size = 12, color = "#6c757d")
        ) %>%
        layout(
          xaxis = list(visible = FALSE),
          yaxis = list(visible = FALSE)
        )
    })
  })
  
  # Geographic Analysis Chart
  output$exec_geographic_analysis <- renderPlotly({
    # Suppress stderr during initial render to prevent "Expecting a single value" errors
    tryCatch({
      cat("[EXEC DEBUG] exec_geographic_analysis starting...\n", file = stderr())
      # Safely get analytics data with error suppression
      analytics <- tryCatch({
        analytics_data()
      }, error = function(e) {
        cat("[EXEC DEBUG] Error in analytics_data() for geo:", conditionMessage(e), "\n", file = stderr())
        return(NULL)
      })

      if (is.null(analytics)) {
        cat("[EXEC GUARD] exec_geographic_analysis analytics NULL – placeholder will be returned\n", file = stderr())
      }

      # Validate analytics structure before accessing nested data
      if (is.null(analytics) || !is.list(analytics) ||
          is.null(analytics$geographic_analysis) ||
          !is.list(analytics$geographic_analysis)) {
        cat("[EXEC GUARD] exec_geographic_analysis geographic_analysis not ready – placeholder plot\n", file = stderr())
        return(plot_ly() %>%
          add_annotations(
            text = "Loading geographic data...",
            x = 0.5, y = 0.5,
            showarrow = FALSE,
            font = list(size = 14, color = "#6c757d")
          ) %>%
          layout(xaxis = list(showgrid = FALSE, showticklabels = FALSE, zeroline = FALSE),
                 yaxis = list(showgrid = FALSE, showticklabels = FALSE, zeroline = FALSE)))
      }

      geo_data <- analytics$geographic_analysis$state_analysis
      if (is.null(geo_data)) {
        cat("[EXEC GUARD] exec_geographic_analysis state_analysis NULL – placeholder plot\n", file = stderr())
      }

      if (!is.null(geo_data) && is.data.frame(geo_data) && nrow(geo_data) > 0) {
        
        cat("[EXEC DEBUG] exec_geographic_analysis rendering geographic chart\n", file = stderr())
        
        # Select metric based on input
        metric_col <- switch(input$exec_geo_metric %||% "count",
          "count" = "document_count",
          "activity" = "recent_activity", 
          "transport" = "transport_intensity",
          "recent" = "recent_activity"
        )
        
        metric_title <- switch(input$exec_geo_metric %||% "count",
          "count" = "Document Count",
          "activity" = "Activity Level",
          "transport" = "Transport Focus %",
          "recent" = "Recent Activity"
        )
        
        # Create bar chart
        geo_data_top <- head(geo_data[order(geo_data[[metric_col]], decreasing = TRUE), ], 15)
        
        plot_ly(geo_data_top, 
                x = ~reorder(state_clean, get(metric_col)), 
                y = ~get(metric_col),
                type = 'bar',
                marker = list(
                  color = ~get(metric_col),
                  colorscale = 'Viridis',
                  showscale = TRUE
                ),
                hovertemplate = paste0(
                  "<b>%{x}</b><br>",
                  metric_title, ": %{y}<br>",
                  "Region: ", geo_data_top$region, "<br>",
                  "<extra></extra>"
                )) %>%
          layout(
            title = list(text = paste("Geographic Distribution by", metric_title), font = list(size = 14)),
            xaxis = list(title = "State", tickangle = -45),
            yaxis = list(title = metric_title),
            margin = list(t = 50, b = 100, l = 60, r = 20)
        )
        
      } else {
        cat("[EXEC GUARD] exec_geographic_analysis insufficient data – placeholder plot\n", file = stderr())
        # Fallback empty plot
        plot_ly() %>%
          add_annotations(
            text = "No geographic data available",
            x = 0.5, y = 0.5,
            showarrow = FALSE,
            font = list(size = 14, color = "#6c757d")
          ) %>%
          layout(
            xaxis = list(visible = FALSE),
            yaxis = list(visible = FALSE)
          )
      }
      
    }, error = function(e) {
      # Silently handle "Expecting a single value" errors during startup
      if (!grepl("Expecting a single value", e$message, fixed = TRUE)) {
        cat("❌ Error in exec_geographic_analysis:", e$message, "\n", file = stderr())
      } else {
        cat("[EXEC SUPPRESS] exec_geographic_analysis captured extent error\n", file = stderr())
      }
      plot_ly() %>%
        add_annotations(
          text = "Loading chart...",
          x = 0.5, y = 0.5,
          showarrow = FALSE,
          font = list(size = 12, color = "#6c757d")
        ) %>%
        layout(
          xaxis = list(visible = FALSE),
          yaxis = list(visible = FALSE)
        )
    })
  })
  
  # ============================================================================
  # 6. ACTION BUTTON HANDLERS
  # ============================================================================
  
  # Refresh All Data
  observeEvent(input$exec_refresh_all_data, {
    cat("🔄 Manual refresh triggered\n")
    values$cache_valid <- FALSE
    showNotification("Data refresh initiated...", type = "message", duration = 3)
  })
  
  # Export Executive Summary
  observeEvent(input$exec_export_executive_summary, {
    showNotification("Executive Summary export feature coming soon!", type = "message", duration = 5)
  })
  
  # Configure Alerts
  observeEvent(input$exec_configure_alerts, {
    showNotification("Alert configuration panel coming soon!", type = "message", duration = 5)
  })
  
  # ============================================================================
  # 7. UTILITY FUNCTIONS
  # ============================================================================
  
  # Create fallback analytics structure
  create_fallback_analytics <- function() {
    list(
      dashboard_summary = list(
        total_documents = 0,
        states_covered = 0,
        current_year_documents = 0,
        transport_relevance = 0,
        data_quality_score = 0,
        most_active_region = "N/A",
        trend_direction = "stable",
        alert_count = 0
      ),
      temporal_analysis = list(
        monthly_trends = data.frame(),
        summary = list(recent_monthly_avg = 0),
        statistical_insights = list(year_over_year_growth = NA),
        forecast_results = NULL
      ),
      geographic_analysis = list(
        state_analysis = data.frame(),
        regional_analysis = data.frame()
      ),
      kpi_analysis = list(
        core_kpis = list(complete_metadata_pct = 0),
        alert_system = list()
      ),
      metadata = list(
        generated_at = Sys.time(),
        analysis_failed = TRUE
      )
    )
  }
  
  # Return reactive values for external use
  return(list(
    analytics_data = analytics_data,
    refresh_data = function() { values$cache_valid <- FALSE }
  ))
}

cat("🎯 Executive Summary Server Functions ready for integration\n")

# ============================================================================
# WRAPPER FUNCTION FOR APP.R COMPATIBILITY
# ============================================================================
# app.R looks for executive_summary_server(), so we provide a wrapper
executive_summary_server <- function(input, output, session) {
  # Get document data function from global environment
  get_doc_data <- if (exists("get_documents")) get_documents else function(...) data.frame()
  init_executive_summary_server(input, output, session, get_doc_data)
}
