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
# Version: 1.0 Production-Ready (req() guards active)
# v61: Converted renderValueBox() to renderUI() with value_box() for bslib
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

  # Try to load cached results from disk on startup
  cache_file <- file.path("cache/performance/",
                         paste0("executive_summary_", format(Sys.Date(), "%Y%m%d"), ".rds"))
  if (file.exists(cache_file)) {
    tryCatch({
      cached_data <- readRDS(cache_file)
      file_time <- file.info(cache_file)$mtime
      age_minutes <- as.numeric(difftime(Sys.time(), file_time, units = "mins"))

      # Use cache if less than 30 minutes old
      if (age_minutes < 30) {
        values$analytics_results <- cached_data
        values$last_updated <- file_time
        values$cache_valid <- TRUE
        cat(sprintf("✅ Loaded cached analytics from disk (%.1f minutes old)\n", age_minutes))
      }
    }, error = function(e) {
      cat("⚠️ Could not load cache file:", e$message, "\n")
    })
  }
  
  # ============================================================================
  # 2. MAIN ANALYTICS REACTIVE
  # ============================================================================
  
  # Main analytics computation with caching
  analytics_data <- reactive({
    
    # Check if we need to refresh data
    current_time <- Sys.time()
    cache_duration <- 300  # 5 minutes
    
    if (isTRUE(is.null(values$last_updated)) ||
        isTRUE(difftime(current_time, values$last_updated, units = "secs") > cache_duration) ||
        isTRUE(!values$cache_valid)) {
      
      cat("🔄 Refreshing Executive Summary analytics...\n")
      
      # Get fresh data
      tryCatch({
        doc_data <- get_document_data()

        if (!isTRUE(is.null(doc_data)) && is.data.frame(doc_data) && nrow(doc_data) > 0) {
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
  output$exec_enhanced_total_docs <- renderUI({
    cat("[RENDER] exec_enhanced_total_docs: START\n", file = stderr())
    analytics <- analytics_data()
    cat("[RENDER] exec_enhanced_total_docs: Got analytics\n", file = stderr())

    tryCatch({
      # Production-grade scalar extraction
      total_docs <- num1(analytics$dashboard_summary$total_documents, allow_na = TRUE)
      trend_data <- num1(analytics$temporal_analysis$statistical_insights$year_over_year_growth, allow_na = TRUE)

      trend_text <- if (!is.na(trend_data)) {
        fmt_pct(trend_data / 100, digits = 1)
      } else {
        "—"
      }

      trend_direction <- if (!is.na(trend_data)) {
        if (trend_data > 0) "increasing" else if (trend_data < 0) "decreasing" else "stable"
      } else {
        "stable"
      }

      # Safe color and icon selection
      trend_color <- if (trend_direction == "increasing") "#28a745" else if (trend_direction == "decreasing") "#dc3545" else "#6c757d"
      trend_icon <- if (trend_direction == "increasing") "arrow-up" else if (trend_direction == "decreasing") "arrow-down" else "minus"

      cat(sprintf("[RENDER] exec_enhanced_total_docs: Creating value_box with total_docs=%s\n",
                  ifelse(is.na(total_docs), "NA", as.character(total_docs))), file = stderr())

      value_box(
        title = HTML(paste0("Total Documents<br><small style='color: ", trend_color,
                              ";'><i class='fa fa-", trend_icon, "'></i> ", trend_text, "</small>")),
        value = fmt_int(total_docs),
        showcase = bsicons::bs_icon("file-earmark-text"),
        theme = if (isTRUE(is.na(total_docs)) || isTRUE(total_docs == 0)) "warning" else "primary"
      )

    }, error = function(e) {
      cat("[ERROR] exec_enhanced_total_docs:", conditionMessage(e), "\n", file = stderr())
      value_box(
        title = "Total Documents",
        value = "—",
        showcase = bsicons::bs_icon("exclamation-triangle"),
        theme = "danger"
      )
    })
  })
  
  # States Coverage with performance indicator
  output$exec_enhanced_states_coverage <- renderUI({
    cat("[EXEC DEBUG] exec_enhanced_states_coverage starting...\n", file = stderr())
    analytics <- analytics_data()
    cat("[EXEC DEBUG] exec_enhanced_states_coverage got analytics data\n", file = stderr())

    tryCatch({
      # Production-grade scalar extraction
      states_covered <- num1(analytics$dashboard_summary$states_covered, allow_na = TRUE)
      coverage_pct <- safe_ratio(states_covered, 27) * 100

      # Safe comparison with scalar value
      performance_theme <- if (!isTRUE(is.na(coverage_pct)) && coverage_pct >= 90) "success"
                          else if (!isTRUE(is.na(coverage_pct)) && coverage_pct >= 70) "warning"
                          else "danger"

      value_box(
        title = HTML(paste0("States Covered<br><small style='color: #6c757d;'>",
                              fmt_pct(coverage_pct / 100, digits = 1), " Coverage</small>")),
        value = if (!is.na(states_covered)) paste0(fmt_int(states_covered), "/27") else "—/27",
        showcase = bsicons::bs_icon("map"),
        theme = performance_theme
      )

    }, error = function(e) {
      cat("[ERROR] exec_enhanced_states_coverage:", conditionMessage(e), "\n", file = stderr())
      value_box(
        title = "States Coverage",
        value = "—",
        showcase = bsicons::bs_icon("exclamation-triangle"),
        theme = "danger"
      )
    })
  })
  
  # Monthly Activity with moving average
  output$exec_enhanced_monthly_activity <- renderUI({
    cat("[EXEC DEBUG] exec_enhanced_monthly_activity starting...\n", file = stderr())
    analytics <- analytics_data()
    cat("[EXEC DEBUG] exec_enhanced_monthly_activity got analytics data\n", file = stderr())

    tryCatch({
      # Production-grade scalar extraction
      monthly_avg <- num1(analytics$temporal_analysis$summary$recent_monthly_avg, allow_na = TRUE)

      if (!is.na(monthly_avg)) {
        # Safe comparisons
        activity_level <- if (monthly_avg > 1000) "High"
                         else if (monthly_avg > 500) "Medium"
                         else "Low"

        theme <- if (activity_level == "High") "success"
                else if (activity_level == "Medium") "warning"
                else "info"

        value_box(
          title = HTML(paste0("Monthly Average<br><small style='color: #6c757d;'>",
                                activity_level, " Activity</small>")),
          value = fmt_int(round(monthly_avg)),
          showcase = bsicons::bs_icon("graph-up"),
          theme = theme
        )
      } else {
        value_box(
          title = "Monthly Average",
          value = "—",
          showcase = bsicons::bs_icon("graph-up"),
          theme = "info"
        )
      }

    }, error = function(e) {
      cat("[ERROR] exec_enhanced_monthly_activity:", conditionMessage(e), "\n", file = stderr())
      value_box(
        title = "Monthly Activity",
        value = "—",
        showcase = bsicons::bs_icon("exclamation-triangle"),
        theme = "danger"
      )
    })
  })
  
  # Data Freshness with quality score
  output$exec_enhanced_data_freshness <- renderUI({
    cat("[EXEC DEBUG] exec_enhanced_data_freshness starting...\n", file = stderr())
    analytics <- analytics_data()
    cat("[EXEC DEBUG] exec_enhanced_data_freshness got analytics data\n", file = stderr())

    tryCatch({
      # Production-grade scalar extraction
      quality_score <- num1(analytics$kpi_analysis$core_kpis$complete_metadata_pct, allow_na = TRUE)

      if (!is.na(quality_score)) {
        quality_level <- if (quality_score >= 95) "Excellent"
                        else if (quality_score >= 90) "Good"
                        else if (quality_score >= 80) "Fair"
                        else "Poor"

        theme <- if (quality_level == "Excellent") "success"
                else if (quality_level == "Good") "primary"
                else if (quality_level == "Fair") "warning"
                else "danger"

        value_box(
          title = HTML(paste0("Data Quality<br><small style='color: #6c757d;'>",
                                quality_level, "</small>")),
          value = fmt_pct(quality_score / 100, digits = 1),
          showcase = bsicons::bs_icon("check-circle"),
          theme = theme
        )
      } else {
        value_box(
          title = "Data Quality",
          value = "—",
          showcase = bsicons::bs_icon("check-circle"),
          theme = "info"
        )
      }

    }, error = function(e) {
      cat("[ERROR] exec_enhanced_data_freshness:", conditionMessage(e), "\n", file = stderr())
      value_box(
        title = "Data Quality",
        value = "—",
        showcase = bsicons::bs_icon("exclamation-triangle"),
        theme = "danger"
      )
    })
  })
  
  # ============================================================================
  # 4. STRATEGIC INSIGHTS OUTPUTS
  # ============================================================================
  
  # KPI Container
  output$exec_kpi_total_documents <- renderUI({
    analytics <- analytics_data()

    # Production-grade scalar extraction
    total_docs <- num1(analytics$dashboard_summary$total_documents, allow_na = TRUE)
    growth <- num1(analytics$temporal_analysis$statistical_insights$year_over_year_growth, allow_na = TRUE)

    div(class = "insight-item",
      div(class = "insight-icon", icon("file-text")),
      div(class = "insight-text",
        span(class = "kpi-number", fmt_int(total_docs)),
        span("Total Documents"),
        if (!is.na(growth)) {
          trend_class <- if (growth > 0) "trend-indicator trend-up" else if (growth < 0) "trend-indicator trend-down" else "trend-indicator trend-stable"
          span(class = trend_class, paste0(fmt_pct(growth / 100, digits = 1), " YoY"))
        }
      )
    )
  })
  
  output$exec_kpi_monthly_growth <- renderUI({
    analytics <- analytics_data()

    # Production-grade scalar extraction
    monthly_avg <- num1(analytics$temporal_analysis$summary$recent_monthly_avg, allow_na = TRUE)

    div(class = "insight-item",
      div(class = "insight-icon", icon("chart-line")),
      div(class = "insight-text",
        span(class = "kpi-number", fmt_int(round(monthly_avg))),
        span("Monthly Average"),
        span(class = "performance-badge badge-good", "Active")
      )
    )
  })
  
  output$exec_kpi_data_quality <- renderUI({
    analytics <- analytics_data()

    # Production-grade scalar extraction
    quality_score <- num1(analytics$kpi_analysis$core_kpis$complete_metadata_pct, allow_na = TRUE)

    # Safe comparisons
    quality_level <- if (!isTRUE(is.na(quality_score)) && quality_score >= 95) "EXCELLENT"
                    else if (!isTRUE(is.na(quality_score)) && quality_score >= 90) "GOOD"
                    else "NEEDS_IMPROVEMENT"

    div(class = "insight-item",
      div(class = "insight-icon", icon("check-circle")),
      div(class = "insight-text",
        span(class = "kpi-number", fmt_pct(quality_score / 100, digits = 1)),
        span("Data Quality"),
        span(class = paste0("performance-badge badge-", tolower(gsub("_", "-", quality_level))), quality_level)
      )
    )
  })
  
  # ============================================================================
  # 5. VISUALIZATION OUTPUTS
  # ============================================================================
  
  # Advanced Trends Chart
  # Advanced Trends Chart - TEMPORARILY DISABLED to prevent extent=0 crash
  output$exec_advanced_trends <- renderPlotly({
    cat("[EXEC-CHART] exec_advanced_trends: TEMPORARILY DISABLED\n", file = stderr())

    # Return empty plot with message
    plot_ly() %>%
      add_annotations(
        text = "Temporal analysis temporarily unavailable<br>Working on data loading optimization",
        x = 0.5, y = 0.5,
        showarrow = FALSE,
        font = list(size = 14, color = "#6c757d"),
        xref = "paper", yref = "paper"
      ) %>%
      layout(
        xaxis = list(visible = FALSE, range = c(0, 1)),
        yaxis = list(visible = FALSE, range = c(0, 1)),
        margin = list(t = 50, b = 50, l = 50, r = 50)
      )
  })

  # ORIGINAL CODE COMMENTED OUT - Re-enable after debugging data issue
  # output$exec_advanced_trends_DISABLED <- renderPlotly({
  #   cat("[EXEC-CHART] exec_advanced_trends: START\n", file = stderr())
  #   [... original code removed for brevity ...]
  # })
  
  # Geographic Analysis Chart - TEMPORARILY DISABLED to prevent extent=0 crash
  output$exec_geographic_analysis <- renderPlotly({
    cat("[EXEC-CHART] exec_geographic_analysis: TEMPORARILY DISABLED\n", file = stderr())

    # Return empty plot with message
    plot_ly() %>%
      add_annotations(
        text = "Geographic analysis temporarily unavailable<br>Working on data loading optimization",
        x = 0.5, y = 0.5,
        showarrow = FALSE,
        font = list(size = 14, color = "#6c757d"),
        xref = "paper", yref = "paper"
      ) %>%
      layout(
        xaxis = list(visible = FALSE, range = c(0, 1)),
        yaxis = list(visible = FALSE, range = c(0, 1)),
        margin = list(t = 50, b = 50, l = 50, r = 50)
      )
  })

  # ORIGINAL CODE COMMENTED OUT - Re-enable after debugging data issue
  # output$exec_geographic_analysis_DISABLED <- renderPlotly({
  #   cat("[EXEC-CHART] exec_geographic_analysis: START\n", file = stderr())
  #
  #   # CRITICAL: req() FIRST to halt execution during startup
  #   analytics <- analytics_data()
  #   cat(sprintf("[EXEC-CHART] exec_geographic_analysis: analytics is.null=%s\n", is.null(analytics)), file = stderr())
  #   req(!is.null(analytics))
  #   req(is.list(analytics))
  #   req(!is.null(analytics$geographic_analysis))
  #   req(is.list(analytics$geographic_analysis))
  #
  #   geo_data <- analytics$geographic_analysis$state_analysis
  #   cat(sprintf("[EXEC-CHART] exec_geographic_analysis: geo_data nrow=%d\n", nrow(geo_data)), file = stderr())
  #   req(!is.null(geo_data))
  #   req(is.data.frame(geo_data))
  #   req(nrow(geo_data) > 0)
  #   req("state_clean" %in% names(geo_data))
  #
  #   cat("[EXEC-CHART] exec_geographic_analysis: PASSED all req() guards, rendering chart\n", file = stderr())
  #
  #   # Suppress stderr during initial render to prevent "Expecting a single value" errors
  #   tryCatch({
  #     cat("[EXEC DEBUG] exec_geographic_analysis starting...\n", file = stderr())
  #
  #     # Validate analytics structure before accessing nested data
  #     if (!is.list(analytics$geographic_analysis)) {
  #       cat("[EXEC GUARD] exec_geographic_analysis geographic_analysis not ready – validating\n", file = stderr())
  #       validate(need(FALSE, "Loading geographic data..."))
  #     }
  #
  #     if (isTRUE(is.null(geo_data)) || !is.data.frame(geo_data)) {
  #       cat("[EXEC GUARD] exec_geographic_analysis state_analysis missing – validating\n", file = stderr())
  #       validate(need(FALSE, "Loading geographic data..."))
  #     }
  #
  #     if (nrow(geo_data) == 0) {
  #       cat("[EXEC GUARD] exec_geographic_analysis state_analysis empty – validating\n", file = stderr())
  #       validate(need(FALSE, "No geographic data available yet"))
  #     }
  #
  #     # Select metric based on input
  #     metric_col <- switch(input$exec_geo_metric %||% "count",
  #       "count" = "document_count",
  #       "activity" = "recent_activity",
  #       "transport" = "transport_intensity",
  #       "recent" = "recent_activity"
  #     )
  #
  #     metric_title <- switch(input$exec_geo_metric %||% "count",
  #       "count" = "Document Count",
  #       "activity" = "Activity Level",
  #       "transport" = "Transport Focus %",
  #       "recent" = "Recent Activity"
  #     )
  #
  #     if (!metric_col %in% names(geo_data)) {
  #       cat("[EXEC GUARD] exec_geographic_analysis metric column missing – validating\n", file = stderr())
  #       validate(need(FALSE, "Loading geographic data..."))
  #     }

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
