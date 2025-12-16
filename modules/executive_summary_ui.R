# ============================================================================
# ENHANCED EXECUTIVE SUMMARY UI COMPONENTS (NAVBARPAGE COMPATIBLE)
# ============================================================================
#
# Advanced UI components for the Executive Summary tab with integrated analytics
# Provides government-relevant insights and actionable intelligence
#
# CONVERTED FROM shinydashboard TO navbarPage LAYOUT
# - Replaced tabItem() with tagList()
# - Replaced box() with wellPanel() for navbarPage compatibility
#
# Features:
# - Real-time KPI dashboards with trend indicators
# - Interactive temporal and geographic visualizations
# - Smart alerts and anomaly detection displays
# - Actionable insights and recommendations panels
# - Performance-optimized rendering with caching
#
# Author: Data Science Consultant
# Date: 2025-08-29
# Version: 2.0 Production-Ready (navbarPage compatible)
# ============================================================================

# Load required UI libraries
required_ui_packages <- c("shiny", "shinydashboard", "shinydashboardPlus",
                         "shinyWidgets", "DT", "plotly", "leaflet", "htmltools",
                         "shinycssloaders", "shinyjs")

# Never install packages at runtime in production
if (identical(tolower(Sys.getenv("K_SERVICE")), "production") || nzchar(Sys.getenv("K_SERVICE"))) {
  # Load only if available, skip if not
  for (pkg in required_ui_packages) {
    if (requireNamespace(pkg, quietly = TRUE)) {
      suppressPackageStartupMessages(library(pkg, character.only = TRUE))
    } else {
      message("[exec_summary_ui] Package '", pkg, "' not available, skipping")
    }
  }
} else if (isTRUE(as.logical(Sys.getenv("ALLOW_RUNTIME_INSTALL", "FALSE")))) {
  # Only install if explicitly allowed via env var
  for (pkg in required_ui_packages) {
    if (!requireNamespace(pkg, quietly = TRUE)) {
      message("[startup] Runtime install skipped; all packages must be baked into the image")
    }
    suppressPackageStartupMessages(library(pkg, character.only = TRUE))
  }
} else {
  # Default: load only available packages
  for (pkg in required_ui_packages) {
    if (requireNamespace(pkg, quietly = TRUE)) {
      suppressPackageStartupMessages(library(pkg, character.only = TRUE))
    }
  }
}

# Safe spinner wrapper (shinycssloaders optional)
with_spinner_safe <- function(ui_element, type = 4, color = NULL, ...) {
  if (requireNamespace("shinycssloaders", quietly = TRUE)) {
    shinycssloaders::withSpinner(ui_element, type = type, color = color, ...)
  } else {
    ui_element
  }
}

cat("✅ Enhanced Executive Summary UI components loaded (navbarPage compatible)\n")

# ============================================================================
# HELPER: BOX REPLACEMENT FOR NAVBARPAGE
# ============================================================================

#' Create a styled panel that replaces shinydashboard box() for navbarPage
#' @param ... Panel content
#' @param title Panel title (HTML or text)
#' @param status Color status (primary, info, success, warning, danger)
#' @param solidHeader Whether to use solid header (ignored, always solid)
#' @param width Panel width (NULL for auto)
#' @param background Background color (ignored in favor of status)
#' @param footer Footer content
panel_box <- function(..., title = NULL, status = "primary", solidHeader = TRUE,
                     width = NULL, background = NULL, footer = NULL) {

  # Map status to Bootstrap colors
  status_colors <- list(
    "primary" = "#007bff",
    "info" = "#17a2b8",
    "success" = "#28a745",
    "warning" = "#ffc107",
    "danger" = "#dc3545"
  )

  border_color <- status_colors[[status]] %||% "#007bff"

  # Build panel style
  panel_style <- sprintf(
    "border-left: 4px solid %s; margin-bottom: 20px; background: white; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);",
    border_color
  )

  # Build header if title provided
  header_html <- NULL
  if (!is.null(title)) {
    header_html <- div(
      style = sprintf("background: %s; color: white; padding: 10px 15px; font-weight: bold; border-radius: 4px 4px 0 0; margin: -15px -15px 15px -15px;", border_color),
      title
    )
  }

  # Build footer if provided
  footer_html <- NULL
  if (!is.null(footer)) {
    footer_html <- div(
      style = "margin-top: 15px; padding-top: 10px; border-top: 1px solid #e9ecef; color: #6c757d; font-size: 12px;",
      footer
    )
  }

  # Return wellPanel with custom styling
  wellPanel(
    style = panel_style,
    header_html,
    ...,
    footer_html
  )
}

# ============================================================================
# 1. ENHANCED VALUE BOX COMPONENTS
# ============================================================================

#' Create enhanced value boxes with trend indicators
create_enhanced_value_box <- function(value, subtitle, icon_name, color, trend = NULL,
                                     trend_direction = NULL, additional_info = NULL) {

  # Create trend indicator HTML
  trend_html <- ""
  if (!isTRUE(is.null(trend)) && !is.null(trend_direction)) {
    trend_color <- dplyr::case_when(
      trend_direction == "increasing" ~ "#28a745",  # Green
      trend_direction == "decreasing" ~ "#dc3545",  # Red
      TRUE ~ "#6c757d"  # Gray for stable
    )

    trend_icon <- dplyr::case_when(
      trend_direction == "increasing" ~ "arrow-up",
      trend_direction == "decreasing" ~ "arrow-down",
      TRUE ~ "minus"
    )

    trend_html <- sprintf(
      '<div style="font-size: 12px; color: %s; margin-top: 5px;">
        <i class="fa fa-%s"></i> %s
       </div>',
      trend_color, trend_icon, trend
    )
  }

  # Additional info HTML
  info_html <- ""
  if (!is.null(additional_info)) {
    info_html <- sprintf(
      '<div style="font-size: 11px; color: #6c757d; margin-top: 3px;">%s</div>',
      additional_info
    )
  }

  # Combine all HTML content
  subtitle_with_extras <- HTML(paste0(subtitle, trend_html, info_html))

  safe_valueBox(
    value = value,
    subtitle = subtitle_with_extras,
    icon = icon(icon_name),
    color = color,
    width = NULL
  )
}

# ============================================================================
# 2. STRATEGIC INSIGHTS PANELS
# ============================================================================

#' Create strategic insights panel UI (navbarPage compatible)
#' @param ns Namespace function for module outputs
create_strategic_insights_ui <- function(ns = NULL) {
  # Create fallback namespace if not provided
  if (is.null(ns)) ns <- function(x) x

  fluidRow(
    panel_box(
      title = HTML("<i class='fa fa-lightbulb'></i> Strategic Intelligence Dashboard"),
      status = "primary",
      width = 12,

      fluidRow(
        # Key Performance Indicators
        column(4,
          div(class = "insight-card enhanced-card",
            h4(HTML("<i class='fa fa-chart-line'></i> Performance Metrics"),
               style = "color: #2c3e50; margin-top: 0;"),

            # KPI Values with trends
            div(id = "kpi-container",
              uiOutput(ns("exec_kpi_total_documents")),
              uiOutput(ns("exec_kpi_monthly_growth")),
              uiOutput(ns("exec_kpi_data_quality")),
              style = "margin-bottom: 15px;"
            ),

            # Mini chart placeholder
            div(
              plotlyOutput(ns("exec_mini_trend_chart"), height = "120px"),
              style = "margin-top: 10px;"
            ),

            style = "padding: 15px; background: white; border-radius: 8px; margin: 5px;
                     border-left: 4px solid #3498db;"
          )
        ),

        # Geographic Intelligence
        column(4,
          div(class = "insight-card enhanced-card",
            h4(HTML("<i class='fa fa-map-marked-alt'></i> Geographic Intelligence"),
               style = "color: #2c3e50; margin-top: 0;"),

            div(id = "geo-intelligence",
              uiOutput(ns("exec_geo_coverage")),
              uiOutput(ns("exec_geo_hotspots")),
              uiOutput(ns("exec_geo_gaps")),
              style = "margin-bottom: 15px;"
            ),

            # Mini map or chart
            div(
              plotlyOutput(ns("exec_mini_geo_chart"), height = "120px"),
              style = "margin-top: 10px;"
            ),

            style = "padding: 15px; background: white; border-radius: 8px; margin: 5px;
                     border-left: 4px solid #28a745;"
          )
        ),

        # Smart Alerts & Anomalies
        column(4,
          div(class = "insight-card enhanced-card",
            h4(HTML("<i class='fa fa-exclamation-triangle'></i> Smart Alerts"),
               style = "color: #2c3e50; margin-top: 0;"),

            div(id = "smart-alerts",
              uiOutput(ns("exec_alert_system")),
              uiOutput(ns("exec_anomaly_detection")),
              style = "margin-bottom: 15px;"
            ),

            # Alert status indicator
            div(
              uiOutput(ns("exec_alert_status_indicator")),
              style = "margin-top: 10px;"
            ),

            style = "padding: 15px; background: white; border-radius: 8px; margin: 5px;
                     border-left: 4px solid #f39c12;"
          )
        )
      )
    )
  )
}

# ============================================================================
# 3. ADVANCED VISUALIZATION PANELS
# ============================================================================

#' Create advanced visualization panels UI (navbarPage compatible)
#' @param ns Namespace function for module outputs
create_advanced_visualizations_ui <- function(ns = NULL) {
  # Create fallback namespace if not provided
  if (is.null(ns)) ns <- function(x) x

  fluidRow(
    # Temporal Trends with Forecasting
    column(8,
      panel_box(
        title = HTML("<i class='fa fa-chart-area'></i> Legislative Activity Trends & Forecasting"),
        status = "info",
        width = NULL,

        # Trend controls
        fluidRow(
          column(3,
            selectInput(ns("exec_trend_period"), "Time Period:",
              choices = list(
                "Last 12 Months" = "12m",
                "Last 24 Months" = "24m",
                "Last 3 Years" = "3y",
                "All Available" = "all"
              ),
              selected = "24m"
            )
          ),
          column(3,
            selectInput(ns("exec_trend_grouping"), "Group By:",
              choices = list(
                "Monthly" = "month",
                "Quarterly" = "quarter",
                "Yearly" = "year"
              ),
              selected = "month"
            )
          ),
          column(3,
            checkboxInput(ns("exec_show_forecast"), "Show Forecast", value = TRUE)
          ),
          column(3,
            checkboxInput(ns("exec_show_anomalies"), "Highlight Anomalies", value = TRUE)
          )
        ),

        # Main trend visualization
        with_spinner_safe(
          plotlyOutput(ns("exec_advanced_trends"), height = "400px"),
          type = 4, color = "#3498db"
        ),

        # Trend insights summary
        div(
          uiOutput(ns("exec_trend_insights")),
          style = "margin-top: 15px; padding: 10px; background: #f8f9fa; border-radius: 5px;"
        ),

        footer = HTML("<i class='fa fa-info-circle'></i> Interactive chart with forecasting capabilities and anomaly detection")
      )
    ),

    # Enhanced Geographic Analysis
    column(4,
      panel_box(
        title = HTML("<i class='fa fa-globe-americas'></i> Geographic Distribution"),
        status = "success",
        width = NULL,

        # Geographic controls
        fluidRow(
          column(12,
            selectInput(ns("exec_geo_metric"), "Display Metric:",
              choices = list(
                "Document Count" = "count",
                "Activity Level" = "activity",
                "Transport Focus" = "transport",
                "Recent Activity" = "recent"
              ),
              selected = "count"
            )
          )
        ),

        # Geographic visualization
        with_spinner_safe(
          plotlyOutput(ns("exec_geographic_analysis"), height = "300px"),
          type = 4, color = "#28a745"
        ),

        # Top regions summary
        div(
          h5("Top Performing Regions", style = "margin-bottom: 10px;"),
          uiOutput(ns("exec_top_regions")),
          style = "margin-top: 15px;"
        ),

        footer = "State-level legislative activity patterns"
      )
    )
  )
}

# ============================================================================
# 4. ACTIONABLE INSIGHTS AND RECOMMENDATIONS
# ============================================================================

#' Create actionable insights panel UI (navbarPage compatible)
#' @param ns Namespace function for module outputs
create_actionable_insights_ui <- function(ns = NULL) {
  # Create fallback namespace if not provided
  if (is.null(ns)) ns <- function(x) x

  fluidRow(
    # Priority Actions
    column(6,
      panel_box(
        title = HTML("<i class='fa fa-tasks'></i> Priority Actions"),
        status = "warning",
        width = NULL,

        # Priority action items
        div(id = "priority-actions",
          uiOutput(ns("exec_priority_actions_list")),
          style = "min-height: 200px;"
        ),

        # Action buttons
        div(
          actionButton(ns("exec_export_actions"),
            HTML("<i class='fa fa-download'></i> Export Action Plan"),
            class = "btn-warning btn-sm",
            style = "margin-right: 10px;"
          ),
          actionButton(ns("exec_schedule_review"),
            HTML("<i class='fa fa-calendar'></i> Schedule Review"),
            class = "btn-outline-warning btn-sm"
          ),
          style = "margin-top: 15px;"
        ),

        footer = "High-impact actions based on data analysis"
      )
    ),

    # Strategic Recommendations
    column(6,
      panel_box(
        title = HTML("<i class='fa fa-compass'></i> Strategic Recommendations"),
        status = "danger",
        width = NULL,

        # Strategic recommendation items
        div(id = "strategic-recommendations",
          uiOutput(ns("exec_strategic_recommendations_list")),
          style = "min-height: 200px;"
        ),

        # Recommendation actions
        div(
          actionButton(ns("exec_create_report"),
            HTML("<i class='fa fa-file-alt'></i> Generate Report"),
            class = "btn-danger btn-sm",
            style = "margin-right: 10px;"
          ),
          actionButton(ns("exec_share_insights"),
            HTML("<i class='fa fa-share-alt'></i> Share Insights"),
            class = "btn-outline-danger btn-sm"
          ),
          style = "margin-top: 15px;"
        ),

        footer = "Long-term strategic guidance for policy makers"
      )
    )
  )
}

# ============================================================================
# 5. ADVANCED DATA TABLES AND DETAILED VIEWS
# ============================================================================

#' Create advanced data tables UI (navbarPage compatible)
#' @param ns Namespace function for module outputs
create_advanced_tables_ui <- function(ns = NULL) {
  # Create fallback namespace if not provided
  if (is.null(ns)) ns <- function(x) x

  fluidRow(
    # Document Pattern Analysis
    column(6,
      panel_box(
        title = HTML("<i class='fa fa-search'></i> Document Pattern Analysis"),
        status = "primary",
        width = NULL,

        # Pattern analysis controls
        fluidRow(
          column(6,
            selectInput(ns("exec_pattern_view"), "Analysis View:",
              choices = list(
                "Document Types" = "types",
                "Transport Modes" = "transport",
                "Regulatory Agencies" = "agencies",
                "Keyword Frequency" = "keywords"
              ),
              selected = "types"
            )
          ),
          column(6,
            numericInput(ns("exec_pattern_limit"), "Show Top:",
              value = 10, min = 5, max = 50, step = 5
            )
          )
        ),

        # Pattern analysis table
        with_spinner_safe(
          DT::dataTableOutput(ns("exec_pattern_analysis_table")),
          type = 4, color = "#007bff"
        ),

        footer = "Detailed breakdown of document patterns and classifications"
      )
    ),

    # Recent High-Impact Documents
    column(6,
      panel_box(
        title = HTML("<i class='fa fa-star'></i> High-Impact Recent Documents"),
        status = "info",
        width = NULL,

        # Document filter controls
        fluidRow(
          column(6,
            selectInput(ns("exec_impact_category"), "Category:",
              choices = list(
                "All Categories" = "all",
                "Legislation" = "legislation",
                "Jurisprudence" = "jurisprudence",
                "Transport Focus" = "transport"
              ),
              selected = "all"
            )
          ),
          column(6,
            selectInput(ns("exec_impact_period"), "Time Period:",
              choices = list(
                "Last 30 Days" = "30d",
                "Last 90 Days" = "90d",
                "Last 6 Months" = "6m",
                "Current Year" = "year"
              ),
              selected = "90d"
            )
          )
        ),

        # High-impact documents table
        with_spinner_safe(
          DT::dataTableOutput(ns("exec_high_impact_documents")),
          type = 4, color = "#17a2b8"
        ),

        footer = "Recently published documents with significant policy implications"
      )
    )
  )
}

# ============================================================================
# 6. SYSTEM HEALTH AND MONITORING PANEL
# ============================================================================

#' Create system health monitoring UI (navbarPage compatible)
#' @param ns Namespace function for module outputs
create_system_health_ui <- function(ns = NULL) {
  # Create fallback namespace if not provided
  if (is.null(ns)) ns <- function(x) x

  fluidRow(
    # Data Quality Dashboard
    column(8,
      panel_box(
        title = HTML("<i class='fa fa-heartbeat'></i> System Health & Data Quality"),
        status = "primary",
        width = NULL,

        # Quality metrics row
        fluidRow(
          column(3,
            div(class = "quality-metric-card",
              div(class = "metric-value", uiOutput(ns("exec_completeness_metric"))),
              div(class = "metric-label", "Completeness"),
              div(class = "metric-progress", uiOutput(ns("exec_completeness_progress")))
            )
          ),
          column(3,
            div(class = "quality-metric-card",
              div(class = "metric-value", uiOutput(ns("exec_recency_metric"))),
              div(class = "metric-label", "Data Recency"),
              div(class = "metric-progress", uiOutput(ns("exec_recency_progress")))
            )
          ),
          column(3,
            div(class = "quality-metric-card",
              div(class = "metric-value", uiOutput(ns("exec_accuracy_metric"))),
              div(class = "metric-label", "Accuracy"),
              div(class = "metric-progress", uiOutput(ns("exec_accuracy_progress")))
            )
          ),
          column(3,
            div(class = "quality-metric-card",
              div(class = "metric-value", uiOutput(ns("exec_coverage_metric"))),
              div(class = "metric-label", "Coverage"),
              div(class = "metric-progress", uiOutput(ns("exec_coverage_progress")))
            )
          )
        ),

        # Detailed system status
        div(
          h5("Detailed System Status", style = "margin-top: 20px; margin-bottom: 15px;"),
          verbatimTextOutput(ns("exec_detailed_system_status")),
          style = "margin-top: 20px; background: #f8f9fa; padding: 15px; border-radius: 5px;"
        ),

        footer = "Real-time monitoring of data quality and system performance"
      )
    ),

    # Quick Actions & Tools
    column(4,
      panel_box(
        title = HTML("<i class='fa fa-tools'></i> Quick Actions & Tools"),
        status = "info",
        width = NULL,

        # Action buttons
        div(
          actionButton(ns("exec_refresh_all_data"),
            HTML("<i class='fa fa-sync-alt'></i> Refresh All Data"),
            class = "btn-primary btn-block",
            style = "margin-bottom: 10px;"
          ),
          actionButton(ns("exec_export_executive_summary"),
            HTML("<i class='fa fa-file-pdf'></i> Export Executive Summary"),
            class = "btn-success btn-block",
            style = "margin-bottom: 10px;"
          ),
          actionButton(ns("exec_schedule_automated_report"),
            HTML("<i class='fa fa-calendar-alt'></i> Schedule Automated Report"),
            class = "btn-info btn-block",
            style = "margin-bottom: 10px;"
          ),
          actionButton(ns("exec_configure_alerts"),
            HTML("<i class='fa fa-bell'></i> Configure Alerts"),
            class = "btn-warning btn-block",
            style = "margin-bottom: 10px;"
          )
        ),

        hr(),

        # System health indicators
        div(
          h5("System Health Indicators", style = "margin: 15px 0 5px 0;"),
          uiOutput(ns("exec_system_health_indicators")),
          style = "margin-top: 15px;"
        ),

        # Performance metrics
        div(
          h6("Performance Metrics", style = "margin: 15px 0 5px 0; color: #6c757d;"),
          uiOutput(ns("exec_performance_metrics")),
          style = "font-size: 12px;"
        ),

        footer = "System controls and health monitoring"
      )
    )
  )
}

# ============================================================================
# 7. ENHANCED CSS STYLING
# ============================================================================

#' Generate enhanced CSS for Executive Summary
generate_executive_summary_css <- function() {
  tags$head(
    tags$style(HTML("
      /* Enhanced Executive Summary Styles */
      .enhanced-card {
        box-shadow: 0 4px 8px rgba(0,0,0,0.12);
        transition: all 0.3s ease;
        border: 1px solid rgba(0,0,0,0.05);
      }

      .enhanced-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 16px rgba(0,0,0,0.18);
      }

      .quality-metric-card {
        text-align: center;
        padding: 15px;
        background: white;
        border-radius: 8px;
        border: 1px solid #e9ecef;
        margin-bottom: 15px;
        transition: all 0.3s ease;
      }

      .quality-metric-card:hover {
        border-color: #007bff;
        box-shadow: 0 2px 4px rgba(0,123,255,0.1);
      }

      .metric-value {
        font-size: 24px;
        font-weight: bold;
        color: #2c3e50;
        margin-bottom: 5px;
      }

      .metric-label {
        font-size: 12px;
        color: #6c757d;
        margin-bottom: 10px;
      }

      .metric-progress {
        height: 6px;
        border-radius: 3px;
        overflow: hidden;
      }

      .alert-card {
        border-left: 4px solid;
        padding: 10px 15px;
        margin-bottom: 10px;
        border-radius: 0 4px 4px 0;
        background: white;
      }

      .alert-warning {
        border-left-color: #ffc107;
        background-color: #fff3cd;
      }

      .alert-info {
        border-left-color: #17a2b8;
        background-color: #d1ecf1;
      }

      .alert-success {
        border-left-color: #28a745;
        background-color: #d4edda;
      }

      .insight-item {
        padding: 10px 0;
        border-bottom: 1px solid #e9ecef;
        display: flex;
        align-items: center;
      }

      .insight-item:last-child {
        border-bottom: none;
      }

      .insight-icon {
        margin-right: 10px;
        width: 20px;
        text-align: center;
      }

      .insight-text {
        flex: 1;
        font-size: 14px;
      }

      .trend-indicator {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 12px;
        font-size: 11px;
        font-weight: bold;
        margin-left: 8px;
      }

      .trend-up {
        background-color: #28a745;
        color: white;
      }

      .trend-down {
        background-color: #dc3545;
        color: white;
      }

      .trend-stable {
        background-color: #6c757d;
        color: white;
      }

      .kpi-number {
        font-size: 28px;
        font-weight: bold;
        color: #2c3e50;
        display: block;
      }

      .kpi-change {
        font-size: 12px;
        margin-top: 5px;
      }

      .performance-badge {
        display: inline-block;
        padding: 3px 8px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: bold;
        text-transform: uppercase;
      }

      .badge-excellent {
        background-color: #28a745;
        color: white;
      }

      .badge-good {
        background-color: #17a2b8;
        color: white;
      }

      .badge-needs-improvement {
        background-color: #ffc107;
        color: #212529;
      }
    "))
  )
}

# ============================================================================
# 8. MAIN EXECUTIVE SUMMARY TAB UI FUNCTION (NAVBARPAGE COMPATIBLE)
# ============================================================================

#' Create the complete enhanced Executive Summary tab UI
#'
#' CONVERTED VERSION: navbarPage compatible (no tabItem wrapper)
#' @param id Module namespace ID
#' @return Shiny UI content (tagList) for use in tabPanel
create_enhanced_executive_summary_ui <- function(id = "executive_summary_module") {
  ns <- NS(id)

  # Return tagList instead of tabItem for navbarPage compatibility
  tagList(
    # Add enhanced CSS
    generate_executive_summary_css(),

    # Strategic Insights Panel (now with namespace)
    create_strategic_insights_ui(ns),

    # Enhanced KPI Value Boxes Row (using uiOutput for bslib::value_box compatibility)
    fluidRow(
      column(3, uiOutput(ns("exec_enhanced_total_docs"))),
      column(3, uiOutput(ns("exec_enhanced_states_coverage"))),
      column(3, uiOutput(ns("exec_enhanced_monthly_activity"))),
      column(3, uiOutput(ns("exec_enhanced_data_freshness")))
    ),

    # Secondary KPIs Row (using uiOutput for bslib::value_box compatibility)
    fluidRow(
      column(2, uiOutput(ns("exec_federal_dominance"))),
      column(2, uiOutput(ns("exec_transport_relevance"))),
      column(2, uiOutput(ns("exec_recent_growth"))),
      column(2, uiOutput(ns("exec_quality_score"))),
      column(2, uiOutput(ns("exec_forecast_trend"))),
      column(2, uiOutput(ns("exec_alert_count")))
    ),

    # Advanced Visualizations (now with namespace)
    create_advanced_visualizations_ui(ns),

    # Actionable Insights (now with namespace)
    create_actionable_insights_ui(ns),

    # Detailed Analysis Tables (now with namespace)
    create_advanced_tables_ui(ns),

    # System Health and Monitoring (now with namespace)
    create_system_health_ui(ns)
  )
}

cat("🎯 Enhanced Executive Summary UI components ready for integration (navbarPage compatible)\n")

# ============================================================================
# WRAPPER FUNCTION FOR APP.R COMPATIBILITY
# ============================================================================
# app.R looks for executive_summary_ui(), so we provide a wrapper
# Now with namespace parameter for proper Shiny module integration
executive_summary_ui <- function(id) {
  create_enhanced_executive_summary_ui(id)
}
