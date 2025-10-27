# ============================================================================
# ENHANCED EXECUTIVE SUMMARY UI COMPONENTS
# ============================================================================
# 
# Advanced UI components for the Executive Summary tab with integrated analytics
# Provides government-relevant insights and actionable intelligence
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
# Version: 1.0 Production-Ready
# ============================================================================

# Load required UI libraries
required_ui_packages <- c("shiny", "shinydashboard", "shinydashboardPlus", 
                         "shinyWidgets", "DT", "plotly", "leaflet", "htmltools", 
                         "shinycssloaders", "shinyjs")

# Never install packages at runtime in production
if (identical(tolower(Sys.getenv("RAILWAY_ENVIRONMENT")), "production")) {
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

cat("✅ Enhanced Executive Summary UI components loaded\n")

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

#' Create strategic insights panel UI
create_strategic_insights_ui <- function() {
  fluidRow(
    box(
      title = HTML("<i class='fa fa-lightbulb'></i> Strategic Intelligence Dashboard"), 
      status = "primary", 
      solidHeader = TRUE, 
      width = 12,
      background = "light-blue",
      
      fluidRow(
        # Key Performance Indicators
        column(4,
          div(class = "insight-card enhanced-card",
            h4(HTML("<i class='fa fa-chart-line'></i> Performance Metrics"), 
               style = "color: #2c3e50; margin-top: 0;"),
            
            # KPI Values with trends
            div(id = "kpi-container",
              uiOutput("exec_kpi_total_documents"),
              uiOutput("exec_kpi_monthly_growth"),
              uiOutput("exec_kpi_data_quality"),
              style = "margin-bottom: 15px;"
            ),
            
            # Mini chart placeholder
            div(
              plotlyOutput("exec_mini_trend_chart", height = "120px"),
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
              uiOutput("exec_geo_coverage"),
              uiOutput("exec_geo_hotspots"),
              uiOutput("exec_geo_gaps"),
              style = "margin-bottom: 15px;"
            ),
            
            # Mini map or chart
            div(
              plotlyOutput("exec_mini_geo_chart", height = "120px"),
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
              uiOutput("exec_alert_system"),
              uiOutput("exec_anomaly_detection"),
              style = "margin-bottom: 15px;"
            ),
            
            # Alert status indicator
            div(
              uiOutput("exec_alert_status_indicator"),
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

#' Create advanced visualization panels UI
create_advanced_visualizations_ui <- function() {
  fluidRow(
    # Temporal Trends with Forecasting
    column(8,
      box(
        title = HTML("<i class='fa fa-chart-area'></i> Legislative Activity Trends & Forecasting"), 
        status = "info", 
        solidHeader = TRUE, 
        width = NULL,
        
        # Trend controls
        fluidRow(
          column(3,
            selectInput("exec_trend_period", "Time Period:",
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
            selectInput("exec_trend_grouping", "Group By:",
              choices = list(
                "Monthly" = "month",
                "Quarterly" = "quarter",
                "Yearly" = "year"
              ),
              selected = "month"
            )
          ),
          column(3,
            checkboxInput("exec_show_forecast", "Show Forecast", value = TRUE)
          ),
          column(3,
            checkboxInput("exec_show_anomalies", "Highlight Anomalies", value = TRUE)
          )
        ),
        
        # Main trend visualization
        with_spinner_safe(
          plotlyOutput("exec_advanced_trends", height = "400px"),
          type = 4, color = "#3498db"
        ),
        
        # Trend insights summary
        div(
          uiOutput("exec_trend_insights"),
          style = "margin-top: 15px; padding: 10px; background: #f8f9fa; border-radius: 5px;"
        ),
        
        footer = HTML("<i class='fa fa-info-circle'></i> Interactive chart with forecasting capabilities and anomaly detection")
      )
    ),
    
    # Enhanced Geographic Analysis
    column(4,
      box(
        title = HTML("<i class='fa fa-globe-americas'></i> Geographic Distribution"), 
        status = "success", 
        solidHeader = TRUE, 
        width = NULL,
        
        # Geographic controls
        fluidRow(
          column(12,
            selectInput("exec_geo_metric", "Display Metric:",
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
          plotlyOutput("exec_geographic_analysis", height = "300px"),
          type = 4, color = "#28a745"
        ),
        
        # Top regions summary
        div(
          h5("Top Performing Regions", style = "margin-bottom: 10px;"),
          uiOutput("exec_top_regions"),
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

#' Create actionable insights panel UI
create_actionable_insights_ui <- function() {
  fluidRow(
    # Priority Actions
    column(6,
      box(
        title = HTML("<i class='fa fa-tasks'></i> Priority Actions"), 
        status = "warning", 
        solidHeader = TRUE, 
        width = NULL,
        
        # Priority action items
        div(id = "priority-actions",
          uiOutput("exec_priority_actions_list"),
          style = "min-height: 200px;"
        ),
        
        # Action buttons
        div(
          actionButton("exec_export_actions", 
            HTML("<i class='fa fa-download'></i> Export Action Plan"), 
            class = "btn-warning btn-sm",
            style = "margin-right: 10px;"
          ),
          actionButton("exec_schedule_review", 
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
      box(
        title = HTML("<i class='fa fa-compass'></i> Strategic Recommendations"), 
        status = "danger", 
        solidHeader = TRUE, 
        width = NULL,
        
        # Strategic recommendation items
        div(id = "strategic-recommendations",
          uiOutput("exec_strategic_recommendations_list"),
          style = "min-height: 200px;"
        ),
        
        # Recommendation actions
        div(
          actionButton("exec_create_report", 
            HTML("<i class='fa fa-file-alt'></i> Generate Report"), 
            class = "btn-danger btn-sm",
            style = "margin-right: 10px;"
          ),
          actionButton("exec_share_insights", 
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

#' Create advanced data tables UI
create_advanced_tables_ui <- function() {
  fluidRow(
    # Document Pattern Analysis
    column(6,
      box(
        title = HTML("<i class='fa fa-search'></i> Document Pattern Analysis"), 
        status = "primary", 
        solidHeader = TRUE, 
        width = NULL,
        
        # Pattern analysis controls
        fluidRow(
          column(6,
            selectInput("exec_pattern_view", "Analysis View:",
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
            numericInput("exec_pattern_limit", "Show Top:", 
              value = 10, min = 5, max = 50, step = 5
            )
          )
        ),
        
        # Pattern analysis table
        with_spinner_safe(
          DT::dataTableOutput("exec_pattern_analysis_table"),
          type = 4, color = "#007bff"
        ),
        
        footer = "Detailed breakdown of document patterns and classifications"
      )
    ),
    
    # Recent High-Impact Documents
    column(6,
      box(
        title = HTML("<i class='fa fa-star'></i> High-Impact Recent Documents"), 
        status = "info", 
        solidHeader = TRUE, 
        width = NULL,
        
        # Document filter controls
        fluidRow(
          column(6,
            selectInput("exec_impact_category", "Category:",
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
            selectInput("exec_impact_period", "Time Period:",
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
          DT::dataTableOutput("exec_high_impact_documents"),
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

#' Create system health monitoring UI
create_system_health_ui <- function() {
  fluidRow(
    # Data Quality Dashboard
    column(8,
      box(
        title = HTML("<i class='fa fa-heartbeat'></i> System Health & Data Quality"), 
        status = "primary", 
        solidHeader = TRUE, 
        width = NULL,
        
        # Quality metrics row
        fluidRow(
          column(3,
            div(class = "quality-metric-card",
              div(class = "metric-value", uiOutput("exec_completeness_metric")),
              div(class = "metric-label", "Completeness"),
              div(class = "metric-progress", uiOutput("exec_completeness_progress"))
            )
          ),
          column(3,
            div(class = "quality-metric-card",
              div(class = "metric-value", uiOutput("exec_recency_metric")),
              div(class = "metric-label", "Data Recency"),
              div(class = "metric-progress", uiOutput("exec_recency_progress"))
            )
          ),
          column(3,
            div(class = "quality-metric-card",
              div(class = "metric-value", uiOutput("exec_accuracy_metric")),
              div(class = "metric-label", "Accuracy"),
              div(class = "metric-progress", uiOutput("exec_accuracy_progress"))
            )
          ),
          column(3,
            div(class = "quality-metric-card",
              div(class = "metric-value", uiOutput("exec_coverage_metric")),
              div(class = "metric-label", "Coverage"),
              div(class = "metric-progress", uiOutput("exec_coverage_progress"))
            )
          )
        ),
        
        # Detailed system status
        div(
          h5("Detailed System Status", style = "margin-top: 20px; margin-bottom: 15px;"),
          verbatimTextOutput("exec_detailed_system_status"),
          style = "margin-top: 20px; background: #f8f9fa; padding: 15px; border-radius: 5px;"
        ),
        
        footer = "Real-time monitoring of data quality and system performance"
      )
    ),
    
    # Quick Actions & Tools
    column(4,
      box(
        title = HTML("<i class='fa fa-tools'></i> Quick Actions & Tools"), 
        status = "info", 
        solidHeader = TRUE, 
        width = NULL,
        
        # Action buttons
        div(
          actionButton("exec_refresh_all_data", 
            HTML("<i class='fa fa-sync-alt'></i> Refresh All Data"), 
            class = "btn-primary btn-block", 
            style = "margin-bottom: 10px;"
          ),
          actionButton("exec_export_executive_summary", 
            HTML("<i class='fa fa-file-pdf'></i> Export Executive Summary"), 
            class = "btn-success btn-block", 
            style = "margin-bottom: 10px;"
          ),
          actionButton("exec_schedule_automated_report", 
            HTML("<i class='fa fa-calendar-alt'></i> Schedule Automated Report"), 
            class = "btn-info btn-block", 
            style = "margin-bottom: 10px;"
          ),
          actionButton("exec_configure_alerts", 
            HTML("<i class='fa fa-bell'></i> Configure Alerts"), 
            class = "btn-warning btn-block", 
            style = "margin-bottom: 10px;"
          )
        ),
        
        hr(),
        
        # System health indicators
        div(
          h5("System Health Indicators", style = "margin: 15px 0 5px 0;"),
          uiOutput("exec_system_health_indicators"),
          style = "margin-top: 15px;"
        ),
        
        # Performance metrics
        div(
          h6("Performance Metrics", style = "margin: 15px 0 5px 0; color: #6c757d;"),
          uiOutput("exec_performance_metrics"),
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
      
      .executive-summary .box-header {
        border-bottom: 2px solid #e9ecef;
      }
      
      .executive-summary .content-wrapper {
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
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
# 8. MAIN EXECUTIVE SUMMARY TAB UI FUNCTION
# ============================================================================

#' Create the complete enhanced Executive Summary tab UI
#' 
#' @return Shiny tab item with all Executive Summary components
create_enhanced_executive_summary_ui <- function() {
  
  tabItem(tabName = "executive",
    
    # Add enhanced CSS
    generate_executive_summary_css(),
    
    # Strategic Insights Panel
    create_strategic_insights_ui(),
    
    # Enhanced KPI Value Boxes Row
    fluidRow(
      valueBoxOutput("exec_enhanced_total_docs", width = 3),
      valueBoxOutput("exec_enhanced_states_coverage", width = 3),
      valueBoxOutput("exec_enhanced_monthly_activity", width = 3),
      valueBoxOutput("exec_enhanced_data_freshness", width = 3)
    ),
    
    # Secondary KPIs Row
    fluidRow(
      valueBoxOutput("exec_federal_dominance", width = 2),
      valueBoxOutput("exec_transport_relevance", width = 2), 
      valueBoxOutput("exec_recent_growth", width = 2),
      valueBoxOutput("exec_quality_score", width = 2),
      valueBoxOutput("exec_forecast_trend", width = 2),
      valueBoxOutput("exec_alert_count", width = 2)
    ),
    
    # Advanced Visualizations
    create_advanced_visualizations_ui(),
    
    # Actionable Insights
    create_actionable_insights_ui(),
    
    # Detailed Analysis Tables
    create_advanced_tables_ui(),
    
    # System Health and Monitoring
    create_system_health_ui()
  )
}

cat("🎯 Enhanced Executive Summary UI components ready for integration\n")

# ============================================================================
# WRAPPER FUNCTION FOR APP.R COMPATIBILITY
# ============================================================================
# app.R looks for executive_summary_ui(), so we provide a wrapper
executive_summary_ui <- create_enhanced_executive_summary_ui
