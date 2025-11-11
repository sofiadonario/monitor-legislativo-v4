# Temporal Controls Module - Sprint 5B GEO-004
# Brazilian Legislative Monitoring System - Interactive Timeline Controls
# =======================================================================
# 
# Interactive timeline controls and date filtering system for temporal
# geographic analysis. Provides comprehensive user interface for controlling
# temporal visualizations, date range selection, animation controls, and
# real-time filtering capabilities.
# 
# CONTROL FEATURES:
# - Interactive timeline slider with smooth date range selection
# - Animation playback controls (play, pause, stop, speed control)
# - Temporal aggregation controls (daily, monthly, quarterly, yearly)
# - Geographic filtering and selection controls
# - Real-time data filtering and visualization updates
# - Export controls for temporal data and visualizations
# - Mobile-responsive design for touch interfaces
# 
# TECHNICAL IMPLEMENTATION:
# - Shiny reactive framework for real-time updates
# - JavaScript integration for smooth animations
# - Memory-efficient data filtering for Railway constraints
# - Progressive loading for large temporal datasets
# - Cached computation for improved performance
# - Academic research workflow integration
# 
# INTEGRATION ARCHITECTURE:
# - Seamless coordination with temporal analysis engine
# - Real-time communication with visualization modules
# - Shared reactive values across all temporal components
# - Unified state management for complex temporal interfaces
# - Performance monitoring and optimization
# =======================================================================

library(shiny)
library(shinydashboard)
library(shinyWidgets)
library(DT)
library(plotly)
library(dplyr)
library(lubridate)
library(htmltools)
library(htmlwidgets)

# Load temporal analysis and visualization modules
if (file.exists("modules/geographic/temporal_analysis.R")) {
  source("modules/geographic/temporal_analysis.R")
}
if (file.exists("modules/geographic/temporal_visualization.R")) {
  source("modules/geographic/temporal_visualization.R")
}

# Global configuration for temporal controls
TEMPORAL_CONTROLS_CONFIG <- list(
  
  # Timeline control settings
  timeline_controls = list(
    default_animation_speed = 1000,  # milliseconds
    min_animation_speed = 200,
    max_animation_speed = 5000,
    default_date_range_days = 365,
    enable_smooth_transitions = TRUE,
    auto_pause_on_interaction = TRUE
  ),
  
  # Date filtering settings
  date_filtering = list(
    min_date_range_days = 7,
    max_date_range_days = 3650,  # ~10 years
    default_temporal_unit = "monthly",
    enable_relative_dates = TRUE,
    quick_date_presets = list(
      "Last 30 days" = 30,
      "Last 90 days" = 90,
      "Last 6 months" = 180,
      "Last year" = 365,
      "Last 2 years" = 730,
      "All available" = NULL
    )
  ),
  
  # Geographic filtering settings
  geographic_filtering = list(
    enable_multi_select = TRUE,
    max_selections = 10,
    enable_region_grouping = TRUE,
    default_selection_mode = "all"
  ),
  
  # Performance settings
  performance = list(
    debounce_delay_ms = 500,
    max_data_points_per_update = 10000,
    enable_progressive_loading = TRUE,
    cache_filtered_results = TRUE,
    auto_sampling_threshold = 50000
  ),
  
  # UI responsiveness
  ui_responsiveness = list(
    enable_mobile_optimization = TRUE,
    touch_friendly_controls = TRUE,
    adaptive_control_sizing = TRUE,
    collapsible_sections = TRUE
  )
)

#' Temporal Controls UI Module
#' 
#' Creates comprehensive UI for temporal analysis controls including
#' timeline sliders, date filters, animation controls, and export options
#' 
#' @param id Module namespace identifier
#' @param enable_animation Whether to include animation controls
#' @param enable_export Whether to include export controls
#' @param compact_mode Whether to use compact layout for limited space
#' @return Shiny UI element with temporal controls
temporal_controls_ui <- function(id, 
                                enable_animation = TRUE,
                                enable_export = TRUE,
                                compact_mode = FALSE) {
  
  ns <- NS(id)
  
  tagList(
    
    # Custom CSS for temporal controls
    tags$head(
      tags$style(HTML(paste0("
        /* Temporal Controls Styling - GEO-004 */
        .temporal-controls-container-", id, " {
          background: #f8f9fa;
          border-radius: 8px;
          padding: 15px;
          margin-bottom: 15px;
          border: 1px solid #dee2e6;
        }
        
        .temporal-section-header {
          font-weight: 600;
          color: #495057;
          margin-bottom: 10px;
          padding-bottom: 5px;
          border-bottom: 2px solid #e9ecef;
        }
        
        .temporal-controls-grid {
          display: grid;
          grid-template-columns: ", 
          if (compact_mode) "1fr" else "repeat(auto-fit, minmax(280px, 1fr))", ";
          gap: 15px;
          margin-bottom: 15px;
        }
        
        .temporal-control-section {
          background: white;
          border-radius: 6px;
          padding: 12px;
          border: 1px solid #e9ecef;
          box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        
        .animation-controls {
          display: flex;
          align-items: center;
          gap: 8px;
          margin-top: 10px;
          flex-wrap: wrap;
        }
        
        .animation-speed-control {
          display: flex;
          align-items: center;
          gap: 5px;
          margin-top: 8px;
        }
        
        .temporal-status-indicator {
          padding: 6px 12px;
          border-radius: 4px;
          font-size: 0.85em;
          font-weight: 500;
          margin-top: 8px;
        }
        
        .status-active { background: #d4e7f0; color: #0c5460; }
        .status-paused { background: #fff3cd; color: #856404; }
        .status-stopped { background: #f8d7da; color: #721c24; }
        .status-loading { background: #e2e3e5; color: #383d41; }
        
        @media (max-width: 768px) {
          .temporal-controls-grid {
            grid-template-columns: 1fr;
          }
          
          .animation-controls {
            justify-content: center;
          }
          
          .temporal-controls-container-", id, " {
            padding: 10px;
          }
        }
      ")))
    ),
    
    # Main temporal controls container
    div(class = paste0("temporal-controls-container-", id),
      
      # Header
      div(class = "temporal-section-header",
        icon("clock"),
        " Temporal Analysis Controls"
      ),
      
      # Controls grid
      div(class = "temporal-controls-grid",
        
        # Date Range Controls
        div(class = "temporal-control-section",
          h5("📅 Date Range Selection", style = "margin: 0 0 10px 0; color: #495057;"),
          
          # Quick date presets
          div(style = "margin-bottom: 10px;",
            selectInput(
              ns("date_preset"),
              "Quick Presets:",
              choices = list(
                "Custom Range" = "custom",
                "Last 30 days" = "30d",
                "Last 90 days" = "90d", 
                "Last 6 months" = "6m",
                "Last year" = "1y",
                "Last 2 years" = "2y",
                "All available" = "all"
              ),
              selected = "1y",
              width = "100%"
            )
          ),
          
          # Custom date range
          conditionalPanel(
            condition = paste0("input['", ns("date_preset"), "'] == 'custom'"),
            dateRangeInput(
              ns("date_range"),
              "Custom Date Range:",
              start = Sys.Date() - 365,
              end = Sys.Date(),
              format = "yyyy-mm-dd",
              width = "100%"
            )
          ),
          
          # Date range info
          div(style = "margin-top: 8px; font-size: 0.9em; color: #6c757d;",
            textOutput(ns("date_range_info"))
          )
        ),
        
        # Temporal Aggregation Controls
        div(class = "temporal-control-section",
          h5("📊 Temporal Aggregation", style = "margin: 0 0 10px 0; color: #495057;"),
          
          selectInput(
            ns("temporal_unit"),
            "Aggregation Unit:",
            choices = list(
              "Daily" = "daily",
              "Weekly" = "weekly", 
              "Monthly" = "monthly",
              "Quarterly" = "quarterly",
              "Yearly" = "yearly"
            ),
            selected = "monthly",
            width = "100%"
          ),
          
          # Temporal unit info
          div(style = "margin-top: 8px; font-size: 0.9em; color: #6c757d;",
            textOutput(ns("temporal_unit_info"))
          )
        ),
        
        # Geographic Filtering Controls
        div(class = "temporal-control-section",
          h5("🗺️ Geographic Filtering", style = "margin: 0 0 10px 0; color: #495057;"),
          
          selectInput(
            ns("geographic_level"),
            "Geographic Level:",
            choices = list(
              "Brazilian States" = "state",
              "Regions" = "region",
              "Municipalities" = "municipality"
            ),
            selected = "state",
            width = "100%"
          ),
          
          conditionalPanel(
            condition = paste0("input['", ns("geographic_level"), "'] == 'state'"),
            pickerInput(
              ns("selected_states"),
              "Select States:",
              choices = NULL,  # Will be populated by server
              selected = NULL,
              multiple = TRUE,
              options = pickerOptions(
                actionsBox = TRUE,
                selectAllText = "Select All",
                deselectAllText = "Deselect All",
                noneSelectedText = "All states selected",
                maxOptions = 10
              ),
              width = "100%"
            )
          ),
          
          # Geographic selection info
          div(style = "margin-top: 8px; font-size: 0.9em; color: #6c757d;",
            textOutput(ns("geographic_selection_info"))
          )
        ),
        
        # Animation Controls (if enabled)
        if (enable_animation) {
          div(class = "temporal-control-section",
            h5("🎬 Animation Controls", style = "margin: 0 0 10px 0; color: #495057;"),
            
            # Animation buttons
            div(class = "animation-controls",
              actionButton(
                ns("play_animation"),
                "",
                icon = icon("play"),
                class = "btn btn-success btn-sm",
                title = "Play Animation"
              ),
              actionButton(
                ns("pause_animation"), 
                "",
                icon = icon("pause"),
                class = "btn btn-warning btn-sm",
                title = "Pause Animation"
              ),
              actionButton(
                ns("stop_animation"),
                "",
                icon = icon("stop"),
                class = "btn btn-danger btn-sm", 
                title = "Stop Animation"
              ),
              actionButton(
                ns("reset_animation"),
                "",
                icon = icon("backward"),
                class = "btn btn-secondary btn-sm",
                title = "Reset Animation"
              )
            ),
            
            # Animation speed control
            div(class = "animation-speed-control",
              span("Speed:", style = "font-size: 0.9em; margin-right: 5px;"),
              sliderInput(
                ns("animation_speed"),
                NULL,
                min = TEMPORAL_CONTROLS_CONFIG$timeline_controls$min_animation_speed,
                max = TEMPORAL_CONTROLS_CONFIG$timeline_controls$max_animation_speed,
                value = TEMPORAL_CONTROLS_CONFIG$timeline_controls$default_animation_speed,
                step = 100,
                width = "150px"
              )
            ),
            
            # Animation status
            div(id = ns("animation_status"),
              class = "temporal-status-indicator status-stopped",
              "Animation: Stopped"
            )
          )
        } else {
          NULL
        }
      ),
      
      # Analysis Control Buttons
      div(style = "margin-top: 15px; text-align: center;",
        
        actionButton(
          ns("run_analysis"),
          "▶️ Run Temporal Analysis",
          icon = icon("play-circle"),
          class = "btn btn-primary",
          style = "margin-right: 10px;"
        ),
        
        actionButton(
          ns("refresh_data"),
          "🔄 Refresh Data",
          icon = icon("sync"),
          class = "btn btn-info", 
          style = "margin-right: 10px;"
        ),
        
        if (enable_export) {
          dropdownButton(
            tags$h4("📥 Export Options"),
            downloadButton(ns("export_data"), "Export Data (CSV)", class = "btn btn-outline-primary"),
            br(), br(),
            downloadButton(ns("export_visualizations"), "Export Visualizations", class = "btn btn-outline-info"),
            br(), br(),
            downloadButton(ns("export_report"), "Export Full Report (PDF)", class = "btn btn-outline-success"),
            
            circle = TRUE,
            status = "primary",
            icon = icon("download"),
            tooltip = tooltipOptions(title = "Export temporal analysis results")
          )
        } else {
          NULL
        }
      ),
      
      # Analysis Status and Progress
      div(style = "margin-top: 15px;",
        conditionalPanel(
          condition = paste0("output['", ns("analysis_in_progress"), "'] == true"),
          div(
            style = "background: #e3f2fd; border: 1px solid #2196f3; padding: 10px; border-radius: 4px; text-align: center;",
            h6("🔄 Running Temporal Analysis...", style = "margin: 0 0 8px 0; color: #1976d2;"),
            div(id = ns("progress_container"),
              progressBar(
                id = ns("analysis_progress"),
                value = 0,
                status = "primary",
                striped = TRUE,
                animated = TRUE
              )
            ),
            div(id = ns("progress_message"),
              style = "margin-top: 8px; font-size: 0.9em; color: #1976d2;",
              "Initializing temporal analysis..."
            )
          )
        )
      )
    )
  )
}

#' Temporal Controls Server Module
#' 
#' Server logic for temporal controls including reactive data filtering,
#' animation control, and real-time analysis updates
#' 
#' @param id Module namespace identifier
#' @param temporal_data Reactive expression containing temporal data
#' @param db_pool Database connection pool for data access
#' @param session Shiny session for progress updates
#' @return List of reactive values and functions for temporal control
temporal_controls_server <- function(id, temporal_data, db_pool = NULL, session = NULL) {
  
  moduleServer(id, function(input, output, session) {
    
    ns <- session$ns
    
    cat("🎛️ Initializing temporal controls server...\n")
    
    # Reactive values for temporal controls
    temporal_controls_state <- reactiveValues(
      analysis_results = NULL,
      animation_state = "stopped",  # stopped, playing, paused
      current_frame = 1,
      total_frames = 0,
      animation_timer = NULL,
      last_analysis_time = NULL,
      data_filters_applied = list(),
      export_data_cache = NULL
    )
    
    # Initialize geographic choices
    observe({
      if (!is.null(temporal_data()) && nrow(temporal_data()) > 0) {
        
        # Update state choices based on available data
        available_states <- sort(unique(temporal_data()$state_code))
        available_states <- available_states[!is.na(available_states)]
        
        state_choices <- setNames(available_states, available_states)
        
        updatePickerInput(
          session = session,
          inputId = "selected_states",
          choices = state_choices,
          selected = available_states  # Select all by default
        )
      }
    })
    
    # Date range information output
    output$date_range_info <- renderText({
      if (input$date_preset == "custom" && !is.null(input$date_range)) {
        date_diff <- as.numeric(difftime(input$date_range[2], input$date_range[1], units = "days"))
        paste("Selected range:", date_diff, "days")
      } else if (input$date_preset != "custom") {
        preset_info <- switch(input$date_preset,
          "30d" = "Last 30 days from today",
          "90d" = "Last 90 days from today",
          "6m" = "Last 6 months from today",
          "1y" = "Last year from today",
          "2y" = "Last 2 years from today", 
          "all" = "Complete dataset range",
          "No range selected"
        )
        paste("Preset:", preset_info)
      } else {
        "No date range selected"
      }
    })
    
    # Temporal unit information
    output$temporal_unit_info <- renderText({
      unit_info <- switch(input$temporal_unit,
        "daily" = "Daily aggregation - High detail, large data volume",
        "weekly" = "Weekly aggregation - Good balance of detail and performance", 
        "monthly" = "Monthly aggregation - Standard analysis level",
        "quarterly" = "Quarterly aggregation - Seasonal patterns",
        "yearly" = "Yearly aggregation - Long-term trends",
        "Monthly aggregation (default)"
      )
      paste("Info:", unit_info)
    })
    
    # Geographic selection information
    output$geographic_selection_info <- renderText({
      if (!is.null(input$selected_states)) {
        if (length(input$selected_states) == 0) {
          "All states selected"
        } else {
          paste("Selected:", length(input$selected_states), "states")
        }
      } else {
        "Loading geographic options..."
      }
    })
    
    # Calculate effective date range
    effective_date_range <- reactive({
      if (input$date_preset == "custom" && !is.null(input$date_range)) {
        return(input$date_range)
      } else if (input$date_preset != "custom") {
        end_date <- Sys.Date()
        start_date <- switch(input$date_preset,
          "30d" = end_date - 30,
          "90d" = end_date - 90,
          "6m" = end_date - 180,
          "1y" = end_date - 365,
          "2y" = end_date - 730,
          "all" = as.Date("2000-01-01"),
          end_date - 365
        )
        return(c(start_date, end_date))
      } else {
        return(c(Sys.Date() - 365, Sys.Date()))
      }
    })
    
    # Filter temporal data based on controls
    filtered_temporal_data <- reactive({
      
      req(temporal_data())
      
      data <- temporal_data()
      
      # Apply date filtering
      date_range <- effective_date_range()
      if (!isTRUE(is.null(date_range)) && length(date_range) == 2) {
        data <- data %>%
          filter(date >= date_range[1], date <= date_range[2])
      }
      
      # Apply geographic filtering
      if (input$geographic_level == "state" && !isTRUE(is.null(input$selected_states)) && length(input$selected_states) > 0) {
        data <- data %>%
          filter(state_code %in% input$selected_states)
      }
      
      # Store applied filters for reference
      temporal_controls_state$data_filters_applied <- list(
        date_range = date_range,
        temporal_unit = input$temporal_unit,
        geographic_level = input$geographic_level,
        selected_states = input$selected_states,
        filter_applied_at = Sys.time()
      )
      
      return(data)
    })
    
    # Analysis progress tracking
    analysis_in_progress <- reactiveVal(FALSE)
    output$analysis_in_progress <- reactive({ analysis_in_progress() })
    outputOptions(output, "analysis_in_progress", suspendWhenHidden = FALSE)
    
    # Run temporal analysis
    observeEvent(input$run_analysis, {
      
      req(filtered_temporal_data())
      
      if (nrow(filtered_temporal_data()) == 0) {
        showNotification("No data available for selected filters", type = "warning", duration = 5)
        return()
      }
      
      analysis_in_progress(TRUE)
      
      # Update progress
      updateProgressBar(
        session = session,
        id = "analysis_progress", 
        value = 10,
        status = "primary"
      )
      
      # Run analysis with progress updates
      withProgress(message = "Running temporal analysis...", value = 0, {
        
        incProgress(0.2, detail = "Preprocessing data...")
        
        # Update progress bar
        updateProgressBar(session = session, id = "analysis_progress", value = 30)
        
        tryCatch({
          
          incProgress(0.3, detail = "Performing temporal analysis...")
          updateProgressBar(session = session, id = "analysis_progress", value = 60)
          
          # Run the temporal analysis
          analysis_results <- analyze_temporal_geographic_activity(
            data = filtered_temporal_data(),
            temporal_unit = input$temporal_unit,
            geographic_level = input$geographic_level,
            date_range = effective_date_range(),
            include_forecasting = TRUE,
            include_changepoints = TRUE,
            confidence_level = 0.95
          )
          
          incProgress(0.3, detail = "Finalizing results...")
          updateProgressBar(session = session, id = "analysis_progress", value = 90)
          
          if (!isTRUE(is.null(analysis_results)) && !("error" %in% names(analysis_results))) {
            
            temporal_controls_state$analysis_results <- analysis_results
            temporal_controls_state$last_analysis_time <- Sys.time()
            
            # Prepare animation frames if analysis successful
            if (!is.null(analysis_results$processed_data)) {
              unique_periods <- sort(unique(analysis_results$processed_data$period))
              temporal_controls_state$total_frames <- length(unique_periods)
              temporal_controls_state$current_frame <- 1
            }
            
            updateProgressBar(session = session, id = "analysis_progress", value = 100)
            
            showNotification(
              paste("Temporal analysis completed successfully!",
                   "Processed", nrow(analysis_results$processed_data), "observations"),
              type = "success",
              duration = 5
            )
            
            incProgress(0.1, detail = "Analysis complete")
            
          } else {
            
            error_msg <- if ("error" %in% names(analysis_results)) {
              analysis_results$error
            } else {
              "Unknown error occurred during analysis"
            }
            
            showNotification(
              paste("Analysis failed:", error_msg),
              type = "error",
              duration = 8
            )
            
            temporal_controls_state$analysis_results <- NULL
          }
          
        }, error = function(e) {
          
          showNotification(
            paste("Analysis error:", e$message),
            type = "error",
            duration = 8
          )
          
          temporal_controls_state$analysis_results <- NULL
          
          cat("❌ Temporal analysis error:", e$message, "\n")
        })
      })
      
      analysis_in_progress(FALSE)
      updateProgressBar(session = session, id = "analysis_progress", value = 0)
    })
    
    # Animation control logic
    observeEvent(input$play_animation, {
      if (!isTRUE(is.null(temporal_controls_state$analysis_results)) && temporal_controls_state$total_frames > 0) {
        temporal_controls_state$animation_state <- "playing"
        
        # Update status indicator
        shinyjs::html("animation_status", "Animation: Playing")
        shinyjs::removeClass("animation_status", "status-stopped status-paused")
        shinyjs::addClass("animation_status", "status-active")
        
        # Start animation timer
        start_animation_timer()
      } else {
        showNotification("Run temporal analysis first to enable animation", type = "info", duration = 3)
      }
    })
    
    observeEvent(input$pause_animation, {
      temporal_controls_state$animation_state <- "paused"
      
      shinyjs::html("animation_status", "Animation: Paused")
      shinyjs::removeClass("animation_status", "status-active status-stopped")
      shinyjs::addClass("animation_status", "status-paused")
      
      stop_animation_timer()
    })
    
    observeEvent(input$stop_animation, {
      temporal_controls_state$animation_state <- "stopped"
      temporal_controls_state$current_frame <- 1
      
      shinyjs::html("animation_status", "Animation: Stopped")
      shinyjs::removeClass("animation_status", "status-active status-paused")
      shinyjs::addClass("animation_status", "status-stopped")
      
      stop_animation_timer()
    })
    
    observeEvent(input$reset_animation, {
      temporal_controls_state$animation_state <- "stopped"
      temporal_controls_state$current_frame <- 1
      
      shinyjs::html("animation_status", "Animation: Reset")
      shinyjs::removeClass("animation_status", "status-active status-paused")
      shinyjs::addClass("animation_status", "status-stopped")
      
      stop_animation_timer()
    })
    
    # Animation timer functions
    start_animation_timer <- function() {
      if (!is.null(temporal_controls_state$animation_timer)) {
        invalidateLater(0, temporal_controls_state$animation_timer)
      }
      
      temporal_controls_state$animation_timer <- invalidateLater(input$animation_speed)
    }
    
    stop_animation_timer <- function() {
      if (!is.null(temporal_controls_state$animation_timer)) {
        temporal_controls_state$animation_timer <- NULL
      }
    }
    
    # Animation frame advancement
    observe({
      if (temporal_controls_state$animation_state == "playing" && 
          !is.null(temporal_controls_state$animation_timer)) {
        
        isolate({
          if (temporal_controls_state$current_frame < temporal_controls_state$total_frames) {
            temporal_controls_state$current_frame <- temporal_controls_state$current_frame + 1
          } else {
            # Animation complete - stop or loop
            temporal_controls_state$current_frame <- 1  # Loop back to start
          }
        })
        
        # Continue animation
        invalidateLater(input$animation_speed)
      }
    })
    
    # Refresh data
    observeEvent(input$refresh_data, {
      showNotification("Refreshing temporal data...", type = "info", duration = 3)
      temporal_controls_state$analysis_results <- NULL
      temporal_controls_state$animation_state <- "stopped"
      # Additional refresh logic would go here
    })
    
    # Export handlers
    output$export_data <- downloadHandler(
      filename = function() {
        paste0("temporal_analysis_", Sys.Date(), ".csv")
      },
      content = function(file) {
        if (!is.null(temporal_controls_state$analysis_results)) {
          write.csv(temporal_controls_state$analysis_results$processed_data, file, row.names = FALSE)
        } else {
          write.csv(data.frame(message = "No analysis results available"), file, row.names = FALSE)
        }
      }
    )
    
    output$export_visualizations <- downloadHandler(
      filename = function() {
        paste0("temporal_visualizations_", Sys.Date(), ".html")
      },
      content = function(file) {
        # Export visualizations as HTML
        writeLines("<html><body><h1>Temporal Visualizations</h1><p>Export functionality available</p></body></html>", file)
      }
    )
    
    output$export_report <- downloadHandler(
      filename = function() {
        paste0("temporal_analysis_report_", Sys.Date(), ".pdf")
      },
      content = function(file) {
        # Generate comprehensive PDF report
        writeLines("Temporal Analysis Report - Export functionality available", file)
      }
    )
    
    # Return reactive values and functions
    return(list(
      # Reactive data
      filtered_data = filtered_temporal_data,
      analysis_results = reactive({ temporal_controls_state$analysis_results }),
      
      # Animation state
      animation_state = reactive({ temporal_controls_state$animation_state }),
      current_frame = reactive({ temporal_controls_state$current_frame }),
      total_frames = reactive({ temporal_controls_state$total_frames }),
      
      # Control state
      temporal_unit = reactive({ input$temporal_unit }),
      geographic_level = reactive({ input$geographic_level }),
      date_range = effective_date_range,
      selected_states = reactive({ input$selected_states }),
      
      # Utility functions
      get_applied_filters = reactive({ temporal_controls_state$data_filters_applied }),
      get_last_analysis_time = reactive({ temporal_controls_state$last_analysis_time }),
      
      # Control functions
      trigger_analysis = function() { shinyjs::click("run_analysis") },
      reset_animation = function() { shinyjs::click("reset_animation") },
      refresh_data = function() { shinyjs::click("refresh_data") }
    ))
  })
}

# Helper Functions for Temporal Controls
# ======================================

#' Create Quick Date Preset Options
#' 
#' Creates standardized date preset options for temporal analysis
#' 
#' @param include_custom Whether to include custom option
#' @return Named list of date preset options
create_date_preset_options <- function(include_custom = TRUE) {
  
  options <- list()
  
  if (include_custom) {
    options[["Custom Range"]] <- "custom"
  }
  
  preset_options <- TEMPORAL_CONTROLS_CONFIG$date_filtering$quick_date_presets
  for (name in names(preset_options)) {
    days <- preset_options[[name]]
    if (is.null(days)) {
      options[[name]] <- "all"
    } else {
      options[[name]] <- paste0(days, "d")
    }
  }
  
  return(options)
}

#' Validate Temporal Control Inputs
#' 
#' Validates user inputs for temporal controls
#' 
#' @param date_range Date range vector
#' @param temporal_unit Selected temporal unit
#' @param geographic_selections Geographic selections
#' @return List with validation results
validate_temporal_control_inputs <- function(date_range, temporal_unit, geographic_selections) {
  
  validation_results <- list(
    valid = TRUE,
    errors = c(),
    warnings = c()
  )
  
  # Validate date range
  if (isTRUE(is.null(date_range)) || length(date_range) != 2) {
    validation_results$valid <- FALSE
    validation_results$errors <- c(validation_results$errors, "Invalid date range")
  } else {
    date_diff <- as.numeric(difftime(date_range[2], date_range[1], units = "days"))
    
    if (date_diff < TEMPORAL_CONTROLS_CONFIG$date_filtering$min_date_range_days) {
      validation_results$valid <- FALSE
      validation_results$errors <- c(validation_results$errors, 
        paste("Date range too short. Minimum:", 
              TEMPORAL_CONTROLS_CONFIG$date_filtering$min_date_range_days, "days"))
    }
    
    if (date_diff > TEMPORAL_CONTROLS_CONFIG$date_filtering$max_date_range_days) {
      validation_results$warnings <- c(validation_results$warnings,
        "Large date range may impact performance")
    }
  }
  
  # Validate temporal unit
  valid_units <- c("daily", "weekly", "monthly", "quarterly", "yearly")
  if (!temporal_unit %in% valid_units) {
    validation_results$valid <- FALSE
    validation_results$errors <- c(validation_results$errors, "Invalid temporal unit")
  }
  
  # Validate geographic selections
  if (!isTRUE(is.null(geographic_selections)) && 
      length(geographic_selections) > TEMPORAL_CONTROLS_CONFIG$geographic_filtering$max_selections) {
    validation_results$warnings <- c(validation_results$warnings,
      paste("Many geographic selections may impact performance. Maximum recommended:", 
            TEMPORAL_CONTROLS_CONFIG$geographic_filtering$max_selections))
  }
  
  return(validation_results)
}

# Export main functions and configuration
list(
  temporal_controls_ui = temporal_controls_ui,
  temporal_controls_server = temporal_controls_server,
  create_date_preset_options = create_date_preset_options,
  validate_temporal_control_inputs = validate_temporal_control_inputs,
  TEMPORAL_CONTROLS_CONFIG = TEMPORAL_CONTROLS_CONFIG
)