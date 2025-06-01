# Enhanced Geographic Integration - Sprint 5B GEO-003 Final Integration
# Brazilian Legislative Monitoring System - Complete System Integration
# =====================================================================
# 
# Final integration module combining existing Sprint 1 geographic analysis 
# with the new interactive Leaflet mapping system (GEO-003), creating a
# seamless, world-class geographic analysis platform for 134k+ documents
# 
# INTEGRATION FEATURES:
# - Seamless replacement of basic choropleth with enhanced interactive maps
# - Preservation of existing Sprint 1 functionality and academic standards
# - Enhanced interactivity overlaid on proven geographic analysis foundation  
# - Railway-optimized performance with 2GB memory constraint compliance
# - Government-quality user experience with academic research capabilities
# - Backwards compatibility with existing dashboard navigation and data flows
# 
# TECHNICAL APPROACH:
# - Drop-in replacement strategy for existing leaflet outputs
# - Enhanced server module extending geographic_server_sprint1
# - Progressive enhancement of existing UI components
# - Shared data sources and caching strategies
# - Unified error handling and fallback mechanisms
# - Performance monitoring and automatic optimization
# 
# SYSTEM COORDINATION:
# - Coordinated initialization with existing geographic systems
# - Shared reactive values and data caching
# - Unified control interfaces and user interactions
# - Integrated performance monitoring and Railway optimization
# - Seamless navigation and deep-linking capabilities
# - Academic research workflow preservation and enhancement
# =====================================================================

library(shiny)
library(shinydashboard)
library(leaflet)
library(sf)
library(dplyr)
library(htmltools)
library(jsonlite)
library(DBI)
library(pool)

# Load all required systems
if (file.exists("modules/geographic/geographic_server_sprint1.R")) {
  source("modules/geographic/geographic_server_sprint1.R")
}
if (file.exists("modules/geographic/geographic_ui_sprint1.R")) {
  source("modules/geographic/geographic_ui_sprint1.R")
}
if (file.exists("modules/geographic/leaflet_integration.R")) {
  source("modules/geographic/leaflet_integration.R")
}
if (file.exists("modules/geographic/railway_leaflet_optimization.R")) {
  source("modules/geographic/railway_leaflet_optimization.R")
}

# Enhanced Integration Configuration
# =================================

ENHANCED_INTEGRATION_CONFIG <- list(
  
  # Integration strategy
  integration_strategy = list(
    approach = "progressive_enhancement",
    fallback_enabled = TRUE,
    preserve_existing_functionality = TRUE,
    enhance_user_experience = TRUE
  ),
  
  # Component coordination
  component_coordination = list(
    use_existing_data_sources = TRUE,
    shared_reactive_values = TRUE,
    unified_error_handling = TRUE,
    coordinated_loading = TRUE
  ),
  
  # Performance settings
  performance_settings = list(
    railway_optimization_enabled = TRUE,
    memory_monitoring_enabled = TRUE,
    progressive_loading_enabled = TRUE,
    fallback_threshold_mb = 1600
  ),
  
  # UI enhancement levels
  enhancement_levels = list(
    basic = "existing_functionality_preserved",
    enhanced = "interactive_leaflet_enabled",
    advanced = "full_feature_set_available"
  )
)

# Enhanced Geographic Server Module
# =================================

#' Enhanced Geographic Analysis Server Module
#' 
#' Extended version of geographic_server_sprint1 with integrated 
#' interactive Leaflet capabilities (GEO-003)
#' 
#' @param id Module namespace identifier
#' @param pool Database connection pool
#' @param enable_enhanced_maps Enable GEO-003 interactive mapping
#' @param enable_railway_optimization Enable Railway-specific optimizations
#' @return Enhanced server function with interactive mapping capabilities
enhanced_geographic_server <- function(id, pool, 
                                     enable_enhanced_maps = TRUE, 
                                     enable_railway_optimization = TRUE) {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns
    
    cat("🌍+ Initializing Enhanced Geographic Analysis Server...\n")
    
    # Initialize enhanced system components
    enhanced_system <- reactiveValues(
      integrated_system = NULL,
      performance_optimizer = NULL,
      initialization_status = "initializing",
      enhancement_level = "basic",
      error_log = list()
    )
    
    # Initialize the enhanced system
    observe({
      if (is.null(enhanced_system$integrated_system) && enable_enhanced_maps) {
        
        withProgress(message = "Initializing enhanced geographic system...", value = 0, {
          
          incProgress(0.2, detail = "Setting up Railway optimization...")
          
          tryCatch({
            
            # Initialize Railway-optimized system
            if (enable_railway_optimization) {
              
              railway_result <- initialize_railway_geographic_system(
                db_pool = pool,
                session = session,
                enable_monitoring = TRUE
              )
              
              if (railway_result$success) {
                enhanced_system$integrated_system <- railway_result$integrated_system
                enhanced_system$performance_optimizer <- railway_result$performance_optimizer
                enhanced_system$enhancement_level <- "advanced"
                
                incProgress(0.6, detail = "Railway optimization initialized")
                cat("✅ Railway-optimized system initialized successfully\n")
                
              } else {
                # Fall back to standard integration
                incProgress(0.4, detail = "Falling back to standard integration...")
                
                standard_result <- initialize_geographic_analysis_system(
                  db_pool = pool,
                  session = session
                )
                
                if (standard_result$success) {
                  enhanced_system$integrated_system <- standard_result$system
                  enhanced_system$enhancement_level <- "enhanced"
                  
                  incProgress(0.8, detail = "Standard integration successful")
                  cat("✅ Standard enhanced system initialized\n")
                }
              }
              
            } else {
              # Standard enhanced system without Railway optimization
              incProgress(0.4, detail = "Initializing standard enhanced system...")
              
              standard_result <- initialize_geographic_analysis_system(
                db_pool = pool,
                session = session
              )
              
              if (standard_result$success) {
                enhanced_system$integrated_system <- standard_result$system
                enhanced_system$enhancement_level <- "enhanced"
                
                incProgress(0.8, detail = "Standard integration successful")
                cat("✅ Standard enhanced system initialized\n")
              }
            }
            
            incProgress(1, detail = "Enhanced system ready")
            enhanced_system$initialization_status <- "operational"
            
          }, error = function(e) {
            cat("❌ Enhanced system initialization failed:", e$message, "\n")
            enhanced_system$initialization_status <- "failed"
            enhanced_system$enhancement_level <- "basic"
            enhanced_system$error_log <- append(enhanced_system$error_log, e$message)
            
            showNotification(
              "Enhanced mapping unavailable, using standard features",
              type = "warning",
              duration = 8
            )
          })
        })
      }
    })
    
    # Initialize base geographic server functionality from Sprint 1
    base_geographic_server <- geographic_server_sprint1(
      id = "base_geographic",
      pool = pool
    )
    
    # Enhanced interactive choropleth map
    output$interactive_choropleth <- renderLeaflet({
      
      # Check if enhanced system is available
      if (!is.null(enhanced_system$integrated_system) && 
          enhanced_system$initialization_status == "operational") {
        
        tryCatch({
          
          cat("🗺️ Rendering enhanced interactive choropleth...\n")
          
          # Create enhanced interactive map
          enhanced_map <- enhanced_system$integrated_system$create_integrated_map(
            map_id = "interactive_choropleth",
            base_map = "cartodb_positron",
            initial_layers = c("state_boundaries", "document_density"),
            include_controls = TRUE,
            mobile_optimized = TRUE
          )
          
          if (!is.null(enhanced_map)) {
            cat("✅ Enhanced map created successfully\n")
            return(enhanced_map)
          } else {
            cat("⚠️ Enhanced map creation returned NULL, using fallback\n")
            return(create_enhanced_fallback_map())
          }
          
        }, error = function(e) {
          cat("❌ Error creating enhanced map:", e$message, "\n")
          return(create_enhanced_fallback_map())
        })
        
      } else {
        
        # Use base geographic server choropleth with enhancements
        cat("🗺️ Using base geographic choropleth with enhancements...\n")
        
        # Get data from base server
        base_data <- base_geographic_server$geographic_data()
        
        if (!is.null(base_data)) {
          return(create_enhanced_base_map(base_data))
        } else {
          return(create_enhanced_fallback_map())
        }
      }
    })
    
    # Enhanced map controls UI
    output$enhanced_map_controls <- renderUI({
      
      if (!is.null(enhanced_system$integrated_system) &&
          enhanced_system$initialization_status == "operational") {
        
        tryCatch({
          
          # Create enhanced controls from integrated system
          enhanced_system$integrated_system$create_map_controls_ui()
          
        }, error = function(e) {
          cat("❌ Error creating enhanced controls:", e$message, "\n")
          create_basic_map_controls()
        })
        
      } else {
        create_basic_map_controls()
      }
    })
    
    # Enhanced map legend
    output$enhanced_map_legend <- renderUI({
      
      if (!is.null(enhanced_system$integrated_system) &&
          enhanced_system$initialization_status == "operational") {
        
        tryCatch({
          
          enhanced_system$integrated_system$create_map_legend_ui()
          
        }, error = function(e) {
          create_basic_map_legend()
        })
        
      } else {
        create_basic_map_legend()
      }
    })
    
    # System status indicators
    output$system_status_indicator <- renderUI({
      
      status_class <- switch(enhanced_system$enhancement_level,
        "advanced" = "success",
        "enhanced" = "info",
        "basic" = "warning",
        "default"
      )
      
      status_text <- switch(enhanced_system$enhancement_level,
        "advanced" = "Advanced Interactive Mapping (Railway Optimized)",
        "enhanced" = "Enhanced Interactive Mapping",
        "basic" = "Standard Mapping",
        "System Initializing"
      )
      
      status_icon <- switch(enhanced_system$enhancement_level,
        "advanced" = "rocket",
        "enhanced" = "map-marked-alt", 
        "basic" = "map",
        "spinner"
      )
      
      div(
        class = paste0("alert alert-", status_class),
        style = "margin-bottom: 10px; padding: 8px 12px;",
        icon(status_icon),
        " ",
        status_text,
        if (enhanced_system$enhancement_level == "advanced" && 
            !is.null(enhanced_system$performance_optimizer)) {
          
          performance_report <- enhanced_system$performance_optimizer$get_optimization_report()
          
          span(
            style = "float: right; font-size: 0.9em;",
            "Memory: ",
            round(performance_report$performance_monitoring$memory_usage_mb, 0),
            "MB"
          )
        }
      )
    })
    
    # Performance monitoring output
    output$performance_monitoring <- renderUI({
      
      if (!is.null(enhanced_system$performance_optimizer) &&
          enhanced_system$enhancement_level == "advanced") {
        
        performance_report <- enhanced_system$performance_optimizer$get_optimization_report()
        
        div(
          class = "well well-sm",
          style = "margin-top: 10px;",
          
          h5("Railway Performance Monitoring", style = "margin-top: 0;"),
          
          div(style = "display: flex; justify-content: space-between; font-size: 0.9em;",
            span(paste("Memory:", round(performance_report$performance_monitoring$memory_usage_mb, 0), "MB")),
            span(paste("Status:", performance_report$performance_monitoring$monitoring_active)),
            span(paste("Events:", performance_report$optimization_events_count))
          )
        )
        
      } else {
        NULL
      }
    })
    
    # Proxy all other outputs to base geographic server
    output$density_analysis_plot <- base_geographic_server$density_analysis_plot
    output$federal_comparison_table <- base_geographic_server$federal_comparison_table
    output$spatial_statistics_summary <- base_geographic_server$spatial_statistics_summary
    output$data_quality_indicators <- base_geographic_server$data_quality_indicators
    
    # Enhanced event handlers
    observe({
      input$refresh_analysis
      
      # Refresh both base and enhanced systems
      if (!is.null(base_geographic_server$refresh_data)) {
        base_geographic_server$refresh_data()
      }
      
      if (!is.null(enhanced_system$integrated_system)) {
        tryCatch({
          enhanced_system$integrated_system$cleanup_system_resources()
        }, error = function(e) {
          cat("⚠️ Error during system refresh:", e$message, "\n")
        })
      }
    })
    
    # Return enhanced reactive values
    return(list(
      # Enhanced functionality
      enhanced_system = reactive(enhanced_system),
      integrated_system = reactive(enhanced_system$integrated_system),
      performance_optimizer = reactive(enhanced_system$performance_optimizer),
      enhancement_level = reactive(enhanced_system$enhancement_level),
      
      # Base functionality preserved
      geographic_data = base_geographic_server$geographic_data,
      boundaries = base_geographic_server$boundaries,
      spatial_stats = base_geographic_server$spatial_stats,
      
      # Enhanced refresh function
      refresh_data = function() {
        if (!is.null(base_geographic_server$refresh_data)) {
          base_geographic_server$refresh_data()
        }
        if (!is.null(enhanced_system$integrated_system)) {
          enhanced_system$integrated_system$cleanup_system_resources()
        }
      }
    ))
  })
}

# Enhanced Geographic UI Module
# =============================

#' Enhanced Geographic Analysis UI Module
#' 
#' Extended version of geographic_ui_sprint1 with integrated
#' interactive Leaflet capabilities and enhanced controls
#' 
#' @param id Module namespace identifier
#' @return Enhanced UI with interactive mapping capabilities
enhanced_geographic_ui <- function(id) {
  ns <- NS(id)
  
  tagList(
    
    # Base CSS from Sprint 1 plus enhancements
    tags$head(
      tags$style(HTML("
        /* Enhanced Geographic Analysis Styling - GEO-003 */
        .enhanced-geographic-container {
          padding: 15px;
          font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        
        .enhancement-status-bar {
          background: #f8f9fa;
          border-radius: 6px;
          padding: 10px;
          margin-bottom: 15px;
          border-left: 4px solid #17a2b8;
        }
        
        .enhanced-map-container {
          position: relative;
          background: white;
          border-radius: 8px;
          box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
          overflow: hidden;
          margin-bottom: 20px;
        }
        
        .enhanced-controls-panel {
          position: absolute;
          top: 10px;
          right: 10px;
          background: rgba(255, 255, 255, 0.95);
          border-radius: 6px;
          padding: 10px;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
          z-index: 1000;
          min-width: 200px;
          max-width: 300px;
        }
        
        .enhanced-legend-panel {
          position: absolute;
          bottom: 10px;
          right: 10px;
          background: rgba(255, 255, 255, 0.95);
          border-radius: 6px;
          padding: 8px;
          box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
          z-index: 1000;
          max-width: 250px;
        }
        
        .performance-monitor {
          background: #e8f5e8;
          border: 1px solid #d4e6d4;
          border-radius: 4px;
          padding: 8px;
          font-size: 0.85em;
          color: #2d5a2d;
        }
        
        .leaflet-enhanced {
          height: 650px !important;
          border-radius: 8px;
        }
        
        @media (max-width: 768px) {
          .enhanced-controls-panel {
            position: relative;
            top: auto;
            right: auto;
            margin-bottom: 10px;
            max-width: 100%;
          }
          
          .enhanced-legend-panel {
            position: relative;
            bottom: auto;
            right: auto;
            margin-top: 10px;
            max-width: 100%;
          }
          
          .leaflet-enhanced {
            height: 450px !important;
          }
        }
        
        /* Enhanced interaction indicators */
        .interaction-indicator {
          position: absolute;
          top: 50%;
          left: 50%;
          transform: translate(-50%, -50%);
          background: rgba(52, 152, 219, 0.9);
          color: white;
          padding: 15px 20px;
          border-radius: 6px;
          font-size: 14px;
          z-index: 2000;
          display: none;
        }
        
        .loading-overlay {
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(255, 255, 255, 0.8);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1500;
        }
      "))
    ),
    
    # Main enhanced geographic interface
    div(class = "enhanced-geographic-container",
      
      # Enhancement status indicator
      div(class = "enhancement-status-bar",
        uiOutput(ns("system_status_indicator"))
      ),
      
      # Use base header from Sprint 1
      div(class = "academic-header",
        h2("Brazilian Legislative Geographic Analysis"),
        div(class = "academic-subtitle",
          "Enhanced Interactive Platform | GEO-003 Interactive Mapping | Railway Optimized"
        )
      ),
      
      # Enhanced performance indicators
      div(class = "stats-grid",
        div(class = "stat-item",
          div(class = "stat-value", "27"),
          div(class = "stat-label", "Brazilian States")
        ),
        div(class = "stat-item",
          div(class = "stat-value", "134k+"),
          div(class = "stat-label", "Documents Analyzed")
        ),
        div(class = "stat-item",
          div(class = "stat-value", "100%"),
          div(class = "stat-label", "Geographic Coverage")
        ),
        div(class = "stat-item",
          div(class = "stat-value", textOutput(ns("enhancement_level"), inline = TRUE)),
          div(class = "stat-label", "System Enhancement")
        )
      ),
      
      # Enhanced control panel
      div(class = "control-panel",
        h4("Enhanced Analysis Controls", style = "margin-bottom: 15px; color: #2c3e50;"),
        
        div(class = "mobile-stack",
          div(
            selectInput(
              ns("analysis_type"),
              "Analysis Type",
              choices = list(
                "Interactive Choropleth" = "choropleth",
                "Density Analysis" = "density", 
                "Federal Comparison" = "federal",
                "Enhanced Mapping" = "enhanced_mapping",
                "Spatial Analysis" = "spatial"
              ),
              selected = "choropleth"
            )
          ),
          div(
            selectInput(
              ns("map_interaction_mode"),
              "Interaction Mode",
              choices = list(
                "Standard View" = "standard",
                "Interactive Exploration" = "interactive",
                "Analysis Mode" = "analysis",
                "Comparison Mode" = "comparison"
              ),
              selected = "interactive"
            )
          ),
          div(
            div(style = "padding-top: 25px;",
              actionButton(
                ns("refresh_analysis"),
                "Refresh Enhanced System",
                icon = icon("sync-alt"),
                class = "btn btn-primary btn-block"
              )
            )
          )
        ),
        
        # Enhanced options
        br(),
        checkboxGroupInput(
          ns("enhanced_options"),
          "Enhanced Capabilities (GEO-003)",
          choices = list(
            "Interactive hover tooltips" = "tooltips",
            "Click-through navigation" = "navigation",
            "Advanced layer controls" = "layers",
            "Real-time filtering" = "filtering",
            "Performance monitoring" = "performance"
          ),
          selected = c("tooltips", "navigation", "layers"),
          inline = TRUE
        )
      ),
      
      # Enhanced main analysis tabs
      tabsetPanel(
        id = ns("enhanced_analysis_tabs"),
        type = "tabs",
        
        # Enhanced Interactive Map Tab
        tabPanel(
          "Enhanced Interactive Map",
          value = "enhanced_choropleth",
          
          div(class = "tab-content",
            
            # Enhanced map container with integrated controls
            div(class = "enhanced-map-container",
              
              # Loading overlay
              conditionalPanel(
                condition = "false", # Will be controlled by JavaScript
                div(class = "loading-overlay",
                  div(class = "text-center",
                    icon("spinner", class = "fa-spin fa-2x"),
                    h4("Loading Enhanced Interactive Map..."),
                    p("Initializing GEO-003 interactive capabilities")
                  )
                )
              ),
              
              # Enhanced leaflet map
              leafletOutput(ns("interactive_choropleth"), height = "650px"),
              
              # Integrated map controls
              conditionalPanel(
                condition = paste0("input['", ns("enhanced_options"), "'].indexOf('layers') > -1"),
                div(class = "enhanced-controls-panel",
                  uiOutput(ns("enhanced_map_controls"))
                )
              ),
              
              # Integrated map legend
              div(class = "enhanced-legend-panel",
                uiOutput(ns("enhanced_map_legend"))
              ),
              
              # Interaction indicator
              div(class = "interaction-indicator",
                id = ns("interaction_indicator"),
                "Enhanced interaction available - Click and explore!"
              )
            ),
            
            # Performance monitoring panel
            conditionalPanel(
              condition = paste0("input['", ns("enhanced_options"), "'].indexOf('performance') > -1"),
              uiOutput(ns("performance_monitoring"))
            ),
            
            # Enhanced methodology note
            div(class = "methodology-note",
              strong("Enhanced System: "),
              "GEO-003 interactive mapping with Railway optimization. ",
              "Features advanced click-through, hover tooltips, and real-time filtering. ",
              "Optimized for 2GB memory constraints with progressive enhancement."
            )
          )
        ),
        
        # Preserve existing tabs from Sprint 1
        tabPanel(
          "Density Analysis",
          value = "density",
          div(class = "tab-content",
            div(class = "analysis-card",
              h4("Legislative Document Density by Brazilian State"),
              plotlyOutput(ns("density_analysis_plot"), height = "500px")
            )
          )
        ),
        
        tabPanel(
          "Federal System Analysis", 
          value = "federal",
          div(class = "tab-content",
            div(class = "analysis-card",
              h4("Brazilian Federal System Legislative Comparison"),
              DT::dataTableOutput(ns("federal_comparison_table"))
            )
          )
        ),
        
        tabPanel(
          "Spatial Statistics",
          value = "spatial",
          div(class = "tab-content",
            div(class = "analysis-card",
              h4("Enhanced Spatial Statistical Analysis"),
              uiOutput(ns("spatial_statistics_summary"))
            )
          )
        ),
        
        tabPanel(
          "Data Quality",
          value = "quality", 
          div(class = "tab-content",
            div(class = "analysis-card",
              h4("Enhanced Data Quality Assessment"),
              uiOutput(ns("data_quality_indicators"))
            )
          )
        )
      ),
      
      # Enhanced academic citation
      div(class = "academic-citation",
        "Monitor Legislativo v4 | Enhanced Interactive Geographic Analysis (GEO-003) | ",
        "Railway Optimized | Data: IBGE 2020, 134k+ Legislative Documents"
      )
    ),
    
    # Enhanced JavaScript for interactivity
    tags$script(HTML(paste0("
      $(document).ready(function() {
        
        // Enhanced map interaction feedback
        $('#", ns("interactive_choropleth"), "').on('click', function() {
          $('#", ns("interaction_indicator"), "').fadeIn(300).delay(2000).fadeOut(300);
        });
        
        // Performance monitoring updates
        setInterval(function() {
          // This would update performance indicators in real implementation
        }, 30000);
        
        console.log('Enhanced Geographic Analysis (GEO-003) JavaScript loaded');
      });
    ")))
  )
}

# Supporting Functions
# ===================

#' Create Enhanced Fallback Map
#' 
#' Creates an enhanced version of the fallback map when systems are unavailable
#' 
#' @return Enhanced fallback leaflet map
create_enhanced_fallback_map <- function() {
  
  leaflet() %>%
    addTiles() %>%
    setView(lng = -47.9218, lat = -15.8267, zoom = 4) %>%
    addMarkers(
      lng = -47.9218,
      lat = -15.8267,
      popup = paste0(
        "<div style='text-align: center; font-family: system-ui; padding: 10px;'>",
        "<h6 style='margin: 0 0 8px 0; color: #3498db;'>",
        "<i class='fa fa-map'></i> Enhanced System Loading",
        "</h6>",
        "<p style='margin: 0; font-size: 13px;'>",
        "Enhanced interactive features are loading.<br/>",
        "Standard mapping functionality is available.",
        "</p>",
        "</div>"
      )
    ) %>%
    addScaleBar(position = "bottomleft")
}

#' Create Enhanced Base Map
#' 
#' Creates an enhanced version of the base geographic map
#' 
#' @param geo_data Geographic data from base system
#' @return Enhanced base leaflet map
create_enhanced_base_map <- function(geo_data) {
  
  if (is.null(geo_data) || nrow(geo_data) == 0) {
    return(create_enhanced_fallback_map())
  }
  
  tryCatch({
    
    # Enhanced color palette
    pal <- colorNumeric(
      palette = c("#ffffcc", "#41b6c4", "#2c7fb8", "#253494"),
      domain = geo_data$doc_count,
      na.color = "transparent"
    )
    
    # Create enhanced base map
    leaflet(geo_data) %>%
      addTiles(group = "OpenStreetMap") %>%
      addProviderTiles(providers$CartoDB.Positron, group = "CartoDB Light") %>%
      addProviderTiles(providers$Esri.WorldImagery, group = "Satellite") %>%
      setView(lng = -55, lat = -15, zoom = 4) %>%
      addPolygons(
        fillColor = ~pal(doc_count),
        weight = 2,
        opacity = 1,
        color = "white",
        dashArray = "2",
        fillOpacity = 0.8,
        highlight = highlightOptions(
          weight = 4,
          color = "#ff6b35",
          dashArray = "",
          fillOpacity = 0.9,
          bringToFront = TRUE
        ),
        popup = ~paste0(
          "<div style='font-family: system-ui; padding: 5px;'>",
          "<h6 style='margin: 0 0 8px 0; color: #2c3e50;'>", state_name, " (", state_code, ")</h6>",
          "<div style='font-size: 13px;'>",
          "<strong>Region:</strong> ", region, "<br/>",
          "<strong>Documents:</strong> ", format(doc_count, big.mark = ","), "<br/>",
          "<strong>Area:</strong> ", format(round(area_km2, 0), big.mark = ","), " km²<br/>",
          "<strong>Density:</strong> ", format(round(density_per_km2, 3), big.mark = ","), " docs/km²",
          "</div>",
          "</div>"
        ),
        popupOptions = popupOptions(
          style = list("font-weight" = "normal", padding = "3px 8px")
        )
      ) %>%
      addLegend(
        pal = pal,
        values = ~doc_count,
        opacity = 0.8,
        title = "Legislative<br/>Documents",
        position = "bottomright"
      ) %>%
      addLayersControl(
        baseGroups = c("OpenStreetMap", "CartoDB Light", "Satellite"),
        options = layersControlOptions(collapsed = FALSE)
      ) %>%
      addScaleBar(position = "bottomleft")
    
  }, error = function(e) {
    cat("❌ Error creating enhanced base map:", e$message, "\n")
    return(create_enhanced_fallback_map())
  })
}

#' Create Basic Map Controls
#' 
#' Creates basic map controls when enhanced system is unavailable
#' 
#' @return Basic map controls UI
create_basic_map_controls <- function() {
  
  div(
    style = "background: white; padding: 10px; border-radius: 5px;",
    h6("Map Controls", style = "margin: 0 0 10px 0;"),
    p("Enhanced controls available when system is fully loaded.", 
      style = "color: #666; font-size: 12px; margin: 0;"),
    br(),
    checkboxInput("show_satellite", "Satellite View", value = FALSE),
    checkboxInput("show_labels", "Show Labels", value = TRUE)
  )
}

#' Create Basic Map Legend
#' 
#' Creates basic map legend when enhanced system is unavailable
#' 
#' @return Basic map legend UI
create_basic_map_legend <- function() {
  
  div(
    style = "background: white; padding: 8px; border-radius: 4px; font-size: 12px;",
    h6("Map Legend", style = "margin: 0 0 8px 0;"),
    div(
      div(style = "display: flex; align-items: center; margin-bottom: 4px;",
        div(style = "width: 16px; height: 16px; background: #2c7fb8; margin-right: 6px;"),
        span("High Activity")
      ),
      div(style = "display: flex; align-items: center; margin-bottom: 4px;",
        div(style = "width: 16px; height: 16px; background: #41b6c4; margin-right: 6px;"),
        span("Medium Activity")
      ),
      div(style = "display: flex; align-items: center;",
        div(style = "width: 16px; height: 16px; background: #ffffcc; margin-right: 6px;"),
        span("Low Activity")
      )
    )
  )
}

# Export Functions
list(
  enhanced_geographic_server = enhanced_geographic_server,
  enhanced_geographic_ui = enhanced_geographic_ui,
  create_enhanced_fallback_map = create_enhanced_fallback_map,
  create_enhanced_base_map = create_enhanced_base_map,
  ENHANCED_INTEGRATION_CONFIG = ENHANCED_INTEGRATION_CONFIG
)