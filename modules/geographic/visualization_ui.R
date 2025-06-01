# Legislative Density Visualization UI Components - Sprint 5B GEO-002
# Brazilian Legislative Monitoring System - Interactive Map Interface
# ================================================================== 
# 
# Government-quality Shiny UI components for legislative density visualization
# Provides professional interface for Brazilian government users with 134k+ documents
# 
# FEATURES:
# - Professional Brazilian government styling and aesthetics
# - Interactive map controls (zoom, layer selection, export options)
# - Advanced filtering and visualization mode controls
# - Statistical dashboard integration with choropleth maps
# - Mobile-responsive design for government field operations
# - Accessibility compliance for government digital standards
# 
# UI COMPONENTS:
# - Main density visualization interface with advanced controls
# - Statistical summary panels with government-style value boxes
# - Export dialog with multiple format options
# - Interactive legend and color scheme selectors
# - Performance monitoring dashboard for system administrators
# 
# INTEGRATION:
# - Seamless integration with existing shinydashboard framework
# - Compatible with existing geographic analysis tab structure
# - Uses established app styling patterns and color schemes
# ==================================================================

library(shiny)
library(shinydashboard)
library(leaflet)
library(DT)
library(plotly)
library(shinyjs)
library(htmltools)

# Load visualization system
if (file.exists("modules/geographic/density_visualization.R")) {
  source("modules/geographic/density_visualization.R")
}

# UI Configuration and Styling
# ============================

VISUALIZATION_UI_CONFIG <- list(
  
  # Brazilian Government Color Palette
  colors = list(
    primary = "#1e3a8a",      # Brazilian government blue
    secondary = "#059669",     # Brazilian green
    accent = "#dc2626",        # Alert red
    success = "#16a34a",       # Success green
    warning = "#ca8a04",       # Warning amber
    info = "#0284c7",          # Info blue
    light = "#f8fafc",         # Light background
    dark = "#1e293b",          # Dark text
    
    # Map specific colors
    map_background = "#f1f5f9",
    control_background = "#ffffff",
    border_color = "#cbd5e1"
  ),
  
  # Responsive breakpoints
  breakpoints = list(
    mobile = 768,
    tablet = 1024,
    desktop = 1440
  ),
  
  # Component sizing
  sizing = list(
    map_height = "600px",
    mobile_map_height = "400px",
    control_panel_width = 300,
    legend_width = 280,
    statistics_height = 120
  ),
  
  # Animation settings
  animations = list(
    transition_duration = 300,
    fade_duration = 200,
    slide_duration = 400
  )
)

# Main Density Visualization UI
# =============================

#' Create Legislative Density Visualization Interface
#' 
#' Creates the complete UI for legislative density visualization with all controls
#' 
#' @param id Module ID for namespacing
#' @param title Interface title
#' @return Shiny UI elements
density_visualization_ui <- function(id, title = "Legislative Density Analysis") {
  
  ns <- NS(id)
  
  tagList(
    
    # Include custom CSS
    tags$head(
      tags$style(HTML(density_visualization_css())),
      tags$script(HTML(density_visualization_js()))
    ),
    
    # Main interface container
    fluidRow(
      
      # Left panel: Map and visualization
      column(width = 9,
             
        # Map container with controls overlay
        div(class = "map-container",
            
          # Map output
          leafletOutput(ns("density_map"), 
                       height = VISUALIZATION_UI_CONFIG$sizing$map_height),
          
          # Floating control panel
          absolutePanel(
            id = ns("map_controls"),
            class = "panel panel-default map-controls-panel",
            fixed = TRUE,
            draggable = FALSE,
            top = 80, left = 20,
            width = VISUALIZATION_UI_CONFIG$sizing$control_panel_width,
            
            # Panel header
            div(class = "panel-heading",
                h4(class = "panel-title", 
                   icon("layer-group"), 
                   " Visualization Controls")
            ),
            
            # Panel body
            div(class = "panel-body",
                
                # Geographic level selection
                selectInput(ns("geographic_level"),
                           label = "Geographic Level",
                           choices = list(
                             "States" = "state",
                             "Municipalities" = "municipality"
                           ),
                           selected = "state"),
                
                # Visualization mode selection
                selectInput(ns("visualization_mode"),
                           label = "Visualization Mode",
                           choices = list(),  # Populated by server
                           selected = "absolute"),
                
                # State filter (conditional)
                conditionalPanel(
                  condition = "input.geographic_level == 'municipality'",
                  ns = ns,
                  selectizeInput(ns("state_filter"),
                                label = "Filter by States",
                                choices = NULL,
                                multiple = TRUE,
                                options = list(
                                  placeholder = "Select states...",
                                  maxItems = 10
                                ))
                ),
                
                # Color scheme selection
                selectInput(ns("color_scheme"),
                           label = "Color Scheme",
                           choices = list(
                             "Government Primary" = "government_primary",
                             "Government Secondary" = "government_secondary", 
                             "Brazilian Colors" = "brazilian_flag",
                             "Academic Neutral" = "academic_neutral",
                             "Diverging Scale" = "diverging"
                           ),
                           selected = "government_primary"),
                
                # Number of color bins
                sliderInput(ns("color_bins"),
                           label = "Color Categories",
                           min = 3, max = 9, value = 7, step = 1),
                
                hr(),
                
                # Action buttons
                div(class = "btn-toolbar",
                    div(class = "btn-group",
                        actionButton(ns("refresh_map"),
                                   "Refresh Map",
                                   icon = icon("sync-alt"),
                                   class = "btn-primary btn-sm"),
                        
                        actionButton(ns("export_map"), 
                                   "Export",
                                   icon = icon("download"),
                                   class = "btn-success btn-sm")
                    )
                ),
                
                # Loading indicator
                div(id = ns("map_loading"),
                    class = "loading-indicator hidden",
                    div(class = "spinner-border spinner-border-sm", role = "status"),
                    span("Loading map...")
                )
            )
          ),
          
          # Map legend (positioned dynamically)
          absolutePanel(
            id = ns("map_legend"),
            class = "panel panel-default map-legend-panel",
            fixed = TRUE,
            draggable = FALSE,
            bottom = 20, right = 20,
            width = VISUALIZATION_UI_CONFIG$sizing$legend_width,
            
            div(class = "panel-heading",
                h5(class = "panel-title", 
                   icon("info-circle"), 
                   " Map Information")
            ),
            
            div(class = "panel-body",
                div(id = ns("legend_content"),
                    p("Select visualization options to view legend.")
                ),
                
                # Quick statistics
                div(id = ns("quick_stats"),
                    class = "quick-stats",
                    div(class = "stat-row",
                        span(class = "stat-label", "Total Features:"),
                        span(class = "stat-value", id = ns("total_features"), "--")
                    ),
                    div(class = "stat-row",
                        span(class = "stat-label", "Data Range:"),
                        span(class = "stat-value", id = ns("data_range"), "--")
                    ),
                    div(class = "stat-row",
                        span(class = "stat-label", "Last Updated:"),
                        span(class = "stat-value", id = ns("last_updated"), "--")
                    )
                )
            )
          )
        )
      ),
      
      # Right panel: Statistics and analysis
      column(width = 3,
             
        # Statistical summary boxes
        div(class = "statistics-panel",
            
            h4(class = "statistics-title",
               icon("chart-bar"),
               " Statistical Analysis"),
            
            # Key metrics value boxes
            div(class = "metrics-grid",
                
                # Total documents metric
                valueBoxOutput(ns("total_documents_box"), width = NULL),
                
                # Coverage metric  
                valueBoxOutput(ns("coverage_box"), width = NULL),
                
                # Activity metric
                valueBoxOutput(ns("activity_box"), width = NULL)
            ),
            
            hr(),
            
            # Distribution analysis
            h5("Distribution Analysis"),
            
            # Distribution plot
            div(class = "analysis-plot",
                plotlyOutput(ns("distribution_plot"), height = "200px")
            ),
            
            # Top performers table
            h5("Top Performers"),
            
            div(class = "top-performers",
                DT::dataTableOutput(ns("top_performers_table"))
            ),
            
            hr(),
            
            # Additional analysis options
            h5("Analysis Options"),
            
            div(class = "analysis-controls",
                
                checkboxInput(ns("show_statistics"),
                             "Show Statistical Overlays",
                             value = FALSE),
                
                checkboxInput(ns("show_outliers"),
                             "Highlight Outliers", 
                             value = FALSE),
                
                checkboxInput(ns("enable_clustering"),
                             "Enable Geographic Clustering",
                             value = FALSE),
                
                # Export options
                div(class = "export-section",
                    h6("Export Options"),
                    
                    div(class = "btn-group-vertical",
                        downloadButton(ns("download_data"),
                                     "Download Data (CSV)",
                                     class = "btn-outline-primary btn-sm"),
                        
                        downloadButton(ns("download_geojson"),
                                     "Download GeoJSON", 
                                     class = "btn-outline-success btn-sm"),
                        
                        actionButton(ns("generate_report"),
                                   "Generate Report",
                                   icon = icon("file-pdf"),
                                   class = "btn-outline-info btn-sm")
                    )
                )
            )
        )
      )
    ),
    
    # Performance monitoring (admin only)
    conditionalPanel(
      condition = "false", # Enable for admin users
      
      fluidRow(
        column(width = 12,
               
          div(class = "performance-panel",
              
              h4("System Performance Monitoring"),
              
              fluidRow(
                column(width = 3,
                       valueBoxOutput(ns("memory_usage_box"), width = NULL)
                ),
                
                column(width = 3, 
                       valueBoxOutput(ns("render_time_box"), width = NULL)
                ),
                
                column(width = 3,
                       valueBoxOutput(ns("cache_status_box"), width = NULL)
                ),
                
                column(width = 3,
                       valueBoxOutput(ns("db_status_box"), width = NULL)
                )
              )
          )
        )
      )
    )
  )
}

# Supporting UI Components
# =======================

#' Create Export Dialog UI
#' 
#' Creates a modal dialog for map and data export options
#' 
#' @param id Module ID
#' @return Modal dialog UI
export_dialog_ui <- function(id) {
  
  ns <- NS(id)
  
  modalDialog(
    title = tagList(icon("download"), " Export Legislative Density Analysis"),
    size = "l",
    
    fluidRow(
      
      # Export format selection
      column(width = 6,
             
        h4("Export Format"),
        
        radioButtons(ns("export_format"),
                    label = NULL,
                    choices = list(
                      "High-Resolution PNG Image" = "png",
                      "PDF Document" = "pdf", 
                      "SVG Vector Graphics" = "svg",
                      "Interactive HTML" = "html",
                      "Data (CSV)" = "csv",
                      "Geographic Data (GeoJSON)" = "geojson"
                    ),
                    selected = "png"),
        
        # Format-specific options
        conditionalPanel(
          condition = "input.export_format == 'png' || input.export_format == 'pdf'",
          ns = ns,
          
          h5("Image Options"),
          
          selectInput(ns("image_resolution"),
                     "Resolution",
                     choices = list(
                       "Web (72 DPI)" = "72",
                       "Print (300 DPI)" = "300",
                       "High Quality (600 DPI)" = "600"
                     ),
                     selected = "300"),
          
          selectInput(ns("image_size"),
                     "Size",
                     choices = list(
                       "Small (800x600)" = "800x600",
                       "Standard (1200x800)" = "1200x800", 
                       "Large (1600x1200)" = "1600x1200",
                       "Custom" = "custom"
                     ),
                     selected = "1200x800")
        )
      ),
      
      # Content options
      column(width = 6,
             
        h4("Content Options"),
        
        checkboxGroupInput(ns("export_content"),
                          label = NULL,
                          choices = list(
                            "Include Map Legend" = "legend",
                            "Include Statistical Summary" = "statistics", 
                            "Include Data Table" = "data_table",
                            "Include Methodology Notes" = "methodology",
                            "Include Data Sources" = "sources",
                            "Include Timestamp" = "timestamp"
                          ),
                          selected = c("legend", "statistics", "timestamp")),
        
        hr(),
        
        h5("Metadata"),
        
        textInput(ns("export_title"),
                 "Title",
                 value = "Brazilian Legislative Density Analysis"),
        
        textAreaInput(ns("export_description"),
                     "Description",
                     value = "Geographic distribution of legislative documents across Brazilian administrative boundaries.",
                     rows = 3),
        
        textInput(ns("export_author"),
                 "Author/Organization", 
                 value = "Brazilian Legislative Monitoring System")
      )
    ),
    
    hr(),
    
    # Preview section
    div(class = "export-preview",
        h5("Export Preview"),
        div(id = ns("export_preview_content"),
            p(class = "text-muted", "Select export options to see preview...")
        )
    ),
    
    footer = tagList(
      actionButton(ns("cancel_export"), "Cancel", class = "btn-secondary"),
      downloadButton(ns("confirm_export"), "Export", class = "btn-primary")
    )
  )
}

#' Create Settings Dialog UI
#' 
#' Advanced settings for visualization customization
#' 
#' @param id Module ID
#' @return Modal dialog UI
settings_dialog_ui <- function(id) {
  
  ns <- NS(id)
  
  modalDialog(
    title = tagList(icon("cog"), " Visualization Settings"),
    size = "m",
    
    tabsetPanel(
      
      # Map settings
      tabPanel("Map Settings",
               
        h4("Map Configuration"),
        
        numericInput(ns("map_zoom"),
                    "Default Zoom Level",
                    value = 4, min = 1, max = 10, step = 1),
        
        selectInput(ns("map_tiles"),
                   "Base Map Tiles",
                   choices = list(
                     "OpenStreetMap" = "osm",
                     "Satellite" = "satellite", 
                     "Terrain" = "terrain",
                     "Minimal" = "minimal"
                   ),
                   selected = "osm"),
        
        checkboxInput(ns("show_scale_bar"),
                     "Show Scale Bar",
                     value = TRUE),
        
        checkboxInput(ns("show_mini_map"), 
                     "Show Mini Map",
                     value = TRUE)
      ),
      
      # Color settings
      tabPanel("Colors",
               
        h4("Color Configuration"),
        
        selectInput(ns("default_color_scheme"),
                   "Default Color Scheme",
                   choices = list(
                     "Government Primary" = "government_primary",
                     "Government Secondary" = "government_secondary",
                     "Academic" = "academic_neutral"
                   )),
        
        sliderInput(ns("opacity_level"),
                   "Fill Opacity",
                   min = 0.1, max = 1.0, value = 0.7, step = 0.1),
        
        colourInput(ns("stroke_color"), 
                   "Border Color", 
                   value = "#555555")
      ),
      
      # Performance settings
      tabPanel("Performance",
               
        h4("Performance Settings"),
        
        numericInput(ns("max_features"),
                    "Maximum Features to Display",
                    value = 5570, min = 100, max = 10000, step = 100),
        
        sliderInput(ns("simplification_tolerance"),
                   "Geometry Simplification",
                   min = 0.001, max = 0.1, value = 0.01, step = 0.001),
        
        numericInput(ns("cache_duration"),
                    "Cache Duration (minutes)",
                    value = 30, min = 5, max = 180, step = 5),
        
        checkboxInput(ns("enable_progressive_loading"),
                     "Enable Progressive Loading",
                     value = TRUE)
      )
    ),
    
    footer = tagList(
      actionButton(ns("reset_settings"), "Reset to Defaults", class = "btn-warning"),
      actionButton(ns("cancel_settings"), "Cancel", class = "btn-secondary"),
      actionButton(ns("save_settings"), "Save Settings", class = "btn-primary")
    )
  )
}

# Custom CSS Styling
# ==================

density_visualization_css <- function() {
  "
  /* Legislative Density Visualization Styles */
  
  .map-container {
    position: relative;
    background-color: #f8fafc;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    overflow: hidden;
  }
  
  .map-controls-panel {
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(10px);
    border: 1px solid #e2e8f0;
    box-shadow: 0 4px 16px rgba(0,0,0,0.1);
    border-radius: 8px;
    max-height: 80vh;
    overflow-y: auto;
  }
  
  .map-legend-panel {
    background: rgba(255, 255, 255, 0.95);
    backdrop-filter: blur(10px);
    border: 1px solid #e2e8f0;
    box-shadow: 0 4px 16px rgba(0,0,0,0.1);
    border-radius: 8px;
    max-height: 60vh;
    overflow-y: auto;
  }
  
  .statistics-panel {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 20px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.05);
  }
  
  .statistics-title {
    color: #1e3a8a;
    margin-bottom: 15px;
    font-weight: 600;
  }
  
  .metrics-grid {
    display: grid;
    gap: 15px;
    margin-bottom: 20px;
  }
  
  .quick-stats {
    font-size: 12px;
    margin-top: 10px;
  }
  
  .stat-row {
    display: flex;
    justify-content: space-between;
    margin-bottom: 5px;
  }
  
  .stat-label {
    color: #64748b;
  }
  
  .stat-value {
    font-weight: 600;
    color: #0f172a;
  }
  
  .analysis-plot {
    border: 1px solid #e2e8f0;
    border-radius: 4px;
    margin-bottom: 15px;
  }
  
  .top-performers {
    max-height: 200px;
    overflow-y: auto;
    border: 1px solid #e2e8f0;
    border-radius: 4px;
  }
  
  .analysis-controls {
    background: #f8fafc;
    padding: 15px;
    border-radius: 6px;
    border: 1px solid #e2e8f0;
  }
  
  .export-section {
    margin-top: 15px;
    padding-top: 15px;
    border-top: 1px solid #e2e8f0;
  }
  
  .performance-panel {
    background: #fef3c7;
    border: 1px solid #fbbf24;
    border-radius: 8px;
    padding: 20px;
    margin-top: 20px;
  }
  
  .loading-indicator {
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background: rgba(255, 255, 255, 0.9);
    padding: 15px 25px;
    border-radius: 6px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.1);
    z-index: 1000;
  }
  
  .loading-indicator.hidden {
    display: none;
  }
  
  .btn-toolbar {
    display: flex;
    gap: 5px;
  }
  
  .btn-group {
    display: flex;
  }
  
  .btn-group-vertical {
    display: flex;
    flex-direction: column;
    gap: 5px;
  }
  
  /* Responsive design */
  @media (max-width: 768px) {
    .map-controls-panel {
      position: static !important;
      width: 100% !important;
      margin-bottom: 15px;
    }
    
    .map-legend-panel {
      position: static !important;
      width: 100% !important;
      margin-top: 15px;
    }
    
    .statistics-panel {
      margin-top: 15px;
    }
  }
  
  /* Color scheme indicators */
  .color-scheme-preview {
    display: flex;
    height: 20px;
    border-radius: 3px;
    overflow: hidden;
    margin-top: 5px;
  }
  
  .color-scheme-preview > div {
    flex: 1;
  }
  
  /* Brazilian government styling */
  .gov-primary { color: #1e3a8a; }
  .gov-secondary { color: #059669; }
  .gov-accent { color: #dc2626; }
  
  /* Accessibility improvements */
  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0,0,0,0);
    white-space: nowrap;
    border: 0;
  }
  
  /* Focus styles for accessibility */
  .map-controls-panel .form-control:focus,
  .map-controls-panel .btn:focus {
    outline: 2px solid #1e3a8a;
    outline-offset: 2px;
  }
  "
}

# Custom JavaScript
# ================

density_visualization_js <- function() {
  "
  /* Legislative Density Visualization JavaScript */
  
  $(document).ready(function() {
    
    // Initialize tooltips
    $('[data-toggle=\"tooltip\"]').tooltip();
    
    // Map loading state management
    function showMapLoading(show = true) {
      const loadingEl = $('#map_loading');
      if (show) {
        loadingEl.removeClass('hidden');
      } else {
        loadingEl.addClass('hidden');
      }
    }
    
    // Update quick statistics
    function updateQuickStats(stats) {
      if (stats) {
        $('#total_features').text(stats.total_features || '--');
        $('#data_range').text(stats.data_range || '--');
        $('#last_updated').text(stats.last_updated || '--');
      }
    }
    
    // Color scheme preview generation
    function generateColorPreview(scheme, colors) {
      const previewDiv = $('<div class=\"color-scheme-preview\"></div>');
      
      if (colors && colors.length > 0) {
        colors.forEach(function(color) {
          previewDiv.append(
            $('<div></div>').css('background-color', color)
          );
        });
      }
      
      return previewDiv;
    }
    
    // Responsive map height adjustment
    function adjustMapHeight() {
      const windowHeight = $(window).height();
      const mapContainer = $('.map-container');
      
      if ($(window).width() <= 768) { // Mobile
        mapContainer.find('.leaflet-container').height('400px');
      } else {
        const availableHeight = windowHeight - 200; // Account for headers/footers
        const targetHeight = Math.min(Math.max(availableHeight, 400), 800);
        mapContainer.find('.leaflet-container').height(targetHeight + 'px');
      }
    }
    
    // Event handlers
    $(window).resize(function() {
      adjustMapHeight();
    });
    
    // Initialize responsive behavior
    adjustMapHeight();
    
    // Export preview update
    function updateExportPreview() {
      const format = $('input[name$=\"export_format\"]:checked').val();
      const content = $('input[name$=\"export_content\"]:checked').map(function() {
        return $(this).val();
      }).get();
      
      let previewText = 'Export will include: ';
      if (format) {
        previewText += format.toUpperCase() + ' format';
        if (content.length > 0) {
          previewText += ' with ' + content.join(', ');
        }
      }
      
      $('#export_preview_content').html('<p>' + previewText + '</p>');
    }
    
    // Bind export preview updates
    $(document).on('change', 'input[name$=\"export_format\"], input[name$=\"export_content\"]', function() {
      updateExportPreview();
    });
    
    // Performance monitoring (for admin users)
    function updatePerformanceMetrics() {
      // This would connect to actual performance monitoring
      // Implementation depends on server-side metrics collection
    }
    
    // Auto-refresh performance metrics every 30 seconds
    setInterval(updatePerformanceMetrics, 30000);
    
    console.log('Legislative Density Visualization UI initialized');
  });
  "
}

# Utility Functions
# ================

#' Get Available Color Schemes
#' 
#' Returns list of available color schemes for UI selection
#' 
#' @return Named list of color schemes
get_color_scheme_choices <- function() {
  list(
    "Government Primary (Blue)" = "government_primary",
    "Government Secondary (Green)" = "government_secondary", 
    "Brazilian Flag Colors" = "brazilian_flag",
    "Academic Neutral" = "academic_neutral",
    "Diverging Scale" = "diverging"
  )
}

#' Get Visualization Mode Choices
#' 
#' Returns available visualization modes with descriptions
#' 
#' @return Named list of visualization modes
get_visualization_mode_choices <- function() {
  modes <- DENSITY_VIZ_CONFIG$modes
  
  choices <- list()
  for (mode_key in names(modes)) {
    mode_info <- modes[[mode_key]]
    choices[[mode_info$name]] <- mode_key
  }
  
  return(choices)
}

#' Create Responsive Value Box
#' 
#' Creates value boxes that adapt to screen size
#' 
#' @param value Main value to display
#' @param subtitle Subtitle text
#' @param icon Icon name
#' @param color Box color
#' @param width Box width
#' @return Value box output
create_responsive_value_box <- function(value, subtitle, icon, color = "blue", width = 4) {
  
  valueBox(
    value = value,
    subtitle = subtitle,
    icon = icon(icon),
    color = color,
    width = width,
    href = NULL
  )
}

# Export main functions
list(
  density_visualization_ui = density_visualization_ui,
  export_dialog_ui = export_dialog_ui,
  settings_dialog_ui = settings_dialog_ui,
  get_color_scheme_choices = get_color_scheme_choices,
  get_visualization_mode_choices = get_visualization_mode_choices,
  create_responsive_value_box = create_responsive_value_box,
  VISUALIZATION_UI_CONFIG = VISUALIZATION_UI_CONFIG
)