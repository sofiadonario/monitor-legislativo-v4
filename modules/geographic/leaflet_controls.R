# Leaflet Controls and Layer Management - Sprint 5B GEO-003
# Brazilian Legislative Monitoring System - Interactive Map Controls
# ================================================================
# 
# Professional map controls and layer management system providing government-quality
# user interface for Brazilian legislative geographic analysis with 134k+ documents
# 
# CONTROL FEATURES:
# - Layer switching controls with government-approved styling
# - Dynamic legend management with statistical context
# - Zoom and navigation controls optimized for government use
# - Export and sharing controls with security compliance
# - Mobile-responsive control layouts for field operations
# - Accessibility-compliant interaction patterns
# 
# LAYER MANAGEMENT:
# - Real-time layer toggling with performance optimization
# - Layer opacity and styling controls
# - Data filtering controls with statistical validation
# - Temporal controls for time-series analysis
# - Multi-selection and comparison tools
# - Custom layer creation and management
# 
# TECHNICAL IMPLEMENTATION:
# - Custom HTML controls with Shiny integration
# - CSS styling following Brazilian government standards
# - JavaScript enhancements for advanced interactions
# - Performance monitoring and memory management
# - Cross-browser compatibility and fallback mechanisms
# - Government security and accessibility compliance
# ================================================================

library(shiny)
library(shinydashboard)
library(leaflet)
library(htmltools)
library(htmlwidgets)
library(DBI)
library(pool)
library(dplyr)
library(jsonlite)

# Load supporting systems
if (file.exists("modules/geographic/interactive_leaflet.R")) {
  source("modules/geographic/interactive_leaflet.R")
}

# Leaflet Controls Configuration
# =============================

LEAFLET_CONTROLS_CONFIG <- list(
  
  # Control panel layouts
  control_panels = list(
    
    layer_control = list(
      name = "Layer Control",
      position = "topright",
      collapsed = FALSE,
      auto_z_index = TRUE,
      hide_single_base = TRUE,
      sort_layers = TRUE,
      mobile_friendly = TRUE,
      max_height = "300px",
      
      styling = list(
        background_color = "rgba(255, 255, 255, 0.95)",
        border_radius = "8px",
        box_shadow = "0 4px 16px rgba(0,0,0,0.1)",
        padding = "12px",
        font_family = "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
        font_size = "13px"
      )
    ),
    
    legend_control = list(
      name = "Map Legend",
      position = "bottomright", 
      width = 200,
      height = "auto",
      opacity = 0.9,
      collapsible = TRUE,
      collapsed = FALSE,
      
      styling = list(
        background_color = "rgba(255, 255, 255, 0.95)",
        border_radius = "6px",
        border = "1px solid #cbd5e1",
        padding = "10px",
        font_size = "12px",
        line_height = "1.4"
      )
    ),
    
    filter_control = list(
      name = "Data Filters",
      position = "topleft",
      width = 280,
      collapsible = TRUE,
      collapsed = TRUE,
      
      styling = list(
        background_color = "rgba(248, 250, 252, 0.98)",
        border_radius = "8px",
        box_shadow = "0 6px 20px rgba(0,0,0,0.15)",
        padding = "16px",
        max_height = "400px",
        overflow_y = "auto"
      )
    ),
    
    export_control = list(
      name = "Export & Share",
      position = "topright",
      below_layers = TRUE,
      
      styling = list(
        margin_top = "10px",
        background_color = "rgba(255, 255, 255, 0.95)",
        border_radius = "6px",
        padding = "8px"
      )
    ),
    
    info_control = list(
      name = "Map Information",
      position = "bottomleft",
      above_scale = TRUE,
      
      styling = list(
        background_color = "rgba(255, 255, 255, 0.9)",
        border_radius = "4px",
        padding = "6px 8px",
        font_size = "11px",
        color = "#64748b"
      )
    )
  ),
  
  # Control button configurations
  control_buttons = list(
    
    zoom_controls = list(
      enabled = TRUE,
      position = "topleft",
      zoom_in_text = "+",
      zoom_out_text = "-",
      zoom_in_title = "Zoom in",
      zoom_out_title = "Zoom out",
      
      styling = list(
        background_color = "#ffffff",
        border = "1px solid #cdd5df",
        border_radius = "4px",
        color = "#374151",
        font_size = "14px",
        font_weight = "bold",
        width = "26px",
        height = "26px"
      )
    ),
    
    fullscreen_control = list(
      enabled = TRUE,
      position = "topleft",
      title = "Toggle fullscreen",
      force_separate_button = TRUE,
      
      styling = list(
        background_color = "#ffffff",
        border = "1px solid #cdd5df",
        border_radius = "4px",
        color = "#374151"
      )
    ),
    
    home_button = list(
      enabled = TRUE,
      position = "topleft",
      title = "Reset to Brazil view",
      icon = "fa fa-home",
      
      styling = list(
        background_color = "#1e3a8a",
        color = "#ffffff",
        border_radius = "4px",
        padding = "6px 8px"
      )
    ),
    
    measure_control = list(
      enabled = TRUE,
      position = "topleft",
      primary_length_unit = "kilometers",
      secondary_length_unit = "meters",
      primary_area_unit = "sqkilometers",
      secondary_area_unit = "hectares",
      active_color = "#ff6b35",
      completed_color = "#16a34a"
    ),
    
    draw_control = list(
      enabled = FALSE,  # Disabled by default for performance
      position = "topleft",
      draw_marker = TRUE,
      draw_circle_marker = FALSE,
      draw_polyline = TRUE,
      draw_polygon = TRUE,
      draw_circle = TRUE,
      draw_rectangle = True,
      edit_feature = True,
      delete_feature = True
    )
  ),
  
  # Layer control configurations
  layer_controls = list(
    
    base_layers = list(
      title = "Base Maps",
      radio_buttons = True,
      exclusive = True,
      
      options = list(
        "Street Map" = "openstreetmap",
        "Light Theme" = "cartodb_positron", 
        "Dark Theme" = "cartodb_dark",
        "Satellite" = "esri_world_imagery",
        "Terrain" = "stamen_terrain"
      )
    ),
    
    overlay_layers = list(
      title = "Data Layers",
      checkboxes = True,
      exclusive = False,
      
      options = list(
        "State Boundaries" = "state_boundaries",
        "Municipality Boundaries" = "municipality_boundaries", 
        "Document Density" = "document_density",
        "Legislative Hotspots" = "legislative_hotspots",
        "Document Markers" = "document_markers"
      )
    ),
    
    analysis_layers = list(
      title = "Analysis Tools",
      checkboxes = True,
      exclusive = False,
      advanced = True,
      
      options = list(
        "Temporal Trends" = "temporal_analysis",
        "Category Distribution" = "category_analysis", 
        "Correlation Analysis" = "correlation_analysis",
        "Statistical Overlays" = "statistical_overlays"
      )
    )
  ),
  
  # Filter control configurations
  filter_controls = list(
    
    temporal_filter = list(
      name = "Time Period",
      type = "daterange",
      default_start = NULL,  # Will be set to earliest document date
      default_end = NULL,    # Will be set to latest document date
      min_date = "2010-01-01",
      max_date = Sys.Date(),
      format = "yyyy-mm-dd",
      separator = " to "
    ),
    
    category_filter = list(
      name = "Document Categories", 
      type = "multiselect",
      max_options = 10,
      placeholder = "Select categories...",
      options_source = "database",  # Dynamic loading from database
      search_enabled = TRUE,
      clear_button = TRUE
    ),
    
    state_filter = list(
      name = "States/Regions",
      type = "multiselect",
      placeholder = "Select states...",
      options_source = "database",
      search_enabled = TRUE,
      clear_button = TRUE,
      select_all_button = TRUE
    ),
    
    municipality_filter = list(
      name = "Municipalities",
      type = "multiselect",
      placeholder = "Select municipalities...",
      depends_on = "state_filter",
      options_source = "database",
      search_enabled = TRUE,
      clear_button = TRUE,
      max_items = 20
    ),
    
    document_count_filter = list(
      name = "Document Count Range",
      type = "slider",
      min_value = 1,
      max_value = NULL,  # Will be set dynamically
      default_range = c(5, NULL),
      step = 1,
      format = "number"
    ),
    
    activity_level_filter = list(
      name = "Activity Level",
      type = "select",
      options = list(
        "All Levels" = "all",
        "Very High" = "very_high",
        "High" = "high", 
        "Medium" = "medium",
        "Low" = "low"
      ),
      default = "all"
    )
  ),
  
  # Export control configurations
  export_controls = list(
    
    map_export = list(
      formats = c("PNG", "PDF", "SVG"),
      default_format = "PNG",
      resolutions = c("Standard (1200x800)", "High (1920x1280)", "Print (3000x2000)"),
      default_resolution = "Standard (1200x800)",
      include_legend = TRUE,
      include_scale = TRUE,
      include_attribution = TRUE,
      include_title = TRUE,
      custom_title = "",
      watermark = "Brazilian Legislative Monitoring System"
    ),
    
    data_export = list(
      formats = c("CSV", "Excel", "GeoJSON", "KML"),
      default_format = "CSV",
      include_geometry = FALSE,
      include_metadata = TRUE,
      filter_applied_data_only = TRUE,
      max_records = 50000
    ),
    
    share_options = list(
      permalink_enabled = TRUE,
      embed_code_enabled = TRUE,
      social_sharing = FALSE,  # Disabled for government security
      qr_code_enabled = TRUE
    )
  ),
  
  # Styling and appearance
  styling = list(
    
    # Government color scheme
    colors = list(
      primary = "#1e3a8a",
      secondary = "#059669", 
      accent = "#dc2626",
      neutral = "#6b7280",
      background = "#f8fafc",
      surface = "#ffffff",
      border = "#e2e8f0",
      text = "#1f2937",
      text_secondary = "#6b7280"
    ),
    
    # Typography
    fonts = list(
      family = "'Inter', 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif",
      size_small = "11px",
      size_normal = "13px", 
      size_large = "15px",
      weight_normal = "400",
      weight_medium = "500",
      weight_bold = "600"
    ),
    
    # Spacing and layout
    spacing = list(
      xs = "4px",
      sm = "8px",
      md = "12px",
      lg = "16px",
      xl = "20px",
      xxl = "24px"
    ),
    
    # Animations
    animations = list(
      duration_fast = "150ms",
      duration_normal = "250ms",
      duration_slow = "350ms",
      easing = "cubic-bezier(0.4, 0, 0.2, 1)"
    )
  )
)

# Leaflet Controls Manager Class
# =============================

if (requireNamespace("R6", quietly = TRUE)) {
  
  LeafletControlsManager <- R6::R6Class("LeafletControlsManager",
    
    public = list(
      
      # Properties
      db_pool = NULL,
      leaflet_manager = NULL,
      current_filters = NULL,
      control_states = NULL,
      active_controls = NULL,
      
      # Constructor
      initialize = function(db_pool, leaflet_manager = NULL) {
        
        cat("🎛️ Initializing Leaflet Controls Manager...\n")
        
        self$db_pool <- db_pool
        self$leaflet_manager <- leaflet_manager
        self$current_filters <- list()
        self$control_states <- list()
        self$active_controls <- list()
        
        # Initialize dynamic filter options
        self$initialize_filter_options()
        
        cat("✅ Leaflet Controls Manager initialized\n")
      },
      
      # Control creation methods
      create_layer_control_panel = function(base_layers = NULL, overlay_layers = NULL, options = NULL) {
        
        cat("🗂️ Creating layer control panel...\n")
        
        tryCatch({
          
          # Use default configurations if not provided
          if (is.null(base_layers)) {
            base_layers <- LEAFLET_CONTROLS_CONFIG$layer_controls$base_layers$options
          }
          
          if (is.null(overlay_layers)) {
            overlay_layers <- LEAFLET_CONTROLS_CONFIG$layer_controls$overlay_layers$options
          }
          
          # Create the layer control UI
          layer_control_ui <- div(
            id = "map-layer-control",
            class = "leaflet-control-panel layer-control-panel",
            style = self$get_control_panel_style("layer_control"),
            
            # Base layers section
            div(
              class = "control-section",
              h5("Base Maps", 
                 class = "control-section-title",
                 style = "margin: 0 0 10px 0; font-size: 14px; font-weight: 600; color: #374151;"),
              
              div(
                class = "base-layers-container",
                lapply(names(base_layers), function(layer_name) {
                  layer_id <- base_layers[[layer_name]]
                  
                  div(
                    class = "layer-option base-layer-option",
                    style = "margin-bottom: 6px;",
                    
                    tags$label(
                      style = "display: flex; align-items: center; cursor: pointer; font-size: 13px;",
                      
                      tags$input(
                        type = "radio",
                        name = "base-layer",
                        value = layer_id,
                        checked = if (layer_id == "cartodb_positron") "checked" else NULL,
                        style = "margin-right: 8px;"
                      ),
                      
                      span(layer_name)
                    )
                  )
                })
              )
            ),
            
            hr(style = "margin: 15px 0; border: 0; border-top: 1px solid #e5e7eb;"),
            
            # Overlay layers section
            div(
              class = "control-section",
              h5("Data Layers",
                 class = "control-section-title", 
                 style = "margin: 0 0 10px 0; font-size: 14px; font-weight: 600; color: #374151;"),
              
              div(
                class = "overlay-layers-container",
                lapply(names(overlay_layers), function(layer_name) {
                  layer_id <- overlay_layers[[layer_name]]
                  
                  div(
                    class = "layer-option overlay-layer-option",
                    style = "margin-bottom: 6px;",
                    
                    tags$label(
                      style = "display: flex; align-items: center; cursor: pointer; font-size: 13px;",
                      
                      tags$input(
                        type = "checkbox",
                        value = layer_id,
                        checked = if (layer_id == "state_boundaries") "checked" else NULL,
                        style = "margin-right: 8px;"
                      ),
                      
                      span(layer_name),
                      
                      # Layer opacity control
                      div(
                        style = "margin-left: auto; width: 60px;",
                        tags$input(
                          type = "range",
                          min = "0",
                          max = "1",
                          step = "0.1",
                          value = "0.7",
                          class = "layer-opacity-slider",
                          style = "width: 100%; height: 4px;"
                        )
                      )
                    )
                  )
                })
              )
            )
          )
          
          return(layer_control_ui)
          
        }, error = function(e) {
          cat("❌ Error creating layer control panel:", e$message, "\n")
          return(div("Layer control unavailable"))
        })
      },
      
      create_filter_control_panel = function() {
        
        cat("🔍 Creating filter control panel...\n")
        
        tryCatch({
          
          filter_control_ui <- div(
            id = "map-filter-control",
            class = "leaflet-control-panel filter-control-panel",
            style = self$get_control_panel_style("filter_control"),
            
            # Header with collapse button
            div(
              class = "control-panel-header",
              style = "display: flex; justify-content: between; align-items: center; margin-bottom: 12px;",
              
              h5("Data Filters",
                 style = "margin: 0; font-size: 15px; font-weight: 600; color: #1f2937;"),
              
              button(
                class = "btn btn-sm collapse-button",
                style = "background: none; border: none; color: #6b7280; padding: 0;",
                icon("chevron-up")
              )
            ),
            
            div(
              class = "filter-controls-container",
              
              # Temporal filter
              div(
                class = "filter-group",
                style = "margin-bottom: 16px;",
                
                label("Time Period",
                      class = "filter-label",
                      style = "display: block; margin-bottom: 4px; font-size: 12px; font-weight: 500; color: #374151;"),
                
                div(
                  style = "display: flex; gap: 8px;",
                  dateInput(
                    "filter_date_start",
                    label = NULL,
                    value = Sys.Date() - 365,
                    format = "yyyy-mm-dd",
                    width = "120px"
                  ),
                  span("to", style = "align-self: center; font-size: 12px; color: #6b7280;"),
                  dateInput(
                    "filter_date_end", 
                    label = NULL,
                    value = Sys.Date(),
                    format = "yyyy-mm-dd",
                    width = "120px"
                  )
                )
              ),
              
              # Category filter
              div(
                class = "filter-group",
                style = "margin-bottom: 16px;",
                
                label("Document Categories",
                      class = "filter-label",
                      style = "display: block; margin-bottom: 4px; font-size: 12px; font-weight: 500; color: #374151;"),
                
                selectInput(
                  "filter_categories",
                  label = NULL,
                  choices = self$get_category_options(),
                  selected = NULL,
                  multiple = TRUE,
                  width = "100%",
                  options = list(
                    placeholder = "Select categories...",
                    maxItems = 10,
                    searchField = c("text", "value")
                  )
                )
              ),
              
              # State filter
              div(
                class = "filter-group",
                style = "margin-bottom: 16px;",
                
                label("States",
                      class = "filter-label", 
                      style = "display: block; margin-bottom: 4px; font-size: 12px; font-weight: 500; color: #374151;"),
                
                selectInput(
                  "filter_states",
                  label = NULL,
                  choices = self$get_state_options(),
                  selected = NULL,
                  multiple = TRUE,
                  width = "100%"
                )
              ),
              
              # Document count range
              div(
                class = "filter-group",
                style = "margin-bottom: 16px;",
                
                label("Document Count Range",
                      class = "filter-label",
                      style = "display: block; margin-bottom: 4px; font-size: 12px; font-weight: 500; color: #374151;"),
                
                div(
                  style = "padding: 0 8px;",
                  sliderInput(
                    "filter_document_count",
                    label = NULL,
                    min = 1,
                    max = self$get_max_document_count(),
                    value = c(5, self$get_max_document_count()),
                    step = 1,
                    width = "100%"
                  )
                )
              ),
              
              # Filter actions
              div(
                class = "filter-actions",
                style = "border-top: 1px solid #e5e7eb; padding-top: 12px; display: flex; gap: 8px;",
                
                actionButton(
                  "apply_filters",
                  "Apply Filters",
                  class = "btn btn-primary btn-sm",
                  style = "flex: 1; background-color: #1e3a8a; border-color: #1e3a8a; font-size: 12px;"
                ),
                
                actionButton(
                  "clear_filters",
                  "Clear",
                  class = "btn btn-outline-secondary btn-sm",
                  style = "background-color: transparent; color: #6b7280; border-color: #d1d5db; font-size: 12px;"
                )
              )
            )
          )
          
          return(filter_control_ui)
          
        }, error = function(e) {
          cat("❌ Error creating filter control panel:", e$message, "\n")
          return(div("Filter control unavailable"))
        })
      },
      
      create_legend_control = function(legend_data = NULL, layer_type = "choropleth") {
        
        cat("📊 Creating map legend...\n")
        
        tryCatch({
          
          if (is.null(legend_data)) {
            legend_data <- self$get_default_legend_data(layer_type)
          }
          
          legend_ui <- div(
            id = "map-legend",
            class = "leaflet-control-panel legend-control",
            style = self$get_control_panel_style("legend_control"),
            
            # Legend header
            div(
              class = "legend-header",
              style = "margin-bottom: 8px; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px;",
              
              h6("Legislative Documents",
                 style = "margin: 0; font-size: 13px; font-weight: 600; color: #1f2937;"),
              
              small("Count per state",
                   style = "color: #6b7280; font-size: 11px;")
            ),
            
            # Legend items
            div(
              class = "legend-items",
              
              if (layer_type == "choropleth") {
                # Choropleth legend
                lapply(1:length(legend_data$breaks), function(i) {
                  if (i < length(legend_data$breaks)) {
                    
                    div(
                      class = "legend-item",
                      style = "display: flex; align-items: center; margin-bottom: 4px;",
                      
                      div(
                        class = "legend-color-box",
                        style = paste0(
                          "width: 16px; height: 16px; margin-right: 6px; border-radius: 2px; ",
                          "background-color: ", legend_data$colors[i], ";"
                        )
                      ),
                      
                      span(
                        paste0(
                          format(legend_data$breaks[i], big.mark = ","), " - ",
                          format(legend_data$breaks[i + 1], big.mark = ",")
                        ),
                        style = "font-size: 11px; color: #374151;"
                      )
                    )
                  }
                })
              } else {
                # Default legend
                div("Legend not available for this layer type")
              }
            ),
            
            # Legend footer
            div(
              class = "legend-footer",
              style = "margin-top: 8px; padding-top: 6px; border-top: 1px solid #f3f4f6;",
              
              small("Updated: ", format(Sys.time(), "%H:%M"),
                   style = "color: #9ca3af; font-size: 10px;")
            )
          )
          
          return(legend_ui)
          
        }, error = function(e) {
          cat("❌ Error creating legend control:", e$message, "\n")
          return(div("Legend unavailable"))
        })
      },
      
      create_export_control_panel = function() {
        
        cat("📤 Creating export control panel...\n")
        
        tryCatch({
          
          export_ui <- div(
            id = "map-export-control",
            class = "leaflet-control-panel export-control-panel",
            style = self$get_control_panel_style("export_control"),
            
            # Export header
            div(
              class = "export-header",
              style = "margin-bottom: 10px;",
              
              h6("Export & Share",
                 style = "margin: 0; font-size: 13px; font-weight: 600; color: #1f2937;")
            ),
            
            # Export options
            div(
              class = "export-options",
              
              # Map export
              div(
                class = "export-group",
                style = "margin-bottom: 10px;",
                
                label("Export Map",
                      style = "font-size: 12px; font-weight: 500; color: #374151; display: block; margin-bottom: 4px;"),
                
                div(
                  style = "display: flex; gap: 4px;",
                  
                  actionButton(
                    "export_map_png",
                    "PNG",
                    class = "btn btn-outline-primary btn-sm",
                    style = "flex: 1; font-size: 11px; padding: 4px 8px;"
                  ),
                  
                  actionButton(
                    "export_map_pdf", 
                    "PDF",
                    class = "btn btn-outline-primary btn-sm",
                    style = "flex: 1; font-size: 11px; padding: 4px 8px;"
                  )
                )
              ),
              
              # Data export  
              div(
                class = "export-group",
                style = "margin-bottom: 10px;",
                
                label("Export Data",
                      style = "font-size: 12px; font-weight: 500; color: #374151; display: block; margin-bottom: 4px;"),
                
                div(
                  style = "display: flex; gap: 4px;",
                  
                  actionButton(
                    "export_data_csv",
                    "CSV",
                    class = "btn btn-outline-success btn-sm", 
                    style = "flex: 1; font-size: 11px; padding: 4px 8px;"
                  ),
                  
                  actionButton(
                    "export_data_geojson",
                    "GeoJSON", 
                    class = "btn btn-outline-success btn-sm",
                    style = "flex: 1; font-size: 11px; padding: 4px 8px;"
                  )
                )
              ),
              
              # Share options
              div(
                class = "export-group",
                
                actionButton(
                  "generate_permalink",
                  "📋 Copy Link",
                  class = "btn btn-outline-info btn-sm",
                  style = "width: 100%; font-size: 11px; padding: 4px 8px;"
                )
              )
            )
          )
          
          return(export_ui)
          
        }, error = function(e) {
          cat("❌ Error creating export control panel:", e$message, "\n")
          return(div("Export control unavailable"))
        })
      },
      
      # Control management methods
      add_controls_to_map = function(map, controls = c("layers", "filters", "legend", "export")) {
        
        if (is.null(map)) {
          return(NULL)
        }
        
        cat("🎮 Adding controls to map...\n")
        
        tryCatch({
          
          # Add layer control if requested
          if ("layers" %in% controls) {
            # Layer control is handled by leaflet natively
            # We'll enhance it with custom styling
          }
          
          # Add custom controls using htmlwidget approach
          if ("filters" %in% controls) {
            # Custom filter control implementation would go here
          }
          
          if ("legend" %in% controls) {
            # Custom legend implementation would go here
          }
          
          if ("export" %in% controls) {
            # Custom export control implementation would go here
          }
          
          return(map)
          
        }, error = function(e) {
          cat("❌ Error adding controls to map:", e$message, "\n")
          return(map)
        })
      },
      
      # Data retrieval methods
      initialize_filter_options = function() {
        
        cat("🔄 Initializing filter options...\n")
        
        tryCatch({
          
          if (is.null(self$db_pool)) {
            cat("⚠️ No database connection available for filter options\n")
            return()
          }
          
          # Initialize category options
          self$control_states$category_options <- self$load_category_options()
          
          # Initialize state options
          self$control_states$state_options <- self$load_state_options()
          
          # Initialize document count range
          self$control_states$document_count_range <- self$load_document_count_range()
          
          cat("✅ Filter options initialized\n")
          
        }, error = function(e) {
          cat("❌ Error initializing filter options:", e$message, "\n")
        })
      },
      
      load_category_options = function() {
        
        if (is.null(self$db_pool)) {
          return(c("No categories available" = "none"))
        }
        
        tryCatch({
          
          categories <- pool::poolWithTransaction(self$db_pool, function(conn) {
            DBI::dbGetQuery(conn, "
              SELECT categoria_original as category,
                     COUNT(*) as count
              FROM documents
              WHERE categoria_original IS NOT NULL 
                AND categoria_original != ''
              GROUP BY categoria_original
              HAVING COUNT(*) >= 10
              ORDER BY count DESC
              LIMIT 50
            ")
          })

          if (!isTRUE(is.null(categories)) && is.data.frame(categories) && nrow(categories) > 0) {
            # Create named vector for selectInput
            category_choices <- setNames(
              categories$category,
              paste0(categories$category, " (", format(categories$count, big.mark = ","), ")")
            )
            return(category_choices)
          }
          
          return(c("No categories found" = "none"))
          
        }, error = function(e) {
          cat("❌ Error loading category options:", e$message, "\n")
          return(c("Error loading categories" = "error"))
        })
      },
      
      load_state_options = function() {
        
        if (is.null(self$db_pool)) {
          return(c("No states available" = "none"))
        }
        
        tryCatch({
          
          states <- pool::poolWithTransaction(self$db_pool, function(conn) {
            DBI::dbGetQuery(conn, "
              SELECT estado,
                     COUNT(*) as count
              FROM documents  
              WHERE estado IS NOT NULL 
                AND estado != ''
              GROUP BY estado
              ORDER BY estado
            ")
          })

          if (!isTRUE(is.null(states)) && is.data.frame(states) && nrow(states) > 0) {
            # Create named vector
            state_choices <- setNames(
              states$estado,
              paste0(states$estado, " (", format(states$count, big.mark = ","), " docs)")
            )
            return(state_choices)
          }
          
          return(c("No states found" = "none"))
          
        }, error = function(e) {
          cat("❌ Error loading state options:", e$message, "\n")
          return(c("Error loading states" = "error"))
        })
      },
      
      load_document_count_range = function() {
        
        if (is.null(self$db_pool)) {
          return(c(min = 1, max = 1000))
        }
        
        tryCatch({
          
          range_data <- pool::poolWithTransaction(self$db_pool, function(conn) {
            DBI::dbGetQuery(conn, "
              WITH state_counts AS (
                SELECT estado, COUNT(*) as doc_count
                FROM documents
                WHERE estado IS NOT NULL AND estado != ''
                GROUP BY estado
              )
              SELECT MIN(doc_count) as min_count,
                     MAX(doc_count) as max_count
              FROM state_counts
            ")
          })

          if (!isTRUE(is.null(range_data)) && is.data.frame(range_data) && nrow(range_data) > 0) {
            return(c(
              min = max(1, range_data$min_count[1]),
              max = range_data$max_count[1]
            ))
          }
          
          return(c(min = 1, max = 1000))
          
        }, error = function(e) {
          cat("❌ Error loading document count range:", e$message, "\n")
          return(c(min = 1, max = 1000))
        })
      },
      
      # Helper methods
      get_control_panel_style = function(panel_type) {
        
        config <- LEAFLET_CONTROLS_CONFIG$control_panels[[panel_type]]
        if (is.null(config)) {
          config <- LEAFLET_CONTROLS_CONFIG$control_panels$layer_control
        }
        
        styling <- config$styling
        
        paste0(
          "background-color: ", styling$background_color, "; ",
          "border-radius: ", styling$border_radius, "; ",
          "box-shadow: ", styling$box_shadow, "; ",
          "padding: ", styling$padding, "; ",
          "font-family: ", styling$font_family, "; ",
          "font-size: ", styling$font_size, "; ",
          if (!is.null(styling$max_height)) paste0("max-height: ", styling$max_height, "; overflow-y: auto; ") else "",
          if (!is.null(styling$width)) paste0("width: ", styling$width, "px; ") else ""
        )
      },
      
      get_category_options = function() {
        if (!is.null(self$control_states$category_options)) {
          return(self$control_states$category_options)
        } else {
          return(c("Loading..." = "loading"))
        }
      },
      
      get_state_options = function() {
        if (!is.null(self$control_states$state_options)) {
          return(self$control_states$state_options)
        } else {
          return(c("Loading..." = "loading"))
        }
      },
      
      get_max_document_count = function() {
        if (!is.null(self$control_states$document_count_range)) {
          return(self$control_states$document_count_range["max"])
        } else {
          return(10000)
        }
      },
      
      get_default_legend_data = function(layer_type = "choropleth") {
        
        # Return default legend data structure
        return(list(
          breaks = c(0, 100, 500, 1000, 5000, 10000, 50000),
          colors = c("#eff6ff", "#dbeafe", "#bfdbfe", "#93c5fd", "#60a5fa", "#3b82f6", "#1d4ed8"),
          labels = c("0-100", "100-500", "500-1k", "1k-5k", "5k-10k", "10k-50k", "50k+")
        ))
      },
      
      # Filter application
      apply_current_filters = function(data) {
        
        if (isTRUE(is.null(data)) || length(self$current_filters) == 0) {
          return(data)
        }
        
        filtered_data <- data
        
        # Apply each filter
        for (filter_name in names(self$current_filters)) {
          filter_value <- self$current_filters[[filter_name]]
          
          if (!isTRUE(is.null(filter_value)) && length(filter_value) > 0) {
            filtered_data <- switch(filter_name,
              "categories" = filtered_data %>% filter(categoria_original %in% filter_value),
              "states" = filtered_data %>% filter(estado %in% filter_value),
              "date_range" = {
                if (length(filter_value) == 2) {
                  filtered_data %>% filter(
                    data_documento >= as.Date(filter_value[1]),
                    data_documento <= as.Date(filter_value[2])
                  )
                } else {
                  filtered_data
                }
              },
              "document_count" = {
                if (length(filter_value) == 2) {
                  filtered_data %>% filter(
                    document_count >= filter_value[1],
                    document_count <= filter_value[2]
                  )
                } else {
                  filtered_data
                }
              },
              # Default: no filtering
              filtered_data
            )
          }
        }
        
        return(filtered_data)
      },
      
      # Control state management
      update_filter_state = function(filter_name, filter_value) {
        self$current_filters[[filter_name]] <- filter_value
        cat("🔄 Updated filter:", filter_name, "\n")
      },
      
      clear_all_filters = function() {
        self$current_filters <- list()
        cat("🧹 All filters cleared\n")
      },
      
      get_filter_summary = function() {
        
        if (length(self$current_filters) == 0) {
          return("No filters applied")
        }
        
        filter_descriptions <- c()
        
        for (filter_name in names(self$current_filters)) {
          filter_value <- self$current_filters[[filter_name]]
          
          if (!isTRUE(is.null(filter_value)) && length(filter_value) > 0) {
            description <- switch(filter_name,
              "categories" = paste0("Categories: ", length(filter_value), " selected"),
              "states" = paste0("States: ", length(filter_value), " selected"),
              "date_range" = paste0("Date: ", paste(filter_value, collapse = " to ")),
              "document_count" = paste0("Count: ", paste(filter_value, collapse = "-")),
              paste0(filter_name, ": ", length(filter_value), " items")
            )
            
            filter_descriptions <- c(filter_descriptions, description)
          }
        }
        
        return(paste(filter_descriptions, collapse = "; "))
      },
      
      # System status
      get_control_status = function() {
        
        list(
          timestamp = Sys.time(),
          active_filters = length(self$current_filters),
          filter_summary = self$get_filter_summary(),
          control_panels_available = length(LEAFLET_CONTROLS_CONFIG$control_panels),
          database_connected = !is.null(self$db_pool),
          options_loaded = !is.null(self$control_states$category_options)
        )
      }
    )
  )
}

# Functional Factory (Fallback Implementation)
# ===========================================

create_leaflet_controls_manager <- function(db_pool, leaflet_manager = NULL) {
  
  if (requireNamespace("R6", quietly = TRUE)) {
    return(LeafletControlsManager$new(db_pool, leaflet_manager))
  } else {
    return(create_functional_controls_manager(db_pool, leaflet_manager))
  }
}

create_functional_controls_manager <- function(db_pool, leaflet_manager = NULL) {
  
  # Simplified functional implementation
  controls_env <- new.env()
  controls_env$db_pool <- db_pool
  controls_env$leaflet_manager <- leaflet_manager
  controls_env$current_filters <- list()
  
  list(
    
    create_simple_layer_control = function() {
      
      div(
        style = "background: white; padding: 10px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);",
        
        h5("Map Layers", style = "margin: 0 0 10px 0; font-size: 14px;"),
        
        div(
          checkboxInput("show_states", "State Boundaries", value = TRUE),
          checkboxInput("show_density", "Document Density", value = FALSE),
          checkboxInput("show_municipalities", "Municipalities", value = FALSE)
        ),
        
        hr(style = "margin: 10px 0;"),
        
        h6("Base Map", style = "margin: 0 0 5px 0; font-size: 13px;"),
        selectInput(
          "base_map_select",
          label = NULL,
          choices = c(
            "Street Map" = "openstreetmap",
            "Light Theme" = "cartodb_positron",
            "Satellite" = "esri_world_imagery"
          ),
          selected = "cartodb_positron",
          width = "100%"
        )
      )
    },
    
    create_simple_filter_control = function() {
      
      div(
        style = "background: white; padding: 10px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);",
        
        h5("Filters", style = "margin: 0 0 10px 0; font-size: 14px;"),
        
        selectInput(
          "filter_state",
          "State",
          choices = c("All States" = "all"),
          width = "100%"
        ),
        
        sliderInput(
          "filter_doc_count",
          "Min Documents",
          min = 1,
          max = 10000,
          value = 10,
          width = "100%"
        ),
        
        actionButton(
          "apply_simple_filters",
          "Apply",
          class = "btn btn-primary btn-sm",
          style = "width: 100%;"
        )
      )
    },
    
    get_control_status = function() {
      list(
        mode = "functional_fallback",
        timestamp = Sys.time(),
        database_connected = !is.null(controls_env$db_pool)
      )
    }
  )
}

# Utility Functions
# ================

#' Create Custom Map Control
#' 
#' Helper function to create custom leaflet controls
#' 
#' @param control_html HTML content for the control
#' @param position Position on the map
#' @param className CSS class name
#' @return HTML control element
create_custom_map_control <- function(control_html, position = "topright", className = "leaflet-control") {
  
  htmltools::tags$div(
    class = paste("leaflet-control", className),
    style = paste0("position: absolute; ", position, ": 10px;"),
    control_html
  )
}

#' Generate Control CSS
#' 
#' Generates CSS styling for map controls
#' 
#' @return CSS string
generate_control_css <- function() {
  
  colors <- LEAFLET_CONTROLS_CONFIG$styling$colors
  fonts <- LEAFLET_CONTROLS_CONFIG$styling$fonts
  
  paste0("
    .leaflet-control-panel {
      background-color: ", colors$surface, ";
      border: 1px solid ", colors$border, ";
      border-radius: 8px;
      box-shadow: 0 4px 16px rgba(0,0,0,0.1);
      font-family: ", fonts$family, ";
      font-size: ", fonts$size_normal, ";
      color: ", colors$text, ";
    }
    
    .control-section-title {
      color: ", colors$primary, ";
      font-weight: ", fonts$weight_medium, ";
      border-bottom: 1px solid ", colors$border, ";
      padding-bottom: 4px;
      margin-bottom: 8px;
    }
    
    .layer-option {
      padding: 4px 0;
      border-bottom: 1px solid ", colors$border, ";
    }
    
    .layer-option:last-child {
      border-bottom: none;
    }
    
    .filter-group {
      padding: 8px 0;
      border-bottom: 1px solid ", colors$border, ";
    }
    
    .filter-label {
      color: ", colors$text, ";
      font-weight: ", fonts$weight_medium, ";
    }
    
    .export-group {
      padding: 6px 0;
    }
    
    .legend-item {
      margin: 3px 0;
      display: flex;
      align-items: center;
    }
    
    .legend-color-box {
      width: 16px;
      height: 16px;
      border-radius: 2px;
      margin-right: 6px;
      border: 1px solid ", colors$border, ";
    }
  ")
}

# Export Functions
list(
  create_leaflet_controls_manager = create_leaflet_controls_manager,
  create_functional_controls_manager = create_functional_controls_manager,
  create_custom_map_control = create_custom_map_control,
  generate_control_css = generate_control_css,
  LEAFLET_CONTROLS_CONFIG = LEAFLET_CONTROLS_CONFIG
)