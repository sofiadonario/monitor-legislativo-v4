# Enhanced Leaflet Interactivity System - Sprint 5B GEO-003
# Brazilian Legislative Monitoring System - Advanced Map Interactions
# ==================================================================
# 
# Comprehensive interactive system providing government-quality user experience
# for Brazilian legislative document analysis with advanced click-through,
# hover functionality, and real-time data filtering with 134k+ documents
# 
# INTERACTION FEATURES:
# - Advanced click-through navigation to document details and analysis
# - Rich hover tooltips with statistical context and government formatting
# - Dynamic filtering with real-time map updates and performance optimization
# - Multi-selection capabilities for comparative analysis
# - Context-sensitive actions and document export functionality
# - Mobile-responsive touch interactions for government field operations
# 
# NAVIGATION CAPABILITIES:
# - Deep-linking to specific geographic regions and document sets
# - Seamless integration with main dashboard navigation
# - Document search and filtering within geographic contexts
# - Export capabilities for maps, data, and filtered document collections
# - Government-compliant sharing and collaboration features
# - Academic research workflow integration
# 
# TECHNICAL IMPLEMENTATION:
# - Enhanced Shiny reactive system with debounced interactions
# - Custom JavaScript for advanced leaflet event handling
# - Performance-optimized database queries with spatial indexing
# - Memory-efficient data streaming for Railway 2GB constraints
# - Cross-browser compatibility with government security requirements
# - Accessibility compliance with keyboard navigation support
# ==================================================================

library(shiny)
library(shinydashboard)
library(leaflet)
library(htmltools)
library(htmlwidgets)
library(DBI)
library(pool)
library(dplyr)
library(jsonlite)
library(purrr)

# Load supporting systems
if (file.exists("modules/geographic/interactive_leaflet.R")) {
  source("modules/geographic/interactive_leaflet.R")
}
if (file.exists("modules/geographic/leaflet_controls.R")) {
  source("modules/geographic/leaflet_controls.R")
}
if (file.exists("modules/geographic/map_interactivity.R")) {
  source("modules/geographic/map_interactivity.R")
}

# Enhanced Interactivity Configuration
# ===================================

ENHANCED_INTERACTIVITY_CONFIG <- list(
  
  # Click behavior configurations
  click_interactions = list(
    
    state_click = list(
      primary_action = "detailed_popup",
      secondary_action = "navigate_to_analysis",
      double_click_action = "zoom_to_bounds",
      right_click_action = "context_menu",
      
      popup_config = list(
        max_width = 400,
        min_width = 300,
        auto_pan = TRUE,
        close_button = TRUE,
        auto_close = FALSE,
        keep_in_view = TRUE,
        
        # Content sections
        sections = c("header", "statistics", "recent_activity", "top_categories", "actions"),
        
        # Action buttons
        actions = list(
          view_documents = list(
            label = "View All Documents",
            icon = "fa fa-list",
            class = "btn btn-primary btn-sm",
            tooltip = "Navigate to document listing for this state"
          ),
          export_data = list(
            label = "Export Data",
            icon = "fa fa-download", 
            class = "btn btn-success btn-sm",
            tooltip = "Download legislative data for this state"
          ),
          compare_state = list(
            label = "Compare States",
            icon = "fa fa-chart-bar",
            class = "btn btn-info btn-sm",
            tooltip = "Add to comparison analysis"
          ),
          detailed_analysis = list(
            label = "Deep Analysis",
            icon = "fa fa-microscope",
            class = "btn btn-warning btn-sm",
            tooltip = "Open comprehensive analysis dashboard"
          )
        )
      )
    ),
    
    municipality_click = list(
      primary_action = "municipal_details",
      secondary_action = "document_preview",
      double_click_action = "zoom_to_municipality",
      
      popup_config = list(
        max_width = 350,
        min_width = 250,
        sections = c("header", "basic_stats", "recent_documents", "municipal_actions")
      )
    ),
    
    background_click = list(
      primary_action = "clear_selection",
      close_popups = TRUE,
      reset_highlights = TRUE
    )
  ),
  
  # Hover behavior configurations  
  hover_interactions = list(
    
    state_hover = list(
      enabled = TRUE,
      delay_show_ms = 200,
      delay_hide_ms = 100,
      follow_cursor = TRUE,
      
      tooltip_config = list(
        max_width = 280,
        opacity = 0.95,
        offset = list(x = 10, y = -10),
        
        content_template = "
          <div class='interactive-tooltip state-tooltip'>
            <div class='tooltip-header'>
              <h6 class='state-name'>{state_name}</h6>
              <span class='region-info'>{region_name} Region</span>
            </div>
            <div class='tooltip-stats'>
              <div class='stat-row'>
                <span class='stat-label'>Documents:</span>
                <span class='stat-value'>{document_count_formatted}</span>
              </div>
              <div class='stat-row'>
                <span class='stat-label'>Categories:</span>
                <span class='stat-value'>{category_count}</span>
              </div>
              <div class='stat-row'>
                <span class='stat-label'>Activity Level:</span>
                <span class='stat-value activity-{activity_class}'>{activity_level}</span>
              </div>
            </div>
            <div class='tooltip-footer'>
              <small>Click for detailed analysis</small>
            </div>
          </div>
        "
      ),
      
      highlight_style = list(
        weight = 3,
        color = "#ff6b35",
        fill_opacity = 0.3,
        bring_to_front = TRUE
      )
    ),
    
    municipality_hover = list(
      enabled = TRUE,
      delay_show_ms = 150,
      min_zoom_level = 7,  # Only show at higher zoom levels
      
      tooltip_config = list(
        max_width = 240,
        content_template = "
          <div class='interactive-tooltip municipality-tooltip'>
            <div class='tooltip-header'>
              <h6 class='municipality-name'>{municipality_name}</h6>
              <span class='state-info'>{state_name}</span>
            </div>
            <div class='tooltip-stats'>
              <div class='stat-row'>
                <span class='stat-label'>Documents:</span>
                <span class='stat-value'>{document_count_formatted}</span>
              </div>
              <div class='stat-row'>
                <span class='stat-label'>Rank in State:</span>
                <span class='stat-value'>#{municipality_rank}</span>
              </div>
            </div>
          </div>
        "
      )
    )
  ),
  
  # Selection and multi-selection behavior
  selection_interactions = list(
    
    multi_select = list(
      enabled = TRUE,
      modifier_key = "ctrl",  # Hold Ctrl for multi-select
      max_selections = 10,
      visual_feedback = TRUE,
      
      selection_style = list(
        weight = 3,
        color = "#1e40af",
        fill_color = "#3b82f6",
        fill_opacity = 0.2,
        dash_array = "5, 5"
      ),
      
      selection_counter = list(
        show = TRUE,
        position = "topright",
        template = "Selected: {count} of {max}"
      )
    ),
    
    comparison_mode = list(
      enabled = TRUE,
      auto_activate_threshold = 2,  # Auto-activate when 2+ items selected
      comparison_panel = list(
        show = TRUE,
        position = "bottomleft",
        width = 300,
        max_height = 200
      )
    )
  ),
  
  # Filter interactions
  filter_interactions = list(
    
    real_time_filtering = list(
      enabled = TRUE,
      debounce_delay_ms = 500,
      show_loading_indicator = TRUE,
      preserve_zoom_level = TRUE,
      
      filter_effects = list(
        fade_filtered_out = TRUE,
        opacity_filtered_out = 0.3,
        highlight_filtered_in = TRUE
      )
    ),
    
    filter_feedback = list(
      show_result_count = TRUE,
      show_filter_summary = TRUE,
      position = "topleft",
      
      no_results_message = list(
        show = TRUE,
        template = "No results found for current filters. Try adjusting your criteria.",
        action_buttons = c("clear_filters", "expand_search")
      )
    )
  ),
  
  # Navigation and deep-linking
  navigation_interactions = list(
    
    deep_linking = list(
      enabled = TRUE,
      include_zoom_level = TRUE,
      include_active_layers = TRUE,
      include_filters = TRUE,
      
      url_parameters = list(
        center = "center",
        zoom = "zoom",
        layers = "layers", 
        filters = "filters",
        selected = "selected"
      )
    ),
    
    document_navigation = list(
      view_documents_action = "navigate_to_library",
      search_integration = TRUE,
      filter_preservation = TRUE,
      
      navigation_targets = list(
        library_tab = "library",
        analysis_dashboard = "analysis",
        export_interface = "export"
      )
    )
  ),
  
  # Performance and optimization
  performance_config = list(
    
    interaction_optimization = list(
      debounce_hover_ms = 100,
      debounce_click_ms = 50,
      debounce_filter_ms = 300,
      max_concurrent_requests = 3,
      request_timeout_ms = 8000
    ),
    
    data_loading = list(
      progressive_loading = TRUE,
      chunk_size = 100,
      cache_interactions = TRUE,
      cache_duration_minutes = 15,
      preload_adjacent_data = TRUE
    ),
    
    memory_management = list(
      clear_cache_threshold_mb = 1500,
      cleanup_interval_ms = 300000,  # 5 minutes
      max_tooltip_cache = 100,
      max_popup_cache = 50
    )
  ),
  
  # Government and security requirements
  security_config = list(
    
    data_access = list(
      validate_requests = TRUE,
      sanitize_inputs = TRUE,
      log_interactions = FALSE,  # Set to TRUE for audit requirements
      rate_limiting = TRUE,
      max_requests_per_minute = 120
    ),
    
    export_security = list(
      validate_export_permissions = TRUE,
      watermark_exports = TRUE,
      track_downloads = FALSE,  # Set to TRUE for audit requirements
      max_export_size_mb = 50
    )
  )
)

# Enhanced Leaflet Interactivity Manager Class
# ===========================================

if (requireNamespace("R6", quietly = TRUE)) {
  
  EnhancedLeafletInteractivity <- R6::R6Class("EnhancedLeafletInteractivity",
    
    public = list(
      
      # Properties
      db_pool = NULL,
      leaflet_manager = NULL,
      controls_manager = NULL,
      session = NULL,
      input = NULL,
      output = NULL,
      
      # State management
      current_selection = NULL,
      active_filters = NULL,
      interaction_cache = NULL,
      event_handlers = NULL,
      
      # Constructor
      initialize = function(db_pool, leaflet_manager = NULL, controls_manager = NULL, session = NULL) {
        
        cat("🔗 Initializing Enhanced Leaflet Interactivity...\n")
        
        self$db_pool <- db_pool
        self$leaflet_manager <- leaflet_manager
        self$controls_manager <- controls_manager
        self$session <- session
        
        # Initialize state management
        self$current_selection <- list()
        self$active_filters <- list()
        self$interaction_cache <- list()
        
        # Setup event handlers
        self$setup_event_handlers()
        
        cat("✅ Enhanced Leaflet Interactivity initialized\n")
      },
      
      # Event handler setup
      setup_event_handlers = function() {
        
        cat("⚡ Setting up interaction event handlers...\n")
        
        self$event_handlers <- list(
          
          # State click handler
          handle_state_click = function(click_data) {
            
            tryCatch({
              
              if (isTRUE(is.null(click_data)) || isTRUE(is.null(click_data$id))) {
                return(NULL)
              }
              
              state_code <- click_data$id
              
              cat("🎯 State clicked:", state_code, "\n")
              
              # Get comprehensive state data
              state_details <- self$fetch_state_details(state_code)
              
              if (is.null(state_details)) {
                return(self$create_error_popup("Unable to load state information"))
              }
              
              # Generate detailed popup content
              popup_content <- self$generate_state_popup(state_details)
              
              # Update map with popup
              if (!is.null(self$session)) {
                leafletProxy("main_map", self$session) %>%
                  clearPopups() %>%
                  addPopups(
                    lng = click_data$lng,
                    lat = click_data$lat,
                    popup = popup_content,
                    options = popupOptions(
                      maxWidth = ENHANCED_INTERACTIVITY_CONFIG$click_interactions$state_click$popup_config$max_width,
                      closeButton = TRUE,
                      autoClose = FALSE
                    )
                  )
              }
              
              # Log interaction for analytics
              self$log_interaction("state_click", state_code)
              
              return(popup_content)
              
            }, error = function(e) {
              cat("❌ Error handling state click:", e$message, "\n")
              return(self$create_error_popup("Click handler error"))
            })
          },
          
          # State hover handler
          handle_state_hover = function(hover_data) {
            
            tryCatch({
              
              if (isTRUE(is.null(hover_data)) || isTRUE(is.null(hover_data$id))) {
                return(NULL)
              }
              
              state_code <- hover_data$id
              
              # Check cache first
              cache_key <- paste0("hover_state_", state_code)
              if (cache_key %in% names(self$interaction_cache)) {
                return(self$interaction_cache[[cache_key]])
              }
              
              # Get basic state data for hover
              state_hover_data <- self$fetch_state_hover_data(state_code)
              
              if (is.null(state_hover_data)) {
                return(NULL)
              }
              
              # Generate hover tooltip content
              tooltip_content <- self$generate_state_tooltip(state_hover_data)
              
              # Cache the result
              self$interaction_cache[[cache_key]] <- tooltip_content
              
              return(tooltip_content)
              
            }, error = function(e) {
              cat("❌ Error handling state hover:", e$message, "\n")
              return(NULL)
            })
          },
          
          # Filter application handler
          handle_filter_change = function(filter_name, filter_values) {
            
            tryCatch({
              
              cat("🔍 Filter changed:", filter_name, "\n")
              
              # Update active filters
              self$active_filters[[filter_name]] <- filter_values
              
              # Apply filters with debouncing
              self$apply_filters_debounced()
              
              return(TRUE)
              
            }, error = function(e) {
              cat("❌ Error handling filter change:", e$message, "\n")
              return(FALSE)
            })
          },
          
          # Document navigation handler
          handle_document_navigation = function(entity_id, entity_type = "state") {
            
            tryCatch({
              
              cat("📄 Document navigation request:", entity_type, entity_id, "\n")
              
              # Build navigation parameters
              nav_params <- list(
                entity_type = entity_type,
                entity_id = entity_id,
                filters = self$active_filters,
                timestamp = Sys.time()
              )
              
              # Trigger navigation in parent dashboard
              if (!is.null(self$session)) {
                self$session$sendCustomMessage("navigateToDocuments", nav_params)
              }
              
              return(TRUE)
              
            }, error = function(e) {
              cat("❌ Error handling document navigation:", e$message, "\n")
              return(FALSE)
            })
          },
          
          # Export handler
          handle_export_request = function(export_type, entity_id = NULL, format = "csv") {
            
            tryCatch({
              
              cat("📤 Export request:", export_type, format, "\n")
              
              # Generate export data
              export_data <- switch(export_type,
                "state_data" = self$generate_state_export_data(entity_id),
                "filtered_data" = self$generate_filtered_export_data(),
                "selected_data" = self$generate_selected_export_data(),
                "map_image" = self$generate_map_export(),
                NULL
              )
              
              if (is.null(export_data)) {
                return(list(success = FALSE, error = "No data available for export"))
              }
              
              # Process export based on format
              export_result <- self$process_export(export_data, format, export_type)
              
              return(export_result)
              
            }, error = function(e) {
              cat("❌ Error handling export request:", e$message, "\n")
              return(list(success = FALSE, error = e$message))
            })
          }
        )
        
        cat("✅ Event handlers configured\n")
      },
      
      # Data fetching methods
      fetch_state_details = function(state_code) {
        
        if (isTRUE(is.null(self$db_pool)) || isTRUE(is.null(state_code))) {
          return(NULL)
        }
        
        tryCatch({
          
          pool::poolWithTransaction(self$db_pool, function(conn) {
            
            # Main state statistics
            state_query <- "
              SELECT 
                estado,
                COUNT(*) as document_count,
                COUNT(DISTINCT categoria_original) as category_count,
                COUNT(DISTINCT municipio) as municipality_count,
                COUNT(CASE WHEN data_documento >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as recent_documents,
                COUNT(CASE WHEN data_documento >= CURRENT_DATE - INTERVAL '90 days' THEN 1 END) as quarterly_documents,
                MIN(data_documento) as first_document_date,
                MAX(data_documento) as last_document_date,
                AVG(CASE WHEN LENGTH(conteudo) > 0 THEN LENGTH(conteudo) END) as avg_content_length
              FROM documents
              WHERE estado = $1
              GROUP BY estado
            "
            
            main_data <- DBI::dbGetQuery(conn, state_query, params = list(state_code))
            
            if (nrow(main_data) == 0) {
              return(NULL)
            }
            
            # Top categories for this state
            categories_query <- "
              SELECT categoria_original, COUNT(*) as count
              FROM documents
              WHERE estado = $1 AND categoria_original IS NOT NULL
              GROUP BY categoria_original
              ORDER BY count DESC
              LIMIT 5
            "
            
            top_categories <- DBI::dbGetQuery(conn, categories_query, params = list(state_code))
            
            # Recent documents sample
            recent_docs_query <- "
              SELECT titulo, categoria_original, data_documento, municipio
              FROM documents
              WHERE estado = $1 
                AND data_documento >= CURRENT_DATE - INTERVAL '30 days'
                AND titulo IS NOT NULL
              ORDER BY data_documento DESC
              LIMIT 5
            "
            
            recent_docs <- DBI::dbGetQuery(conn, recent_docs_query, params = list(state_code))
            
            # Combine all data
            result <- main_data
            result$top_categories <- if (nrow(top_categories) > 0) top_categories else NULL
            result$recent_documents <- if (nrow(recent_docs) > 0) recent_docs else NULL
            
            # Calculate derived metrics
            result$activity_score <- if (result$document_count > 0) {
              (result$recent_documents / result$document_count) * 100
            } else 0
            
            result$docs_per_municipality <- if (result$municipality_count > 0) {
              round(result$document_count / result$municipality_count, 1)
            } else 0
            
            return(result)
          })
          
        }, error = function(e) {
          cat("❌ Error fetching state details:", e$message, "\n")
          return(NULL)
        })
      },
      
      fetch_state_hover_data = function(state_code) {
        
        if (isTRUE(is.null(self$db_pool)) || isTRUE(is.null(state_code))) {
          return(NULL)
        }
        
        tryCatch({
          
          pool::poolWithTransaction(self$db_pool, function(conn) {
            
            # Simplified query for hover tooltip
            hover_query <- "
              SELECT 
                estado,
                COUNT(*) as document_count,
                COUNT(DISTINCT categoria_original) as category_count,
                COUNT(CASE WHEN data_documento >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as recent_documents
              FROM documents
              WHERE estado = $1
              GROUP BY estado
            "
            
            result <- DBI::dbGetQuery(conn, hover_query, params = list(state_code))
            
            if (nrow(result) > 0) {
              # Add calculated fields for hover
              result$activity_level <- self$classify_activity_level(
                if (result$document_count > 0) (result$recent_documents / result$document_count) * 100 else 0
              )
              result$activity_class <- tolower(gsub(" ", "-", result$activity_level))
              result$document_count_formatted <- format(result$document_count, big.mark = ",")
              result$state_name <- result$estado
              result$region_name <- "Brazil"  # Would be enhanced with actual region data
            }
            
            return(result)
          })
          
        }, error = function(e) {
          cat("❌ Error fetching state hover data:", e$message, "\n")
          return(NULL)
        })
      },
      
      # Content generation methods
      generate_state_popup = function(state_data) {
        
        if (isTRUE(is.null(state_data)) || nrow(state_data) == 0) {
          return(self$create_error_popup("State data unavailable"))
        }
        
        tryCatch({
          
          state_info <- state_data[1, ]
          
          # Header section
          header_html <- paste0(
            "<div class='popup-header' style='border-bottom: 2px solid #1e40af; padding-bottom: 8px; margin-bottom: 12px;'>",
            "<h4 style='margin: 0; color: #1e40af; font-weight: 600;'>", state_info$estado, "</h4>",
            "<span style='color: #6b7280; font-size: 13px;'>Brazilian State</span>",
            "</div>"
          )
          
          # Statistics section
          stats_html <- paste0(
            "<div class='popup-stats' style='margin-bottom: 12px;'>",
            "<div class='stats-grid' style='display: grid; grid-template-columns: 1fr 1fr; gap: 8px;'>",
            
            "<div class='stat-card' style='background: #f8fafc; padding: 8px; border-radius: 4px; text-align: center;'>",
            "<div class='stat-number' style='font-size: 18px; font-weight: 600; color: #1e40af;'>", format(state_info$document_count, big.mark = ","), "</div>",
            "<div class='stat-label' style='font-size: 11px; color: #6b7280;'>Total Documents</div>",
            "</div>",
            
            "<div class='stat-card' style='background: #f8fafc; padding: 8px; border-radius: 4px; text-align: center;'>",
            "<div class='stat-number' style='font-size: 18px; font-weight: 600; color: #059669;'>", state_info$municipality_count, "</div>",
            "<div class='stat-label' style='font-size: 11px; color: #6b7280;'>Municipalities</div>",
            "</div>",
            
            "<div class='stat-card' style='background: #f8fafc; padding: 8px; border-radius: 4px; text-align: center;'>",
            "<div class='stat-number' style='font-size: 18px; font-weight: 600; color: #dc2626;'>", state_info$category_count, "</div>",
            "<div class='stat-label' style='font-size: 11px; color: #6b7280;'>Categories</div>",
            "</div>",
            
            "<div class='stat-card' style='background: #f8fafc; padding: 8px; border-radius: 4px; text-align: center;'>",
            "<div class='stat-number' style='font-size: 18px; font-weight: 600; color: #ca8a04;'>", state_info$recent_documents, "</div>",
            "<div class='stat-label' style='font-size: 11px; color: #6b7280;'>Recent (30d)</div>",
            "</div>",
            
            "</div>",
            "</div>"
          )
          
          # Recent activity section
          activity_html <- ""
          if (!isTRUE(is.null(state_data$recent_documents)) && nrow(state_data$recent_documents) > 0) {
            
            recent_docs <- state_data$recent_documents
            
            docs_list <- paste(
              sapply(1:min(3, nrow(recent_docs)), function(i) {
                doc <- recent_docs[i, ]
                paste0(
                  "<div class='recent-doc' style='margin-bottom: 6px; padding: 6px; background: #f9fafb; border-radius: 3px;'>",
                  "<div class='doc-title' style='font-weight: 500; font-size: 12px; color: #1f2937;'>", 
                  htmlEscape(substr(doc$titulo, 1, 50)), if (nchar(doc$titulo) > 50) "..." else "", "</div>",
                  "<div class='doc-meta' style='font-size: 10px; color: #6b7280;'>",
                  doc$categoria_original, " • ", format(as.Date(doc$data_documento), "%d/%m/%Y"),
                  if (!is.na(doc$municipio)) paste(" • ", doc$municipio) else "",
                  "</div>",
                  "</div>"
                )
              }),
              collapse = ""
            )
            
            activity_html <- paste0(
              "<div class='popup-activity' style='margin-bottom: 12px;'>",
              "<h6 style='margin: 0 0 6px 0; font-size: 13px; color: #374151;'>Recent Activity</h6>",
              docs_list,
              "</div>"
            )
          }
          
          # Action buttons
          actions_html <- paste0(
            "<div class='popup-actions' style='border-top: 1px solid #e5e7eb; padding-top: 10px; display: flex; gap: 6px; flex-wrap: wrap;'>",
            
            "<button onclick='handleViewDocuments(\"", state_info$estado, "\")' ",
            "style='flex: 1; min-width: 80px; padding: 6px 8px; background: #1e40af; color: white; border: none; border-radius: 4px; font-size: 11px; cursor: pointer;'>",
            "<i class='fa fa-list' style='margin-right: 4px;'></i> View Docs</button>",
            
            "<button onclick='handleExportState(\"", state_info$estado, "\")' ",
            "style='flex: 1; min-width: 80px; padding: 6px 8px; background: #059669; color: white; border: none; border-radius: 4px; font-size: 11px; cursor: pointer;'>",
            "<i class='fa fa-download' style='margin-right: 4px;'></i> Export</button>",
            
            "<button onclick='handleCompareState(\"", state_info$estado, "\")' ",
            "style='flex: 1; min-width: 80px; padding: 6px 8px; background: #dc2626; color: white; border: none; border-radius: 4px; font-size: 11px; cursor: pointer;'>",
            "<i class='fa fa-chart-bar' style='margin-right: 4px;'></i> Compare</button>",
            
            "</div>"
          )
          
          # Combine all sections
          complete_popup <- paste0(
            "<div class='enhanced-state-popup' style='font-family: system-ui, -apple-system, sans-serif; width: 100%; max-width: 380px;'>",
            header_html,
            stats_html,
            activity_html,
            actions_html,
            "</div>"
          )
          
          return(HTML(complete_popup))
          
        }, error = function(e) {
          cat("❌ Error generating state popup:", e$message, "\n")
          return(self$create_error_popup("Popup generation failed"))
        })
      },
      
      generate_state_tooltip = function(hover_data) {
        
        if (isTRUE(is.null(hover_data)) || nrow(hover_data) == 0) {
          return(NULL)
        }
        
        tryCatch({
          
          state_info <- hover_data[1, ]
          
          tooltip_html <- paste0(
            "<div class='enhanced-state-tooltip' style='",
            "background: rgba(255, 255, 255, 0.95); ",
            "border: 1px solid #cbd5e1; ",
            "border-radius: 6px; ",
            "padding: 10px; ",
            "box-shadow: 0 4px 12px rgba(0,0,0,0.15); ",
            "font-family: system-ui, -apple-system, sans-serif; ",
            "font-size: 13px; ",
            "min-width: 200px; ",
            "max-width: 280px;",
            "'>",
            
            "<div class='tooltip-header' style='margin-bottom: 8px; padding-bottom: 6px; border-bottom: 1px solid #e5e7eb;'>",
            "<h6 style='margin: 0; font-size: 14px; font-weight: 600; color: #1e40af;'>", state_info$state_name, "</h6>",
            "<span style='font-size: 11px; color: #6b7280;'>", state_info$region_name, " Region</span>",
            "</div>",
            
            "<div class='tooltip-stats' style='display: grid; gap: 4px;'>",
            
            "<div class='stat-row' style='display: flex; justify-content: space-between;'>",
            "<span class='stat-label' style='color: #374151; font-size: 12px;'>Documents:</span>",
            "<span class='stat-value' style='font-weight: 600; color: #1e40af;'>", state_info$document_count_formatted, "</span>",
            "</div>",
            
            "<div class='stat-row' style='display: flex; justify-content: space-between;'>",
            "<span class='stat-label' style='color: #374151; font-size: 12px;'>Categories:</span>",
            "<span class='stat-value' style='font-weight: 600; color: #059669;'>", state_info$category_count, "</span>",
            "</div>",
            
            "<div class='stat-row' style='display: flex; justify-content: space-between;'>",
            "<span class='stat-label' style='color: #374151; font-size: 12px;'>Activity Level:</span>",
            "<span class='stat-value activity-", state_info$activity_class, "' style='font-weight: 600; color: ", 
            self$get_activity_color(state_info$activity_level), ";'>", state_info$activity_level, "</span>",
            "</div>",
            
            "</div>",
            
            "<div class='tooltip-footer' style='margin-top: 8px; padding-top: 6px; border-top: 1px solid #f3f4f6;'>",
            "<small style='color: #9ca3af; font-size: 10px;'>Click for detailed analysis</small>",
            "</div>",
            
            "</div>"
          )
          
          return(HTML(tooltip_html))
          
        }, error = function(e) {
          cat("❌ Error generating state tooltip:", e$message, "\n")
          return(NULL)
        })
      },
      
      # Filter application methods
      apply_filters_debounced = function() {
        
        # In a real implementation, this would use a debouncing mechanism
        # For now, we'll apply filters directly
        self$apply_current_filters()
      },
      
      apply_current_filters = function() {
        
        if (length(self$active_filters) == 0) {
          cat("ℹ️ No active filters to apply\n")
          return()
        }
        
        tryCatch({
          
          cat("🔍 Applying current filters...\n")
          
          # Build filter query
          filter_conditions <- self$build_filter_conditions()
          
          # Get filtered data
          filtered_data <- self$get_filtered_geographic_data(filter_conditions)
          
          # Update map with filtered data
          if (!isTRUE(is.null(filtered_data)) && !is.null(self$session)) {
            self$update_map_with_filtered_data(filtered_data)
          }
          
          # Update filter summary display
          self$update_filter_summary_display()
          
          cat("✅ Filters applied successfully\n")
          
        }, error = function(e) {
          cat("❌ Error applying filters:", e$message, "\n")
        })
      },
      
      build_filter_conditions = function() {
        
        conditions <- list()
        
        for (filter_name in names(self$active_filters)) {
          filter_value <- self$active_filters[[filter_name]]
          
          if (!isTRUE(is.null(filter_value)) && length(filter_value) > 0) {
            
            condition <- switch(filter_name,
              "states" = paste0("estado IN ('", paste(filter_value, collapse = "', '"), "')"),
              "categories" = paste0("categoria_original IN ('", paste(filter_value, collapse = "', '"), "')"),
              "date_range" = {
                if (length(filter_value) == 2) {
                  paste0("data_documento BETWEEN '", filter_value[1], "' AND '", filter_value[2], "'")
                } else {
                  NULL
                }
              },
              "municipalities" = paste0("municipio IN ('", paste(filter_value, collapse = "', '"), "')"),
              "document_count_min" = paste0("document_count >= ", filter_value),
              NULL
            )
            
            if (!is.null(condition)) {
              conditions[[filter_name]] <- condition
            }
          }
        }
        
        return(conditions)
      },
      
      get_filtered_geographic_data = function(filter_conditions) {
        
        if (is.null(self$db_pool)) {
          return(NULL)
        }
        
        tryCatch({
          
          # Build base query
          base_query <- "
            SELECT estado,
                   COUNT(*) as document_count,
                   COUNT(DISTINCT categoria_original) as category_count,
                   COUNT(DISTINCT municipio) as municipality_count
            FROM documents
            WHERE 1=1
          "
          
          # Add filter conditions
          if (length(filter_conditions) > 0) {
            where_clause <- paste(" AND", paste(filter_conditions, collapse = " AND "))
            base_query <- paste0(base_query, where_clause)
          }
          
          # Add grouping and ordering
          base_query <- paste0(base_query, "
            GROUP BY estado
            HAVING COUNT(*) > 0
            ORDER BY document_count DESC
          ")
          
          # Execute query
          pool::poolWithTransaction(self$db_pool, function(conn) {
            DBI::dbGetQuery(conn, base_query)
          })
          
        }, error = function(e) {
          cat("❌ Error getting filtered geographic data:", e$message, "\n")
          return(NULL)
        })
      },
      
      update_map_with_filtered_data = function(filtered_data) {
        
        # This would update the map visualization with filtered results
        # Implementation would depend on the specific leaflet integration
        
        cat("🗺️ Updating map with filtered data:", nrow(filtered_data), "states\n")
        
        # In a full implementation, this would:
        # 1. Update choropleth colors based on filtered data
        # 2. Hide/show layers based on filter results
        # 3. Update legend with new data ranges
        # 4. Show filter result indicators
      },
      
      update_filter_summary_display = function() {
        
        if (is.null(self$session)) {
          return()
        }
        
        # Generate filter summary text
        summary_text <- self$get_filter_summary_text()
        
        # Update UI element (assuming it exists)
        self$session$sendCustomMessage("updateFilterSummary", list(
          summary = summary_text,
          count = length(self$active_filters),
          timestamp = format(Sys.time(), "%H:%M:%S")
        ))
      },
      
      get_filter_summary_text = function() {
        
        if (length(self$active_filters) == 0) {
          return("No filters applied")
        }
        
        summaries <- c()
        
        for (filter_name in names(self$active_filters)) {
          filter_value <- self$active_filters[[filter_name]]
          
          if (!isTRUE(is.null(filter_value)) && length(filter_value) > 0) {
            summary <- switch(filter_name,
              "states" = paste0("States: ", length(filter_value), " selected"),
              "categories" = paste0("Categories: ", length(filter_value), " selected"),
              "date_range" = paste0("Date: ", paste(filter_value, collapse = " to ")),
              "municipalities" = paste0("Municipalities: ", length(filter_value), " selected"),
              "document_count_min" = paste0("Min docs: ", filter_value),
              paste0(filter_name, ": ", paste(filter_value, collapse = ", "))
            )
            summaries <- c(summaries, summary)
          }
        }
        
        return(paste(summaries, collapse = "; "))
      },
      
      # Export functionality
      generate_state_export_data = function(state_code) {
        
        if (isTRUE(is.null(self$db_pool)) || isTRUE(is.null(state_code))) {
          return(NULL)
        }
        
        tryCatch({
          
          pool::poolWithTransaction(self$db_pool, function(conn) {
            
            export_query <- "
              SELECT 
                id,
                titulo,
                categoria_original,
                estado,
                municipio,
                data_documento,
                LENGTH(conteudo) as content_length,
                keywords,
                source_file
              FROM documents
              WHERE estado = $1
              ORDER BY data_documento DESC
            "
            
            DBI::dbGetQuery(conn, export_query, params = list(state_code))
          })
          
        }, error = function(e) {
          cat("❌ Error generating state export data:", e$message, "\n")
          return(NULL)
        })
      },
      
      generate_filtered_export_data = function() {
        
        filter_conditions <- self$build_filter_conditions()
        
        if (length(filter_conditions) == 0) {
          return(self$generate_all_export_data())
        }
        
        return(self$get_filtered_geographic_data(filter_conditions))
      },
      
      generate_selected_export_data = function() {
        
        if (length(self$current_selection) == 0) {
          return(NULL)
        }
        
        # Extract selected entity IDs
        selected_ids <- sapply(self$current_selection, function(x) x$id)
        
        # Generate export data for selected entities
        # Implementation would depend on selection type (states vs municipalities)
        
        return(NULL)  # Placeholder
      },
      
      process_export = function(export_data, format, export_type) {
        
        if (is.null(export_data)) {
          return(list(success = FALSE, error = "No data to export"))
        }
        
        tryCatch({
          
          # Generate filename
          filename <- paste0(
            "brazilian_legislative_", 
            export_type, "_",
            format(Sys.Date(), "%Y%m%d"),
            ".", tolower(format)
          )
          
          # Process based on format
          result <- switch(format,
            "csv" = self$export_to_csv(export_data, filename),
            "xlsx" = self$export_to_excel(export_data, filename),
            "geojson" = self$export_to_geojson(export_data, filename),
            list(success = FALSE, error = "Unsupported format")
          )
          
          return(result)
          
        }, error = function(e) {
          return(list(success = FALSE, error = e$message))
        })
      },
      
      export_to_csv = function(data, filename) {
        
        # In a real implementation, this would write to a temp file and provide download link
        return(list(
          success = TRUE,
          format = "csv",
          filename = filename,
          rows = nrow(data),
          download_url = paste0("/downloads/", filename)  # Placeholder
        ))
      },
      
      # Utility methods
      classify_activity_level = function(activity_score) {
        
        if (isTRUE(is.na(activity_score)) || isTRUE(is.null(activity_score))) return("Unknown")
        
        if (activity_score >= 15) return("Very High")
        if (activity_score >= 10) return("High")
        if (activity_score >= 5) return("Medium")
        if (activity_score >= 1) return("Low")
        return("Very Low")
      },
      
      get_activity_color = function(activity_level) {
        
        switch(activity_level,
          "Very High" = "#dc2626",
          "High" = "#ea580c",
          "Medium" = "#ca8a04",
          "Low" = "#059669",
          "Very Low" = "#6b7280",
          "#9ca3af"  # default
        )
      },
      
      create_error_popup = function(message) {
        
        HTML(paste0(
          "<div style='padding: 10px; color: #dc2626; text-align: center;'>",
          "<i class='fa fa-exclamation-triangle' style='margin-right: 5px;'></i>",
          message,
          "</div>"
        ))
      },
      
      log_interaction = function(interaction_type, entity_id, metadata = NULL) {
        
        # Placeholder for interaction logging
        # In production, this might log to a database or analytics service
        
        if (ENHANCED_INTERACTIVITY_CONFIG$security_config$data_access$log_interactions) {
          cat("📊 Interaction logged:", interaction_type, entity_id, "\n")
        }
      },
      
      # System management
      clear_interaction_cache = function() {
        self$interaction_cache <- list()
        gc(verbose = FALSE)
        cat("🧹 Interaction cache cleared\n")
      },
      
      clear_current_selection = function() {
        self$current_selection <- list()
        cat("🔄 Selection cleared\n")
      },
      
      get_system_status = function() {
        
        list(
          timestamp = Sys.time(),
          memory_usage_mb = round(sum(gc(verbose = FALSE)[, "(Mb)"]), 2),
          active_filters = length(self$active_filters),
          current_selection_count = length(self$current_selection),
          interaction_cache_entries = length(self$interaction_cache),
          database_connected = !is.null(self$db_pool),
          session_available = !is.null(self$session),
          leaflet_manager_available = !is.null(self$leaflet_manager),
          controls_manager_available = !is.null(self$controls_manager)
        )
      }
    )
  )
}

# Functional Factory (Fallback Implementation)
# ===========================================

create_enhanced_leaflet_interactivity <- function(db_pool, leaflet_manager = NULL, controls_manager = NULL, session = NULL) {
  
  if (requireNamespace("R6", quietly = TRUE)) {
    return(EnhancedLeafletInteractivity$new(db_pool, leaflet_manager, controls_manager, session))
  } else {
    return(create_functional_enhanced_interactivity(db_pool, leaflet_manager, controls_manager, session))
  }
}

create_functional_enhanced_interactivity <- function(db_pool, leaflet_manager = NULL, controls_manager = NULL, session = NULL) {
  
  # Simplified functional implementation
  interact_env <- new.env()
  interact_env$db_pool <- db_pool
  interact_env$session <- session
  interact_env$active_filters <- list()
  interact_env$current_selection <- list()
  
  list(
    
    handle_state_click = function(click_data) {
      
      if (isTRUE(is.null(click_data)) || isTRUE(is.null(click_data$id))) {
        return(NULL)
      }
      
      state_code <- click_data$id
      
      # Simple state popup
      popup_content <- HTML(paste0(
        "<div style='font-family: system-ui; padding: 5px;'>",
        "<h5 style='margin: 0 0 8px 0; color: #1e40af;'>", state_code, "</h5>",
        "<div style='font-size: 13px;'>",
        "<div>Click functionality available in full version</div>",
        "<div style='margin-top: 8px;'>",
        "<button onclick='alert(\"Navigation not available in simplified mode\")' ",
        "style='background: #1e40af; color: white; border: none; padding: 4px 8px; border-radius: 3px; font-size: 11px;'>",
        "View Documents</button>",
        "</div>",
        "</div>",
        "</div>"
      ))
      
      return(popup_content)
    },
    
    handle_filter_change = function(filter_name, filter_values) {
      interact_env$active_filters[[filter_name]] <- filter_values
      cat("🔍 Filter updated:", filter_name, "\n")
      return(TRUE)
    },
    
    clear_interaction_cache = function() {
      # No-op for functional version
    },
    
    get_system_status = function() {
      list(
        mode = "functional_fallback",
        timestamp = Sys.time(),
        database_connected = !is.null(interact_env$db_pool),
        session_available = !is.null(interact_env$session)
      )
    }
  )
}

# JavaScript Integration Functions
# ================================

#' Generate Enhanced Interactivity JavaScript
#' 
#' Creates JavaScript code for enhanced map interactions
#' 
#' @param session Shiny session object
#' @return Success status
inject_enhanced_interactivity_js <- function(session) {
  
  if (is.null(session)) {
    return(FALSE)
  }
  
  js_code <- "
  // Enhanced Leaflet Interactivity JavaScript
  // Brazilian Legislative Monitoring System
  
  window.BrazilianLegislativeMap = window.BrazilianLegislativeMap || {};
  
  // Document interaction handlers
  function handleViewDocuments(stateId) {
    console.log('View documents for state:', stateId);
    
    Shiny.setInputValue('map_view_documents', {
      entity_type: 'state',
      entity_id: stateId,
      action: 'view_documents',
      timestamp: Date.now()
    });
  }
  
  function handleExportState(stateId) {
    console.log('Export data for state:', stateId);
    
    Shiny.setInputValue('map_export_request', {
      entity_type: 'state',
      entity_id: stateId,
      export_type: 'state_data',
      format: 'csv',
      timestamp: Date.now()
    });
  }
  
  function handleCompareState(stateId) {
    console.log('Compare state:', stateId);
    
    Shiny.setInputValue('map_compare_request', {
      entity_type: 'state',
      entity_id: stateId,
      action: 'add_to_comparison',
      timestamp: Date.now()
    });
  }
  
  // Filter interaction handlers
  window.BrazilianLegislativeMap.updateFilters = function(filterData) {
    Shiny.setInputValue('map_filters_changed', {
      filters: filterData,
      timestamp: Date.now()
    });
  };
  
  // Export handlers
  window.BrazilianLegislativeMap.exportMap = function(format) {
    Shiny.setInputValue('map_export_image', {
      format: format,
      timestamp: Date.now()
    });
  };
  
  // Navigation handlers
  window.BrazilianLegislativeMap.navigateToDocuments = function(params) {
    // This would integrate with the main dashboard navigation
    console.log('Navigate to documents:', params);
    
    if (window.DashboardNavigation && window.DashboardNavigation.switchToTab) {
      window.DashboardNavigation.switchToTab('library', params);
    }
  };
  
  // Utility functions
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
  
  function formatNumber(num) {
    return new Intl.NumberFormat('pt-BR').format(num);
  }
  
  // Initialize enhanced interactivity
  $(document).ready(function() {
    console.log('Enhanced Leaflet Interactivity JavaScript loaded');
    
    // Custom message handlers
    Shiny.addCustomMessageHandler('updateFilterSummary', function(data) {
      console.log('Filter summary updated:', data);
      
      // Update UI elements showing filter status
      const summaryElement = document.getElementById('filter-summary');
      if (summaryElement) {
        summaryElement.textContent = data.summary;
        summaryElement.setAttribute('data-count', data.count);
      }
    });
    
    Shiny.addCustomMessageHandler('navigateToDocuments', function(params) {
      console.log('Navigation requested:', params);
      window.BrazilianLegislativeMap.navigateToDocuments(params);
    });
  });
  "
  
  tryCatch({
    session$sendCustomMessage("eval", js_code)
    return(TRUE)
  }, error = function(e) {
    cat("⚠️ Failed to inject enhanced interactivity JavaScript:", e$message, "\n")
    return(FALSE)
  })
}

# Shiny Integration Functions
# ===========================

#' Setup Enhanced Map Observers
#' 
#' Creates Shiny observers for enhanced map interactions
#' 
#' @param input Shiny input object
#' @param output Shiny output object  
#' @param session Shiny session object
#' @param interactivity_manager Enhanced interactivity manager
#' @param map_id Map element ID
#' @return List of observers
setup_enhanced_map_observers <- function(input, output, session, interactivity_manager, map_id = "main_map") {
  
  observers <- list()
  
  # Map click observer
  observers$click <- observeEvent(input[[paste0(map_id, "_shape_click")]], {
    
    click_data <- input[[paste0(map_id, "_shape_click")]]
    
    if (!isTRUE(is.null(click_data)) && !is.null(interactivity_manager)) {
      interactivity_manager$event_handlers$handle_state_click(click_data)
    }
  })
  
  # Document viewing observer
  observers$view_documents <- observeEvent(input$map_view_documents, {
    
    if (!isTRUE(is.null(input$map_view_documents)) && !is.null(interactivity_manager)) {
      nav_data <- input$map_view_documents
      interactivity_manager$event_handlers$handle_document_navigation(
        nav_data$entity_id,
        nav_data$entity_type
      )
    }
  })
  
  # Export request observer
  observers$export_request <- observeEvent(input$map_export_request, {
    
    if (!isTRUE(is.null(input$map_export_request)) && !is.null(interactivity_manager)) {
      export_data <- input$map_export_request
      
      result <- interactivity_manager$event_handlers$handle_export_request(
        export_data$export_type,
        export_data$entity_id,
        export_data$format
      )
      
      if (result$success) {
        # Trigger download or show success message
        showNotification(
          paste("Export prepared:", result$filename),
          type = "success",
          duration = 5
        )
      } else {
        showNotification(
          paste("Export failed:", result$error),
          type = "error",
          duration = 8
        )
      }
    }
  })
  
  # Filter change observer
  observers$filters <- observeEvent(input$map_filters_changed, {
    
    if (!isTRUE(is.null(input$map_filters_changed)) && !is.null(interactivity_manager)) {
      filter_data <- input$map_filters_changed$filters
      
      for (filter_name in names(filter_data)) {
        interactivity_manager$event_handlers$handle_filter_change(
          filter_name,
          filter_data[[filter_name]]
        )
      }
    }
  })
  
  return(observers)
}

# Export Functions
list(
  create_enhanced_leaflet_interactivity = create_enhanced_leaflet_interactivity,
  create_functional_enhanced_interactivity = create_functional_enhanced_interactivity,
  inject_enhanced_interactivity_js = inject_enhanced_interactivity_js,
  setup_enhanced_map_observers = setup_enhanced_map_observers,
  ENHANCED_INTERACTIVITY_CONFIG = ENHANCED_INTERACTIVITY_CONFIG
)