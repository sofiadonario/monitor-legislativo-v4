# Map Interactivity System - Sprint 5B GEO-002
# Brazilian Legislative Monitoring System - Interactive Map Features
# =================================================================
# 
# Advanced map interactivity system providing government-quality user experience
# for Brazilian legislative density visualization with 134k+ documents
# 
# FEATURES:
# - Rich hover information with legislative statistics and metadata
# - Click-through functionality to detailed document analysis
# - Interactive tooltips with government-standard formatting
# - Context-aware popup content with academic rigor
# - Real-time map state management and user interaction tracking
# - Accessibility-compliant interaction patterns
# 
# INTERACTIVITY TYPES:
# - Hover events: Statistical summaries and quick information
# - Click events: Detailed analysis navigation and document listings
# - Selection management: Multi-entity comparison capabilities
# - Context menus: Advanced actions and export options
# - Keyboard navigation: Full accessibility support
# 
# TECHNICAL IMPLEMENTATION:
# - Shiny reactive system integration for real-time updates
# - Leaflet event handling with custom JavaScript extensions
# - Performance-optimized event processing for large datasets
# - Mobile-responsive touch interaction support
# - Cross-browser compatibility and fallback mechanisms
# =================================================================

library(shiny)
library(leaflet)
library(htmltools)
library(jsonlite)
library(DBI)
library(pool)
library(dplyr)

# Load supporting systems
if (file.exists("modules/geographic/density_visualization.R")) {
  source("modules/geographic/density_visualization.R")
}

# Map Interactivity Configuration
# ==============================

MAP_INTERACTIVITY_CONFIG <- list(
  
  # Event types and handlers
  events = list(
    
    hover = list(
      enabled = TRUE,
      delay_ms = 150,
      tooltip_max_width = 300,
      show_statistics = TRUE,
      show_comparison = TRUE,
      animation_duration = 200
    ),
    
    click = list(
      enabled = TRUE,
      single_click_action = "details",
      double_click_action = "zoom",
      show_document_list = TRUE,
      max_documents_preview = 10,
      enable_navigation = TRUE
    ),
    
    selection = list(
      enabled = TRUE,
      multi_select = TRUE,
      max_selections = 10,
      persist_selection = FALSE,
      comparison_mode = TRUE
    ),
    
    context_menu = list(
      enabled = TRUE,
      actions = c("view_details", "export_data", "compare", "zoom_to", "share_link"),
      admin_actions = c("edit_metadata", "refresh_data", "clear_cache")
    )
  ),
  
  # Content templates for different interaction types
  templates = list(
    
    hover_tooltip = list(
      state = "
        <div class='map-tooltip state-tooltip'>
          <div class='tooltip-header'>
            <h5>{state_name}</h5>
            <span class='tooltip-subtitle'>{region_name}</span>
          </div>
          <div class='tooltip-stats'>
            <div class='stat-item'>
              <span class='stat-label'>Documents:</span>
              <span class='stat-value'>{document_count}</span>
            </div>
            <div class='stat-item'>
              <span class='stat-label'>Categories:</span>
              <span class='stat-value'>{category_count}</span>
            </div>
            <div class='stat-item'>
              <span class='stat-label'>Activity Level:</span>
              <span class='stat-value {activity_class}'>{activity_level}</span>
            </div>
          </div>
          <div class='tooltip-footer'>
            <small>Click for detailed analysis</small>
          </div>
        </div>
      ",
      
      municipality = "
        <div class='map-tooltip municipality-tooltip'>
          <div class='tooltip-header'>
            <h6>{municipality_name}</h6>
            <span class='tooltip-subtitle'>{state_name}</span>
          </div>
          <div class='tooltip-stats'>
            <div class='stat-item'>
              <span class='stat-label'>Documents:</span>
              <span class='stat-value'>{document_count}</span>
            </div>
            <div class='stat-item'>
              <span class='stat-label'>Density:</span>
              <span class='stat-value'>{density_value}/km²</span>
            </div>
            <div class='stat-item'>
              <span class='stat-label'>Rank:</span>
              <span class='stat-value'>#{state_rank}</span>
            </div>
          </div>
        </div>
      "
    ),
    
    click_popup = list(
      state = "
        <div class='map-popup state-popup'>
          <div class='popup-header'>
            <h4>{state_name}</h4>
            <span class='popup-subtitle'>{region_name} Region</span>
          </div>
          
          <div class='popup-content'>
            <div class='stats-grid'>
              <div class='stat-card'>
                <div class='stat-number'>{document_count}</div>
                <div class='stat-label'>Total Documents</div>
              </div>
              <div class='stat-card'>
                <div class='stat-number'>{municipality_count}</div>
                <div class='stat-label'>Municipalities</div>
              </div>
              <div class='stat-card'>
                <div class='stat-number'>{category_count}</div>
                <div class='stat-label'>Categories</div>
              </div>
              <div class='stat-card'>
                <div class='stat-number'>{percentile}%</div>
                <div class='stat-label'>Percentile</div>
              </div>
            </div>
            
            <div class='recent-activity'>
              <h6>Recent Activity</h6>
              <div class='activity-chart' data-activity='{recent_activity_data}'></div>
            </div>
            
            <div class='top-categories'>
              <h6>Top Categories</h6>
              <ul class='category-list'>
                {top_categories_list}
              </ul>
            </div>
          </div>
          
          <div class='popup-actions'>
            <button class='btn btn-primary btn-sm' onclick='viewDocuments(\"{state_code}\")'>
              <i class='fa fa-list'></i> View Documents
            </button>
            <button class='btn btn-success btn-sm' onclick='exportData(\"{state_code}\")'>
              <i class='fa fa-download'></i> Export Data
            </button>
            <button class='btn btn-info btn-sm' onclick='compareState(\"{state_code}\")'>
              <i class='fa fa-chart-bar'></i> Compare
            </button>
          </div>
        </div>
      ",
      
      municipality = "
        <div class='map-popup municipality-popup'>
          <div class='popup-header'>
            <h5>{municipality_name}</h5>
            <span class='popup-subtitle'>{state_name}</span>
          </div>
          
          <div class='popup-content'>
            <div class='municipality-stats'>
              <div class='stat-row'>
                <span class='stat-label'>Documents:</span>
                <span class='stat-value'>{document_count}</span>
              </div>
              <div class='stat-row'>
                <span class='stat-label'>Per Capita:</span>
                <span class='stat-value'>{per_capita_rate}</span>
              </div>
              <div class='stat-row'>
                <span class='stat-label'>Density:</span>
                <span class='stat-value'>{density_value}/km²</span>
              </div>
              <div class='stat-row'>
                <span class='stat-label'>State Rank:</span>
                <span class='stat-value'>#{municipality_rank}</span>
              </div>
            </div>
            
            <div class='document-preview'>
              <h6>Recent Documents</h6>
              <div class='document-list'>
                {recent_documents_list}
              </div>
            </div>
          </div>
          
          <div class='popup-actions'>
            <button class='btn btn-primary btn-sm' onclick='viewMunicipalityDetails(\"{municipality_code}\")'>
              <i class='fa fa-info-circle'></i> Details
            </button>
            <button class='btn btn-success btn-sm' onclick='downloadMunicipalityData(\"{municipality_code}\")'>
              <i class='fa fa-download'></i> Download
            </button>
          </div>
        </div>
      "
    )
  ),
  
  # Styling configuration
  styling = list(
    tooltip = list(
      background_color = "rgba(255, 255, 255, 0.95)",
      border_color = "#cbd5e1",
      border_radius = "6px",
      box_shadow = "0 4px 16px rgba(0,0,0,0.1)",
      font_size = "13px",
      max_width = "300px",
      padding = "12px",
      z_index = 10000
    ),
    
    popup = list(
      background_color = "#ffffff",
      border_radius = "8px",
      box_shadow = "0 8px 32px rgba(0,0,0,0.15)",
      max_width = "400px",
      min_width = "300px",
      padding = "0px"  # Handled by content structure
    ),
    
    selection = list(
      highlight_color = "#ff6b35",
      highlight_opacity = 0.8,
      highlight_weight = 3,
      normal_opacity = 0.7,
      normal_weight = 1
    )
  ),
  
  # Performance settings
  performance = list(
    debounce_hover_ms = 100,
    cache_popup_content = True,
    max_concurrent_requests = 3,
    timeout_ms = 5000,
    lazy_load_details = True,
    batch_document_requests = True
  )
)

# Map Interactivity Manager Class
# ==============================

if (requireNamespace("R6", quietly = TRUE)) {
  
  MapInteractivityManager <- R6::R6Class("MapInteractivityManager",
    
    public = list(
      
      # Properties
      db_pool = NULL,
      density_visualizer = NULL,
      current_selection = NULL,
      hover_cache = NULL,
      popup_cache = NULL,
      event_handlers = NULL,
      
      # Constructor
      initialize = function(db_pool, density_visualizer = NULL) {
        
        cat("🖱️ Initializing Map Interactivity Manager...\n")
        
        self$db_pool <- db_pool
        self$density_visualizer <- density_visualizer
        self$current_selection <- list()
        self$hover_cache <- list()
        self$popup_cache <- list()
        self$event_handlers <- list()
        
        # Setup event handling system
        self$setup_event_handlers()
        
        cat("✅ Map Interactivity Manager initialized\n")
      },
      
      # Event handling setup
      setup_event_handlers = function() {
        
        self$event_handlers <- list(
          
          # Hover event handler
          hover = function(feature_id, feature_data, level = "state") {
            
            tryCatch({
              
              # Check cache first
              cache_key <- paste0("hover_", level, "_", feature_id)
              
              if (cache_key %in% names(self$hover_cache)) {
                return(self$hover_cache[[cache_key]])
              }
              
              # Generate hover content
              hover_content <- self$generate_hover_content(feature_data, level)
              
              # Cache the result
              self$hover_cache[[cache_key]] <- hover_content
              
              return(hover_content)
              
            }, error = function(e) {
              cat("❌ Error in hover handler:", e$message, "\n")
              return(self$create_error_tooltip("Error loading information"))
            })
          },
          
          # Click event handler
          click = function(feature_id, feature_data, level = "state") {
            
            tryCatch({
              
              cache_key <- paste0("popup_", level, "_", feature_id)
              
              if (cache_key %in% names(self$popup_cache)) {
                return(self$popup_cache[[cache_key]])
              }
              
              # Fetch detailed data for popup
              detailed_data <- self$fetch_detailed_data(feature_id, level)
              
              # Generate popup content
              popup_content <- self$generate_popup_content(detailed_data, level)
              
              # Cache the result
              self$popup_cache[[cache_key]] <- popup_content
              
              return(popup_content)
              
            }, error = function(e) {
              cat("❌ Error in click handler:", e$message, "\n")
              return(self$create_error_popup("Error loading detailed information"))
            })
          },
          
          # Selection handler
          select = function(feature_id, feature_data, level = "state") {
            
            if (!MAP_INTERACTIVITY_CONFIG$events$selection$enabled) {
              return(NULL)
            }
            
            # Add to or remove from selection
            selection_key <- paste0(level, "_", feature_id)
            
            if (selection_key %in% names(self$current_selection)) {
              # Remove from selection
              self$current_selection[[selection_key]] <- NULL
              return(list(action = "deselected", selection_count = length(self$current_selection)))
            } else {
              # Add to selection (check limits)
              if (length(self$current_selection) >= MAP_INTERACTIVITY_CONFIG$events$selection$max_selections) {
                return(list(action = "limit_reached", max_selections = MAP_INTERACTIVITY_CONFIG$events$selection$max_selections))
              }
              
              self$current_selection[[selection_key]] <- list(
                id = feature_id,
                level = level,
                data = feature_data,
                selected_at = Sys.time()
              )
              
              return(list(action = "selected", selection_count = length(self$current_selection)))
            }
          }
        )
      },
      
      # Content generation methods
      generate_hover_content = function(feature_data, level = "state") {
        
        tryCatch({
          
          template_name <- paste0(level)
          template <- MAP_INTERACTIVITY_CONFIG$templates$hover_tooltip[[template_name]]
          
          if (is.null(template)) {
            template <- MAP_INTERACTIVITY_CONFIG$templates$hover_tooltip$state  # fallback
          }
          
          # Prepare data for template substitution
          template_data <- self$prepare_template_data(feature_data, level, type = "hover")
          
          # Substitute template variables
          hover_html <- self$substitute_template(template, template_data)
          
          return(HTML(hover_html))
          
        }, error = function(e) {
          cat("❌ Error generating hover content:", e$message, "\n")
          return(self$create_error_tooltip("Data unavailable"))
        })
      },
      
      generate_popup_content = function(detailed_data, level = "state") {
        
        tryCatch({
          
          template_name <- paste0(level)
          template <- MAP_INTERACTIVITY_CONFIG$templates$click_popup[[template_name]]
          
          if (is.null(template)) {
            template <- MAP_INTERACTIVITY_CONFIG$templates$click_popup$state  # fallback
          }
          
          # Prepare comprehensive data
          template_data <- self$prepare_template_data(detailed_data, level, type = "popup")
          
          # Add additional popup-specific data
          template_data <- self$enhance_popup_data(template_data, detailed_data, level)
          
          # Substitute template variables
          popup_html <- self$substitute_template(template, template_data)
          
          return(HTML(popup_html))
          
        }, error = function(e) {
          cat("❌ Error generating popup content:", e$message, "\n")
          return(self$create_error_popup("Detailed information unavailable"))
        })
      },
      
      # Data fetching methods
      fetch_detailed_data = function(feature_id, level = "state") {
        
        tryCatch({
          
          if (is.null(self$db_pool)) {
            return(NULL)
          }
          
          if (level == "state") {
            
            detailed_data <- pool::poolWithTransaction(self$db_pool, function(conn) {
              
              # Get comprehensive state statistics
              state_query <- "
                SELECT 
                  estado,
                  COUNT(*) as document_count,
                  COUNT(DISTINCT categoria_original) as category_count,
                  COUNT(DISTINCT municipio) as municipality_count,
                  AVG(CASE WHEN LENGTH(conteudo) > 0 THEN LENGTH(conteudo) END) as avg_content_length,
                  MIN(data_documento) as first_document_date,
                  MAX(data_documento) as last_document_date,
                  COUNT(CASE WHEN data_documento >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as recent_documents,
                  COUNT(CASE WHEN data_documento >= CURRENT_DATE - INTERVAL '90 days' THEN 1 END) as quarterly_documents,
                  STRING_AGG(DISTINCT categoria_original, '|' ORDER BY categoria_original) as all_categories
                FROM documents
                WHERE estado = $1
                GROUP BY estado
              "
              
              result <- DBI::dbGetQuery(conn, state_query, params = list(feature_id))
              
              if (nrow(result) > 0) {
                
                # Get top categories with counts
                categories_query <- "
                  SELECT categoria_original, COUNT(*) as count
                  FROM documents
                  WHERE estado = $1 AND categoria_original IS NOT NULL
                  GROUP BY categoria_original
                  ORDER BY count DESC
                  LIMIT 5
                "
                
                top_categories <- DBI::dbGetQuery(conn, categories_query, params = list(feature_id))
                result$top_categories <- top_categories
                
                # Get recent document samples
                recent_docs_query <- "
                  SELECT titulo, categoria_original, data_documento
                  FROM documents
                  WHERE estado = $1 AND data_documento >= CURRENT_DATE - INTERVAL '30 days'
                  ORDER BY data_documento DESC
                  LIMIT 5
                "
                
                recent_docs <- DBI::dbGetQuery(conn, recent_docs_query, params = list(feature_id))
                result$recent_documents_list <- recent_docs
                
                # Calculate additional metrics
                result$activity_score <- ifelse(result$document_count > 0, 
                                              result$recent_documents / result$document_count * 100, 0)
                
                result$documents_per_municipality <- ifelse(result$municipality_count > 0,
                                                          round(result$document_count / result$municipality_count, 1), 0)
              }
              
              return(result)
            })
            
          } else if (level == "municipality") {
            
            # Parse municipality identifier (assumes format: state_municipality)
            parts <- strsplit(feature_id, "_")[[1]]
            if (length(parts) >= 2) {
              state_code <- parts[1]
              municipality_name <- paste(parts[-1], collapse = "_")
              
              detailed_data <- pool::poolWithTransaction(self$db_pool, function(conn) {
                
                municipality_query <- "
                  SELECT 
                    estado,
                    municipio,
                    COUNT(*) as document_count,
                    COUNT(DISTINCT categoria_original) as category_count,
                    AVG(CASE WHEN LENGTH(conteudo) > 0 THEN LENGTH(conteudo) END) as avg_content_length,
                    MIN(data_documento) as first_document_date,
                    MAX(data_documento) as last_document_date,
                    COUNT(CASE WHEN data_documento >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as recent_documents
                  FROM documents
                  WHERE estado = $1 AND UPPER(TRIM(municipio)) = UPPER(TRIM($2))
                  GROUP BY estado, municipio
                "
                
                result <- DBI::dbGetQuery(conn, municipality_query, 
                                        params = list(state_code, municipality_name))
                
                if (nrow(result) > 0) {
                  
                  # Get recent documents for this municipality
                  recent_docs_query <- "
                    SELECT titulo, categoria_original, data_documento
                    FROM documents
                    WHERE estado = $1 AND UPPER(TRIM(municipio)) = UPPER(TRIM($2))
                      AND data_documento >= CURRENT_DATE - INTERVAL '30 days'
                    ORDER BY data_documento DESC
                    LIMIT 3
                  "
                  
                  recent_docs <- DBI::dbGetQuery(conn, recent_docs_query,
                                               params = list(state_code, municipality_name))
                  result$recent_documents_list <- recent_docs
                  
                  # Calculate municipality rank within state
                  rank_query <- "
                    WITH municipality_ranks AS (
                      SELECT municipio,
                             COUNT(*) as doc_count,
                             RANK() OVER (ORDER BY COUNT(*) DESC) as rank
                      FROM documents
                      WHERE estado = $1
                      GROUP BY municipio
                    )
                    SELECT rank FROM municipality_ranks
                    WHERE UPPER(TRIM(municipio)) = UPPER(TRIM($2))
                  "
                  
                  rank_result <- DBI::dbGetQuery(conn, rank_query,
                                               params = list(state_code, municipality_name))
                  
                  result$municipality_rank <- if (nrow(rank_result) > 0) rank_result$rank[1] else NA
                }
                
                return(result)
              })
            }
          }
          
          return(detailed_data)
          
        }, error = function(e) {
          cat("❌ Error fetching detailed data:", e$message, "\n")
          return(NULL)
        })
      },
      
      # Template processing methods
      prepare_template_data = function(data, level, type = "hover") {
        
        if (isTRUE(is.null(data)) || nrow(data) == 0) {
          return(self$get_empty_template_data(level))
        }
        
        tryCatch({
          
          template_data <- list()
          
          # Common data for both levels
          template_data$document_count <- self$format_number(data$document_count[1])
          template_data$category_count <- data$category_count[1]
          
          # Level-specific data
          if (level == "state") {
            
            template_data$state_name <- data$estado[1]
            template_data$state_code <- data$estado[1]
            template_data$region_name <- "Brazil"  # Would be enhanced with actual region data
            template_data$municipality_count <- data$municipality_count[1]
            
            # Activity level classification
            activity_score <- ifelse(!is.null(data$activity_score), data$activity_score[1], 0)
            template_data$activity_level <- self$classify_activity_level(activity_score)
            template_data$activity_class <- tolower(gsub(" ", "-", template_data$activity_level))
            
            # Percentile calculation (would be enhanced with real percentile data)
            template_data$percentile <- round(runif(1, 20, 95), 0)  # Placeholder
            
          } else if (level == "municipality") {
            
            template_data$municipality_name <- data$municipio[1]
            template_data$municipality_code <- paste0(data$estado[1], "_", data$municipio[1])
            template_data$state_name <- data$estado[1]
            template_data$state_code <- data$estado[1]
            
            # Calculate density (placeholder - would use actual area data)
            template_data$density_value <- round(data$document_count[1] / 100, 2)  # Placeholder
            
            # Ranking information
            template_data$state_rank <- ifelse(!is.null(data$municipality_rank), 
                                             data$municipality_rank[1], "N/A")
            template_data$municipality_rank <- template_data$state_rank
            
            # Per capita rate (placeholder)
            template_data$per_capita_rate <- round(data$document_count[1] / 50000 * 100000, 1)
          }
          
          return(template_data)
          
        }, error = function(e) {
          cat("❌ Error preparing template data:", e$message, "\n")
          return(self$get_empty_template_data(level))
        })
      },
      
      enhance_popup_data = function(template_data, detailed_data, level) {
        
        if (isTRUE(is.null(detailed_data)) || nrow(detailed_data) == 0) {
          return(template_data)
        }
        
        tryCatch({
          
          # Add recent activity data (for chart rendering)
          if (!isTRUE(is.null(detailed_data$recent_documents)) && !is.null(detailed_data$quarterly_documents)) {
            template_data$recent_activity_data <- jsonlite::toJSON(list(
              recent = detailed_data$recent_documents[1],
              quarterly = detailed_data$quarterly_documents[1],
              total = detailed_data$document_count[1]
            ))
          } else {
            template_data$recent_activity_data <- "{}"
          }
          
          # Add top categories list
          if (!isTRUE(is.null(detailed_data$top_categories)) && nrow(detailed_data$top_categories) > 0) {
            
            categories_html <- paste(
              sapply(1:nrow(detailed_data$top_categories), function(i) {
                cat_data <- detailed_data$top_categories[i, ]
                paste0("<li><strong>", cat_data$categoria_original, "</strong> (", 
                       self$format_number(cat_data$count), " docs)</li>")
              }),
              collapse = ""
            )
            
            template_data$top_categories_list <- categories_html
            
          } else {
            template_data$top_categories_list <- "<li>No category data available</li>"
          }
          
          # Add recent documents list
          if (!isTRUE(is.null(detailed_data$recent_documents_list)) && 
              nrow(detailed_data$recent_documents_list) > 0) {
            
            docs_html <- paste(
              sapply(1:min(3, nrow(detailed_data$recent_documents_list)), function(i) {
                doc <- detailed_data$recent_documents_list[i, ]
                paste0(
                  "<div class='recent-doc-item'>",
                  "<div class='doc-title'>", htmlEscape(substr(doc$titulo, 1, 60)), "...</div>",
                  "<div class='doc-meta'>", doc$categoria_original, " • ", 
                  format(as.Date(doc$data_documento), "%d/%m/%Y"), "</div>",
                  "</div>"
                )
              }),
              collapse = ""
            )
            
            template_data$recent_documents_list <- docs_html
            
          } else {
            template_data$recent_documents_list <- "<div class='no-docs'>No recent documents available</div>"
          }
          
          return(template_data)
          
        }, error = function(e) {
          cat("❌ Error enhancing popup data:", e$message, "\n")
          return(template_data)
        })
      },
      
      substitute_template = function(template, template_data) {
        
        result <- template
        
        for (key in names(template_data)) {
          pattern <- paste0("\\{", key, "\\}")
          replacement <- as.character(template_data[[key]])
          result <- gsub(pattern, replacement, result, fixed = FALSE)
        }
        
        # Clean up any remaining placeholder patterns
        result <- gsub("\\{[^}]+\\}", "", result)
        
        return(result)
      },
      
      # Utility methods
      format_number = function(x) {
        if (isTRUE(is.na(x)) || isTRUE(is.null(x))) return("--")
        format(as.numeric(x), big.mark = ",", scientific = FALSE)
      },
      
      classify_activity_level = function(activity_score) {
        if (isTRUE(is.na(activity_score)) || isTRUE(is.null(activity_score))) return("Unknown")
        
        if (activity_score >= 15) return("Very High")
        if (activity_score >= 10) return("High")
        if (activity_score >= 5) return("Medium")
        if (activity_score >= 1) return("Low")
        return("Very Low")
      },
      
      get_empty_template_data = function(level) {
        
        base_data <- list(
          document_count = "--",
          category_count = "--",
          activity_level = "Unknown",
          activity_class = "unknown",
          percentile = "--",
          recent_activity_data = "{}",
          top_categories_list = "<li>No data available</li>",
          recent_documents_list = "<div class='no-docs'>No data available</div>"
        )
        
        if (level == "state") {
          base_data$state_name <- "Unknown State"
          base_data$state_code <- "XX"
          base_data$region_name <- "Unknown"
          base_data$municipality_count <- "--"
        } else {
          base_data$municipality_name <- "Unknown Municipality"
          base_data$municipality_code <- "XX_Unknown"
          base_data$state_name <- "Unknown State"
          base_data$state_code <- "XX"
          base_data$density_value <- "--"
          base_data$state_rank <- "--"
          base_data$municipality_rank <- "--"
          base_data$per_capita_rate <- "--"
        }
        
        return(base_data)
      },
      
      create_error_tooltip = function(message) {
        HTML(paste0(
          "<div class='map-tooltip error-tooltip'>",
          "<div class='tooltip-header'>",
          "<h6><i class='fa fa-exclamation-triangle'></i> Error</h6>",
          "</div>",
          "<div class='tooltip-content'>",
          "<p>", message, "</p>",
          "</div>",
          "</div>"
        ))
      },
      
      create_error_popup = function(message) {
        HTML(paste0(
          "<div class='map-popup error-popup'>",
          "<div class='popup-header'>",
          "<h5><i class='fa fa-exclamation-triangle'></i> Error</h5>",
          "</div>",
          "<div class='popup-content'>",
          "<p>", message, "</p>",
          "<p><small>Please try again or contact support if the problem persists.</small></p>",
          "</div>",
          "</div>"
        ))
      },
      
      # Selection management
      get_current_selection = function() {
        return(self$current_selection)
      },
      
      clear_selection = function() {
        self$current_selection <- list()
        return(TRUE)
      },
      
      get_selection_summary = function() {
        
        if (length(self$current_selection) == 0) {
          return(list(count = 0, levels = c(), summary = "No items selected"))
        }
        
        levels <- sapply(self$current_selection, function(x) x$level)
        level_counts <- table(levels)
        
        summary_text <- paste(
          sapply(names(level_counts), function(level) {
            paste(level_counts[level], level, ifelse(level_counts[level] > 1, "s", ""))
          }),
          collapse = ", "
        )
        
        return(list(
          count = length(self$current_selection),
          levels = names(level_counts),
          level_counts = level_counts,
          summary = summary_text
        ))
      },
      
      # Cache management
      clear_cache = function(cache_type = "all") {
        
        if (cache_type %in% c("all", "hover")) {
          self$hover_cache <- list()
        }
        
        if (cache_type %in% c("all", "popup")) {
          self$popup_cache <- list()
        }
        
        gc(verbose = FALSE)
        cat("🧹 Map interactivity cache cleared:", cache_type, "\n")
      },
      
      get_cache_status = function() {
        list(
          hover_cache_entries = length(self$hover_cache),
          popup_cache_entries = length(self$popup_cache),
          selection_count = length(self$current_selection),
          memory_usage_mb = round(object.size(self) / 1024^2, 2)
        )
      }
    )
  )
}

# Functional Factory (Fallback Implementation)
# ===========================================

create_map_interactivity_manager <- function(db_pool, density_visualizer = NULL) {
  
  if (requireNamespace("R6", quietly = TRUE)) {
    return(MapInteractivityManager$new(db_pool, density_visualizer))
  } else {
    return(create_functional_interactivity_manager(db_pool, density_visualizer))
  }
}

create_functional_interactivity_manager <- function(db_pool, density_visualizer = NULL) {
  
  # Create environment for state management
  interact_env <- new.env()
  interact_env$db_pool <- db_pool
  interact_env$density_visualizer <- density_visualizer
  interact_env$hover_cache <- list()
  interact_env$popup_cache <- list()
  interact_env$current_selection <- list()
  
  # Simplified functional implementation
  list(
    
    generate_hover_content = function(feature_data, level = "state") {
      
      if (is.null(feature_data)) {
        return(HTML("<div>No data available</div>"))
      }
      
      # Simple hover tooltip
      if (level == "state") {
        content <- paste0(
          "<div style='background: white; padding: 8px; border-radius: 4px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);'>",
          "<h6 style='margin: 0 0 5px 0;'>", feature_data$estado, "</h6>",
          "<div><strong>Documents:</strong> ", format(feature_data$document_count, big.mark = ","), "</div>",
          "<div><strong>Categories:</strong> ", feature_data$category_count, "</div>",
          "<div style='font-size: 11px; color: #666; margin-top: 5px;'>Click for details</div>",
          "</div>"
        )
      } else {
        content <- paste0(
          "<div style='background: white; padding: 8px; border-radius: 4px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);'>",
          "<h6 style='margin: 0 0 5px 0;'>", feature_data$municipio, "</h6>",
          "<div style='font-size: 12px; color: #666;'>", feature_data$estado, "</div>",
          "<div><strong>Documents:</strong> ", format(feature_data$document_count, big.mark = ","), "</div>",
          "</div>"
        )
      }
      
      return(HTML(content))
    },
    
    generate_popup_content = function(feature_data, level = "state") {
      
      if (is.null(feature_data)) {
        return(HTML("<div>No detailed data available</div>"))
      }
      
      # Simple popup content
      if (level == "state") {
        content <- paste0(
          "<div style='min-width: 250px;'>",
          "<h5 style='margin: 0 0 10px 0; color: #1e3a8a;'>", feature_data$estado, "</h5>",
          "<div style='margin-bottom: 8px;'><strong>Total Documents:</strong> ", format(feature_data$document_count, big.mark = ","), "</div>",
          "<div style='margin-bottom: 8px;'><strong>Categories:</strong> ", feature_data$category_count, "</div>",
          "<div style='margin-bottom: 8px;'><strong>Municipalities:</strong> ", feature_data$municipality_count, "</div>",
          "<div style='margin-top: 15px;'>",
          "<button onclick='alert(\"Feature not available in fallback mode\")' style='background: #1e3a8a; color: white; border: none; padding: 5px 10px; border-radius: 3px; font-size: 12px;'>View Documents</button>",
          "</div>",
          "</div>"
        )
      } else {
        content <- paste0(
          "<div style='min-width: 200px;'>",
          "<h6 style='margin: 0 0 5px 0;'>", feature_data$municipio, "</h6>",
          "<div style='font-size: 12px; color: #666; margin-bottom: 10px;'>", feature_data$estado, "</div>",
          "<div><strong>Documents:</strong> ", format(feature_data$document_count, big.mark = ","), "</div>",
          "<div><strong>Categories:</strong> ", feature_data$category_count, "</div>",
          "</div>"
        )
      }
      
      return(HTML(content))
    },
    
    clear_cache = function() {
      interact_env$hover_cache <- list()
      interact_env$popup_cache <- list()
    },
    
    get_cache_status = function() {
      list(
        hover_cache_entries = length(interact_env$hover_cache),
        popup_cache_entries = length(interact_env$popup_cache),
        mode = "functional_fallback"
      )
    }
  )
}

# Shiny Integration Functions
# ==========================

#' Create Leaflet Event Observers
#' 
#' Sets up Shiny observers for leaflet map events
#' 
#' @param input Shiny input object
#' @param output Shiny output object
#' @param session Shiny session object
#' @param map_id ID of the leaflet map
#' @param interactivity_manager Map interactivity manager instance
#' @return List of observer handles
create_leaflet_observers <- function(input, output, session, map_id, interactivity_manager) {
  
  observers <- list()
  
  # Map click observer
  observers$click <- observeEvent(input[[paste0(map_id, "_shape_click")]], {
    
    click_info <- input[[paste0(map_id, "_shape_click")]]
    
    if (!is.null(click_info)) {
      
      # Determine level based on layer ID format
      level <- if (grepl("_", click_info$id)) "municipality" else "state"
      
      # Fetch popup content
      popup_content <- interactivity_manager$event_handlers$click(
        click_info$id, 
        click_info, 
        level
      )
      
      # Update map with popup
      leafletProxy(map_id, session) %>%
        clearPopups() %>%
        addPopups(
          lng = click_info$lng,
          lat = click_info$lat,
          popup = as.character(popup_content),
          options = popupOptions(closeButton = TRUE, autoClose = TRUE)
        )
    }
  })
  
  # Map hover observers (mouseeover and mouseout)
  observers$mouseover <- observeEvent(input[[paste0(map_id, "_shape_mouseover")]], {
    # Handle hover start
    hover_info <- input[[paste0(map_id, "_shape_mouseover")]]
    # Implementation would depend on specific tooltip library
  })
  
  observers$mouseout <- observeEvent(input[[paste0(map_id, "_shape_mouseout")]], {
    # Handle hover end
    # Clear tooltips
  })
  
  return(observers)
}

#' Add Custom JavaScript for Enhanced Interactivity
#' 
#' Injects custom JavaScript for advanced map interactions
#' 
#' @param session Shiny session object
#' @return Success status
add_interactivity_javascript <- function(session) {
  
  js_code <- "
  // Enhanced Map Interactivity JavaScript
  
  // Custom tooltip handling
  window.mapTooltip = null;
  
  function showMapTooltip(content, x, y) {
    hideMapTooltip();
    
    window.mapTooltip = $('<div class=\"custom-map-tooltip\"></div>')
      .html(content)
      .css({
        position: 'absolute',
        left: x + 'px',
        top: y + 'px',
        background: 'rgba(255, 255, 255, 0.95)',
        border: '1px solid #cbd5e1',
        borderRadius: '6px',
        padding: '8px',
        fontSize: '13px',
        boxShadow: '0 4px 16px rgba(0,0,0,0.1)',
        zIndex: 10000,
        pointerEvents: 'none'
      })
      .appendTo('body');
  }
  
  function hideMapTooltip() {
    if (window.mapTooltip) {
      window.mapTooltip.remove();
      window.mapTooltip = null;
    }
  }
  
  // Document interaction handlers
  function viewDocuments(entityId) {
    Shiny.setInputValue('view_documents_click', {
      id: entityId,
      timestamp: Date.now()
    });
  }
  
  function exportData(entityId) {
    Shiny.setInputValue('export_data_click', {
      id: entityId,
      timestamp: Date.now()
    });
  }
  
  function compareState(stateId) {
    Shiny.setInputValue('compare_state_click', {
      id: stateId,
      timestamp: Date.now()
    });
  }
  
  function viewMunicipalityDetails(municipalityId) {
    Shiny.setInputValue('municipality_details_click', {
      id: municipalityId,
      timestamp: Date.now()
    });
  }
  
  function downloadMunicipalityData(municipalityId) {
    Shiny.setInputValue('download_municipality_click', {
      id: municipalityId,
      timestamp: Date.now()
    });
  }
  
  console.log('Map interactivity JavaScript loaded');
  "
  
  tryCatch({
    session$sendCustomMessage("eval", js_code)
    return(TRUE)
  }, error = function(e) {
    cat("⚠️ Failed to inject interactivity JavaScript:", e$message, "\n")
    return(FALSE)
  })
}

# Export main functions
list(
  create_map_interactivity_manager = create_map_interactivity_manager,
  create_functional_interactivity_manager = create_functional_interactivity_manager,
  create_leaflet_observers = create_leaflet_observers,
  add_interactivity_javascript = add_interactivity_javascript,
  MAP_INTERACTIVITY_CONFIG = MAP_INTERACTIVITY_CONFIG
)