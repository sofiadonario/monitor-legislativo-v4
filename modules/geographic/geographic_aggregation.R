# Geographic Aggregation System - Sprint 5B Implementation
# Brazilian Legislative Monitoring System - Document Aggregation by Geography
# =============================================================================
# 
# Advanced geographic aggregation system for 134k+ legislative documents
# Provides efficient document counting, statistical analysis, and spatial
# aggregation capabilities for Brazilian administrative boundaries
# 
# FEATURES:
# - State and municipality-level document aggregation
# - Temporal analysis with geographic dimensions
# - Category-based geographic distribution analysis
# - Performance-optimized aggregation queries
# - Statistical measures and trending analysis
# - Export capabilities for choropleth visualizations
# - Academic-grade statistical validation
# 
# PERFORMANCE OPTIMIZATIONS:
# - Materialized view integration for fast queries
# - Cached aggregation results with smart invalidation
# - Chunked processing for large datasets
# - Memory-efficient statistical computations
# - Parallel processing for complex aggregations
# =============================================================================

library(dplyr)
library(DBI)
library(pool)
library(lubridate)
library(sf)

# Load geographic data systems
if (file.exists("modules/geographic/ibge_integration.R")) {
  source("modules/geographic/ibge_integration.R")
}
if (file.exists("modules/geographic/geographic_data_loader.R")) {
  source("modules/geographic/geographic_data_loader.R")
}

# Geographic Aggregation Configuration
# ===================================

AGGREGATION_CONFIG <- list(
  
  # Aggregation levels
  levels = list(
    state = list(
      group_columns = c("estado"),
      spatial_join_column = "state_code",
      min_documents = 10,  # Minimum documents for meaningful statistics
      cache_hours = 6
    ),
    municipality = list(
      group_columns = c("estado", "municipio"),
      spatial_join_column = "municipality_code", 
      min_documents = 5,
      cache_hours = 12
    ),
    region = list(
      group_columns = c("region_name"),
      spatial_join_column = "region_code",
      min_documents = 50,
      cache_hours = 24
    )
  ),
  
  # Statistical measures
  statistics = list(
    basic = c("count", "mean_length", "median_length", "std_dev"),
    temporal = c("first_date", "last_date", "time_span", "documents_per_day"),
    categories = c("category_count", "top_categories", "category_diversity"),
    trends = c("monthly_trend", "yearly_trend", "growth_rate")
  ),
  
  # Performance settings
  performance = list(
    use_materialized_views = TRUE,
    batch_size = 1000,
    parallel_processing = FALSE,  # Disabled for Railway constraints
    cache_aggregations = TRUE,
    max_processing_time_sec = 60
  ),
  
  # Export formats
  export = list(
    choropleth_ready = TRUE,
    include_geometries = TRUE,
    coordinate_system = 4674,  # SIRGAS 2000
    simplification_tolerance = 0.01
  )
)

# Core Aggregation Functions
# ==========================

#' Create Geographic Document Aggregator
#' 
#' Factory function to create a geographic aggregation system
#' 
#' @param db_pool Database connection pool
#' @param geographic_loader Geographic data loader instance
#' @return GeographicAggregator instance or functional equivalent
create_geographic_aggregator <- function(db_pool, geographic_loader = NULL) {
  
  if (requireNamespace("R6", quietly = TRUE)) {
    return(GeographicAggregator$new(db_pool, geographic_loader))
  } else {
    return(create_functional_aggregator(db_pool, geographic_loader))
  }
}

# Geographic Aggregator Class (R6)
# ================================

if (requireNamespace("R6", quietly = TRUE)) {
  
  GeographicAggregator <- R6::R6Class("GeographicAggregator",
    
    public = list(
      
      # Properties
      db_pool = NULL,
      geographic_loader = NULL,
      cache_manager = NULL,
      aggregation_cache = NULL,
      
      # Constructor
      initialize = function(db_pool, geographic_loader = NULL) {
        
        cat("📊 Initializing Geographic Aggregator...\n")
        
        self$db_pool <- db_pool
        self$geographic_loader <- geographic_loader
        self$aggregation_cache <- list()
        
        # Setup cache directory
        cache_dir <- "cache/aggregations"
        if (!dir.exists(cache_dir)) {
          dir.create(cache_dir, recursive = TRUE, showWarnings = FALSE)
        }
        
        cat("✅ Geographic Aggregator ready\n")
      },
      
      # Main aggregation methods
      aggregate_by_state = function(filters = NULL, include_geometry = TRUE, use_cache = TRUE) {
        
        cat("🏛️ Aggregating documents by state...\n")
        
        tryCatch({
          
          # Check cache
          cache_key <- paste0("state_aggregation_", digest::digest(list(filters, include_geometry)))
          if (use_cache && cache_key %in% names(self$aggregation_cache)) {
            cat("💾 Using cached state aggregation\n")
            return(self$aggregation_cache[[cache_key]])
          }
          
          # Get base aggregation data
          base_aggregation <- self$get_state_aggregation_data(filters)
          
          if (is.null(base_aggregation) || nrow(base_aggregation) == 0) {
            cat("⚠️ No data found for state aggregation\n")
            return(NULL)
          }
          
          # Add geographic data if requested
          if (include_geometry && !is.null(self$geographic_loader)) {
            
            # Load state boundaries
            states_data <- self$geographic_loader$load_states()
            
            if (!is.null(states_data)) {
              
              # Join aggregation with geographic data
              aggregation_with_geo <- base_aggregation %>%
                left_join(
                  states_data %>% sf::st_drop_geometry() %>% select(state_code, state_name, region_name),
                  by = c("estado" = "state_code")
                ) %>%
                left_join(
                  states_data %>% select(state_code, geometry),
                  by = c("estado" = "state_code")
                )
              
              # Convert to SF object if geometries were joined
              if ("geometry" %in% names(aggregation_with_geo)) {
                aggregation_with_geo <- sf::st_as_sf(aggregation_with_geo)
              }
              
              result <- aggregation_with_geo
              
            } else {
              result <- base_aggregation
            }
            
          } else {
            result <- base_aggregation
          }
          
          # Calculate additional statistics
          result <- self$calculate_advanced_statistics(result, level = "state")
          
          # Cache results
          if (use_cache) {
            self$aggregation_cache[[cache_key]] <- result
          }
          
          cat("✅ State aggregation completed:", nrow(result), "states\n")
          return(result)
          
        }, error = function(e) {
          cat("❌ Error in state aggregation:", e$message, "\n")
          return(NULL)
        })
      },
      
      aggregate_by_municipality = function(state_filter = NULL, top_n = NULL, include_geometry = FALSE) {
        
        cat("🏙️ Aggregating documents by municipality...\n")
        
        tryCatch({
          
          # Generate cache key
          cache_key <- paste0("municipality_aggregation_", 
                             digest::digest(list(state_filter, top_n, include_geometry)))
          
          if (cache_key %in% names(self$aggregation_cache)) {
            cat("💾 Using cached municipality aggregation\n")
            return(self$aggregation_cache[[cache_key]])
          }
          
          # Build query filters
          filters <- list()
          if (!is.null(state_filter)) {
            if (length(state_filter) == 1) {
              filters$estado <- paste0("= '", state_filter, "'")
            } else {
              filters$estado <- paste0("IN ('", paste(state_filter, collapse = "', '"), "')")
            }
          }
          
          # Get municipality aggregation data
          municipality_aggregation <- self$get_municipality_aggregation_data(filters, top_n)
          
          if (is.null(municipality_aggregation) || nrow(municipality_aggregation) == 0) {
            cat("⚠️ No municipality data found\n")
            return(NULL)
          }
          
          # Add geometry if requested and available
          if (include_geometry && !is.null(self$geographic_loader)) {
            
            municipality_data <- self$geographic_loader$load_municipalities(
              state_codes = state_filter,
              priority_only = TRUE
            )
            
            if (!is.null(municipality_data)) {
              
              municipality_aggregation <- municipality_aggregation %>%
                left_join(
                  municipality_data %>% 
                    mutate(
                      estado_municipio = paste(state_code, municipality_name_clean, sep = "_")
                    ) %>%
                    select(estado_municipio, geometry),
                  by = c("estado_municipio" = "estado_municipio")
                )
              
              # Convert to SF if geometries present
              if ("geometry" %in% names(municipality_aggregation) && 
                  any(!is.na(municipality_aggregation$geometry))) {
                municipality_aggregation <- sf::st_as_sf(municipality_aggregation)
              }
            }
          }
          
          # Calculate advanced statistics
          result <- self$calculate_advanced_statistics(municipality_aggregation, level = "municipality")
          
          # Cache results
          self$aggregation_cache[[cache_key]] <- result
          
          cat("✅ Municipality aggregation completed:", nrow(result), "municipalities\n")
          return(result)
          
        }, error = function(e) {
          cat("❌ Error in municipality aggregation:", e$message, "\n")
          return(NULL)
        })
      },
      
      aggregate_temporal_geographic = function(time_unit = "month", geographic_level = "state") {
        
        cat("📅 Creating temporal-geographic aggregation...\n")
        
        tryCatch({
          
          cache_key <- paste0("temporal_geo_", time_unit, "_", geographic_level)
          
          if (cache_key %in% names(self$aggregation_cache)) {
            return(self$aggregation_cache[[cache_key]])
          }
          
          # Build temporal aggregation query
          time_column <- switch(time_unit,
            "day" = "DATE(data_documento)",
            "week" = "DATE_TRUNC('week', data_documento)",
            "month" = "DATE_TRUNC('month', data_documento)",
            "quarter" = "DATE_TRUNC('quarter', data_documento)",
            "year" = "DATE_TRUNC('year', data_documento)",
            "DATE_TRUNC('month', data_documento)"  # default
          )
          
          geographic_column <- switch(geographic_level,
            "state" = "estado",
            "municipality" = "estado, municipio",
            "region" = "region_name",
            "estado"  # default
          )
          
          temporal_geo_data <- pool::poolWithTransaction(self$db_pool, function(conn) {
            
            query <- paste0("
              SELECT ", time_column, " as time_period,
                     ", geographic_column, ",
                     COUNT(*) as document_count,
                     COUNT(DISTINCT categoria_original) as category_count,
                     AVG(LENGTH(conteudo)) as avg_content_length
              FROM documents
              WHERE data_documento IS NOT NULL
                AND estado IS NOT NULL
                AND data_documento >= CURRENT_DATE - INTERVAL '2 years'
              GROUP BY ", time_column, ", ", geographic_column, "
              ORDER BY time_period DESC, document_count DESC
              LIMIT 5000;
            ")
            
            DBI::dbGetQuery(conn, query)
          })
          
          if (!is.null(temporal_geo_data) && nrow(temporal_geo_data) > 0) {
            
            # Process temporal data
            temporal_geo_processed <- temporal_geo_data %>%
              mutate(
                time_period = as.Date(time_period),
                document_density = document_count / as.numeric(difftime(
                  lead(time_period), time_period, units = "days"
                )),
                category_diversity = category_count / document_count
              ) %>%
              arrange(desc(time_period))
            
            # Cache results
            self$aggregation_cache[[cache_key]] <- temporal_geo_processed
            
            cat("✅ Temporal-geographic aggregation completed:", nrow(temporal_geo_processed), "records\n")
            return(temporal_geo_processed)
          }
          
          return(NULL)
          
        }, error = function(e) {
          cat("❌ Error in temporal-geographic aggregation:", e$message, "\n")
          return(NULL)
        })
      },
      
      # Data retrieval methods
      get_state_aggregation_data = function(filters = NULL) {
        
        tryCatch({
          
          pool::poolWithTransaction(self$db_pool, function(conn) {
            
            # Use materialized view if available
            if (AGGREGATION_CONFIG$performance$use_materialized_views) {
              
              base_query <- "
                SELECT estado,
                       SUM(doc_count) as document_count,
                       AVG(avg_content_length) as avg_content_length,
                       MIN(first_doc) as first_document_date,
                       MAX(last_doc) as last_document_date,
                       COUNT(DISTINCT categoria_original) as category_count,
                       COUNT(DISTINCT municipio) as municipality_count,
                       STRING_AGG(DISTINCT categoria_original, ', ' ORDER BY categoria_original) as categories
                FROM mv_geographic_stats
                WHERE doc_count > 0
              "
              
            } else {
              
              base_query <- "
                SELECT estado,
                       COUNT(*) as document_count,
                       AVG(CASE WHEN LENGTH(conteudo) > 0 THEN LENGTH(conteudo) END) as avg_content_length,
                       MIN(data_documento) as first_document_date,
                       MAX(data_documento) as last_document_date,
                       COUNT(DISTINCT categoria_original) as category_count,
                       COUNT(DISTINCT municipio) as municipality_count,
                       STRING_AGG(DISTINCT categoria_original, ', ' ORDER BY categoria_original) as categories
                FROM documents
                WHERE estado IS NOT NULL AND estado != ''
              "
            }
            
            # Add filters if provided
            if (!is.null(filters) && length(filters) > 0) {
              filter_conditions <- paste(
                names(filters), filters, 
                collapse = " AND "
              )
              base_query <- paste(base_query, "AND", filter_conditions)
            }
            
            # Add GROUP BY and ORDER BY
            base_query <- paste(base_query, "
              GROUP BY estado
              ORDER BY document_count DESC
            ")
            
            result <- DBI::dbGetQuery(conn, base_query)

            # Data validation
            if (!is.null(result) && is.data.frame(result) && nrow(result) > 0) {
              result <- result %>%
                filter(document_count >= AGGREGATION_CONFIG$levels$state$min_documents) %>%
                mutate(
                  avg_content_length = round(as.numeric(avg_content_length), 2),
                  documents_per_municipality = round(document_count / pmax(municipality_count, 1), 2),
                  time_span_days = as.numeric(difftime(last_document_date, first_document_date, units = "days"))
                )
            }
            
            return(result)
          })
          
        }, error = function(e) {
          cat("❌ Error getting state aggregation data:", e$message, "\n")
          return(NULL)
        })
      },
      
      get_municipality_aggregation_data = function(filters = NULL, top_n = NULL) {
        
        tryCatch({
          
          pool::poolWithTransaction(self$db_pool, function(conn) {
            
            # Base query for municipality aggregation
            base_query <- "
              SELECT estado,
                     municipio,
                     CONCAT(estado, '_', UPPER(TRIM(municipio))) as estado_municipio,
                     COUNT(*) as document_count,
                     COUNT(DISTINCT categoria_original) as category_count,
                     AVG(CASE WHEN LENGTH(conteudo) > 0 THEN LENGTH(conteudo) END) as avg_content_length,
                     MIN(data_documento) as first_document_date,
                     MAX(data_documento) as last_document_date,
                     COUNT(CASE WHEN data_documento >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as recent_documents
              FROM documents
              WHERE estado IS NOT NULL AND estado != ''
                AND municipio IS NOT NULL AND municipio != ''
            "
            
            # Add filters
            if (!is.null(filters) && length(filters) > 0) {
              filter_conditions <- paste(
                names(filters), filters,
                collapse = " AND "
              )
              base_query <- paste(base_query, "AND", filter_conditions)
            }
            
            # Add GROUP BY
            base_query <- paste(base_query, "
              GROUP BY estado, municipio
              HAVING COUNT(*) >= ", AGGREGATION_CONFIG$levels$municipality$min_documents, "
              ORDER BY document_count DESC
            ")
            
            # Add LIMIT if specified
            if (!is.null(top_n) && is.numeric(top_n)) {
              base_query <- paste(base_query, "LIMIT", top_n)
            }

            result <- DBI::dbGetQuery(conn, base_query)

            if (!is.null(result) && is.data.frame(result) && nrow(result) > 0) {
              result <- result %>%
                mutate(
                  avg_content_length = round(as.numeric(avg_content_length), 2),
                  time_span_days = as.numeric(difftime(last_document_date, first_document_date, units = "days")),
                  activity_score = recent_documents / pmax(document_count, 1)
                )
            }
            
            return(result)
          })
          
        }, error = function(e) {
          cat("❌ Error getting municipality aggregation data:", e$message, "\n")
          return(NULL)
        })
      },
      
      # Statistical analysis methods
      calculate_advanced_statistics = function(aggregation_data, level = "state") {
        
        if (is.null(aggregation_data) || nrow(aggregation_data) == 0) {
          return(aggregation_data)
        }
        
        tryCatch({
          
          # Calculate percentiles and statistical measures
          result <- aggregation_data %>%
            mutate(
              # Document count statistics
              doc_count_percentile = percent_rank(document_count),
              doc_count_quartile = ntile(document_count, 4),
              doc_count_zscore = scale(document_count)[, 1],
              
              # Content length statistics
              content_length_percentile = case_when(
                !is.na(avg_content_length) ~ percent_rank(avg_content_length),
                TRUE ~ NA_real_
              ),
              
              # Recency score
              recency_score = case_when(
                !is.na(last_document_date) ~ as.numeric(Sys.Date() - as.Date(last_document_date)),
                TRUE ~ NA_real_
              ),
              
              # Activity classification
              activity_level = case_when(
                document_count >= quantile(document_count, 0.75, na.rm = TRUE) ~ "high",
                document_count >= quantile(document_count, 0.5, na.rm = TRUE) ~ "medium",
                document_count >= quantile(document_count, 0.25, na.rm = TRUE) ~ "low",
                TRUE ~ "very_low"
              )
            )
          
          # Add level-specific statistics
          if (level == "state") {
            result <- result %>%
              mutate(
                documents_per_municipality = case_when(
                  !is.na(municipality_count) & municipality_count > 0 ~ 
                    round(document_count / municipality_count, 2),
                  TRUE ~ NA_real_
                )
              )
          }
          
          return(result)
          
        }, error = function(e) {
          warning("Error calculating advanced statistics: ", e$message)
          return(aggregation_data)
        })
      },
      
      # Export methods
      export_for_choropleth = function(aggregation_data, level = "state") {
        
        if (is.null(aggregation_data) || nrow(aggregation_data) == 0) {
          return(NULL)
        }
        
        tryCatch({
          
          # Prepare data for choropleth visualization
          choropleth_data <- aggregation_data
          
          # Ensure required columns exist
          required_columns <- c("document_count", "activity_level")
          missing_columns <- setdiff(required_columns, names(choropleth_data))
          
          for (col in missing_columns) {
            choropleth_data[[col]] <- NA
          }
          
          # Add visualization-specific columns
          choropleth_data <- choropleth_data %>%
            mutate(
              # Color mapping values
              fill_value = document_count,
              fill_category = activity_level,
              
              # Popup content
              popup_text = case_when(
                level == "state" ~ paste0(
                  "<b>", coalesce(state_name, estado), "</b><br/>",
                  "Documents: ", format(document_count, big.mark = ","), "<br/>",
                  "Municipalities: ", coalesce(municipality_count, 0), "<br/>",
                  "Categories: ", coalesce(category_count, 0)
                ),
                level == "municipality" ~ paste0(
                  "<b>", coalesce(municipio, "Unknown"), " (", estado, ")</b><br/>",
                  "Documents: ", format(document_count, big.mark = ","), "<br/>",
                  "Categories: ", coalesce(category_count, 0), "<br/>",
                  "Recent Activity: ", scales::percent(coalesce(activity_score, 0))
                ),
                TRUE ~ paste0("Documents: ", format(document_count, big.mark = ","))
              ),
              
              # Legend labels
              legend_label = case_when(
                level == "state" ~ estado,
                level == "municipality" ~ paste0(municipio, " (", estado, ")"),
                TRUE ~ as.character(row_number())
              )
            )
          
          # Simplify geometry if present for web performance
          if ("geometry" %in% names(choropleth_data) && 
              any(class(choropleth_data) %in% c("sf", "sfc"))) {
            
            choropleth_data <- choropleth_data %>%
              sf::st_simplify(
                preserveTopology = TRUE,
                dTolerance = AGGREGATION_CONFIG$export$simplification_tolerance
              )
          }
          
          return(choropleth_data)
          
        }, error = function(e) {
          cat("❌ Error preparing choropleth data:", e$message, "\n")
          return(aggregation_data)
        })
      },
      
      # Summary and status methods
      get_aggregation_summary = function() {
        
        summary <- list(
          timestamp = Sys.time(),
          cache_entries = length(self$aggregation_cache),
          database_connected = !is.null(self$db_pool),
          geographic_loader_available = !is.null(self$geographic_loader)
        )
        
        # Test basic aggregation
        tryCatch({
          test_states <- self$aggregate_by_state(use_cache = FALSE, include_geometry = FALSE)
          summary$states_available <- !is.null(test_states) && nrow(test_states) > 0
          summary$states_count <- ifelse(summary$states_available, nrow(test_states), 0)
        }, error = function(e) {
          summary$states_available <- FALSE
          summary$states_count <- 0
        })
        
        return(summary)
      },
      
      clear_cache = function() {
        self$aggregation_cache <- list()
        cat("🧹 Aggregation cache cleared\n")
      }
    )
  )
}

# Functional Aggregator (Fallback)
# ================================

create_functional_aggregator <- function(db_pool, geographic_loader = NULL) {
  
  # Create environment for state
  agg_env <- new.env()
  agg_env$db_pool <- db_pool
  agg_env$geographic_loader <- geographic_loader
  agg_env$cache <- list()
  
  list(
    aggregate_by_state = function(filters = NULL, include_geometry = TRUE) {
      
      cache_key <- paste0("states_", digest::digest(list(filters, include_geometry)))
      
      if (cache_key %in% names(agg_env$cache)) {
        return(agg_env$cache[[cache_key]])
      }
      
      tryCatch({
        
        state_data <- pool::poolWithTransaction(agg_env$db_pool, function(conn) {
          DBI::dbGetQuery(conn, "
            SELECT estado,
                   COUNT(*) as document_count,
                   COUNT(DISTINCT categoria_original) as category_count,
                   MIN(data_documento) as first_document_date,
                   MAX(data_documento) as last_document_date
            FROM documents
            WHERE estado IS NOT NULL AND estado != ''
            GROUP BY estado
            ORDER BY document_count DESC
          ")
        })
        
        if (include_geometry && !is.null(agg_env$geographic_loader)) {
          states_geo <- agg_env$geographic_loader$load_states()
          if (!is.null(states_geo)) {
            state_data <- state_data %>%
              left_join(states_geo %>% sf::st_drop_geometry(), by = c("estado" = "state_code"))
          }
        }
        
        agg_env$cache[[cache_key]] <- state_data
        return(state_data)
        
      }, error = function(e) {
        return(NULL)
      })
    },
    
    aggregate_by_municipality = function(state_filter = NULL, top_n = 100) {
      
      cache_key <- paste0("municipalities_", digest::digest(list(state_filter, top_n)))
      
      if (cache_key %in% names(agg_env$cache)) {
        return(agg_env$cache[[cache_key]])
      }
      
      tryCatch({
        
        query <- "
          SELECT estado, municipio,
                 COUNT(*) as document_count,
                 COUNT(DISTINCT categoria_original) as category_count
          FROM documents
          WHERE estado IS NOT NULL AND estado != ''
            AND municipio IS NOT NULL AND municipio != ''
        "
        
        if (!is.null(state_filter)) {
          if (length(state_filter) == 1) {
            query <- paste(query, "AND estado =", paste0("'", state_filter, "'"))
          } else {
            query <- paste(query, "AND estado IN (", 
                          paste0("'", paste(state_filter, collapse = "', '"), "'"), ")")
          }
        }
        
        query <- paste(query, "
          GROUP BY estado, municipio
          ORDER BY document_count DESC
        ")
        
        if (!is.null(top_n)) {
          query <- paste(query, "LIMIT", top_n)
        }
        
        municipality_data <- pool::poolWithTransaction(agg_env$db_pool, function(conn) {
          DBI::dbGetQuery(conn, query)
        })
        
        agg_env$cache[[cache_key]] <- municipality_data
        return(municipality_data)
        
      }, error = function(e) {
        return(NULL)
      })
    },
    
    get_summary = function() {
      list(
        timestamp = Sys.time(),
        cache_entries = length(agg_env$cache),
        database_connected = !is.null(agg_env$db_pool)
      )
    },
    
    clear_cache = function() {
      agg_env$cache <- list()
    }
  )
}

# Utility Functions
# ================

#' Quick State Summary
#' 
#' Provides a quick summary of document distribution by state
#' 
#' @param db_pool Database connection pool
#' @return Data frame with state document counts
get_quick_state_summary <- function(db_pool) {
  
  tryCatch({
    
    pool::poolWithTransaction(db_pool, function(conn) {
      DBI::dbGetQuery(conn, "
        SELECT estado,
               COUNT(*) as document_count,
               COUNT(DISTINCT categoria_original) as categories,
               MAX(data_documento) as latest_document
        FROM documents
        WHERE estado IS NOT NULL AND estado != ''
        GROUP BY estado
        ORDER BY document_count DESC
        LIMIT 27;  -- All Brazilian states
      ")
    })
    
  }, error = function(e) {
    cat("❌ Error getting quick state summary:", e$message, "\n")
    return(NULL)
  })
}

#' Export Aggregation to JSON
#' 
#' Exports aggregation results to JSON format for web visualization
#' 
#' @param aggregation_data Aggregation results
#' @param file_path Output file path (optional)
#' @return JSON string or file export status
export_aggregation_json <- function(aggregation_data, file_path = NULL) {
  
  if (is.null(aggregation_data) || nrow(aggregation_data) == 0) {
    return(NULL)
  }
  
  tryCatch({
    
    # Convert SF objects to regular data frames for JSON export
    if (any(class(aggregation_data) %in% c("sf", "sfc"))) {
      export_data <- aggregation_data %>%
        sf::st_drop_geometry() %>%
        as.data.frame()
    } else {
      export_data <- as.data.frame(aggregation_data)
    }
    
    # Convert dates and special values
    export_data <- export_data %>%
      mutate(across(where(is.Date), as.character)) %>%
      mutate(across(where(is.POSIXt), as.character))
    
    json_result <- jsonlite::toJSON(export_data, pretty = TRUE, na = "null")
    
    if (!is.null(file_path)) {
      writeLines(json_result, file_path)
      return(list(success = TRUE, file = file_path))
    }
    
    return(json_result)
    
  }, error = function(e) {
    cat("❌ Error exporting to JSON:", e$message, "\n")
    return(NULL)
  })
}

# Main Export
list(
  create_geographic_aggregator = create_geographic_aggregator,
  create_functional_aggregator = create_functional_aggregator,
  get_quick_state_summary = get_quick_state_summary,
  export_aggregation_json = export_aggregation_json,
  AGGREGATION_CONFIG = AGGREGATION_CONFIG
)