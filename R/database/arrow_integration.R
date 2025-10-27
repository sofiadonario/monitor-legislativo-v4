# Arrow Database Integration
# Monitor Legislativo v4 - Arrow-Enhanced Database Layer
# ======================================================

#' Arrow Integration for Existing Database Queries
#' 
#' This module integrates Apache Arrow optimizations with the existing
#' database query layer, providing backward compatibility while enabling
#' high-performance data processing for Brazilian Legislative data.
#' 
#' Maintains compatibility with existing dplyr pipelines while adding
#' Arrow acceleration for Railway deployment constraints.

# Load required libraries
library(arrow)
library(dplyr)
library(pool)

# Source existing modules
source("R/data/arrow_pipeline.R")
source("R/utils/parquet_conversion.R")
source("R/database/queries.R")

# Global Arrow integration state
.arrow_integration <- new.env(parent = emptyenv())
.arrow_integration$enabled <- FALSE
.arrow_integration$dataset <- NULL
.arrow_integration$fallback_mode <- "database"  # "database", "csv", or "none"
.arrow_integration$parquet_path <- NULL
.arrow_integration$performance_stats <- list(
  arrow_queries = 0,
  fallback_queries = 0,
  avg_arrow_time = 0,
  avg_fallback_time = 0
)

#' Initialize Arrow-Enhanced Database System
#' 
#' Sets up the hybrid database system with Arrow acceleration
#' 
#' @param parquet_path Path to Parquet dataset (optional)
#' @param enable_arrow Whether to enable Arrow processing
#' @param fallback_mode Fallback strategy when Arrow fails
#' @return Initialization status
#' @export
init_arrow_database_system <- function(parquet_path = NULL, 
                                     enable_arrow = TRUE,
                                     fallback_mode = "database") {
  
  cat("🚀 Initializing Arrow-enhanced database system...\n")
  
  .arrow_integration$fallback_mode <- fallback_mode
  .arrow_integration$enabled <- enable_arrow
  
  # Try to initialize Arrow dataset if path provided
  if (!isTRUE(is.null(parquet_path)) && enable_arrow) {
    tryCatch({
      .arrow_integration$dataset <- init_arrow_dataset(parquet_path, cache_key = "main_dataset")
      .arrow_integration$parquet_path <- parquet_path
      
      if (!is.null(.arrow_integration$dataset)) {
        cat("✅ Arrow dataset initialized successfully\n")
        
        # Test dataset with a simple query
        test_result <- .arrow_integration$dataset %>%
          head(10) %>%
          collect()
        
        if (nrow(test_result) > 0) {
          cat("   Test query successful:", nrow(test_result), "records\n")
          .arrow_integration$enabled <- TRUE
        }
        
      } else {
        cat("⚠️ Arrow dataset initialization failed, using fallback mode\n")
        .arrow_integration$enabled <- FALSE
      }
      
    }, error = function(e) {
      cat("❌ Arrow initialization error:", e$message, "\n")
      cat("   Falling back to:", fallback_mode, "mode\n")
      .arrow_integration$enabled <- FALSE
    })
  }
  
  # Check for existing CSV data for conversion
  if (!.arrow_integration$enabled && enable_arrow) {
    cat("🔍 Checking for CSV data to convert to Parquet...\n")
    csv_conversion_result <- check_and_convert_csv_data()
    
    if (csv_conversion_result$success) {
      .arrow_integration$parquet_path <- csv_conversion_result$parquet_path
      .arrow_integration$dataset <- init_arrow_dataset(csv_conversion_result$parquet_path)
      .arrow_integration$enabled <- !is.null(.arrow_integration$dataset)
    }
  }
  
  return(list(
    arrow_enabled = .arrow_integration$enabled,
    dataset_available = !is.null(.arrow_integration$dataset),
    parquet_path = .arrow_integration$parquet_path,
    fallback_mode = .arrow_integration$fallback_mode
  ))
}

#' Enhanced Get Documents with Arrow Acceleration
#' 
#' Drop-in replacement for existing get_documents() function
#' with Arrow acceleration when available
#' 
#' @param pool Database connection pool (maintained for compatibility)
#' @param limit Maximum number of documents to retrieve
#' @param offset Starting offset for pagination
#' @param filters List of filters
#' @return Data frame of legislative documents
#' @export
get_documents_arrow_enhanced <- function(pool = NULL, limit = 1000, offset = 0, filters = list()) {
  
  query_start <- Sys.time()
  
  # Try Arrow acceleration first if enabled
  if (.arrow_integration$enabled && !is.null(.arrow_integration$dataset)) {
    tryCatch({
      
      # Convert filters to Arrow-compatible format
      arrow_filters <- convert_filters_for_arrow(filters)
      
      # Execute Arrow query with pagination simulation
      result <- query_legislative_documents(
        dataset = .arrow_integration$dataset,
        filters = arrow_filters,
        limit = limit + offset  # Get extra records for offset
      )
      
      # Apply offset manually (Arrow doesn't have native offset)
      if (offset > 0 && nrow(result) > offset) {
        start_idx <- offset + 1
        end_idx <- min(nrow(result), offset + limit)
        result <- result[start_idx:end_idx, ]
      } else if (offset > 0) {
        result <- result[0, ]  # Empty result if offset exceeds data
      }
      
      # Standardize column names to match existing interface
      result <- standardize_columns_for_compatibility(result)
      
      # Update performance statistics
      query_time <- as.numeric(difftime(Sys.time(), query_start, units = "secs"))
      update_performance_stats("arrow", query_time)
      
      cat("⚡ Arrow-accelerated query completed:", nrow(result), "records in", 
          round(query_time, 3), "seconds\n")
      
      return(result)
      
    }, error = function(e) {
      cat("⚠️ Arrow query failed, falling back:", e$message, "\n")
      # Continue to fallback
    })
  }
  
  # Fallback to original implementation
  fallback_start <- Sys.time()
  
  result <- switch(.arrow_integration$fallback_mode,
    "database" = get_documents(pool, limit, offset, filters),
    "csv" = get_documents_from_csv(limit, offset, filters),
    "none" = data.frame()  # Return empty if no fallback
  )
  
  fallback_time <- as.numeric(difftime(Sys.time(), fallback_start, units = "secs"))
  update_performance_stats("fallback", fallback_time)
  
  return(result)
}

#' Enhanced Search Documents with Arrow Text Search
#' 
#' Drop-in replacement for search_documents() with Arrow acceleration
#' 
#' @param pool Database connection pool
#' @param query Search query string
#' @param filters Additional filters
#' @param limit Maximum results
#' @return Data frame of matching documents
#' @export
search_documents_arrow_enhanced <- function(pool = NULL, query = "", filters = list(), limit = 100) {
  
  if (query == "" || isTRUE(is.null(query))) {
    return(get_documents_arrow_enhanced(pool, limit = limit, filters = filters))
  }
  
  search_start <- Sys.time()
  
  # Try Arrow search first
  if (.arrow_integration$enabled && !is.null(.arrow_integration$dataset)) {
    tryCatch({
      
      # Execute Arrow search
      result <- search_legislative_arrow(
        dataset = .arrow_integration$dataset,
        search_term = query,
        limit = limit
      )
      
      # Apply additional filters if provided
      if (length(filters) > 0) {
        result <- apply_post_search_filters(result, filters)
      }
      
      # Standardize columns
      result <- standardize_columns_for_compatibility(result)
      
      search_time <- as.numeric(difftime(Sys.time(), search_start, units = "secs"))
      update_performance_stats("arrow", search_time)
      
      cat("🔍 Arrow search completed:", nrow(result), "results in", 
          round(search_time, 3), "seconds\n")
      
      return(result)
      
    }, error = function(e) {
      cat("⚠️ Arrow search failed, falling back:", e$message, "\n")
    })
  }
  
  # Fallback to original search
  result <- switch(.arrow_integration$fallback_mode,
    "database" = search_documents(pool, query, filters, limit),
    "csv" = search_documents_csv(query, filters, limit),
    "none" = data.frame()
  )
  
  return(result)
}

#' Enhanced Filter Values with Arrow Optimization
#' 
#' Optimized filter value retrieval using Arrow when available
#' 
#' @param pool Database connection pool
#' @param column Column name to get unique values for
#' @return Character vector of unique values
#' @export
get_filter_values_arrow_enhanced <- function(pool = NULL, column = "estado") {
  
  # Try Arrow optimization first
  if (.arrow_integration$enabled && !is.null(.arrow_integration$dataset)) {
    tryCatch({
      
      # Map column names to Arrow dataset schema
      arrow_column <- map_column_name_to_arrow(column)
      
      if (!is.null(arrow_column)) {
        result <- get_arrow_filter_values(.arrow_integration$dataset, arrow_column)
        
        if (length(result) > 0) {
          cat("⚡ Arrow filter values retrieved:", length(result), "unique values\n")
          return(result)
        }
      }
      
    }, error = function(e) {
      cat("⚠️ Arrow filter query failed:", e$message, "\n")
    })
  }
  
  # Fallback to original implementation
  return(get_filter_values(pool, column))
}

#' Convert Legacy Filters to Arrow Format
#' 
#' Converts filter parameters to Arrow-compatible format
#' 
#' @param filters Legacy filter list
#' @return Arrow-compatible filter list
convert_filters_for_arrow <- function(filters) {
  
  arrow_filters <- list()
  
  # Map common filter parameters
  if (!isTRUE(is.null(filters$estado)) && filters$estado != "") {
    arrow_filters$state <- filters$estado
  }
  
  if (!isTRUE(is.null(filters$tipo)) && filters$tipo != "") {
    arrow_filters$document_type <- filters$tipo
  }
  
  if (!is.null(filters$ano_min)) {
    arrow_filters$year_min <- as.numeric(filters$ano_min)
  }
  
  if (!is.null(filters$ano_max)) {
    arrow_filters$year_max <- as.numeric(filters$ano_max)
  }
  
  if (!isTRUE(is.null(filters$municipio)) && filters$municipio != "") {
    arrow_filters$municipality <- filters$municipio
  }
  
  return(arrow_filters)
}

#' Standardize Column Names for Backward Compatibility
#' 
#' Ensures Arrow results match expected column names
#' 
#' @param data Data frame from Arrow query
#' @return Data frame with standardized columns
standardize_columns_for_compatibility <- function(data) {
  
  if (nrow(data) == 0) return(data)
  
  # Column name mapping from Arrow to legacy format
  column_mapping <- c(
    "titulo" = "title",
    "estado" = "state", 
    "municipio" = "municipality",
    "tipo" = "document_type_full",
    "ano" = "year",
    "content" = "document_description",
    "data_publicacao" = "promulgation_date",
    "orgao_emissor" = "authority"
  )
  
  # Apply reverse mapping to convert Arrow columns to legacy names
  for (legacy_name in names(column_mapping)) {
    arrow_name <- column_mapping[legacy_name]
    if (arrow_name %in% names(data) && !(legacy_name %in% names(data))) {
      names(data)[names(data) == arrow_name] <- legacy_name
    }
  }
  
  # Ensure required columns exist with default values
  required_columns <- c("id", "titulo", "content", "tipo", "ano", "estado", "municipio")
  
  for (col in required_columns) {
    if (!(col %in% names(data))) {
      data[[col]] <- switch(col,
        "id" = seq_len(nrow(data)),
        "titulo" = data$title %||% "Unknown Title",
        "content" = data$document_description %||% "",
        "tipo" = data$document_type_full %||% "Unknown Type", 
        "ano" = data$year %||% 2024,
        "estado" = data$state %||% "Unknown State",
        "municipio" = data$municipality %||% "Unknown Municipality",
        ""  # Default empty string
      )
    }
  }
  
  return(data)
}

#' Map Column Names to Arrow Schema
#' 
#' Maps legacy column names to Arrow dataset column names
#' 
#' @param column Legacy column name
#' @return Arrow column name or NULL if not found
map_column_name_to_arrow <- function(column) {
  
  mapping <- c(
    "estado" = "state",
    "tipo" = "document_type_full", 
    "ano" = "year",
    "municipio" = "municipality",
    "orgao_emissor" = "authority"
  )
  
  return(mapping[column] %||% column)
}

#' Apply Post-Search Filters
#' 
#' Applies additional filters to Arrow search results
#' 
#' @param data Search results
#' @param filters Filter list
#' @return Filtered data
apply_post_search_filters <- function(data, filters) {
  
  if (nrow(data) == 0) return(data)
  
  # Apply year filters
  if (!isTRUE(is.null(filters$ano_min)) && "year" %in% names(data)) {
    data <- data[data$year >= filters$ano_min, ]
  }
  
  if (!isTRUE(is.null(filters$ano_max)) && "year" %in% names(data)) {
    data <- data[data$year <= filters$ano_max, ]
  }
  
  # Apply state filter
  if (!isTRUE(is.null(filters$estado)) && filters$estado != "" && "state" %in% names(data)) {
    data <- data[data$state == filters$estado, ]
  }
  
  return(data)
}

#' Update Performance Statistics
#' 
#' Tracks performance metrics for optimization analysis
#' 
#' @param query_type Type of query ("arrow" or "fallback")
#' @param query_time Query execution time in seconds
update_performance_stats <- function(query_type, query_time) {
  
  if (query_type == "arrow") {
    .arrow_integration$performance_stats$arrow_queries <- 
      .arrow_integration$performance_stats$arrow_queries + 1
    
    current_avg <- .arrow_integration$performance_stats$avg_arrow_time
    current_count <- .arrow_integration$performance_stats$arrow_queries
    
    .arrow_integration$performance_stats$avg_arrow_time <- 
      (current_avg * (current_count - 1) + query_time) / current_count
      
  } else {
    .arrow_integration$performance_stats$fallback_queries <- 
      .arrow_integration$performance_stats$fallback_queries + 1
    
    current_avg <- .arrow_integration$performance_stats$avg_fallback_time
    current_count <- .arrow_integration$performance_stats$fallback_queries
    
    .arrow_integration$performance_stats$avg_fallback_time <- 
      (current_avg * (current_count - 1) + query_time) / current_count
  }
}

#' Check and Convert CSV Data to Parquet
#' 
#' Automatically converts CSV data to Parquet for Arrow acceleration
#' 
#' @return Conversion status and parquet path
check_and_convert_csv_data <- function() {
  
  # Look for CSV files in data directories
  csv_files <- c(
    "data/monitor_legislativo_cleaned.csv",
    "data_current/monitor_legislativo_cleaned.csv",
    "legacy/data/processed/lexml_parsed_enhanced_fixed.csv",
    "legacy/data/processed/lexml_complete_dataset_20250714_171207.csv"
  )
  
  for (csv_file in csv_files) {
    if (file.exists(csv_file)) {
      cat("📄 Found CSV data:", csv_file, "\n")
      
      # Create parquet output directory
      parquet_dir <- file.path(dirname(csv_file), "parquet_dataset")
      
      # Check if parquet version already exists and is newer
      if (dir.exists(parquet_dir)) {
        csv_time <- file.mtime(csv_file)
        parquet_time <- max(file.mtime(list.files(parquet_dir, recursive = TRUE, full.names = TRUE)))
        
        if (parquet_time >= csv_time) {
          cat("✅ Parquet dataset is up to date\n")
          return(list(success = TRUE, parquet_path = parquet_dir))
        }
      }
      
      cat("🔄 Converting CSV to Parquet...\n")
      
      # Convert to Parquet
      conversion_result <- convert_csv_to_parquet(
        csv_path = csv_file,
        output_dir = parquet_dir,
        chunk_size = 25000  # Conservative chunk size for Railway
      )
      
      if (conversion_result$success) {
        cat("✅ CSV conversion successful\n")
        return(list(success = TRUE, parquet_path = parquet_dir))
      }
    }
  }
  
  return(list(success = FALSE, error = "No CSV data found for conversion"))
}

#' Get Arrow Integration Status
#' 
#' Returns current status of Arrow integration
#' 
#' @return Integration status information
#' @export
get_arrow_integration_status <- function() {
  return(list(
    arrow_enabled = .arrow_integration$enabled,
    dataset_available = !is.null(.arrow_integration$dataset),
    parquet_path = .arrow_integration$parquet_path,
    fallback_mode = .arrow_integration$fallback_mode,
    performance_stats = .arrow_integration$performance_stats
  ))
}

#' Disable Arrow Integration
#' 
#' Disables Arrow processing and falls back to original methods
#' 
#' @export
disable_arrow_integration <- function() {
  .arrow_integration$enabled <- FALSE
  .arrow_integration$dataset <- NULL
  clear_arrow_cache()
  cat("⚠️ Arrow integration disabled, using fallback mode\n")
}

cat("✅ Arrow database integration module loaded successfully\n")
cat("   Backward compatible with existing query interface\n")
cat("   Automatic CSV to Parquet conversion\n")
cat("   Performance monitoring and fallback support\n")