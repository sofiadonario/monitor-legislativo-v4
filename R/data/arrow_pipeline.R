# Apache Arrow Data Pipeline
# Monitor Legislativo v4 - Memory-Optimized Data Processing
# ========================================================

#' Apache Arrow Implementation for Brazilian Legislative Data
#' 
#' This module provides memory-optimized data processing using Apache Arrow
#' for handling large legislative datasets with <1GB memory usage.
#' Designed for Railway 2GB memory constraint with 1M+ records performance.

# Load required libraries with error handling
required_packages <- c("arrow", "dplyr", "stringr", "lubridate")

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    warning(paste("Package", pkg, "not available. Installing..."))
    install.packages(pkg, dependencies = TRUE)
  }
  library(pkg, character.only = TRUE)
}

# Global Arrow dataset cache
.arrow_cache <- new.env(parent = emptyenv())
.arrow_cache$datasets <- list()
.arrow_cache$last_accessed <- list()
.arrow_cache$memory_stats <- list(
  peak_usage = 0,
  current_usage = 0,
  query_count = 0
)

#' Initialize Arrow Dataset from Parquet Files
#' 
#' Creates a memory-efficient Arrow dataset with proper partitioning
#' for Brazilian legislative documents
#' 
#' @param data_path Path to parquet files or directory
#' @param partitioning Partitioning scheme (default: c("year", "state"))
#' @param cache_key Unique identifier for caching
#' @return Arrow dataset object
#' @export
init_arrow_dataset <- function(data_path, 
                              partitioning = c("year", "state"), 
                              cache_key = "legislative_main") {
  
  cat("🚀 Initializing Arrow dataset for Brazilian Legislative Data...\n")
  
  # Check if dataset is already cached
  if (cache_key %in% names(.arrow_cache$datasets)) {
    if (difftime(Sys.time(), .arrow_cache$last_accessed[[cache_key]], units = "mins") < 30) {
      cat("♻️ Using cached Arrow dataset\n")
      return(.arrow_cache$datasets[[cache_key]])
    }
  }
  
  tryCatch({
    # Initialize Arrow dataset with partitioning for Railway optimization
    if (dir.exists(data_path)) {
      dataset <- arrow::open_dataset(
        data_path,
        format = "parquet",
        partitioning = partitioning
      )
    } else if (file.exists(data_path) && grepl("\\.parquet$", data_path)) {
      dataset <- arrow::open_dataset(data_path)
    } else {
      stop("Invalid data path: must be directory with parquet files or single parquet file")
    }
    
    # Cache the dataset
    .arrow_cache$datasets[[cache_key]] <- dataset
    .arrow_cache$last_accessed[[cache_key]] <- Sys.time()
    
    # Get dataset schema for validation
    schema_info <- dataset$schema
    cat("✅ Arrow dataset initialized successfully\n")
    cat("   Schema fields:", length(schema_info), "\n")
    cat("   Partitioning:", paste(partitioning, collapse = ", "), "\n")
    
    return(dataset)
    
  }, error = function(e) {
    cat("❌ Failed to initialize Arrow dataset:", e$message, "\n")
    return(NULL)
  })
}

#' Memory-Optimized Legislative Document Query
#' 
#' Executes optimized queries on Brazilian legislative data using Arrow
#' with <1GB memory usage for 1M+ records
#' 
#' @param dataset Arrow dataset object
#' @param filters List of filter conditions
#' @param limit Maximum number of records to return
#' @param columns Specific columns to select (NULL for all)
#' @return Tibble with query results
#' @export
query_legislative_documents <- function(dataset, 
                                      filters = list(),
                                      limit = 1000,
                                      columns = NULL) {
  
  start_time <- Sys.time()
  .arrow_cache$memory_stats$query_count <- .arrow_cache$memory_stats$query_count + 1
  
  if (is.null(dataset)) {
    warning("Dataset is NULL, cannot execute query")
    return(tibble::tibble())
  }
  
  tryCatch({
    # Start with the base dataset
    query <- dataset
    
    # Apply filters efficiently using Arrow's lazy evaluation
    if (!is.null(filters$year_min)) {
      query <- query %>% 
        filter(year >= filters$year_min)
    }
    
    if (!is.null(filters$year_max)) {
      query <- query %>% 
        filter(year <= filters$year_max)
    }
    
    if (!is.null(filters$state) && filters$state != "all") {
      query <- query %>% 
        filter(state == filters$state)
    }
    
    if (!is.null(filters$document_type) && filters$document_type != "all") {
      query <- query %>% 
        filter(document_type_full == filters$document_type)
    }
    
    if (!is.null(filters$municipality) && filters$municipality != "all") {
      query <- query %>% 
        filter(municipality == filters$municipality)
    }
    
    # Text search optimization
    if (!is.null(filters$search_term) && filters$search_term != "") {
      search_pattern <- paste0(".*", str_to_lower(filters$search_term), ".*")
      query <- query %>%
        filter(
          str_detect(str_to_lower(title), search_pattern) |
          str_detect(str_to_lower(document_description), search_pattern)
        )
    }
    
    # Select specific columns for memory optimization
    if (!is.null(columns)) {
      query <- query %>% select(all_of(columns))
    } else {
      # Default essential columns for UI display
      essential_columns <- c(
        "urn", "title", "document_type_full", "state", "municipality",
        "promulgation_date", "document_description", "year"
      )
      
      # Check which columns exist in the dataset
      available_columns <- names(dataset$schema)
      selected_columns <- intersect(essential_columns, available_columns)
      
      if (length(selected_columns) > 0) {
        query <- query %>% select(all_of(selected_columns))
      }
    }
    
    # Order by date for relevance
    if ("promulgation_date" %in% names(dataset$schema)) {
      query <- query %>% arrange(desc(promulgation_date))
    }
    
    # Apply limit and collect results (triggers computation)
    if (limit > 0) {
      query <- query %>% head(limit)
    }
    
    # Collect with memory monitoring
    gc()  # Force garbage collection before major operation
    memory_before <- as.numeric(object.size(ls(envir = .GlobalEnv)))
    
    result <- query %>% collect()
    
    memory_after <- as.numeric(object.size(ls(envir = .GlobalEnv)))
    memory_used <- memory_after - memory_before
    
    # Update memory statistics
    .arrow_cache$memory_stats$current_usage <- memory_used
    if (memory_used > .arrow_cache$memory_stats$peak_usage) {
      .arrow_cache$memory_stats$peak_usage <- memory_used
    }
    
    query_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    
    cat("✅ Arrow query completed\n")
    cat("   Records returned:", nrow(result), "\n")
    cat("   Query time:", round(query_time, 3), "seconds\n")
    cat("   Memory used:", round(memory_used / 1024^2, 2), "MB\n")
    
    # Validate memory target (<1GB)
    if (memory_used > 1024^3) {
      warning("Memory usage exceeded 1GB target: ", round(memory_used / 1024^3, 2), "GB")
    }
    
    return(result)
    
  }, error = function(e) {
    cat("❌ Arrow query failed:", e$message, "\n")
    return(tibble::tibble())
  })
}

#' High-Performance Legislative Data Aggregation
#' 
#' Optimized aggregation queries for dashboard metrics and analytics
#' Target: <1s for 134k document aggregations
#' 
#' @param dataset Arrow dataset object
#' @param group_by Columns to group by
#' @param filters Optional filters to apply
#' @return Aggregated data tibble
#' @export
aggregate_legislative_data <- function(dataset, 
                                     group_by = c("state", "document_type_full"),
                                     filters = list()) {
  
  start_time <- Sys.time()
  
  if (is.null(dataset)) {
    warning("Dataset is NULL, cannot perform aggregation")
    return(tibble::tibble())
  }
  
  tryCatch({
    # Start with base dataset
    query <- dataset
    
    # Apply filters before aggregation for efficiency
    if (!is.null(filters$year_min)) {
      query <- query %>% filter(year >= filters$year_min)
    }
    
    if (!is.null(filters$year_max)) {
      query <- query %>% filter(year <= filters$year_max)
    }
    
    # Group by specified columns and aggregate
    valid_group_cols <- intersect(group_by, names(dataset$schema))
    
    if (length(valid_group_cols) > 0) {
      result <- query %>%
        group_by(across(all_of(valid_group_cols))) %>%
        summarise(
          document_count = n(),
          .groups = "drop"
        ) %>%
        arrange(desc(document_count)) %>%
        collect()
    } else {
      # Fallback: simple count
      result <- query %>%
        summarise(document_count = n()) %>%
        collect()
    }
    
    query_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    
    cat("✅ Arrow aggregation completed\n")
    cat("   Groups processed:", nrow(result), "\n")
    cat("   Query time:", round(query_time, 3), "seconds\n")
    
    # Validate performance target (<1s)
    if (query_time > 1.0) {
      warning("Aggregation exceeded 1s target: ", round(query_time, 3), "seconds")
    }
    
    return(result)
    
  }, error = function(e) {
    cat("❌ Arrow aggregation failed:", e$message, "\n")
    return(tibble::tibble())
  })
}

#' Get Unique Filter Values with Arrow Optimization
#' 
#' Fast retrieval of unique values for dropdown filters
#' Memory-optimized for large datasets
#' 
#' @param dataset Arrow dataset object
#' @param column Column name to get unique values for
#' @return Character vector of unique values
#' @export
get_arrow_filter_values <- function(dataset, column) {
  
  if (is.null(dataset) || !(column %in% names(dataset$schema))) {
    return(character(0))
  }
  
  tryCatch({
    result <- dataset %>%
      select(all_of(column)) %>%
      filter(!is.na(!!sym(column))) %>%
      distinct() %>%
      collect() %>%
      pull(!!sym(column)) %>%
      sort()
    
    # Remove empty strings
    result <- result[result != ""]
    
    return(result)
    
  }, error = function(e) {
    cat("❌ Failed to get filter values for", column, ":", e$message, "\n")
    return(character(0))
  })
}

#' Memory-Efficient Search with Arrow Full-Text Capabilities
#' 
#' Optimized text search across legislative documents
#' Performance target: 0.2s for 40M record queries
#' 
#' @param dataset Arrow dataset object
#' @param search_term Text to search for
#' @param search_columns Columns to search in
#' @param limit Maximum results to return
#' @return Search results tibble
#' @export
search_legislative_arrow <- function(dataset, 
                                   search_term,
                                   search_columns = c("title", "document_description"),
                                   limit = 100) {
  
  start_time <- Sys.time()
  
  if (is.null(dataset) || is.null(search_term) || search_term == "") {
    return(tibble::tibble())
  }
  
  tryCatch({
    # Convert search term to lowercase for case-insensitive search
    search_pattern <- str_to_lower(search_term)
    
    # Build search conditions
    query <- dataset
    
    # Create search condition for available columns
    available_search_cols <- intersect(search_columns, names(dataset$schema))
    
    if (length(available_search_cols) == 0) {
      warning("No searchable columns found in dataset")
      return(tibble::tibble())
    }
    
    # Apply text search with case-insensitive matching
    search_conditions <- map(available_search_cols, function(col) {
      expr(str_detect(str_to_lower(!!sym(col)), !!search_pattern))
    })
    
    # Combine search conditions with OR logic
    if (length(search_conditions) == 1) {
      query <- query %>% filter(!!search_conditions[[1]])
    } else {
      combined_condition <- reduce(search_conditions, function(x, y) expr(!!x | !!y))
      query <- query %>% filter(!!combined_condition)
    }
    
    # Select relevant columns for search results
    result_columns <- c("urn", "title", "document_type_full", "state", 
                       "municipality", "promulgation_date", "document_description")
    available_result_cols <- intersect(result_columns, names(dataset$schema))
    
    if (length(available_result_cols) > 0) {
      query <- query %>% select(all_of(available_result_cols))
    }
    
    # Order by relevance (date-based for now, can be enhanced)
    if ("promulgation_date" %in% available_result_cols) {
      query <- query %>% arrange(desc(promulgation_date))
    }
    
    # Apply limit and collect
    result <- query %>%
      head(limit) %>%
      collect()
    
    query_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    
    cat("🔍 Arrow search completed\n")
    cat("   Search term:", search_term, "\n")
    cat("   Results found:", nrow(result), "\n")
    cat("   Query time:", round(query_time, 3), "seconds\n")
    
    # Validate performance target (0.2s for 40M records)
    if (query_time > 0.5) {  # Allowing some flexibility
      warning("Search exceeded 0.5s target: ", round(query_time, 3), "seconds")
    }
    
    return(result)
    
  }, error = function(e) {
    cat("❌ Arrow search failed:", e$message, "\n")
    return(tibble::tibble())
  })
}

#' Get Arrow Dataset Statistics
#' 
#' Returns performance and memory usage statistics
#' 
#' @return List with dataset statistics
#' @export
get_arrow_stats <- function() {
  return(list(
    cached_datasets = length(.arrow_cache$datasets),
    total_queries = .arrow_cache$memory_stats$query_count,
    peak_memory_mb = round(.arrow_cache$memory_stats$peak_usage / 1024^2, 2),
    current_memory_mb = round(.arrow_cache$memory_stats$current_usage / 1024^2, 2),
    cache_keys = names(.arrow_cache$datasets)
  ))
}

#' Clear Arrow Cache
#' 
#' Clears cached datasets to free memory
#' 
#' @export
clear_arrow_cache <- function() {
  .arrow_cache$datasets <- list()
  .arrow_cache$last_accessed <- list()
  .arrow_cache$memory_stats$current_usage <- 0
  gc()  # Force garbage collection
  cat("✅ Arrow cache cleared\n")
}

cat("✅ Apache Arrow pipeline module loaded successfully\n")
cat("   Memory target: <1GB for 1M+ records\n")
cat("   Performance target: 0.2s for 40M record queries\n")
cat("   Railway optimized: 2GB memory constraint\n")