# Performance Optimization for Monitor Legislativo v4
# Advanced caching, memory management, and async operations

library(promises)
library(future)
library(memoise)
library(digest)

# Set up future for async operations
if (!future::supportsMulticore()) {
  future::plan(future::multisession, workers = 2)
} else {
  future::plan(future::multicore, workers = 2)
}

#' Memoized version of expensive functions
#' Create memoized versions of commonly used functions

# Memoize geographic data loading (1 hour cache)
load_brazilian_states_memo <- memoise::memoise(
  load_brazilian_states,
  ~memoise::timeout(3600)
)

load_brazilian_municipalities_memo <- memoise::memoise(
  load_brazilian_municipalities,
  ~memoise::timeout(3600)
)

# Memoize API calls (30 minutes cache)
search_legislative_data_memo <- memoise::memoise(
  search_legislative_data,
  ~memoise::timeout(1800)
)

#' Advanced cache key generation
#' @param ... Parameters to create cache key from
#' @return MD5 hash cache key
create_cache_key <- function(...) {
  params <- list(...)
  # Remove NULL values and sort for consistent keys
  params <- params[!sapply(params, is.null)]
  params <- params[order(names(params))]
  
  # Create hash
  key_string <- paste(sapply(params, function(x) {
    if (is.list(x)) {
      digest::digest(x)
    } else {
      paste(x, collapse = "_")
    }
  }), collapse = "|")
  
  digest::digest(key_string, algo = "md5")
}

#' Async search with caching
#' @param query Search query
#' @param filters Additional filters
#' @param force_refresh Force refresh of cache
#' @return Promise with search results
async_search_legislative_data <- function(query = NULL, filters = list(), force_refresh = FALSE) {
  
  # Create cache key
  cache_key <- create_cache_key(
    query = query,
    filters = filters,
    timestamp = if (force_refresh) Sys.time() else NULL
  )
  
  # Check cache first
  if (!force_refresh) {
    cached_result <- get_cache(cache_key)
    if (!is.null(cached_result)) {
      log_event("Returning cached search results")
      return(future::resolved(cached_result))
    }
  }
  
  # Perform async search
  future_promise({
    log_event("Starting async search operation")
    
    # Use memoized search function
    result <- search_legislative_data_memo(
      query = query,
      date_from = filters$date_from,
      date_to = filters$date_to,
      types = filters$types,
      states = filters$states,
      limit = filters$limit %||% 1000
    )
    
    if (!is.null(result)) {
      # Process and enrich data
      processed_result <- result %>%
        normalize_document_data() %>%
        enrich_legislative_data()
      
      # Cache results for 30 minutes
      set_cache(cache_key, processed_result, 1800)
      
      log_event(paste("Async search completed:", nrow(processed_result), "results"))
      return(processed_result)
    } else {
      log_event("Async search returned no results", "WARN")
      return(data.frame())
    }
    
  }) %...>% {
    # Success handler
    .
  } %...!% {
    # Error handler
    log_event(paste("Async search failed:", .$message), "ERROR")
    create_fallback_data()
  }
}

#' Async geographic data loading
#' @param state_codes Optional state codes to filter
#' @param include_municipalities Whether to include municipality data
#' @return Promise with geographic data
async_load_geographic_data <- function(state_codes = NULL, include_municipalities = FALSE) {
  
  cache_key <- create_cache_key(
    states = state_codes,
    municipalities = include_municipalities,
    type = "geographic_data"
  )
  
  # Check cache
  cached_data <- get_cache(cache_key)
  if (!is.null(cached_data)) {
    return(future::resolved(cached_data))
  }
  
  future_promise({
    log_event("Loading geographic data asynchronously")
    
    geo_data <- list(
      states = NULL,
      municipalities = NULL
    )
    
    # Load states
    geo_data$states <- load_brazilian_states_memo()
    
    # Filter by state codes if specified
    if (!is.null(state_codes) && !is.null(geo_data$states)) {
      geo_data$states <- geo_data$states %>%
        filter(state_code %in% state_codes)
    }
    
    # Load municipalities if requested
    if (include_municipalities) {
      if (!is.null(state_codes)) {
        # Load municipalities for specific states
        geo_data$municipalities <- map_dfr(state_codes, function(state) {
          load_brazilian_municipalities_memo(state)
        })
      } else {
        # Load all municipalities (memory intensive)
        geo_data$municipalities <- load_brazilian_municipalities_memo()
      }
    }
    
    # Cache for 1 hour
    set_cache(cache_key, geo_data, 3600)
    
    log_event("Geographic data loading completed")
    return(geo_data)
    
  }) %...!% {
    log_event(paste("Geographic data loading failed:", .$message), "ERROR")
    list(states = create_fallback_states_data(), municipalities = NULL)
  }
}

#' Memory management utilities
#' Monitor and optimize memory usage

#' Get current memory usage
#' @return List with memory statistics
get_memory_usage <- function() {
  gc_info <- gc()
  
  list(
    used_mb = round(sum(gc_info[, 2]), 1),
    available_mb = round(sum(gc_info[, 4]), 1),
    max_used_mb = round(sum(gc_info[, 6]), 1),
    gc_count = sum(gc_info[, 5])
  )
}

#' Clean up memory and caches
#' @param aggressive Whether to perform aggressive cleanup
cleanup_memory <- function(aggressive = FALSE) {
  
  log_event("Starting memory cleanup")
  
  initial_memory <- get_memory_usage()
  
  # Clear memoised caches
  if (aggressive) {
    memoise::forget(load_brazilian_states_memo)
    memoise::forget(load_brazilian_municipalities_memo)
    memoise::forget(search_legislative_data_memo)
  }
  
  # Clear application caches
  cleared_entries <- clear_cache()
  
  # Force garbage collection
  gc()
  
  final_memory <- get_memory_usage()
  memory_freed <- initial_memory$used_mb - final_memory$used_mb
  
  log_event(paste("Memory cleanup completed:", 
                 round(memory_freed, 1), "MB freed,",
                 cleared_entries, "cache entries cleared"))
  
  return(list(
    memory_freed_mb = memory_freed,
    cache_entries_cleared = cleared_entries,
    final_memory = final_memory
  ))
}

#' Performance monitoring
#' Track application performance metrics

# Global performance metrics
.performance_metrics <- new.env()
.performance_metrics$start_time <- Sys.time()
.performance_metrics$request_count <- 0
.performance_metrics$search_times <- numeric(0)
.performance_metrics$error_count <- 0

#' Record performance metric
#' @param metric_name Name of the metric
#' @param value Metric value
#' @param category Metric category
record_metric <- function(metric_name, value, category = "general") {
  
  timestamp <- Sys.time()
  
  # Initialize category if it doesn't exist
  if (!exists(category, envir = .performance_metrics)) {
    assign(category, list(), envir = .performance_metrics)
  }
  
  category_metrics <- get(category, envir = .performance_metrics)
  
  # Add metric
  if (!metric_name %in% names(category_metrics)) {
    category_metrics[[metric_name]] <- list()
  }
  
  category_metrics[[metric_name]][[length(category_metrics[[metric_name]]) + 1]] <- list(
    value = value,
    timestamp = timestamp
  )
  
  # Keep only last 100 entries per metric
  if (length(category_metrics[[metric_name]]) > 100) {
    category_metrics[[metric_name]] <- tail(category_metrics[[metric_name]], 100)
  }
  
  assign(category, category_metrics, envir = .performance_metrics)
}

#' Get performance statistics
#' @param category Optional category filter
#' @return Performance statistics
get_performance_stats <- function(category = NULL) {
  
  stats <- list(
    uptime_hours = round(as.numeric(Sys.time() - .performance_metrics$start_time, units = "hours"), 2),
    total_requests = .performance_metrics$request_count,
    total_errors = .performance_metrics$error_count
  )
  
  # Add search performance
  if (length(.performance_metrics$search_times) > 0) {
    stats$search_performance <- list(
      average_time_ms = round(mean(.performance_metrics$search_times), 0),
      median_time_ms = round(median(.performance_metrics$search_times), 0),
      max_time_ms = round(max(.performance_metrics$search_times), 0),
      total_searches = length(.performance_metrics$search_times)
    )
  }
  
  # Add memory stats
  stats$memory <- get_memory_usage()
  
  # Add category-specific stats if requested
  if (!is.null(category) && exists(category, envir = .performance_metrics)) {
    category_data <- get(category, envir = .performance_metrics)
    
    stats[[category]] <- lapply(category_data, function(metric_data) {
      values <- sapply(metric_data, `[[`, "value")
      list(
        count = length(values),
        average = if (length(values) > 0) round(mean(values), 2) else 0,
        latest = if (length(values) > 0) tail(values, 1) else 0
      )
    })
  }
  
  return(stats)
}

#' Timed execution wrapper
#' @param expr Expression to execute
#' @param metric_name Name for performance metric
#' @param category Metric category
#' @return Result of expression
timed_execution <- function(expr, metric_name = "execution_time", category = "performance") {
  
  start_time <- Sys.time()
  
  result <- tryCatch({
    force(expr)
  }, error = function(e) {
    .performance_metrics$error_count <- .performance_metrics$error_count + 1
    record_metric("error", 1, "errors")
    stop(e)
  })
  
  execution_time <- as.numeric(Sys.time() - start_time, units = "secs") * 1000
  record_metric(metric_name, execution_time, category)
  
  return(result)
}

#' Batch processing with progress tracking
#' @param data_list List of data to process
#' @param process_function Function to apply to each item
#' @param batch_size Number of items to process in each batch
#' @param progress_callback Optional progress callback function
#' @return List of processed results
batch_process <- function(data_list, process_function, batch_size = 10, progress_callback = NULL) {
  
  total_items <- length(data_list)
  
  if (total_items == 0) {
    return(list())
  }
  
  log_event(paste("Starting batch processing of", total_items, "items"))
  
  results <- list()
  
  # Process in batches
  for (i in seq(1, total_items, batch_size)) {
    batch_end <- min(i + batch_size - 1, total_items)
    batch_indices <- i:batch_end
    
    log_event(paste("Processing batch", ceiling(i / batch_size), "of", ceiling(total_items / batch_size)))
    
    # Process batch
    batch_results <- lapply(batch_indices, function(idx) {
      tryCatch({
        process_function(data_list[[idx]])
      }, error = function(e) {
        log_event(paste("Error processing item", idx, ":", e$message), "ERROR")
        NULL
      })
    })
    
    results <- c(results, batch_results)
    
    # Call progress callback if provided
    if (!is.null(progress_callback)) {
      progress_callback(batch_end / total_items)
    }
    
    # Small delay to prevent overwhelming the system
    Sys.sleep(0.1)
  }
  
  # Remove NULL results
  results <- results[!sapply(results, is.null)]
  
  log_event(paste("Batch processing completed:", length(results), "items processed successfully"))
  
  return(results)
}

#' Cache warming for frequently accessed data
#' @param warmup_data List of data to pre-cache
warm_cache <- function(warmup_data = NULL) {
  
  log_event("Starting cache warming")
  
  # Default warmup operations
  default_warmup <- list(
    states = function() load_brazilian_states_memo(),
    common_searches = function() {
      common_terms <- c("transporte", "mobilidade", "lei", "decreto")
      lapply(common_terms, function(term) {
        search_legislative_data_memo(query = term, limit = 100)
      })
    }
  )
  
  warmup_operations <- if (is.null(warmup_data)) default_warmup else warmup_data
  
  # Execute warmup operations asynchronously
  future_promise({
    lapply(names(warmup_operations), function(op_name) {
      tryCatch({
        log_event(paste("Warming cache for:", op_name))
        warmup_operations[[op_name]]()
      }, error = function(e) {
        log_event(paste("Cache warming failed for", op_name, ":", e$message), "WARN")
      })
    })
    
    log_event("Cache warming completed")
  })
}

#' Performance health check
#' @return Health status with performance metrics
performance_health_check <- function() {
  
  stats <- get_performance_stats()
  memory <- get_memory_usage()
  
  # Determine health status
  health_status <- "healthy"
  issues <- character(0)
  
  # Check memory usage
  if (memory$used_mb > 1000) {  # More than 1GB
    health_status <- "warning"
    issues <- c(issues, "High memory usage")
  }
  
  # Check error rate
  if (stats$total_requests > 0) {
    error_rate <- (stats$total_errors / stats$total_requests) * 100
    if (error_rate > 5) {  # More than 5% error rate
      health_status <- "unhealthy"
      issues <- c(issues, "High error rate")
    }
  }
  
  # Check average search time
  if (!is.null(stats$search_performance) && stats$search_performance$average_time_ms > 5000) {
    health_status <- "warning"
    issues <- c(issues, "Slow search performance")
  }
  
  return(list(
    status = health_status,
    issues = issues,
    metrics = stats,
    memory = memory,
    timestamp = Sys.time()
  ))
}