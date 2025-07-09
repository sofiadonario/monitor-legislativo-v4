# Performance Optimization for Monitor Legislativo v4
# Database query optimization, lazy loading, virtual scrolling, and memory management

library(DBI)
library(pool)
library(dplyr)
library(future)
library(promises)
library(memoise)
library(profvis)
library(pryr)

# Performance optimization configuration
PERF_CONFIG <- list(
  database = list(
    connection_pool_size = 10,
    query_timeout = 30,
    batch_size = 1000,
    parallel_queries = TRUE,
    connection_lifetime = 3600,  # 1 hour
    prepared_statements = TRUE
  ),
  
  memory = list(
    gc_threshold_mb = 500,
    gc_frequency_minutes = 15,
    object_size_limit_mb = 100,
    enable_memory_profiling = TRUE,
    cleanup_aggressive = FALSE
  ),
  
  lazy_loading = list(
    chunk_size = 100,
    preload_chunks = 2,
    enable_virtualization = TRUE,
    scroll_buffer_size = 50,
    enable_infinite_scroll = TRUE
  ),
  
  query_optimization = list(
    enable_query_cache = TRUE,
    cache_ttl_seconds = 300,
    enable_query_batching = TRUE,
    max_batch_size = 10,
    enable_prepared_statements = TRUE,
    connection_pooling = TRUE
  ),
  
  monitoring = list(
    track_query_performance = TRUE,
    track_memory_usage = TRUE,
    alert_slow_queries_ms = 2000,
    alert_memory_usage_mb = 1000,
    enable_profiling = FALSE  # Only enable for debugging
  )
)

# Global performance state
perf_state <- list(
  query_cache = list(),
  memory_stats = list(),
  query_stats = list(),
  connection_pool = NULL,
  last_gc = Sys.time()
)

#' Initialize database connection pool for optimal performance
#' @param db_config Database configuration
#' @return Database pool object
initialize_connection_pool <- function(db_config = NULL) {
  tryCatch({
    # Use default configuration if none provided
    if (is.null(db_config)) {
      db_config <- list(
        host = Sys.getenv("DB_HOST", "localhost"),
        port = Sys.getenv("DB_PORT", "5432"),
        dbname = Sys.getenv("DB_NAME", "monitor_legislativo"),
        user = Sys.getenv("DB_USER", "postgres"),
        password = Sys.getenv("DB_PASSWORD", "")
      )
    }
    
    # Create connection pool
    pool <- pool::dbPool(
      drv = RPostgres::Postgres(),
      host = db_config$host,
      port = as.integer(db_config$port),
      dbname = db_config$dbname,
      user = db_config$user,
      password = db_config$password,
      minSize = 2,
      maxSize = PERF_CONFIG$database$connection_pool_size,
      idleTimeout = PERF_CONFIG$database$connection_lifetime,
      validationQuery = "SELECT 1"
    )
    
    perf_state$connection_pool <<- pool
    log_event("Database connection pool initialized successfully", "INFO")
    
    return(pool)
    
  }, error = function(e) {
    log_event(paste("Failed to initialize connection pool:", e$message), "ERROR")
    return(NULL)
  })
}

#' Execute optimized database query with caching and performance monitoring
#' @param query SQL query string
#' @param params Query parameters
#' @param cache_key Optional cache key
#' @param use_cache Whether to use caching
#' @return Query results
execute_optimized_query <- function(query, params = NULL, cache_key = NULL, use_cache = TRUE) {
  start_time <- Sys.time()
  
  # Generate cache key if not provided
  if (is.null(cache_key) && use_cache) {
    cache_key <- generate_query_cache_key(query, params)
  }
  
  # Check cache first
  if (use_cache && !is.null(cache_key)) {
    cached_result <- get_query_cache(cache_key)
    if (!is.null(cached_result)) {
      record_query_metric("cache_hit", query, 0)
      return(cached_result)
    }
  }
  
  # Execute query with performance monitoring
  tryCatch({
    if (is.null(perf_state$connection_pool)) {
      stop("Database connection pool not initialized")
    }
    
    # Execute query with timeout
    result <- if (is.null(params)) {
      dbGetQuery(perf_state$connection_pool, query)
    } else {
      dbGetQuery(perf_state$connection_pool, query, params = params)
    }
    
    # Calculate execution time
    execution_time <- as.numeric(Sys.time() - start_time, units = "secs") * 1000
    
    # Record performance metrics
    record_query_metric("execution_time", query, execution_time)
    
    # Alert on slow queries
    if (PERF_CONFIG$monitoring$alert_slow_queries_ms < execution_time) {
      log_event(paste("Slow query detected:", execution_time, "ms -", substr(query, 1, 100)), "WARN")
    }
    
    # Cache result if caching is enabled
    if (use_cache && !is.null(cache_key)) {
      set_query_cache(cache_key, result)
    }
    
    return(result)
    
  }, error = function(e) {
    execution_time <- as.numeric(Sys.time() - start_time, units = "secs") * 1000
    record_query_metric("error", query, execution_time)
    log_event(paste("Query execution error:", e$message), "ERROR")
    stop(e)
  })
}

#' Execute batch queries for improved performance
#' @param queries List of query objects with query and params
#' @param parallel Whether to execute in parallel
#' @return List of query results
execute_batch_queries <- function(queries, parallel = TRUE) {
  if (!PERF_CONFIG$query_optimization$enable_query_batching) {
    # Execute sequentially if batching is disabled
    return(lapply(queries, function(q) execute_optimized_query(q$query, q$params)))
  }
  
  # Split into batches
  batch_size <- PERF_CONFIG$query_optimization$max_batch_size
  batches <- split(queries, ceiling(seq_along(queries) / batch_size))
  
  # Execute batches
  if (parallel && length(batches) > 1) {
    # Execute batches in parallel
    future_lapply(batches, function(batch) {
      lapply(batch, function(q) execute_optimized_query(q$query, q$params))
    }) %...>% {
      # Flatten results
      unlist(., recursive = FALSE)
    }
  } else {
    # Execute sequentially
    results <- list()
    for (batch in batches) {
      batch_results <- lapply(batch, function(q) execute_optimized_query(q$query, q$params))
      results <- c(results, batch_results)
    }
    return(results)
  }
}

#' Create optimized data loader with lazy loading and virtualization
#' @param data_source Data source function or query
#' @param chunk_size Size of each data chunk
#' @param total_rows Total number of rows (if known)
#' @return Data loader object
create_optimized_data_loader <- function(data_source, chunk_size = NULL, total_rows = NULL) {
  chunk_size <- chunk_size %||% PERF_CONFIG$lazy_loading$chunk_size
  
  # Create loader state
  loader_state <- list(
    data_source = data_source,
    chunk_size = chunk_size,
    total_rows = total_rows,
    loaded_chunks = list(),
    current_position = 0,
    is_loading = FALSE
  )
  
  # Return loader functions
  list(
    load_chunk = function(chunk_index) {
      load_data_chunk(loader_state, chunk_index)
    },
    
    get_chunk = function(chunk_index) {
      get_cached_chunk(loader_state, chunk_index)
    },
    
    preload_chunks = function(start_index, count = NULL) {
      count <- count %||% PERF_CONFIG$lazy_loading$preload_chunks
      preload_data_chunks(loader_state, start_index, count)
    },
    
    get_total_rows = function() {
      loader_state$total_rows
    },
    
    get_loaded_chunks = function() {
      names(loader_state$loaded_chunks)
    }
  )
}

#' Load data chunk with caching
#' @param loader_state Loader state object
#' @param chunk_index Index of chunk to load
#' @return Data chunk
load_data_chunk <- function(loader_state, chunk_index) {
  # Check if chunk is already loaded
  chunk_key <- as.character(chunk_index)
  if (chunk_key %in% names(loader_state$loaded_chunks)) {
    return(loader_state$loaded_chunks[[chunk_key]])
  }
  
  # Avoid loading if already in progress
  if (loader_state$is_loading) {
    return(NULL)
  }
  
  loader_state$is_loading <- TRUE
  
  tryCatch({
    # Calculate offset and limit
    offset <- (chunk_index - 1) * loader_state$chunk_size
    limit <- loader_state$chunk_size
    
    # Load data chunk
    chunk_data <- if (is.function(loader_state$data_source)) {
      loader_state$data_source(offset, limit)
    } else {
      # Assume it's a query string
      query <- paste(loader_state$data_source, "LIMIT", limit, "OFFSET", offset)
      execute_optimized_query(query)
    }
    
    # Cache chunk
    loader_state$loaded_chunks[[chunk_key]] <- chunk_data
    
    # Update total rows if not known
    if (is.null(loader_state$total_rows) && nrow(chunk_data) < loader_state$chunk_size) {
      loader_state$total_rows <- offset + nrow(chunk_data)
    }
    
    loader_state$is_loading <- FALSE
    return(chunk_data)
    
  }, error = function(e) {
    loader_state$is_loading <- FALSE
    log_event(paste("Error loading data chunk", chunk_index, ":", e$message), "ERROR")
    return(NULL)
  })
}

#' Get cached data chunk
#' @param loader_state Loader state object
#' @param chunk_index Index of chunk to get
#' @return Cached chunk or NULL
get_cached_chunk <- function(loader_state, chunk_index) {
  chunk_key <- as.character(chunk_index)
  return(loader_state$loaded_chunks[[chunk_key]])
}

#' Preload multiple data chunks
#' @param loader_state Loader state object
#' @param start_index Starting chunk index
#' @param count Number of chunks to preload
preload_data_chunks <- function(loader_state, start_index, count) {
  future_lapply(start_index:(start_index + count - 1), function(chunk_index) {
    load_data_chunk(loader_state, chunk_index)
  }) %...>% {
    log_event(paste("Preloaded", count, "data chunks starting from", start_index), "INFO")
  }
}

#' Optimize memory usage with intelligent garbage collection
#' @param aggressive Whether to perform aggressive cleanup
#' @return Memory statistics
optimize_memory_usage <- function(aggressive = FALSE) {
  start_memory <- get_memory_usage()
  
  # Check if GC is needed
  if (!should_run_gc(aggressive)) {
    return(start_memory)
  }
  
  tryCatch({
    # Clear query cache if memory is high
    if (start_memory$used_mb > PERF_CONFIG$memory$gc_threshold_mb) {
      clear_query_cache(max_age_minutes = 30)
    }
    
    # Clear large objects from environment
    if (aggressive) {
      clear_large_objects()
    }
    
    # Run garbage collection
    gc_result <- gc(verbose = FALSE)
    
    # Update last GC time
    perf_state$last_gc <<- Sys.time()
    
    # Calculate memory freed
    end_memory <- get_memory_usage()
    memory_freed <- start_memory$used_mb - end_memory$used_mb
    
    # Record memory metrics
    record_memory_metric("gc_freed_mb", memory_freed)
    record_memory_metric("gc_time", as.numeric(Sys.time() - start_memory$timestamp, units = "secs"))
    
    if (memory_freed > 10) {  # Only log if significant memory was freed
      log_event(paste("Memory optimization completed:", round(memory_freed, 1), "MB freed"), "INFO")
    }
    
    return(end_memory)
    
  }, error = function(e) {
    log_event(paste("Memory optimization error:", e$message), "ERROR")
    return(start_memory)
  })
}

#' Check if garbage collection should be run
#' @param force Force GC regardless of conditions
#' @return Boolean indicating if GC should run
should_run_gc <- function(force = FALSE) {
  if (force) return(TRUE)
  
  # Check memory threshold
  current_memory <- get_memory_usage()
  if (current_memory$used_mb > PERF_CONFIG$memory$gc_threshold_mb) {
    return(TRUE)
  }
  
  # Check time threshold
  time_since_gc <- as.numeric(Sys.time() - perf_state$last_gc, units = "mins")
  if (time_since_gc > PERF_CONFIG$memory$gc_frequency_minutes) {
    return(TRUE)
  }
  
  return(FALSE)
}

#' Get current memory usage statistics
#' @return Memory usage information
get_memory_usage <- function() {
  # Get memory info from different sources
  mem_info <- list(
    timestamp = Sys.time()
  )
  
  tryCatch({
    # R memory usage
    gc_info <- gc(verbose = FALSE)
    mem_info$used_mb <- sum(gc_info[, "used"]) * 8 / 1024 / 1024  # Convert to MB
    mem_info$max_mb <- sum(gc_info[, "max used"]) * 8 / 1024 / 1024
    
    # System memory (if available)
    if (Sys.info()["sysname"] == "Linux") {
      mem_info$system_total_mb <- get_system_memory_linux()
    }
    
    # Object sizes in current environment
    if (PERF_CONFIG$memory$enable_memory_profiling) {
      mem_info$large_objects <- find_large_objects()
    }
    
  }, error = function(e) {
    log_event(paste("Error getting memory usage:", e$message), "WARN")
    mem_info$used_mb <- 0
  })
  
  return(mem_info)
}

#' Find large objects in the environment
#' @param size_limit_mb Size limit in MB
#' @return List of large objects
find_large_objects <- function(size_limit_mb = NULL) {
  size_limit_mb <- size_limit_mb %||% PERF_CONFIG$memory$object_size_limit_mb
  size_limit_bytes <- size_limit_mb * 1024 * 1024
  
  tryCatch({
    # Get all objects in global environment
    obj_names <- ls(envir = .GlobalEnv)
    large_objects <- list()
    
    for (obj_name in obj_names) {
      obj <- get(obj_name, envir = .GlobalEnv)
      obj_size <- as.numeric(object.size(obj))
      
      if (obj_size > size_limit_bytes) {
        large_objects[[obj_name]] <- list(
          size_mb = round(obj_size / 1024 / 1024, 2),
          class = class(obj)[1]
        )
      }
    }
    
    return(large_objects)
    
  }, error = function(e) {
    return(list())
  })
}

#' Clear large objects from environment
#' @param size_threshold_mb Size threshold for removal
clear_large_objects <- function(size_threshold_mb = NULL) {
  size_threshold_mb <- size_threshold_mb %||% PERF_CONFIG$memory$object_size_limit_mb
  
  large_objects <- find_large_objects(size_threshold_mb)
  
  if (length(large_objects) > 0) {
    removed_count <- 0
    for (obj_name in names(large_objects)) {
      # Only remove objects that look like temporary data
      if (grepl("^(temp_|cache_|tmp_)", obj_name)) {
        rm(list = obj_name, envir = .GlobalEnv)
        removed_count <- removed_count + 1
      }
    }
    
    if (removed_count > 0) {
      log_event(paste("Removed", removed_count, "large temporary objects"), "INFO")
    }
  }
}

#' Generate cache key for query results
#' @param query SQL query
#' @param params Query parameters
#' @return Cache key string
generate_query_cache_key <- function(query, params = NULL) {
  hash_input <- list(query = query, params = params)
  digest::digest(hash_input, algo = "md5")
}

#' Store query result in cache
#' @param cache_key Cache key
#' @param result Query result
set_query_cache <- function(cache_key, result) {
  if (!PERF_CONFIG$query_optimization$enable_query_cache) {
    return()
  }
  
  cache_entry <- list(
    result = result,
    timestamp = Sys.time(),
    ttl = PERF_CONFIG$query_optimization$cache_ttl_seconds
  )
  
  perf_state$query_cache[[cache_key]] <<- cache_entry
  
  # Limit cache size
  if (length(perf_state$query_cache) > 100) {
    clear_oldest_cache_entries(10)
  }
}

#' Get query result from cache
#' @param cache_key Cache key
#' @return Cached result or NULL
get_query_cache <- function(cache_key) {
  if (!PERF_CONFIG$query_optimization$enable_query_cache) {
    return(NULL)
  }
  
  cache_entry <- perf_state$query_cache[[cache_key]]
  
  if (is.null(cache_entry)) {
    return(NULL)
  }
  
  # Check if cache entry has expired
  age_seconds <- as.numeric(Sys.time() - cache_entry$timestamp, units = "secs")
  if (age_seconds > cache_entry$ttl) {
    perf_state$query_cache[[cache_key]] <<- NULL
    return(NULL)
  }
  
  return(cache_entry$result)
}

#' Clear query cache
#' @param max_age_minutes Maximum age in minutes
clear_query_cache <- function(max_age_minutes = NULL) {
  if (is.null(max_age_minutes)) {
    # Clear all cache
    cleared_count <- length(perf_state$query_cache)
    perf_state$query_cache <<- list()
  } else {
    # Clear old entries
    current_time <- Sys.time()
    cleared_count <- 0
    
    for (key in names(perf_state$query_cache)) {
      entry <- perf_state$query_cache[[key]]
      age_minutes <- as.numeric(current_time - entry$timestamp, units = "mins")
      
      if (age_minutes > max_age_minutes) {
        perf_state$query_cache[[key]] <<- NULL
        cleared_count <- cleared_count + 1
      }
    }
  }
  
  if (cleared_count > 0) {
    log_event(paste("Cleared", cleared_count, "query cache entries"), "INFO")
  }
  
  return(cleared_count)
}

#' Clear oldest cache entries
#' @param count Number of entries to clear
clear_oldest_cache_entries <- function(count) {
  if (length(perf_state$query_cache) == 0) {
    return(0)
  }
  
  # Sort by timestamp
  timestamps <- sapply(perf_state$query_cache, function(x) x$timestamp)
  oldest_keys <- names(sort(timestamps))[1:min(count, length(timestamps))]
  
  for (key in oldest_keys) {
    perf_state$query_cache[[key]] <<- NULL
  }
  
  return(length(oldest_keys))
}

#' Record query performance metric
#' @param metric_type Type of metric
#' @param query Query string
#' @param value Metric value
record_query_metric <- function(metric_type, query, value) {
  if (!PERF_CONFIG$monitoring$track_query_performance) {
    return()
  }
  
  metric_entry <- list(
    timestamp = Sys.time(),
    query_hash = substr(digest::digest(query), 1, 8),
    metric_type = metric_type,
    value = value
  )
  
  if (is.null(perf_state$query_stats)) {
    perf_state$query_stats <<- list()
  }
  
  perf_state$query_stats <<- append(perf_state$query_stats, list(metric_entry))
  
  # Limit stats size
  if (length(perf_state$query_stats) > 1000) {
    perf_state$query_stats <<- tail(perf_state$query_stats, 500)
  }
}

#' Record memory performance metric
#' @param metric_type Type of metric
#' @param value Metric value
record_memory_metric <- function(metric_type, value) {
  if (!PERF_CONFIG$monitoring$track_memory_usage) {
    return()
  }
  
  metric_entry <- list(
    timestamp = Sys.time(),
    metric_type = metric_type,
    value = value
  )
  
  if (is.null(perf_state$memory_stats)) {
    perf_state$memory_stats <<- list()
  }
  
  perf_state$memory_stats <<- append(perf_state$memory_stats, list(metric_entry))
  
  # Limit stats size
  if (length(perf_state$memory_stats) > 500) {
    perf_state$memory_stats <<- tail(perf_state$memory_stats, 250)
  }
}

#' Get performance statistics summary
#' @return Performance statistics
get_performance_stats <- function() {
  stats <- list(
    timestamp = Sys.time(),
    memory = get_memory_usage(),
    query_cache = list(
      size = length(perf_state$query_cache),
      hit_rate = calculate_cache_hit_rate()
    )
  )
  
  # Query performance stats
  if (length(perf_state$query_stats) > 0) {
    execution_times <- sapply(perf_state$query_stats, function(x) {
      if (x$metric_type == "execution_time") x$value else NA
    })
    execution_times <- execution_times[!is.na(execution_times)]
    
    if (length(execution_times) > 0) {
      stats$query_performance <- list(
        avg_time_ms = round(mean(execution_times), 2),
        median_time_ms = round(median(execution_times), 2),
        max_time_ms = round(max(execution_times), 2),
        total_queries = length(execution_times)
      )
    }
  }
  
  # Memory performance stats
  if (length(perf_state$memory_stats) > 0) {
    gc_times <- sapply(perf_state$memory_stats, function(x) {
      if (x$metric_type == "gc_time") x$value else NA
    })
    gc_times <- gc_times[!is.na(gc_times)]
    
    if (length(gc_times) > 0) {
      stats$memory_performance <- list(
        avg_gc_time_sec = round(mean(gc_times), 2),
        total_gc_runs = length(gc_times)
      )
    }
  }
  
  return(stats)
}

#' Calculate cache hit rate
#' @return Cache hit rate percentage
calculate_cache_hit_rate <- function() {
  if (length(perf_state$query_stats) == 0) {
    return(0)
  }
  
  hits <- sum(sapply(perf_state$query_stats, function(x) x$metric_type == "cache_hit"))
  total <- length(perf_state$query_stats)
  
  if (total == 0) return(0)
  
  return(round((hits / total) * 100, 2))
}

#' Get system memory on Linux
#' @return System memory in MB
get_system_memory_linux <- function() {
  tryCatch({
    meminfo <- readLines("/proc/meminfo")
    mem_total_line <- meminfo[grepl("^MemTotal:", meminfo)]
    mem_total_kb <- as.numeric(gsub(".*?(\\d+).*", "\\1", mem_total_line))
    return(round(mem_total_kb / 1024, 0))
  }, error = function(e) {
    return(NULL)
  })
}

#' Initialize performance optimization system
#' @param config Optional configuration override
#' @return Initialization status
initialize_performance_optimization <- function(config = NULL) {
  if (!is.null(config)) {
    PERF_CONFIG <<- modifyList(PERF_CONFIG, config)
  }
  
  log_event("Initializing performance optimization system...", "INFO")
  
  # Initialize connection pool
  pool_result <- initialize_connection_pool()
  
  # Initialize memory monitoring
  perf_state$memory_stats <<- list()
  perf_state$query_stats <<- list()
  perf_state$query_cache <<- list()
  perf_state$last_gc <<- Sys.time()
  
  # Initial memory optimization
  initial_memory <- optimize_memory_usage(aggressive = FALSE)
  
  log_event("Performance optimization system initialized", "INFO")
  
  return(list(
    status = "success",
    connection_pool = !is.null(pool_result),
    initial_memory_mb = initial_memory$used_mb
  ))
}