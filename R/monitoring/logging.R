# Production Logging and Monitoring Module
# Monitor Legislativo v4 - LGPD Compliant Logging for Academic Research
# ======================================================================

library(jsonlite)

# Global logging configuration
.log_config <- list(
  level = Sys.getenv("LOG_LEVEL", "INFO"),
  structured = TRUE,
  privacy_mode = "STRICT",  # LGPD compliance
  max_log_size_mb = 50,
  retention_days = 30,
  include_performance_metrics = TRUE,
  railway_optimized = TRUE
)

# Log levels hierarchy
.log_levels <- list(
  ERROR = 1,
  WARN = 2,
  INFO = 3,
  DEBUG = 4,
  TRACE = 5
)

# Performance metrics storage
.perf_metrics <- list(
  query_times = numeric(),
  cache_hits = 0,
  cache_misses = 0,
  memory_snapshots = list(),
  error_counts = list(),
  last_cleanup = Sys.time()
)

#' Initialize Production Logging System
#' 
#' Sets up LGPD-compliant logging for academic research platform
#' Optimized for Railway deployment with structured logging
#' 
#' @export
init_logging_system <- function() {
  
  cat("📊 Initializing production logging system (LGPD compliant)...\n")
  
  # Set timezone for Brazilian context
  Sys.setenv(TZ = "America/Sao_Paulo")
  
  # Create logs directory if it doesn't exist
  if (!dir.exists("logs")) {
    dir.create("logs", recursive = TRUE)
  }
  
  # Initialize performance monitoring
  .perf_metrics$session_start <<- Sys.time()
  .perf_metrics$environment <<- Sys.getenv("RAILWAY_ENVIRONMENT", "development")
  
  # Log system initialization
  log_info("logging_system_initialized", list(
    environment = .perf_metrics$environment,
    log_level = .log_config$level,
    privacy_mode = .log_config$privacy_mode,
    timezone = Sys.timezone(),
    r_version = R.version.string
  ))
  
  cat("✅ Logging system initialized with LGPD compliance\n")
  
  return(TRUE)
}

#' Structured Logging Function
#' 
#' Core logging function with LGPD compliance and performance tracking
#' 
#' @param level Log level (ERROR, WARN, INFO, DEBUG, TRACE)
#' @param event Event identifier
#' @param data Additional data (will be sanitized for privacy)
#' @param performance_data Performance metrics to include
#' @export
log_event <- function(level, event, data = NULL, performance_data = NULL) {
  
  # Check if this level should be logged
  if (.log_levels[[level]] > .log_levels[[.log_config$level]]) {
    return(invisible(NULL))
  }
  
  # Create structured log entry
  log_entry <- list(
    timestamp = format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z"),
    level = level,
    event = event,
    environment = Sys.getenv("RAILWAY_ENVIRONMENT", "development"),
    session_id = get_session_id()
  )
  
  # Add sanitized data (LGPD compliance)
  if (!is.null(data)) {
    log_entry$data <- sanitize_log_data(data)
  }
  
  # Add performance metrics if enabled
  if (.log_config$include_performance_metrics && !is.null(performance_data)) {
    log_entry$performance <- performance_data
  }
  
  # Format log message
  if (.log_config$structured) {
    log_message <- toJSON(log_entry, auto_unbox = TRUE)
  } else {
    log_message <- sprintf("[%s] %s - %s: %s", 
                          log_entry$timestamp, level, event, 
                          ifelse(is.null(data), "", paste(data, collapse = " ")))
  }
  
  # Output to console (Railway logs)
  cat(log_message, "\n")
  
  # Write to log file (if in production)
  if (Sys.getenv("RAILWAY_ENVIRONMENT") == "production") {
    write_to_log_file(log_message, level)
  }
  
  # Update performance metrics
  update_performance_metrics(level, event, performance_data)
  
  invisible(log_entry)
}

#' Convenience Logging Functions
#' 
#' @param event Event identifier
#' @param data Additional data
#' @param performance_data Performance metrics
#' @export
log_error <- function(event, data = NULL, performance_data = NULL) {
  log_event("ERROR", event, data, performance_data)
}

#' @export
log_warn <- function(event, data = NULL, performance_data = NULL) {
  log_event("WARN", event, data, performance_data)
}

#' @export
log_info <- function(event, data = NULL, performance_data = NULL) {
  log_event("INFO", event, data, performance_data)
}

#' @export
log_debug <- function(event, data = NULL, performance_data = NULL) {
  log_event("DEBUG", event, data, performance_data)
}

#' Log Database Query Performance
#' 
#' Specialized function for logging database query performance
#' 
#' @param query_type Type of query (SELECT, INSERT, UPDATE, etc.)
#' @param execution_time_ms Execution time in milliseconds
#' @param record_count Number of records affected/returned
#' @param cached Whether result was cached
#' @export
log_query_performance <- function(query_type, execution_time_ms, record_count = 0, cached = FALSE) {
  
  # Store query time for analysis
  .perf_metrics$query_times <<- c(.perf_metrics$query_times, execution_time_ms)
  
  # Keep only recent query times (memory management)
  if (length(.perf_metrics$query_times) > 1000) {
    .perf_metrics$query_times <<- tail(.perf_metrics$query_times, 500)
  }
  
  # Update cache statistics
  if (cached) {
    .perf_metrics$cache_hits <<- .perf_metrics$cache_hits + 1
  } else {
    .perf_metrics$cache_misses <<- .perf_metrics$cache_misses + 1
  }
  
  performance_data <- list(
    execution_time_ms = execution_time_ms,
    record_count = record_count,
    cached = cached,
    avg_query_time = mean(.perf_metrics$query_times, na.rm = TRUE),
    cache_hit_rate = calculate_cache_hit_rate()
  )
  
  # Log with appropriate level based on performance
  level <- if (execution_time_ms > 5000) {
    "WARN"  # Slow query warning
  } else if (execution_time_ms > 10000) {
    "ERROR"  # Very slow query
  } else {
    "DEBUG"  # Normal performance logging
  }
  
  log_event(level, "database_query", list(
    query_type = query_type,
    performance_category = categorize_performance(execution_time_ms)
  ), performance_data)
}

#' Log User Action (LGPD Compliant)
#' 
#' Logs user actions while maintaining privacy compliance
#' 
#' @param action Action performed
#' @param component Component/page involved
#' @param success Whether action was successful
#' @param user_context Anonymized user context
#' @export
log_user_action <- function(action, component, success = TRUE, user_context = NULL) {
  
  # Sanitize user context for LGPD compliance
  safe_context <- if (!is.null(user_context)) {
    list(
      session_duration = user_context$session_duration,
      user_type = user_context$user_type,  # academic, researcher, etc.
      access_pattern = user_context$access_pattern  # frequency category
      # NO personal identifiable information
    )
  } else {
    NULL
  }
  
  log_event(
    level = if(success) "INFO" else "WARN",
    event = "user_action",
    data = list(
      action = action,
      component = component,
      success = success,
      user_context = safe_context
    )
  )
}

#' Log System Error with Context
#' 
#' Enhanced error logging with system context and recovery information
#' 
#' @param error_message Error message
#' @param error_context Context where error occurred
#' @param stack_trace Stack trace information
#' @param recovery_attempted Whether automatic recovery was attempted
#' @export
log_system_error <- function(error_message, error_context = NULL, stack_trace = NULL, recovery_attempted = FALSE) {
  
  # Update error count statistics
  context_key <- error_context %||% "unknown"
  if (is.null(.perf_metrics$error_counts[[context_key]])) {
    .perf_metrics$error_counts[[context_key]] <<- 0
  }
  .perf_metrics$error_counts[[context_key]] <<- .perf_metrics$error_counts[[context_key]] + 1
  
  error_data <- list(
    message = substr(error_message, 1, 500),  # Limit message length
    context = error_context,
    recovery_attempted = recovery_attempted,
    error_count_this_session = .perf_metrics$error_counts[[context_key]],
    system_memory_mb = get_current_memory_usage()
  )
  
  # Include stack trace if available (but limit size)
  if (!is.null(stack_trace)) {
    error_data$stack_trace <- substr(paste(stack_trace, collapse = "\n"), 1, 1000)
  }
  
  log_error("system_error", error_data)
  
  # If too many errors in this context, escalate
  if (.perf_metrics$error_counts[[context_key]] > 10) {
    log_error("error_storm_detected", list(
      context = context_key,
      error_count = .perf_metrics$error_counts[[context_key]]
    ))
  }
}

#' Sanitize Log Data for LGPD Compliance
#' 
#' Removes or masks personal identifiable information from log data
#' 
#' @param data Data to sanitize
#' @return Sanitized data
sanitize_log_data <- function(data) {
  
  if (isTRUE(is.null(data)) || .log_config$privacy_mode != "STRICT") {
    return(data)
  }
  
  # Define fields that should be removed or masked
  sensitive_fields <- c("email", "name", "cpf", "rg", "telefone", "endereco", 
                       "password", "token", "session_token", "user_id")
  
  if (is.list(data)) {
    # Recursively sanitize list data
    sanitized <- lapply(data, function(item) {
      if (is.list(item)) {
        sanitize_log_data(item)
      } else {
        item
      }
    })
    
    # Remove sensitive fields
    for (field in sensitive_fields) {
      if (field %in% names(sanitized)) {
        sanitized[[field]] <- "[MASKED]"
      }
    }
    
    return(sanitized)
    
  } else if (is.character(data)) {
    # Mask potential email addresses and other PII patterns
    data <- gsub("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", "[EMAIL_MASKED]", data)
    data <- gsub("\\b\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}\\b", "[CPF_MASKED]", data)
    data <- gsub("\\b\\d{2}\\.\\d{3}\\.\\d{3}-\\d{1}\\b", "[RG_MASKED]", data)
    return(data)
  }
  
  return(data)
}

#' Get Anonymous Session ID
#' 
#' Generates session identifier that doesn't contain PII
#' 
#' @return Anonymous session identifier
get_session_id <- function() {
  if (is.null(.GlobalEnv$.session_id)) {
    # Generate anonymous session ID based on process start time
    .GlobalEnv$.session_id <- digest::digest(paste(Sys.getpid(), .perf_metrics$session_start), 
                                           algo = "md5", serialize = FALSE)
  }
  return(substr(.GlobalEnv$.session_id, 1, 8))
}

#' Write to Log File
#' 
#' Writes log entries to rotating log files
#' 
#' @param message Log message
#' @param level Log level
write_to_log_file <- function(message, level) {
  
  tryCatch({
    # Create log filename with date
    log_date <- format(Sys.Date(), "%Y-%m-%d")
    log_file <- file.path("logs", paste0("monitor_legislativo_", log_date, ".log"))
    
    # Write to log file
    cat(message, "\n", file = log_file, append = TRUE)
    
    # Check log file size and rotate if necessary
    if (file.exists(log_file)) {
      file_size_mb <- file.info(log_file)$size / (1024 * 1024)
      
      if (file_size_mb > .log_config$max_log_size_mb) {
        rotate_log_file(log_file)
      }
    }
    
  }, error = function(e) {
    # If file logging fails, at least log to console
    cat("LOG FILE ERROR:", e$message, "\n")
  })
}

#' Rotate Log File
#' 
#' Rotates log files when they exceed size limit
#' 
#' @param log_file Path to log file
rotate_log_file <- function(log_file) {
  
  tryCatch({
    # Create rotated filename
    timestamp <- format(Sys.time(), "%H%M%S")
    rotated_file <- gsub("\\.log$", paste0("_", timestamp, ".log"), log_file)
    
    # Move current log to rotated name
    file.rename(log_file, rotated_file)
    
    # Compress rotated log if possible
    if (requireNamespace("R.utils", quietly = TRUE)) {
      R.utils::gzip(rotated_file)
      file.remove(rotated_file)
    }
    
    log_info("log_file_rotated", list(
      original_file = log_file,
      rotated_file = rotated_file
    ))
    
  }, error = function(e) {
    log_error("log_rotation_failed", list(error = e$message))
  })
}

#' Update Performance Metrics
#' 
#' Updates internal performance tracking metrics
#' 
#' @param level Log level
#' @param event Event name
#' @param performance_data Performance data
update_performance_metrics <- function(level, event, performance_data) {
  
  # Periodic memory snapshots
  if (difftime(Sys.time(), .perf_metrics$last_cleanup, units = "mins") > 5) {
    .perf_metrics$memory_snapshots <<- c(.perf_metrics$memory_snapshots, 
                                        list(list(
                                          timestamp = Sys.time(),
                                          memory_mb = get_current_memory_usage()
                                        )))
    
    # Keep only recent snapshots
    if (length(.perf_metrics$memory_snapshots) > 100) {
      .perf_metrics$memory_snapshots <<- tail(.perf_metrics$memory_snapshots, 50)
    }
    
    .perf_metrics$last_cleanup <<- Sys.time()
  }
}

#' Get Current Memory Usage
#' 
#' Returns current memory usage in MB
#' 
#' @return Memory usage in MB
get_current_memory_usage <- function() {
  
  tryCatch({
    gc_info <- gc(verbose = FALSE)
    memory_mb <- sum(gc_info[, 2])
    return(round(memory_mb, 2))
  }, error = function(e) {
    return(0)
  })
}

#' Calculate Cache Hit Rate
#' 
#' Calculates current cache hit rate percentage
#' 
#' @return Cache hit rate as percentage
calculate_cache_hit_rate <- function() {
  
  total_cache_requests <- .perf_metrics$cache_hits + .perf_metrics$cache_misses
  
  if (total_cache_requests > 0) {
    return(round((.perf_metrics$cache_hits / total_cache_requests) * 100, 2))
  } else {
    return(0)
  }
}

#' Categorize Performance
#' 
#' Categorizes query performance into buckets
#' 
#' @param execution_time_ms Execution time in milliseconds
#' @return Performance category
categorize_performance <- function(execution_time_ms) {
  
  if (execution_time_ms < 100) {
    return("excellent")
  } else if (execution_time_ms < 500) {
    return("good")
  } else if (execution_time_ms < 2000) {
    return("acceptable")
  } else if (execution_time_ms < 5000) {
    return("slow")
  } else {
    return("very_slow")
  }
}

#' Get Performance Summary
#' 
#' Returns comprehensive performance summary for monitoring
#' 
#' @return Performance metrics summary
#' @export
get_performance_summary <- function() {
  
  summary <- list(
    session_uptime_minutes = as.numeric(difftime(Sys.time(), .perf_metrics$session_start, units = "mins")),
    total_queries = length(.perf_metrics$query_times),
    avg_query_time_ms = ifelse(length(.perf_metrics$query_times) > 0, 
                              mean(.perf_metrics$query_times, na.rm = TRUE), 0),
    slowest_query_ms = ifelse(length(.perf_metrics$query_times) > 0, 
                             max(.perf_metrics$query_times, na.rm = TRUE), 0),
    cache_hit_rate_percent = calculate_cache_hit_rate(),
    total_cache_requests = .perf_metrics$cache_hits + .perf_metrics$cache_misses,
    current_memory_mb = get_current_memory_usage(),
    error_contexts = names(.perf_metrics$error_counts),
    total_errors = sum(unlist(.perf_metrics$error_counts), na.rm = TRUE)
  )
  
  # Add memory trend if we have snapshots
  if (length(.perf_metrics$memory_snapshots) > 1) {
    recent_memory <- sapply(.perf_metrics$memory_snapshots, function(x) x$memory_mb)
    summary$memory_trend <- if (length(recent_memory) > 1) {
      ifelse(recent_memory[length(recent_memory)] > recent_memory[1], "increasing", "stable_or_decreasing")
    } else {
      "unknown"
    }
  }
  
  return(summary)
}

#' Cleanup Performance Metrics
#' 
#' Periodic cleanup of performance metrics to prevent memory leaks
#' 
#' @export
cleanup_performance_metrics <- function() {
  
  # Keep only recent query times
  if (length(.perf_metrics$query_times) > 500) {
    .perf_metrics$query_times <<- tail(.perf_metrics$query_times, 250)
  }
  
  # Reset error counts if they're getting too large
  total_errors <- sum(unlist(.perf_metrics$error_counts), na.rm = TRUE)
  if (total_errors > 1000) {
    .perf_metrics$error_counts <<- list()
    log_info("performance_metrics_reset", list(
      reason = "excessive_error_counts",
      previous_total = total_errors
    ))
  }
  
  # Cleanup old memory snapshots
  if (length(.perf_metrics$memory_snapshots) > 50) {
    .perf_metrics$memory_snapshots <<- tail(.perf_metrics$memory_snapshots, 25)
  }
  
  log_debug("performance_metrics_cleaned", list(
    query_times_count = length(.perf_metrics$query_times),
    memory_snapshots_count = length(.perf_metrics$memory_snapshots),
    error_contexts_count = length(.perf_metrics$error_counts)
  ))
}

# Initialize logging system when module is loaded
if (Sys.getenv("RAILWAY_ENVIRONMENT") != "") {
  init_logging_system()
}

cat("✅ Production logging and monitoring module loaded (LGPD compliant)\n")