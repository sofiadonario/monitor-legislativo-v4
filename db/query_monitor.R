# ============================================================================
# QUERY PERFORMANCE MONITORING SYSTEM - Railway PostgreSQL
# ============================================================================
# 
# This module provides comprehensive query performance monitoring for the
# Brazilian Legislative Monitor R Shiny application running on Railway.
#
# Features:
# 1. Real-time query execution tracking
# 2. Slow query identification and logging
# 3. Performance metrics collection and analysis
# 4. Database health monitoring
# 5. Automated alerting for performance issues
# 6. Query optimization recommendations
# 7. Resource usage tracking
# 8. Performance trend analysis
#
# Integration:
# - Works with existing connection.R module
# - Compatible with performance_optimization.R
# - Supports Railway PostgreSQL monitoring
# - Includes Shiny dashboard integration
#
# Railway Optimizations:
# - Low overhead monitoring to preserve resources
# - Efficient data storage and aggregation
# - Memory-conscious metrics collection
# - Automated cleanup of old monitoring data
# ============================================================================

cat("📊 Loading Query Performance Monitoring System for Railway PostgreSQL\n")

# Load required libraries
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
  library(pool)
  library(dplyr)
  library(lubridate)
  library(jsonlite)
})

# ============================================================================
# GLOBAL MONITORING CONFIGURATION
# ============================================================================

.monitor_config <- list(
  enabled = TRUE,
  slow_query_threshold_seconds = 2.0,
  very_slow_query_threshold_seconds = 10.0,
  log_all_queries = FALSE,
  log_slow_queries_only = TRUE,
  max_query_log_entries = 10000,
  cleanup_interval_hours = 24,
  performance_alert_threshold = 5.0,
  monitoring_batch_size = 100,
  metrics_retention_days = 30
)

# Global monitoring state
.monitoring_state <- list(
  initialized = FALSE,
  last_cleanup = NULL,
  total_queries_monitored = 0,
  active_connections = 0,
  monitoring_overhead_ms = 0
)

# Performance metrics storage
.performance_metrics <- list(
  query_log = list(),
  execution_times = numeric(),
  slow_queries = list(),
  connection_metrics = list(),
  error_log = list(),
  daily_stats = list()
)

# Alert thresholds and notifications
.alert_config <- list(
  max_avg_query_time = 3.0,
  max_slow_queries_per_hour = 10,
  max_connection_failures_per_hour = 5,
  alert_cooldown_minutes = 30,
  last_alert_time = NULL
)

# ============================================================================
# MONITORING INITIALIZATION
# ============================================================================

#' Initialize query performance monitoring system
#' @param config Optional configuration overrides
#' @return TRUE if successful
init_query_monitoring <- function(config = list()) {
  cat("🚀 Initializing Query Performance Monitoring System...\n")
  
  # Apply configuration overrides
  for (key in names(config)) {
    if (key %in% names(.monitor_config)) {
      .monitor_config[[key]] <<- config[[key]]
    }
  }
  
  tryCatch({
    # Create monitoring tables if they don't exist
    create_monitoring_tables()
    
    # Initialize monitoring metrics
    initialize_monitoring_metrics()
    
    # Set up cleanup schedule
    schedule_monitoring_cleanup()
    
    .monitoring_state$initialized <<- TRUE
    .monitoring_state$last_cleanup <<- Sys.time()
    
    cat("✅ Query Performance Monitoring initialized successfully\n")
    cat("📊 Monitoring configuration:\n")
    cat("   - Slow query threshold:", .monitor_config$slow_query_threshold_seconds, "seconds\n")
    cat("   - Log all queries:", .monitor_config$log_all_queries, "\n")
    cat("   - Maximum log entries:", .monitor_config$max_query_log_entries, "\n")
    cat("   - Cleanup interval:", .monitor_config$cleanup_interval_hours, "hours\n")
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Failed to initialize query monitoring:", e$message, "\n")
    .monitoring_state$initialized <<- FALSE
    return(FALSE)
  })
}

#' Create monitoring database tables
create_monitoring_tables <- function() {
  # Get database pool
  pool <- get_monitoring_pool()
  if (is.null(pool)) return(FALSE)
  
  tryCatch({
    # Query performance log table
    dbExecute(pool, "
      CREATE TABLE IF NOT EXISTS query_performance_log (
        id SERIAL PRIMARY KEY,
        query_hash VARCHAR(64) NOT NULL,
        query_type VARCHAR(50),
        query_preview TEXT,
        execution_time_ms INTEGER NOT NULL,
        rows_returned INTEGER,
        rows_affected INTEGER,
        parameters_count INTEGER,
        connection_id VARCHAR(100),
        executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_slow_query BOOLEAN DEFAULT FALSE,
        is_error BOOLEAN DEFAULT FALSE,
        error_message TEXT,
        source_function VARCHAR(100),
        user_session VARCHAR(100)
      )
    ")
    
    # Connection metrics table
    dbExecute(pool, "
      CREATE TABLE IF NOT EXISTS connection_metrics_log (
        id SERIAL PRIMARY KEY,
        metric_type VARCHAR(50) NOT NULL,
        metric_value DECIMAL(10,2),
        metric_details JSONB,
        recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    ")
    
    # Daily performance summary table
    dbExecute(pool, "
      CREATE TABLE IF NOT EXISTS daily_performance_summary (
        id SERIAL PRIMARY KEY,
        summary_date DATE NOT NULL UNIQUE,
        total_queries INTEGER,
        avg_execution_time_ms DECIMAL(8,2),
        slow_queries_count INTEGER,
        very_slow_queries_count INTEGER,
        total_errors INTEGER,
        peak_connections INTEGER,
        total_rows_returned BIGINT,
        cache_hit_rate DECIMAL(5,2),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    ")
    
    # Performance alerts table
    dbExecute(pool, "
      CREATE TABLE IF NOT EXISTS performance_alerts (
        id SERIAL PRIMARY KEY,
        alert_type VARCHAR(50) NOT NULL,
        alert_level VARCHAR(20) NOT NULL,
        alert_message TEXT,
        metric_value DECIMAL(10,2),
        threshold_value DECIMAL(10,2),
        additional_context JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        resolved_at TIMESTAMP,
        is_resolved BOOLEAN DEFAULT FALSE
      )
    ")
    
    # Create indexes for performance
    performance_indexes <- c(
      "CREATE INDEX IF NOT EXISTS idx_qpl_executed_at ON query_performance_log (executed_at DESC)",
      "CREATE INDEX IF NOT EXISTS idx_qpl_execution_time ON query_performance_log (execution_time_ms DESC)",
      "CREATE INDEX IF NOT EXISTS idx_qpl_query_type ON query_performance_log (query_type)",
      "CREATE INDEX IF NOT EXISTS idx_qpl_slow_query ON query_performance_log (is_slow_query) WHERE is_slow_query = TRUE",
      "CREATE INDEX IF NOT EXISTS idx_cml_recorded_at ON connection_metrics_log (recorded_at DESC)",
      "CREATE INDEX IF NOT EXISTS idx_cml_metric_type ON connection_metrics_log (metric_type)",
      "CREATE INDEX IF NOT EXISTS idx_dps_summary_date ON daily_performance_summary (summary_date DESC)",
      "CREATE INDEX IF NOT EXISTS idx_pa_created_at ON performance_alerts (created_at DESC)",
      "CREATE INDEX IF NOT EXISTS idx_pa_unresolved ON performance_alerts (is_resolved) WHERE is_resolved = FALSE"
    )
    
    for (index_sql in performance_indexes) {
      dbExecute(pool, index_sql)
    }
    
    cat("📊 Monitoring tables created successfully\n")
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Error creating monitoring tables:", e$message, "\n")
    return(FALSE)
  })
}

#' Get database pool for monitoring (with fallback)
get_monitoring_pool <- function() {
  # Try to get existing pool from connection system
  if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    return(secure_db_pool)
  } else if (exists("get_database_pool")) {
    return(get_database_pool())
  } else if (exists(".db_pool") && !is.null(.db_pool)) {
    return(.db_pool)
  }
  
  cat("⚠️ No database pool available for monitoring\n")
  return(NULL)
}

#' Initialize monitoring metrics
initialize_monitoring_metrics <- function() {
  .performance_metrics$query_log <<- list()
  .performance_metrics$execution_times <<- numeric()
  .performance_metrics$slow_queries <<- list()
  .performance_metrics$connection_metrics <<- list()
  .performance_metrics$error_log <<- list()
  .performance_metrics$daily_stats <<- list()
  
  .monitoring_state$total_queries_monitored <<- 0
  .monitoring_state$active_connections <<- 0
  .monitoring_state$monitoring_overhead_ms <<- 0
}

# ============================================================================
# QUERY EXECUTION MONITORING
# ============================================================================

#' Monitor database query execution with performance tracking
#' @param query SQL query to execute
#' @param params Query parameters
#' @param pool Database connection pool
#' @param source_function Name of calling function
#' @param user_session User session identifier
#' @return List with query result and performance metrics
monitor_query_execution <- function(query, params = NULL, pool = NULL, 
                                   source_function = "unknown", user_session = NULL) {
  
  # Skip monitoring if disabled
  if (!.monitor_config$enabled || !.monitoring_state$initialized) {
    return(execute_query_direct(query, params, pool))
  }
  
  monitor_start_time <- Sys.time()
  
  # Get pool if not provided
  if (is.null(pool)) {
    pool <- get_monitoring_pool()
    if (is.null(pool)) {
      return(list(result = NULL, error = "No database pool available"))
    }
  }
  
  # Generate query metadata
  query_hash <- digest::digest(query, algo = "md5")
  query_type <- detect_query_type(query)
  query_preview <- create_query_preview(query)
  connection_id <- generate_connection_id()
  
  # Execute query with timing
  execution_start <- Sys.time()
  result <- NULL
  error_message <- NULL
  rows_returned <- 0
  rows_affected <- 0
  is_error <- FALSE
  
  tryCatch({
    if (is.null(params) || length(params) == 0) {
      result <- dbGetQuery(pool, query)
    } else {
      result <- dbGetQuery(pool, query, params = params)
    }
    
    rows_returned <- if (is.data.frame(result)) nrow(result) else 0
    
  }, error = function(e) {
    error_message <<- as.character(e$message)
    is_error <<- TRUE
    cat("❌ Query execution error:", error_message, "\n")
  })
  
  execution_end <- Sys.time()
  execution_time_ms <- as.numeric(difftime(execution_end, execution_start, units = "secs")) * 1000
  
  # Determine if this is a slow query
  is_slow_query <- execution_time_ms >= (.monitor_config$slow_query_threshold_seconds * 1000)
  is_very_slow_query <- execution_time_ms >= (.monitor_config$very_slow_query_threshold_seconds * 1000)
  
  # Log query performance
  query_log_entry <- list(
    query_hash = query_hash,
    query_type = query_type,
    query_preview = query_preview,
    execution_time_ms = round(execution_time_ms, 2),
    rows_returned = rows_returned,
    rows_affected = rows_affected,
    parameters_count = if (is.null(params)) 0 else length(params),
    connection_id = connection_id,
    executed_at = execution_start,
    is_slow_query = is_slow_query,
    is_very_slow_query = is_very_slow_query,
    is_error = is_error,
    error_message = error_message,
    source_function = source_function,
    user_session = user_session
  )
  
  # Add to monitoring logs
  add_to_monitoring_log(query_log_entry)
  
  # Log slow queries separately
  if (is_slow_query) {
    log_slow_query(query_log_entry)
  }
  
  # Check for performance alerts
  check_performance_alerts(query_log_entry)
  
  # Update monitoring overhead calculation
  monitor_end_time <- Sys.time()
  monitoring_overhead <- as.numeric(difftime(monitor_end_time, monitor_start_time, units = "secs")) * 1000 - execution_time_ms
  .monitoring_state$monitoring_overhead_ms <<- 
    (.monitoring_state$monitoring_overhead_ms + monitoring_overhead) / 2
  
  # Increment query counter
  .monitoring_state$total_queries_monitored <<- .monitoring_state$total_queries_monitored + 1
  
  # Provide performance feedback
  if (is_very_slow_query && .monitor_config$log_slow_queries_only) {
    cat("🐌 VERY SLOW QUERY:", round(execution_time_ms), "ms -", query_preview, "\n")
  } else if (is_slow_query && .monitor_config$log_slow_queries_only) {
    cat("⏰ Slow query:", round(execution_time_ms), "ms -", query_preview, "\n")
  }
  
  return(list(
    result = result,
    performance = query_log_entry,
    error = error_message
  ))
}

#' Execute query directly without monitoring (fallback)
#' @param query SQL query
#' @param params Query parameters  
#' @param pool Database pool
#' @return Query result
execute_query_direct <- function(query, params = NULL, pool = NULL) {
  if (is.null(pool)) {
    pool <- get_monitoring_pool()
  }
  
  if (is.null(pool)) {
    return(list(result = NULL, error = "No database pool available"))
  }
  
  tryCatch({
    if (is.null(params) || length(params) == 0) {
      result <- dbGetQuery(pool, query)
    } else {
      result <- dbGetQuery(pool, query, params = params)
    }
    return(list(result = result, error = NULL))
  }, error = function(e) {
    return(list(result = NULL, error = e$message))
  })
}

# ============================================================================
# QUERY ANALYSIS FUNCTIONS
# ============================================================================

#' Detect the type of SQL query
#' @param query SQL query string
#' @return String with query type
detect_query_type <- function(query) {
  query_upper <- toupper(trimws(query))
  
  if (grepl("^SELECT", query_upper)) {
    if (grepl("COUNT\\(", query_upper)) return("SELECT_COUNT")
    if (grepl("JOIN", query_upper)) return("SELECT_JOIN")
    if (grepl("GROUP BY", query_upper)) return("SELECT_GROUP")
    if (grepl("ORDER BY", query_upper)) return("SELECT_ORDER")
    return("SELECT")
  } else if (grepl("^INSERT", query_upper)) {
    return("INSERT")
  } else if (grepl("^UPDATE", query_upper)) {
    return("UPDATE") 
  } else if (grepl("^DELETE", query_upper)) {
    return("DELETE")
  } else if (grepl("^CREATE", query_upper)) {
    return("CREATE")
  } else if (grepl("^ALTER", query_upper)) {
    return("ALTER")
  } else if (grepl("^DROP", query_upper)) {
    return("DROP")
  } else if (grepl("^REFRESH MATERIALIZED VIEW", query_upper)) {
    return("REFRESH_MV")
  } else {
    return("OTHER")
  }
}

#' Create a preview of the SQL query for logging
#' @param query SQL query string
#' @return Shortened query preview
create_query_preview <- function(query) {
  # Remove extra whitespace and newlines
  cleaned_query <- gsub("\\s+", " ", trimws(query))
  
  # Limit length
  if (nchar(cleaned_query) > 200) {
    preview <- paste0(substr(cleaned_query, 1, 197), "...")
  } else {
    preview <- cleaned_query
  }
  
  return(preview)
}

#' Generate a unique connection identifier
#' @return String connection ID
generate_connection_id <- function() {
  return(paste0("conn_", format(Sys.time(), "%H%M%S"), "_", sample(1000:9999, 1)))
}

# ============================================================================
# MONITORING LOG MANAGEMENT
# ============================================================================

#' Add query performance entry to monitoring log
#' @param log_entry Query performance log entry
add_to_monitoring_log <- function(log_entry) {
  # Add to in-memory log
  if (.monitor_config$log_all_queries || log_entry$is_slow_query) {
    .performance_metrics$query_log <<- append(.performance_metrics$query_log, list(log_entry))
    
    # Maintain maximum log size
    if (length(.performance_metrics$query_log) > .monitor_config$max_query_log_entries) {
      .performance_metrics$query_log <<- tail(.performance_metrics$query_log, 
                                             .monitor_config$max_query_log_entries)
    }
  }
  
  # Add to execution times for statistics
  .performance_metrics$execution_times <<- c(.performance_metrics$execution_times, log_entry$execution_time_ms)
  if (length(.performance_metrics$execution_times) > 1000) {
    .performance_metrics$execution_times <<- tail(.performance_metrics$execution_times, 1000)
  }
  
  # Persist to database periodically
  persist_monitoring_data_batch()
}

#' Log slow query with additional analysis
#' @param query_entry Slow query log entry
log_slow_query <- function(query_entry) {
  .performance_metrics$slow_queries <<- append(.performance_metrics$slow_queries, list(query_entry))
  
  # Maintain slow query log size
  if (length(.performance_metrics$slow_queries) > 500) {
    .performance_metrics$slow_queries <<- tail(.performance_metrics$slow_queries, 500)
  }
  
  # Add optimization suggestions
  suggestions <- generate_optimization_suggestions(query_entry)
  if (length(suggestions) > 0) {
    cat("💡 Query optimization suggestions:\n")
    for (suggestion in suggestions) {
      cat("   -", suggestion, "\n")
    }
  }
}

#' Generate query optimization suggestions
#' @param query_entry Query log entry
#' @return Vector of optimization suggestions
generate_optimization_suggestions <- function(query_entry) {
  suggestions <- c()
  query_upper <- toupper(query_entry$query_preview)
  
  # Check for missing WHERE clauses
  if (grepl("SELECT.*FROM", query_upper) && !grepl("WHERE", query_upper) && !grepl("LIMIT", query_upper)) {
    suggestions <- c(suggestions, "Consider adding WHERE clause to limit result set")
  }
  
  # Check for missing LIMIT clauses
  if (grepl("SELECT", query_upper) && !grepl("LIMIT", query_upper) && query_entry$rows_returned > 1000) {
    suggestions <- c(suggestions, "Consider adding LIMIT clause for large result sets")
  }
  
  # Check for inefficient LIKE patterns
  if (grepl("LIKE '%.*%'", query_upper)) {
    suggestions <- c(suggestions, "Consider using full-text search instead of LIKE with leading wildcard")
  }
  
  # Check for missing indexes (basic heuristics)
  if (grepl("WHERE.*=", query_upper) && query_entry$execution_time_ms > 5000) {
    suggestions <- c(suggestions, "Check if indexes exist on filtered columns")
  }
  
  # Check for ORDER BY without LIMIT
  if (grepl("ORDER BY", query_upper) && !grepl("LIMIT", query_upper) && query_entry$execution_time_ms > 3000) {
    suggestions <- c(suggestions, "Consider adding LIMIT when using ORDER BY on large datasets")
  }
  
  return(suggestions)
}

# ============================================================================
# PERFORMANCE ALERTING
# ============================================================================

#' Check for performance alerts and trigger notifications
#' @param query_entry Query performance entry
check_performance_alerts <- function(query_entry) {
  current_time <- Sys.time()
  
  # Check cooldown period
  if (!is.null(.alert_config$last_alert_time)) {
    time_since_last_alert <- as.numeric(difftime(current_time, .alert_config$last_alert_time, units = "mins"))
    if (time_since_last_alert < .alert_config$alert_cooldown_minutes) {
      return()  # Still in cooldown period
    }
  }
  
  # Very slow query alert
  if (query_entry$execution_time_ms >= (.monitor_config$very_slow_query_threshold_seconds * 1000)) {
    create_performance_alert(
      alert_type = "very_slow_query",
      alert_level = "HIGH",
      alert_message = paste("Very slow query detected:", query_entry$query_preview),
      metric_value = query_entry$execution_time_ms,
      threshold_value = .monitor_config$very_slow_query_threshold_seconds * 1000,
      additional_context = list(
        query_type = query_entry$query_type,
        source_function = query_entry$source_function,
        rows_returned = query_entry$rows_returned
      )
    )
  }
  
  # Check average performance over recent queries
  if (length(.performance_metrics$execution_times) >= 10) {
    recent_avg <- mean(tail(.performance_metrics$execution_times, 10))
    if (recent_avg > (.alert_config$max_avg_query_time * 1000)) {
      create_performance_alert(
        alert_type = "high_avg_execution_time",
        alert_level = "MEDIUM",
        alert_message = "Average query execution time is high",
        metric_value = recent_avg,
        threshold_value = .alert_config$max_avg_query_time * 1000
      )
    }
  }
  
  # Database error alert
  if (query_entry$is_error) {
    create_performance_alert(
      alert_type = "query_error",
      alert_level = "HIGH", 
      alert_message = paste("Query execution error:", query_entry$error_message),
      metric_value = 1,
      threshold_value = 0,
      additional_context = list(
        query_preview = query_entry$query_preview,
        error_message = query_entry$error_message
      )
    )
  }
}

#' Create performance alert
#' @param alert_type Type of alert
#' @param alert_level Severity level
#' @param alert_message Alert message
#' @param metric_value Current metric value
#' @param threshold_value Threshold that was exceeded
#' @param additional_context Additional context data
create_performance_alert <- function(alert_type, alert_level, alert_message, 
                                   metric_value, threshold_value, additional_context = NULL) {
  
  alert_entry <- list(
    alert_type = alert_type,
    alert_level = alert_level,
    alert_message = alert_message,
    metric_value = metric_value,
    threshold_value = threshold_value,
    additional_context = if (is.null(additional_context)) list() else additional_context,
    created_at = Sys.time(),
    is_resolved = FALSE
  )
  
  # Log alert
  cat("🚨", toupper(alert_level), "ALERT:", alert_message, "\n")
  
  # Persist alert to database
  tryCatch({
    pool <- get_monitoring_pool()
    if (!is.null(pool)) {
      dbExecute(pool, "
        INSERT INTO performance_alerts 
        (alert_type, alert_level, alert_message, metric_value, threshold_value, additional_context)
        VALUES (?, ?, ?, ?, ?, ?)",
        list(
          alert_type,
          alert_level, 
          alert_message,
          metric_value,
          threshold_value,
          jsonlite::toJSON(additional_context, auto_unbox = TRUE)
        )
      )
    }
  }, error = function(e) {
    cat("⚠️ Failed to persist alert:", e$message, "\n")
  })
  
  # Update alert timing
  .alert_config$last_alert_time <<- Sys.time()
}

# ============================================================================
# PERFORMANCE METRICS AND REPORTING
# ============================================================================

#' Get current performance statistics
#' @return List with performance metrics
get_performance_statistics <- function() {
  if (!.monitoring_state$initialized) {
    return(list(error = "Monitoring not initialized"))
  }
  
  execution_times <- .performance_metrics$execution_times
  slow_queries <- .performance_metrics$slow_queries
  
  stats <- list(
    monitoring_status = list(
      enabled = .monitor_config$enabled,
      initialized = .monitoring_state$initialized,
      total_queries_monitored = .monitoring_state$total_queries_monitored,
      monitoring_overhead_ms = round(.monitoring_state$monitoring_overhead_ms, 2),
      last_cleanup = .monitoring_state$last_cleanup
    ),
    execution_metrics = list(
      total_queries = length(execution_times),
      avg_execution_time_ms = if (length(execution_times) > 0) round(mean(execution_times), 2) else 0,
      median_execution_time_ms = if (length(execution_times) > 0) round(median(execution_times), 2) else 0,
      min_execution_time_ms = if (length(execution_times) > 0) round(min(execution_times), 2) else 0,
      max_execution_time_ms = if (length(execution_times) > 0) round(max(execution_times), 2) else 0,
      percentile_95_ms = if (length(execution_times) > 0) round(quantile(execution_times, 0.95), 2) else 0
    ),
    slow_query_metrics = list(
      total_slow_queries = length(slow_queries),
      slow_query_rate = if (.monitoring_state$total_queries_monitored > 0) 
        round(length(slow_queries) / .monitoring_state$total_queries_monitored * 100, 2) else 0,
      avg_slow_query_time_ms = if (length(slow_queries) > 0) 
        round(mean(sapply(slow_queries, function(x) x$execution_time_ms)), 2) else 0
    ),
    recent_performance = list(
      last_10_queries_avg_ms = if (length(execution_times) >= 10) 
        round(mean(tail(execution_times, 10)), 2) else 0,
      last_hour_query_count = get_recent_query_count(hours = 1),
      last_hour_slow_query_count = get_recent_slow_query_count(hours = 1)
    )
  )
  
  return(stats)
}

#' Get recent query count
#' @param hours Number of hours to look back
#' @return Integer count of queries
get_recent_query_count <- function(hours = 1) {
  cutoff_time <- Sys.time() - hours(hours)
  recent_queries <- Filter(function(entry) {
    entry$executed_at >= cutoff_time
  }, .performance_metrics$query_log)
  
  return(length(recent_queries))
}

#' Get recent slow query count  
#' @param hours Number of hours to look back
#' @return Integer count of slow queries
get_recent_slow_query_count <- function(hours = 1) {
  cutoff_time <- Sys.time() - hours(hours)
  recent_slow_queries <- Filter(function(entry) {
    entry$executed_at >= cutoff_time
  }, .performance_metrics$slow_queries)
  
  return(length(recent_slow_queries))
}

#' Generate performance report
#' @param format Output format ("text" or "json")
#' @return Performance report
generate_performance_report <- function(format = "text") {
  stats <- get_performance_statistics()
  
  if (format == "json") {
    return(jsonlite::toJSON(stats, pretty = TRUE, auto_unbox = TRUE))
  }
  
  # Text format report
  report <- paste0(
    "========================================\n",
    "QUERY PERFORMANCE MONITORING REPORT\n", 
    "========================================\n\n",
    "Monitoring Status:\n",
    "- Enabled: ", stats$monitoring_status$enabled, "\n",
    "- Total Queries Monitored: ", stats$monitoring_status$total_queries_monitored, "\n",
    "- Monitoring Overhead: ", stats$monitoring_status$monitoring_overhead_ms, " ms\n\n",
    "Execution Metrics:\n",
    "- Average Execution Time: ", stats$execution_metrics$avg_execution_time_ms, " ms\n",
    "- Median Execution Time: ", stats$execution_metrics$median_execution_time_ms, " ms\n",
    "- 95th Percentile: ", stats$execution_metrics$percentile_95_ms, " ms\n",
    "- Min/Max: ", stats$execution_metrics$min_execution_time_ms, "/", 
    stats$execution_metrics$max_execution_time_ms, " ms\n\n",
    "Slow Query Analysis:\n",
    "- Total Slow Queries: ", stats$slow_query_metrics$total_slow_queries, "\n",
    "- Slow Query Rate: ", stats$slow_query_metrics$slow_query_rate, "%\n",
    "- Avg Slow Query Time: ", stats$slow_query_metrics$avg_slow_query_time_ms, " ms\n\n",
    "Recent Performance (Last Hour):\n",
    "- Query Count: ", stats$recent_performance$last_hour_query_count, "\n",
    "- Slow Query Count: ", stats$recent_performance$last_hour_slow_query_count, "\n",
    "- Last 10 Queries Avg: ", stats$recent_performance$last_10_queries_avg_ms, " ms\n\n"
  )
  
  return(report)
}

# ============================================================================
# DATA PERSISTENCE AND CLEANUP
# ============================================================================

#' Persist monitoring data to database in batches
persist_monitoring_data_batch <- function() {
  # Only persist every N queries to reduce overhead
  if (.monitoring_state$total_queries_monitored %% .monitor_config$monitoring_batch_size != 0) {
    return()
  }
  
  pool <- get_monitoring_pool()
  if (is.null(pool)) return()
  
  tryCatch({
    # Persist recent query logs
    recent_logs <- tail(.performance_metrics$query_log, .monitor_config$monitoring_batch_size)
    
    for (log_entry in recent_logs) {
      dbExecute(pool, "
        INSERT INTO query_performance_log 
        (query_hash, query_type, query_preview, execution_time_ms, rows_returned, 
         rows_affected, parameters_count, connection_id, executed_at, is_slow_query, 
         is_error, error_message, source_function, user_session)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        list(
          log_entry$query_hash,
          log_entry$query_type,
          log_entry$query_preview,
          log_entry$execution_time_ms,
          log_entry$rows_returned,
          log_entry$rows_affected,
          log_entry$parameters_count,
          log_entry$connection_id,
          log_entry$executed_at,
          log_entry$is_slow_query,
          log_entry$is_error,
          log_entry$error_message,
          log_entry$source_function,
          log_entry$user_session
        )
      )
    }
    
  }, error = function(e) {
    cat("⚠️ Error persisting monitoring data:", e$message, "\n")
  })
}

#' Schedule monitoring data cleanup
schedule_monitoring_cleanup <- function() {
  if (is.null(.monitoring_state$last_cleanup)) {
    .monitoring_state$last_cleanup <<- Sys.time()
    return()
  }
  
  hours_since_cleanup <- as.numeric(difftime(Sys.time(), .monitoring_state$last_cleanup, units = "hours"))
  
  if (hours_since_cleanup >= .monitor_config$cleanup_interval_hours) {
    cleanup_monitoring_data()
    .monitoring_state$last_cleanup <<- Sys.time()
  }
}

#' Clean up old monitoring data
cleanup_monitoring_data <- function() {
  cat("🧹 Cleaning up old monitoring data...\n")
  
  pool <- get_monitoring_pool()
  if (is.null(pool)) return()
  
  tryCatch({
    # Clean up old query logs
    cutoff_date <- Sys.Date() - days(.monitor_config$metrics_retention_days)
    
    deleted_queries <- dbExecute(pool, "
      DELETE FROM query_performance_log 
      WHERE executed_at < ?", 
      list(cutoff_date)
    )
    
    # Clean up old connection metrics
    deleted_metrics <- dbExecute(pool, "
      DELETE FROM connection_metrics_log 
      WHERE recorded_at < ?",
      list(cutoff_date)
    )
    
    # Clean up resolved alerts older than retention period
    deleted_alerts <- dbExecute(pool, "
      DELETE FROM performance_alerts 
      WHERE created_at < ? AND is_resolved = TRUE",
      list(cutoff_date)
    )
    
    cat("🗑️ Cleaned up", deleted_queries, "query logs,", deleted_metrics, 
        "metrics, and", deleted_alerts, "resolved alerts\n")
    
  }, error = function(e) {
    cat("❌ Error during monitoring data cleanup:", e$message, "\n")
  })
}

# ============================================================================
# INTEGRATION FUNCTIONS
# ============================================================================

#' Wrapper for get_library_documents with monitoring
#' @param ... Arguments passed to get_library_documents_optimized
#' @return Query result with performance monitoring
get_library_documents_monitored <- function(...) {
  if (exists("get_library_documents_optimized")) {
    # Monitor the optimized version
    result <- monitor_query_execution(
      query = "get_library_documents_optimized(...)",
      params = list(...),
      source_function = "get_library_documents_optimized",
      user_session = Sys.getenv("SHINY_SESSION_ID", "unknown")
    )
    
    if (!is.null(result$result)) {
      return(result$result)
    }
  }
  
  # Fallback to regular function if monitoring fails
  if (exists("get_library_documents")) {
    return(get_library_documents(...))
  }
  
  return(NULL)
}

#' Enable/disable query monitoring
#' @param enabled TRUE to enable, FALSE to disable
toggle_monitoring <- function(enabled) {
  .monitor_config$enabled <<- enabled
  cat("📊 Query monitoring", if (enabled) "ENABLED" else "DISABLED", "\n")
}

# ============================================================================
# INITIALIZATION
# ============================================================================

cat("✅ Query Performance Monitoring System loaded successfully\n")
cat("📊 Ready to monitor Railway PostgreSQL query performance\n")
cat("🔍 Use init_query_monitoring() to start monitoring\n")

# Auto-initialize if conditions are met
tryCatch({
  if (!is.null(get_monitoring_pool())) {
    init_query_monitoring()
  }
}, error = function(e) {
  cat("⚠️ Auto-initialization failed:", e$message, "\n")
  cat("💡 Call init_query_monitoring() manually when database is ready\n")
})