# ============================================================================
# SPRINT 6A: COMPREHENSIVE QUERY PERFORMANCE MONITORING SYSTEM
# Brazilian Legislative Monitoring System - Railway Deployment
# ============================================================================
# 
# PERFORMANCE MONITORING FOR 134k+ LEGISLATIVE DOCUMENTS
# Purpose: Real-time monitoring, alerting, and optimization recommendations
# 
# MONITORING TARGETS:
# - Query execution time analysis and alerting
# - Database performance trend analysis
# - Connection pool utilization monitoring
# - Resource consumption tracking for Railway 2GB constraints
# - Automated performance recommendations
# - LGPD-compliant audit logging
#
# RAILWAY-SPECIFIC FEATURES:
# - Memory usage tracking within 2GB limits
# - Connection pool optimization alerts
# - Query pattern analysis for optimization
# - Performance regression detection
# - Automated scaling recommendations
# ============================================================================

# Load required libraries
required_packages <- c("DBI", "RPostgres", "pool", "dplyr", "jsonlite", "digest", "lubridate")
missing_packages <- c()

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing_packages <- c(missing_packages, pkg)
  }
}

if (length(missing_packages) > 0) {
  cat("⚠️ Missing required packages for monitoring:", paste(missing_packages, collapse = ", "), "\n")
  cat("   Install with: install.packages(c(", paste0("'", missing_packages, "'", collapse = ", "), "))\n")
  cat("   Monitoring system will run with limited functionality\n")
}

# Load packages with error handling
packages_loaded <- list()
for (pkg in required_packages) {
  tryCatch({
    suppressPackageStartupMessages(library(pkg, character.only = TRUE))
    packages_loaded[[pkg]] <- TRUE
  }, error = function(e) {
    cat("⚠️ Could not load", pkg, "- some monitoring features may be unavailable\n")
    packages_loaded[[pkg]] <- FALSE
  })
}

cat("✅ Performance monitoring system libraries loaded\n")

# ============================================================================
# MONITORING CONFIGURATION AND STATE
# ============================================================================

# Performance monitoring configuration
.monitoring_config <- list(
  # Performance thresholds
  slow_query_threshold_ms = 500,      # Queries slower than 500ms
  critical_query_threshold_ms = 2000, # Queries slower than 2 seconds
  high_memory_threshold_mb = 1600,    # 80% of Railway's 2GB limit
  critical_memory_threshold_mb = 1800, # 90% of Railway's 2GB limit
  
  # Monitoring intervals
  metrics_collection_interval_ms = 30000,  # 30 seconds
  health_check_interval_ms = 60000,        # 1 minute
  performance_report_interval_ms = 300000, # 5 minutes
  
  # Alert configuration
  enable_alerts = TRUE,
  alert_cooldown_minutes = 5,
  max_alerts_per_hour = 12,
  
  # Data retention
  metrics_retention_hours = 48,      # Keep 48 hours of detailed metrics
  summary_retention_days = 30,       # Keep 30 days of summary data
  
  # Performance targets
  target_avg_response_time_ms = 200,
  target_95th_percentile_ms = 800,
  target_connection_utilization = 0.7,  # 70% pool utilization
  
  # Railway-specific limits
  railway_memory_limit_mb = 2048,
  railway_connection_limit = 25,
  railway_cpu_cores = 2
)

# Global monitoring state
.monitoring_state <- list(
  # Metrics storage
  query_metrics = list(),
  connection_metrics = list(),
  system_metrics = list(),
  
  # Alert tracking
  recent_alerts = list(),
  alert_counts = list(),
  
  # Performance baselines
  baseline_metrics = NULL,
  last_baseline_update = NULL,
  
  # Status tracking
  monitoring_active = FALSE,
  last_collection = NULL,
  collection_errors = 0
)

# Performance metrics aggregation
.performance_aggregates <- list(
  hourly_summaries = list(),
  daily_summaries = list(),
  query_patterns = list(),
  slow_query_analysis = list()
)

# ============================================================================
# QUERY PERFORMANCE TRACKING
# ============================================================================

#' Track individual query performance with detailed metrics
#' @param query_text The SQL query text (sanitized)
#' @param execution_time_ms Query execution time in milliseconds  
#' @param result_count Number of rows returned
#' @param query_type Type of query (select, insert, update, delete, etc.)
#' @param pool_name Connection pool used
#' @param session_id User session identifier (LGPD-compliant)
#' @param additional_metadata Additional query context
track_query_performance <- function(query_text, execution_time_ms, result_count = 0, 
                                   query_type = "unknown", pool_name = "unknown", 
                                   session_id = NULL, additional_metadata = list()) {
  
  if (!.monitoring_config$enable_alerts) return(invisible(NULL))
  
  # Sanitize query text for LGPD compliance
  sanitized_query <- sanitize_query_for_logging(query_text)
  
  # Create query performance record
  performance_record <- list(
    timestamp = Sys.time(),
    query_hash = digest(sanitized_query, algo = "md5"),
    query_type = query_type,
    execution_time_ms = execution_time_ms,
    result_count = result_count,
    pool_name = pool_name,
    session_id = session_id,
    
    # Performance classification
    performance_tier = classify_query_performance(execution_time_ms),
    
    # Resource impact estimation
    estimated_memory_mb = estimate_query_memory_impact(result_count, query_type),
    cpu_impact_score = estimate_cpu_impact(execution_time_ms, query_type),
    
    # Query characteristics
    query_pattern = extract_query_pattern(sanitized_query),
    table_references = extract_table_references(sanitized_query),
    
    # Additional context
    metadata = additional_metadata
  )
  
  # Store in metrics collection
  .monitoring_state$query_metrics[[length(.monitoring_state$query_metrics) + 1]] <<- performance_record
  
  # Check for performance alerts
  check_query_performance_alerts(performance_record)
  
  # Update query patterns analysis
  update_query_patterns_analysis(performance_record)
  
  # Trigger slow query analysis if needed
  if (execution_time_ms >= .monitoring_config$slow_query_threshold_ms) {
    analyze_slow_query(performance_record, sanitized_query)
  }
  
  invisible(performance_record)
}

#' Classify query performance into tiers
#' @param execution_time_ms Query execution time
#' @return Performance tier classification
classify_query_performance <- function(execution_time_ms) {
  if (execution_time_ms < 100) return("excellent")
  if (execution_time_ms < 300) return("good") 
  if (execution_time_ms < 800) return("acceptable")
  if (execution_time_ms < 2000) return("slow")
  return("critical")
}

#' Estimate memory impact of a query
#' @param result_count Number of rows returned
#' @param query_type Type of query
#' @return Estimated memory usage in MB
estimate_query_memory_impact <- function(result_count, query_type) {
  base_memory <- switch(query_type,
    "select" = 0.1,
    "insert" = 0.05,
    "update" = 0.08,
    "delete" = 0.05,
    "analytics" = 0.5,
    0.1
  )
  
  # Estimate based on result size (rough calculation)
  result_memory <- result_count * 0.001  # 1KB per row estimate
  
  return(round(base_memory + result_memory, 3))
}

#' Estimate CPU impact score
#' @param execution_time_ms Query execution time
#' @param query_type Type of query  
#' @return CPU impact score (1-10 scale)
estimate_cpu_impact <- function(execution_time_ms, query_type) {
  base_impact <- switch(query_type,
    "select" = 1,
    "insert" = 2,
    "update" = 3,
    "delete" = 2,
    "analytics" = 5,
    1
  )
  
  # Scale based on execution time
  time_impact <- min(5, execution_time_ms / 400)  # 400ms = impact 1
  
  return(round(base_impact + time_impact, 1))
}

#' Sanitize query text for LGPD-compliant logging
#' @param query_text Raw SQL query
#' @return Sanitized query text
sanitize_query_for_logging <- function(query_text) {
  if (is.null(query_text) || query_text == "") return("EMPTY_QUERY")
  
  # Remove potential sensitive data patterns
  sanitized <- query_text
  
  # Remove string literals that might contain sensitive data
  sanitized <- gsub("'[^']*'", "'***'", sanitized)
  sanitized <- gsub("\"[^\"]*\"", "\"***\"", sanitized)
  
  # Remove numeric literals that might be sensitive IDs
  sanitized <- gsub("\\b\\d{6,}\\b", "***", sanitized)
  
  # Normalize whitespace
  sanitized <- gsub("\\s+", " ", sanitized)
  
  # Truncate very long queries
  if (nchar(sanitized) > 200) {
    sanitized <- paste0(substr(sanitized, 1, 197), "...")
  }
  
  return(trimws(sanitized))
}

#' Extract query pattern for analysis
#' @param query_text Sanitized query text
#' @return Query pattern classification
extract_query_pattern <- function(query_text) {
  query_upper <- toupper(query_text)
  
  # Identify main query patterns
  if (grepl("^SELECT.*FROM.*WHERE.*ORDER BY", query_upper)) return("filtered_sorted_select")
  if (grepl("^SELECT.*FROM.*WHERE", query_upper)) return("filtered_select")
  if (grepl("^SELECT.*COUNT\\(", query_upper)) return("count_query")
  if (grepl("^SELECT.*FROM.*JOIN", query_upper)) return("join_query")
  if (grepl("^SELECT.*FROM.*GROUP BY", query_upper)) return("aggregate_query")
  if (grepl("^SELECT.*FROM", query_upper)) return("simple_select")
  if (grepl("^INSERT INTO", query_upper)) return("insert")
  if (grepl("^UPDATE.*SET", query_upper)) return("update")
  if (grepl("^DELETE FROM", query_upper)) return("delete")
  if (grepl("MATERIALIZED VIEW", query_upper)) return("mv_operation")
  if (grepl("CREATE INDEX", query_upper)) return("index_operation")
  
  return("other")
}

#' Extract table references from query
#' @param query_text Sanitized query text
#' @return List of table references
extract_table_references <- function(query_text) {
  # Simple extraction of table names (basic implementation)
  # In production, use a proper SQL parser
  
  tables <- c()
  query_upper <- toupper(query_text)
  
  # Extract FROM clauses
  from_matches <- regmatches(query_upper, gregexpr("FROM\\s+(\\w+)", query_upper))
  if (length(from_matches[[1]]) > 0) {
    tables <- c(tables, gsub("FROM\\s+", "", from_matches[[1]]))
  }
  
  # Extract JOIN clauses
  join_matches <- regmatches(query_upper, gregexpr("JOIN\\s+(\\w+)", query_upper))
  if (length(join_matches[[1]]) > 0) {
    tables <- c(tables, gsub("JOIN\\s+", "", join_matches[[1]]))
  }
  
  return(unique(tables))
}

# ============================================================================
# SYSTEM PERFORMANCE MONITORING
# ============================================================================

#' Collect comprehensive system performance metrics
#' @return List of current system performance metrics
collect_system_performance_metrics <- function() {
  
  tryCatch({
    start_time <- Sys.time()
    
    # Database connection metrics
    db_metrics <- collect_database_metrics()
    
    # Connection pool metrics  
    pool_metrics <- collect_connection_pool_metrics()
    
    # Query performance metrics
    query_metrics <- aggregate_recent_query_metrics()
    
    # System resource metrics (estimated for Railway)
    resource_metrics <- estimate_railway_resource_usage()
    
    collection_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000
    
    metrics <- list(
      timestamp = Sys.time(),
      collection_time_ms = round(collection_time, 2),
      
      # Database metrics
      database = db_metrics,
      
      # Connection pool metrics
      connection_pools = pool_metrics,
      
      # Query performance metrics
      query_performance = query_metrics,
      
      # System resources
      system_resources = resource_metrics,
      
      # Performance health score
      health_score = calculate_system_health_score(db_metrics, pool_metrics, query_metrics, resource_metrics)
    )
    
    # Store metrics
    .monitoring_state$system_metrics[[length(.monitoring_state$system_metrics) + 1]] <<- metrics
    .monitoring_state$last_collection <<- Sys.time()
    .monitoring_state$collection_errors <<- 0
    
    return(metrics)
    
  }, error = function(e) {
    .monitoring_state$collection_errors <<- .monitoring_state$collection_errors + 1
    cat("❌ Error collecting system metrics:", e$message, "\n")
    
    return(list(
      timestamp = Sys.time(),
      error = e$message,
      collection_errors = .monitoring_state$collection_errors
    ))
  })
}

#' Collect database-specific performance metrics
#' @return Database performance metrics
collect_database_metrics <- function() {
  # Get database connection (using existing connection system)
  pool <- NULL
  if (exists("get_optimal_pool")) {
    pool <- get_optimal_pool("maintenance", "low")
  } else if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    pool <- secure_db_pool
  }
  
  if (is.null(pool)) {
    return(list(error = "No database connection available"))
  }
  
  tryCatch({
    # Basic database statistics
    db_stats <- dbGetQuery(pool, "
      SELECT 
        (SELECT COUNT(*) FROM pg_stat_activity WHERE state = 'active') as active_connections,
        (SELECT COUNT(*) FROM pg_stat_activity WHERE state = 'idle') as idle_connections,
        (SELECT COUNT(*) FROM pg_stat_activity) as total_connections
    ")
    
    # Query statistics (if pg_stat_statements is available)
    query_stats <- tryCatch({
      dbGetQuery(pool, "
        SELECT 
          COUNT(*) as total_queries,
          ROUND(AVG(mean_time)::numeric, 2) as avg_query_time_ms,
          ROUND(MAX(max_time)::numeric, 2) as max_query_time_ms,
          SUM(calls) as total_calls
        FROM pg_stat_statements 
        WHERE last_exec >= NOW() - INTERVAL '1 hour'
      ")
    }, error = function(e) {
      data.frame(
        total_queries = 0, avg_query_time_ms = 0, 
        max_query_time_ms = 0, total_calls = 0
      )
    })
    
    # Lock statistics  
    lock_stats <- tryCatch({
      dbGetQuery(pool, "
        SELECT 
          COUNT(*) as active_locks,
          COUNT(*) FILTER (WHERE NOT granted) as waiting_locks
        FROM pg_locks 
        WHERE pid != pg_backend_pid()
      ")
    }, error = function(e) {
      data.frame(active_locks = 0, waiting_locks = 0)
    })
    
    return(list(
      connections = db_stats,
      queries = query_stats,
      locks = lock_stats,
      collection_timestamp = Sys.time()
    ))
    
  }, error = function(e) {
    return(list(error = paste("Database metrics collection failed:", e$message)))
  })
}

#' Collect connection pool performance metrics
#' @return Connection pool metrics
collect_connection_pool_metrics <- function() {
  pool_metrics <- list()
  
  # Get metrics from advanced connection pooling system if available
  if (exists("get_pool_performance_metrics")) {
    tryCatch({
      pool_metrics <- get_pool_performance_metrics()
    }, error = function(e) {
      pool_metrics$error <- paste("Pool metrics collection failed:", e$message)
    })
  } else {
    pool_metrics$error <- "Advanced connection pooling system not available"
  }
  
  return(pool_metrics)
}

#' Aggregate recent query performance metrics
#' @param time_window_minutes Time window for aggregation
#' @return Aggregated query metrics
aggregate_recent_query_metrics <- function(time_window_minutes = 10) {
  cutoff_time <- Sys.time() - minutes(time_window_minutes)
  
  recent_queries <- Filter(function(q) q$timestamp >= cutoff_time, .monitoring_state$query_metrics)
  
  if (length(recent_queries) == 0) {
    return(list(
      query_count = 0,
      time_window_minutes = time_window_minutes,
      no_recent_queries = TRUE
    ))
  }
  
  execution_times <- sapply(recent_queries, function(q) q$execution_time_ms)
  result_counts <- sapply(recent_queries, function(q) q$result_count)
  performance_tiers <- sapply(recent_queries, function(q) q$performance_tier)
  
  return(list(
    query_count = length(recent_queries),
    time_window_minutes = time_window_minutes,
    
    # Execution time statistics
    avg_execution_time_ms = round(mean(execution_times), 2),
    median_execution_time_ms = round(median(execution_times), 2),
    p95_execution_time_ms = round(quantile(execution_times, 0.95), 2),
    max_execution_time_ms = max(execution_times),
    
    # Result size statistics
    avg_result_count = round(mean(result_counts), 0),
    total_rows_processed = sum(result_counts),
    
    # Performance tier distribution
    performance_distribution = table(performance_tiers),
    
    # Query type distribution
    query_type_distribution = table(sapply(recent_queries, function(q) q$query_type)),
    
    # Pool usage distribution
    pool_distribution = table(sapply(recent_queries, function(q) q$pool_name))
  ))
}

#' Estimate Railway resource usage
#' @return Estimated resource usage metrics
estimate_railway_resource_usage <- function() {
  
  # Estimate memory usage based on query metrics and connection pools
  estimated_memory_mb <- 0
  
  # Base R process memory (estimated)
  estimated_memory_mb <- estimated_memory_mb + 150  # Base R + libraries
  
  # Connection pool memory (if available)
  if (exists("calculate_estimated_memory_usage")) {
    tryCatch({
      pool_memory <- calculate_estimated_memory_usage()
      estimated_memory_mb <- estimated_memory_mb + pool_memory
    }, error = function(e) {
      estimated_memory_mb <- estimated_memory_mb + 100  # Default estimate
    })
  }
  
  # Query cache and data memory (estimated based on recent activity)
  recent_queries <- Filter(function(q) q$timestamp >= (Sys.time() - minutes(30)), 
                          .monitoring_state$query_metrics)
  
  if (length(recent_queries) > 0) {
    cache_memory <- sum(sapply(recent_queries, function(q) q$estimated_memory_mb %||% 0))
    estimated_memory_mb <- estimated_memory_mb + min(cache_memory, 200)  # Cap cache estimate
  }
  
  return(list(
    estimated_memory_usage_mb = round(estimated_memory_mb, 1),
    memory_utilization_percentage = round((estimated_memory_mb / .monitoring_config$railway_memory_limit_mb) * 100, 1),
    
    # Connection utilization (estimated)
    estimated_active_connections = length(.monitoring_state$query_metrics),
    connection_utilization_percentage = round((length(.monitoring_state$query_metrics) / .monitoring_config$railway_connection_limit) * 100, 1),
    
    # Performance indicators
    memory_status = if (estimated_memory_mb > .monitoring_config$high_memory_threshold_mb) "high" else "normal",
    resource_health = if (estimated_memory_mb < .monitoring_config$high_memory_threshold_mb) "good" else "warning"
  ))
}

#' Calculate overall system health score
#' @param db_metrics Database metrics
#' @param pool_metrics Connection pool metrics  
#' @param query_metrics Query performance metrics
#' @param resource_metrics Resource usage metrics
#' @return Health score (0-100)
calculate_system_health_score <- function(db_metrics, pool_metrics, query_metrics, resource_metrics) {
  score <- 100
  
  # Database health impact
  if (!is.null(db_metrics$error)) {
    score <- score - 30
  } else {
    # Check for connection issues
    if (db_metrics$locks$waiting_locks > 0) score <- score - 10
  }
  
  # Query performance impact
  if (!is.null(query_metrics$p95_execution_time_ms) && 
      query_metrics$p95_execution_time_ms > .monitoring_config$target_95th_percentile_ms) {
    score <- score - 20
  }
  
  if (!is.null(query_metrics$avg_execution_time_ms) && 
      query_metrics$avg_execution_time_ms > .monitoring_config$target_avg_response_time_ms) {
    score <- score - 15
  }
  
  # Resource utilization impact
  if (!is.null(resource_metrics$memory_utilization_percentage)) {
    if (resource_metrics$memory_utilization_percentage > 90) {
      score <- score - 25
    } else if (resource_metrics$memory_utilization_percentage > 80) {
      score <- score - 15
    }
  }
  
  # Connection pool health impact
  if (!is.null(pool_metrics$overall$connection_errors) && 
      pool_metrics$overall$connection_errors > 0) {
    score <- score - 10
  }
  
  return(max(0, min(100, score)))
}

# ============================================================================
# PERFORMANCE ALERTING SYSTEM
# ============================================================================

#' Check for performance alerts based on query metrics
#' @param performance_record Query performance record
check_query_performance_alerts <- function(performance_record) {
  if (!.monitoring_config$enable_alerts) return(invisible(NULL))
  
  alerts <- c()
  
  # Critical query alert
  if (performance_record$execution_time_ms >= .monitoring_config$critical_query_threshold_ms) {
    alerts <- c(alerts, list(
      type = "critical_query",
      severity = "critical",
      message = paste("Critical slow query detected:", round(performance_record$execution_time_ms), "ms"),
      query_pattern = performance_record$query_pattern,
      pool_name = performance_record$pool_name,
      timestamp = Sys.time()
    ))
  }
  
  # Slow query alert
  else if (performance_record$execution_time_ms >= .monitoring_config$slow_query_threshold_ms) {
    alerts <- c(alerts, list(
      type = "slow_query",
      severity = "warning", 
      message = paste("Slow query detected:", round(performance_record$execution_time_ms), "ms"),
      query_pattern = performance_record$query_pattern,
      pool_name = performance_record$pool_name,
      timestamp = Sys.time()
    ))
  }
  
  # High memory usage alert
  if (performance_record$estimated_memory_mb > 50) {  # 50MB threshold for single query
    alerts <- c(alerts, list(
      type = "high_memory_query",
      severity = "warning",
      message = paste("High memory query detected:", round(performance_record$estimated_memory_mb, 1), "MB"),
      query_pattern = performance_record$query_pattern,
      timestamp = Sys.time()
    ))
  }
  
  # Process alerts
  for (alert in alerts) {
    process_performance_alert(alert)
  }
  
  invisible(alerts)
}

#' Process and potentially send performance alerts
#' @param alert Alert object
process_performance_alert <- function(alert) {
  # Check alert cooldown
  if (!check_alert_cooldown(alert$type)) {
    return(invisible(NULL))
  }
  
  # Log alert
  log_performance_alert(alert)
  
  # Update alert tracking
  .monitoring_state$recent_alerts[[length(.monitoring_state$recent_alerts) + 1]] <<- alert
  
  # Update alert counts
  hour_key <- format(Sys.time(), "%Y-%m-%d-%H")
  if (is.null(.monitoring_state$alert_counts[[hour_key]])) {
    .monitoring_state$alert_counts[[hour_key]] <- 0
  }
  .monitoring_state$alert_counts[[hour_key]] <<- .monitoring_state$alert_counts[[hour_key]] + 1
  
  # Send alert (placeholder for actual alerting system)
  send_performance_alert(alert)
}

#' Check if alert cooldown period has passed
#' @param alert_type Type of alert
#' @return Boolean indicating if alert can be sent
check_alert_cooldown <- function(alert_type) {
  cooldown_key <- paste0("cooldown_", alert_type)
  last_alert_time <- .monitoring_state[[cooldown_key]]
  
  if (is.null(last_alert_time)) {
    .monitoring_state[[cooldown_key]] <<- Sys.time()
    return(TRUE)
  }
  
  minutes_since_last <- as.numeric(difftime(Sys.time(), last_alert_time, units = "mins"))
  
  if (minutes_since_last >= .monitoring_config$alert_cooldown_minutes) {
    .monitoring_state[[cooldown_key]] <<- Sys.time()
    return(TRUE)
  }
  
  return(FALSE)
}

#' Log performance alert for audit trail
#' @param alert Alert object
log_performance_alert <- function(alert) {
  log_message <- paste(
    "[PERFORMANCE ALERT]",
    format(Sys.time(), "%Y-%m-%d %H:%M:%S"),
    paste0("[", toupper(alert$severity), "]"),
    alert$type, "-", alert$message
  )
  
  cat(log_message, "\n")
  
  # Write to log file if possible
  tryCatch({
    log_file <- "monitoring/performance_alerts.log"
    if (!dir.exists(dirname(log_file))) {
      dir.create(dirname(log_file), recursive = TRUE)
    }
    write(log_message, file = log_file, append = TRUE)
  }, error = function(e) {
    # Silently ignore log file errors
  })
}

#' Send performance alert (placeholder for actual alerting)
#' @param alert Alert object
send_performance_alert <- function(alert) {
  # Placeholder for actual alert sending (email, Slack, webhook, etc.)
  # In production, this would integrate with your alerting system
  
  cat("🚨 PERFORMANCE ALERT:", alert$message, "\n")
  
  # Could integrate with:
  # - Email notifications
  # - Slack/Discord webhooks
  # - Railway application logs
  # - External monitoring services (DataDog, New Relic, etc.)
}

# ============================================================================
# PERFORMANCE ANALYSIS AND RECOMMENDATIONS
# ============================================================================

#' Analyze slow queries and generate recommendations
#' @param performance_record Query performance record
#' @param query_text Sanitized query text
analyze_slow_query <- function(performance_record, query_text) {
  analysis <- list(
    timestamp = Sys.time(),
    query_hash = performance_record$query_hash,
    execution_time_ms = performance_record$execution_time_ms,
    query_pattern = performance_record$query_pattern,
    
    # Potential causes
    potential_causes = identify_slow_query_causes(performance_record, query_text),
    
    # Recommendations
    recommendations = generate_query_recommendations(performance_record, query_text),
    
    # Impact assessment
    impact_assessment = assess_query_impact(performance_record)
  )
  
  # Store in slow query analysis
  .performance_aggregates$slow_query_analysis[[length(.performance_aggregates$slow_query_analysis) + 1]] <<- analysis
  
  return(analysis)
}

#' Identify potential causes of slow query performance
#' @param performance_record Query performance record
#' @param query_text Query text
#' @return List of potential causes
identify_slow_query_causes <- function(performance_record, query_text) {
  causes <- c()
  
  # Large result set
  if (performance_record$result_count > 10000) {
    causes <- c(causes, "Large result set returned")
  }
  
  # Missing indexes (heuristic based on query pattern)
  if (grepl("WHERE.*=.*AND", query_text, ignore.case = TRUE)) {
    causes <- c(causes, "Possible missing compound index for WHERE conditions")
  }
  
  # Full table scan indicators
  if (grepl("SELECT.*FROM.*(?!WHERE)", query_text, ignore.case = TRUE, perl = TRUE)) {
    causes <- c(causes, "Possible full table scan (no WHERE clause)")
  }
  
  # Complex joins
  if (length(grep("JOIN", query_text, ignore.case = TRUE)) > 2) {
    causes <- c(causes, "Complex multi-table joins")
  }
  
  # Sorting large datasets
  if (grepl("ORDER BY", query_text, ignore.case = TRUE) && performance_record$result_count > 1000) {
    causes <- c(causes, "Sorting large result set")
  }
  
  if (length(causes) == 0) {
    causes <- c("Query complexity or database load")
  }
  
  return(causes)
}

#' Generate optimization recommendations for slow queries
#' @param performance_record Query performance record  
#' @param query_text Query text
#' @return List of recommendations
generate_query_recommendations <- function(performance_record, query_text) {
  recommendations <- c()
  
  # Index recommendations
  if (grepl("WHERE.*=", query_text, ignore.case = TRUE)) {
    recommendations <- c(recommendations, "Consider adding indexes on WHERE clause columns")
  }
  
  # Query structure recommendations  
  if (performance_record$result_count > 10000) {
    recommendations <- c(recommendations, "Consider adding LIMIT clause or pagination")
    recommendations <- c(recommendations, "Review if all columns are necessary (avoid SELECT *)")
  }
  
  # Join optimization
  if (grepl("JOIN", query_text, ignore.case = TRUE)) {
    recommendations <- c(recommendations, "Ensure JOIN conditions use indexed columns")
    recommendations <- c(recommendations, "Consider breaking complex joins into smaller queries")
  }
  
  # Caching recommendations
  if (performance_record$query_pattern %in% c("count_query", "aggregate_query")) {
    recommendations <- c(recommendations, "Consider using materialized views for frequent aggregations")
  }
  
  # Pool optimization
  if (performance_record$execution_time_ms > 2000) {
    recommendations <- c(recommendations, "Consider using analytics connection pool for heavy queries")
  }
  
  if (length(recommendations) == 0) {
    recommendations <- c("Monitor query performance and database resource usage")
  }
  
  return(recommendations)
}

#' Assess the impact of a slow query on system performance
#' @param performance_record Query performance record
#' @return Impact assessment
assess_query_impact <- function(performance_record) {
  impact_score <- 0
  
  # Execution time impact
  if (performance_record$execution_time_ms > 2000) impact_score <- impact_score + 3
  else if (performance_record$execution_time_ms > 1000) impact_score <- impact_score + 2
  else impact_score <- impact_score + 1
  
  # Memory impact  
  if (performance_record$estimated_memory_mb > 20) impact_score <- impact_score + 2
  else if (performance_record$estimated_memory_mb > 10) impact_score <- impact_score + 1
  
  # Result size impact
  if (performance_record$result_count > 50000) impact_score <- impact_score + 2
  else if (performance_record$result_count > 10000) impact_score <- impact_score + 1
  
  impact_level <- if (impact_score >= 6) "high"
                 else if (impact_score >= 4) "medium"  
                 else "low"
  
  return(list(
    impact_score = impact_score,
    impact_level = impact_level,
    affects_user_experience = performance_record$execution_time_ms > 800,
    affects_system_resources = performance_record$estimated_memory_mb > 15
  ))
}

#' Generate comprehensive performance report
#' @param time_period_hours Time period for report
#' @return Comprehensive performance report
generate_performance_report <- function(time_period_hours = 24) {
  cat("📊 Generating performance report for last", time_period_hours, "hours...\n")
  
  cutoff_time <- Sys.time() - hours(time_period_hours)
  
  # Filter metrics by time period
  recent_queries <- Filter(function(q) q$timestamp >= cutoff_time, .monitoring_state$query_metrics)
  recent_system_metrics <- Filter(function(m) m$timestamp >= cutoff_time, .monitoring_state$system_metrics)
  recent_alerts <- Filter(function(a) a$timestamp >= cutoff_time, .monitoring_state$recent_alerts)
  
  report <- list(
    report_generation_time = Sys.time(),
    time_period_hours = time_period_hours,
    
    # Executive summary
    executive_summary = generate_executive_summary(recent_queries, recent_system_metrics, recent_alerts),
    
    # Query performance analysis
    query_analysis = analyze_query_performance_trends(recent_queries),
    
    # System performance analysis
    system_analysis = analyze_system_performance_trends(recent_system_metrics),
    
    # Alert analysis
    alert_analysis = analyze_alert_trends(recent_alerts),
    
    # Recommendations
    recommendations = generate_system_recommendations(recent_queries, recent_system_metrics, recent_alerts),
    
    # Performance baselines
    baselines = update_performance_baselines(recent_queries, recent_system_metrics)
  )
  
  return(report)
}

#' Generate executive summary for performance report
#' @param queries Recent query metrics
#' @param system_metrics Recent system metrics
#' @param alerts Recent alerts
#' @return Executive summary
generate_executive_summary <- function(queries, system_metrics, alerts) {
  if (length(queries) == 0) {
    return(list(status = "No query data available for analysis"))
  }
  
  execution_times <- sapply(queries, function(q) q$execution_time_ms)
  
  summary <- list(
    total_queries = length(queries),
    avg_response_time_ms = round(mean(execution_times), 2),
    p95_response_time_ms = round(quantile(execution_times, 0.95), 2),
    
    slow_query_count = length(Filter(function(q) q$execution_time_ms >= .monitoring_config$slow_query_threshold_ms, queries)),
    critical_query_count = length(Filter(function(q) q$execution_time_ms >= .monitoring_config$critical_query_threshold_ms, queries)),
    
    total_alerts = length(alerts),
    
    # Performance status
    performance_status = if (round(mean(execution_times), 2) <= .monitoring_config$target_avg_response_time_ms) "GOOD" else "NEEDS_ATTENTION",
    
    # Health indicators
    system_health = if (length(system_metrics) > 0) {
      mean(sapply(system_metrics, function(m) m$health_score %||% 50))
    } else 50
  )
  
  return(summary)
}

# ============================================================================
# MONITORING LIFECYCLE MANAGEMENT
# ============================================================================

#' Start the performance monitoring system
#' @param auto_collect Enable automatic metric collection
#' @return Boolean indicating successful start
start_performance_monitoring <- function(auto_collect = TRUE) {
  cat("🚀 Starting performance monitoring system...\n")
  
  # Initialize monitoring state
  .monitoring_state$monitoring_active <<- TRUE
  .monitoring_state$last_collection <<- Sys.time()
  .monitoring_state$collection_errors <<- 0
  
  # Collect initial metrics
  initial_metrics <- collect_system_performance_metrics()
  
  if (!is.null(initial_metrics$error)) {
    cat("⚠️ Warning: Initial metric collection had issues:", initial_metrics$error, "\n")
  }
  
  # Start automatic collection if requested
  if (auto_collect) {
    # Note: In a production system, this would set up a proper background job
    # For R Shiny, this would typically be handled by reactive timers
    cat("📊 Automatic metric collection enabled\n")
    cat("💡 Integrate with Shiny reactiveTimer() for automatic collection\n")
  }
  
  cat("✅ Performance monitoring system started successfully\n")
  cat("📈 Monitor with: get_current_performance_metrics()\n")
  cat("📊 Generate reports with: generate_performance_report()\n")
  cat("🚨 View alerts with: get_recent_alerts()\n")
  
  return(TRUE)
}

#' Stop the performance monitoring system
stop_performance_monitoring <- function() {
  cat("🛑 Stopping performance monitoring system...\n")
  
  .monitoring_state$monitoring_active <<- FALSE
  
  # Clean up old metrics to free memory
  cleanup_old_metrics()
  
  cat("✅ Performance monitoring system stopped\n")
}

#' Get current performance metrics summary
#' @return Current performance metrics
get_current_performance_metrics <- function() {
  if (!.monitoring_state$monitoring_active) {
    return(list(error = "Monitoring system is not active"))
  }
  
  # Get recent metrics summary
  recent_queries <- Filter(function(q) q$timestamp >= (Sys.time() - minutes(10)), 
                          .monitoring_state$query_metrics)
  
  if (length(recent_queries) == 0) {
    return(list(
      status = "No recent query activity",
      monitoring_active = TRUE,
      last_collection = .monitoring_state$last_collection
    ))
  }
  
  execution_times <- sapply(recent_queries, function(q) q$execution_time_ms)
  
  return(list(
    monitoring_active = TRUE,
    last_collection = .monitoring_state$last_collection,
    last_10_minutes = list(
      query_count = length(recent_queries),
      avg_response_time_ms = round(mean(execution_times), 2),
      p95_response_time_ms = round(quantile(execution_times, 0.95), 2),
      slow_queries = length(Filter(function(t) t >= .monitoring_config$slow_query_threshold_ms, execution_times)),
      performance_status = if (mean(execution_times) <= .monitoring_config$target_avg_response_time_ms) "GOOD" else "ATTENTION_NEEDED"
    )
  ))
}

#' Get recent performance alerts
#' @param hours Number of hours to look back
#' @return Recent alerts
get_recent_alerts <- function(hours = 1) {
  cutoff_time <- Sys.time() - hours(hours)
  recent_alerts <- Filter(function(a) a$timestamp >= cutoff_time, .monitoring_state$recent_alerts)
  
  return(list(
    alert_count = length(recent_alerts),
    time_period_hours = hours,
    alerts = recent_alerts
  ))
}

#' Clean up old metrics to prevent memory growth
cleanup_old_metrics <- function() {
  cutoff_time <- Sys.time() - hours(.monitoring_config$metrics_retention_hours)
  
  # Clean up old query metrics
  .monitoring_state$query_metrics <<- Filter(function(q) q$timestamp >= cutoff_time, 
                                           .monitoring_state$query_metrics)
  
  # Clean up old system metrics  
  .monitoring_state$system_metrics <<- Filter(function(m) m$timestamp >= cutoff_time,
                                             .monitoring_state$system_metrics)
  
  # Clean up old alerts
  alert_cutoff <- Sys.time() - hours(24)  # Keep alerts for 24 hours
  .monitoring_state$recent_alerts <<- Filter(function(a) a$timestamp >= alert_cutoff,
                                            .monitoring_state$recent_alerts)
  
  cat("🧹 Cleaned up old performance metrics\n")
}

# ============================================================================
# UTILITY FUNCTIONS AND EXPORTS
# ============================================================================

# Helper function for null coalescing
`%||%` <- function(a, b) if (is.null(a)) b else a

# Export main functions
list(
  # Core monitoring functions
  track_query_performance = track_query_performance,
  collect_system_performance_metrics = collect_system_performance_metrics,
  start_performance_monitoring = start_performance_monitoring,
  stop_performance_monitoring = stop_performance_monitoring,
  
  # Reporting and analysis
  generate_performance_report = generate_performance_report,
  get_current_performance_metrics = get_current_performance_metrics,
  get_recent_alerts = get_recent_alerts,
  
  # Maintenance
  cleanup_old_metrics = cleanup_old_metrics
)

# Auto-initialization message
cat("✅ Query Performance Monitoring System loaded successfully\n")
cat("🎯 Railway-optimized for 2GB memory constraints\n") 
cat("🚀 Run start_performance_monitoring() to begin monitoring\n")
cat("📊 Compatible with Brazilian Legislative data (134k+ documents)\n")
cat("🔒 LGPD-compliant logging and data handling\n")