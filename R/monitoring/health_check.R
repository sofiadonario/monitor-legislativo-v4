# =============================================================================
# Health Check and Monitoring System
# =============================================================================
# Monitor Legislativo v4 - Phase 5: Testing & Monitoring
#
# Provides comprehensive health checks and monitoring for production deployment
# Enables external monitoring tools (Prometheus, Grafana, etc.)
#
# Author: Monitor Legislativo v4 Team
# Version: 4.0.0
# Last Updated: 2025-11-21
# =============================================================================

library(jsonlite)

# =============================================================================
# HEALTH CHECK FUNCTIONS
# =============================================================================

#' Comprehensive System Health Check
#'
#' Performs checks on all critical system components
#'
#' @param db_pool Database connection pool (optional)
#' @param detailed Logical, whether to include detailed component checks
#'
#' @return List with health status and details
#' @export
perform_health_check <- function(db_pool = NULL, detailed = FALSE) {

  start_time <- Sys.time()

  health_status <- list(
    timestamp = format(Sys.time(), "%Y-%m-%d %H:%M:%S UTC", tz = "UTC"),
    status = "healthy",
    version = "4.0.0",
    uptime_seconds = get_application_uptime(),
    checks = list()
  )

  # Check 1: Database connectivity
  db_check <- check_database_health(db_pool)
  health_status$checks$database <- db_check

  if (db_check$status != "healthy") {
    health_status$status <- "unhealthy"
  }

  # Check 2: Memory usage
  memory_check <- check_memory_health()
  health_status$checks$memory <- memory_check

  if (memory_check$status == "critical") {
    health_status$status <- "degraded"
  }

  # Check 3: Disk space
  if (detailed) {
    disk_check <- check_disk_space()
    health_status$checks$disk <- disk_check
  }

  # Check 4: R session health
  session_check <- check_session_health()
  health_status$checks$session <- session_check

  # Calculate response time
  health_status$response_time_ms <- round(
    as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000,
    2
  )

  return(health_status)
}

#' Check Database Health
#'
#' Verifies database connectivity and performance
#'
#' @param db_pool Database connection pool
#'
#' @return List with database health status
#' @export
check_database_health <- function(db_pool = NULL) {

  if (is.null(db_pool)) {
    return(list(
      status = "unavailable",
      message = "Database pool not initialized"
    ))
  }

  tryCatch({
    # Test query
    start_time <- Sys.time()
    result <- pool::dbGetQuery(db_pool, "SELECT 1 as health_check")
    query_time_ms <- round(
      as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000,
      2
    )

    # Get pool stats
    pool_info <- pool::dbGetInfo(db_pool)

    # Get database stats
    db_stats <- pool::dbGetQuery(db_pool, "
      SELECT
        (SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()) as active_connections,
        pg_database_size(current_database()) as database_size_bytes
    ")

    status <- "healthy"
    if (query_time_ms > 1000) {
      status <- "degraded"
    }

    return(list(
      status = status,
      message = "Database is responsive",
      query_time_ms = query_time_ms,
      pool_free = pool_info$free,
      pool_taken = pool_info$taken,
      active_connections = db_stats$active_connections[1],
      database_size_mb = round(db_stats$database_size_bytes[1] / 1024 / 1024, 2)
    ))

  }, error = function(e) {
    return(list(
      status = "unhealthy",
      message = paste("Database check failed:", e$message)
    ))
  })
}

#' Check Memory Health
#'
#' Monitors R session memory usage
#'
#' @return List with memory status
#' @export
check_memory_health <- function() {

  tryCatch({
    # Get memory usage
    mem_info <- pryr::mem_used()
    mem_mb <- round(as.numeric(mem_info) / 1024 / 1024, 2)

    # Get memory limit (if available)
    mem_limit_str <- Sys.getenv("R_MAX_VSIZE", "")
    mem_limit_mb <- if (mem_limit_str != "") {
      # Parse limit (e.g., "2G" -> 2048 MB)
      value <- as.numeric(gsub("[^0-9.]", "", mem_limit_str))
      unit <- gsub("[0-9.]", "", mem_limit_str)
      if (unit == "G") value * 1024 else value
    } else {
      NA
    }

    # Determine status
    status <- "healthy"
    if (!is.na(mem_limit_mb)) {
      usage_pct <- (mem_mb / mem_limit_mb) * 100
      if (usage_pct > 90) {
        status <- "critical"
      } else if (usage_pct > 75) {
        status <- "warning"
      }
    }

    return(list(
      status = status,
      memory_used_mb = mem_mb,
      memory_limit_mb = if (!is.na(mem_limit_mb)) mem_limit_mb else "unlimited",
      usage_percent = if (!is.na(mem_limit_mb)) round(usage_pct, 1) else NA
    ))

  }, error = function(e) {
    # Fallback if pryr not available
    gc_info <- gc()
    mem_mb <- sum(gc_info[, 2])

    return(list(
      status = "healthy",
      memory_used_mb = round(mem_mb, 2),
      message = "Basic memory check (pryr package not available)"
    ))
  })
}

#' Check Disk Space
#'
#' Monitors available disk space
#'
#' @return List with disk space status
#' @export
check_disk_space <- function() {

  tryCatch({
    # Get disk usage (Unix/Linux/Mac)
    if (.Platform$OS.type == "unix") {
      disk_info <- system("df -h / | tail -1", intern = TRUE)
      parts <- strsplit(disk_info, "\\s+")[[1]]

      return(list(
        status = "healthy",
        filesystem = parts[1],
        total = parts[2],
        used = parts[3],
        available = parts[4],
        use_percent = parts[5]
      ))
    } else {
      return(list(
        status = "unavailable",
        message = "Disk check not supported on Windows"
      ))
    }

  }, error = function(e) {
    return(list(
      status = "unavailable",
      message = paste("Disk check failed:", e$message)
    ))
  })
}

#' Check R Session Health
#'
#' Verifies R session is functioning properly
#'
#' @return List with session status
#' @export
check_session_health <- function() {

  return(list(
    status = "healthy",
    r_version = paste(R.version$major, R.version$minor, sep = "."),
    platform = R.version$platform,
    locale = Sys.getlocale("LC_TIME"),
    timezone = Sys.timezone()
  ))
}

# =============================================================================
# APPLICATION METRICS
# =============================================================================

# Initialize metrics storage
if (!exists(".app_metrics", envir = .GlobalEnv)) {
  assign(".app_metrics", list(
    start_time = Sys.time(),
    request_count = 0,
    error_count = 0
  ), envir = .GlobalEnv)
}

#' Get Application Uptime
#'
#' Returns number of seconds since application started
#'
#' @return Numeric uptime in seconds
#' @export
get_application_uptime <- function() {
  metrics <- get(".app_metrics", envir = .GlobalEnv)
  as.numeric(difftime(Sys.time(), metrics$start_time, units = "secs"))
}

#' Increment Request Counter
#'
#' Tracks total number of requests
#'
#' @export
increment_request_counter <- function() {
  metrics <- get(".app_metrics", envir = .GlobalEnv)
  metrics$request_count <- metrics$request_count + 1
  assign(".app_metrics", metrics, envir = .GlobalEnv)
  invisible(NULL)
}

#' Increment Error Counter
#'
#' Tracks total number of errors
#'
#' @export
increment_error_counter <- function() {
  metrics <- get(".app_metrics", envir = .GlobalEnv)
  metrics$error_count <- metrics$error_count + 1
  assign(".app_metrics", metrics, envir = .GlobalEnv)
  invisible(NULL)
}

#' Get Application Metrics
#'
#' Returns current application metrics
#'
#' @return List with metrics
#' @export
get_application_metrics <- function() {
  metrics <- get(".app_metrics", envir = .GlobalEnv)

  list(
    uptime_seconds = get_application_uptime(),
    total_requests = metrics$request_count,
    total_errors = metrics$error_count,
    error_rate = if (metrics$request_count > 0) {
      round(metrics$error_count / metrics$request_count * 100, 2)
    } else {
      0
    }
  )
}

# =============================================================================
# MONITORING ENDPOINTS (for Prometheus, etc.)
# =============================================================================

#' Get Metrics in Prometheus Format
#'
#' Returns metrics compatible with Prometheus scraping
#'
#' @param db_pool Database connection pool
#'
#' @return Character string in Prometheus format
#' @export
get_prometheus_metrics <- function(db_pool = NULL) {

  metrics <- get_application_metrics()
  health <- perform_health_check(db_pool, detailed = FALSE)

  prometheus_output <- c(
    "# HELP app_uptime_seconds Application uptime in seconds",
    "# TYPE app_uptime_seconds gauge",
    sprintf("app_uptime_seconds %d", round(metrics$uptime_seconds)),
    "",
    "# HELP app_requests_total Total number of requests",
    "# TYPE app_requests_total counter",
    sprintf("app_requests_total %d", metrics$total_requests),
    "",
    "# HELP app_errors_total Total number of errors",
    "# TYPE app_errors_total counter",
    sprintf("app_errors_total %d", metrics$total_errors),
    "",
    "# HELP app_health_status Health check status (1=healthy, 0=unhealthy)",
    "# TYPE app_health_status gauge",
    sprintf("app_health_status %d", if (health$status == "healthy") 1 else 0)
  )

  # Add database metrics if available
  if (!is.null(health$checks$database) && health$checks$database$status != "unavailable") {
    db <- health$checks$database
    prometheus_output <- c(
      prometheus_output,
      "",
      "# HELP db_query_time_ms Database query response time in milliseconds",
      "# TYPE db_query_time_ms gauge",
      sprintf("db_query_time_ms %.2f", db$query_time_ms),
      "",
      "# HELP db_pool_free Free connections in pool",
      "# TYPE db_pool_free gauge",
      sprintf("db_pool_free %d", db$pool_free),
      "",
      "# HELP db_active_connections Active database connections",
      "# TYPE db_active_connections gauge",
      sprintf("db_active_connections %d", db$active_connections)
    )
  }

  paste(prometheus_output, collapse = "\n")
}

#' Get Health Status JSON
#'
#' Returns health status as JSON for API endpoints
#'
#' @param db_pool Database connection pool
#' @param detailed Logical, include detailed checks
#'
#' @return JSON string
#' @export
get_health_json <- function(db_pool = NULL, detailed = FALSE) {
  health <- perform_health_check(db_pool, detailed)
  jsonlite::toJSON(health, pretty = TRUE, auto_unbox = TRUE)
}

# =============================================================================
# READINESS AND LIVENESS PROBES
# =============================================================================

#' Readiness Probe
#'
#' Checks if application is ready to serve traffic
#' Returns TRUE if all critical services are available
#'
#' @param db_pool Database connection pool
#'
#' @return Logical
#' @export
is_ready <- function(db_pool = NULL) {
  health <- perform_health_check(db_pool, detailed = FALSE)

  # Check critical services
  db_healthy <- health$checks$database$status %in% c("healthy", "degraded")

  return(db_healthy)
}

#' Liveness Probe
#'
#' Checks if application is alive (not stuck/deadlocked)
#' Returns TRUE if R session is responsive
#'
#' @return Logical
#' @export
is_alive <- function() {
  # Simple check - if this function executes, we're alive
  tryCatch({
    # Test basic R functionality
    test <- 1 + 1
    return(test == 2)
  }, error = function(e) {
    return(FALSE)
  })
}

# =============================================================================
# ALERTING HELPERS
# =============================================================================

#' Check for Alert Conditions
#'
#' Evaluates metrics against thresholds and returns alerts
#'
#' @param db_pool Database connection pool
#'
#' @return List of active alerts
#' @export
get_active_alerts <- function(db_pool = NULL) {

  alerts <- list()

  # Check database health
  if (!is.null(db_pool)) {
    db_check <- check_database_health(db_pool)

    if (db_check$status == "unhealthy") {
      alerts <- c(alerts, list(list(
        severity = "critical",
        component = "database",
        message = "Database is unhealthy",
        timestamp = Sys.time()
      )))
    }

    if (!is.null(db_check$query_time_ms) && db_check$query_time_ms > 1000) {
      alerts <- c(alerts, list(list(
        severity = "warning",
        component = "database",
        message = sprintf("Slow database queries: %.0fms", db_check$query_time_ms),
        timestamp = Sys.time()
      )))
    }
  }

  # Check memory
  mem_check <- check_memory_health()
  if (mem_check$status == "critical") {
    alerts <- c(alerts, list(list(
      severity = "critical",
      component = "memory",
      message = sprintf("Memory usage critical: %.1f%%", mem_check$usage_percent),
      timestamp = Sys.time()
    )))
  }

  # Check error rate
  metrics <- get_application_metrics()
  if (metrics$error_rate > 10) {
    alerts <- c(alerts, list(list(
      severity = "warning",
      component = "application",
      message = sprintf("High error rate: %.1f%%", metrics$error_rate),
      timestamp = Sys.time()
    )))
  }

  return(alerts)
}

# =============================================================================
# EXAMPLE USAGE
# =============================================================================

# Example 1: Basic health check
# health <- perform_health_check(db_pool)
# cat(jsonlite::toJSON(health, pretty = TRUE, auto_unbox = TRUE))

# Example 2: Readiness check (for Kubernetes)
# if (is_ready(db_pool)) {
#   cat("HTTP/1.1 200 OK\n")
# } else {
#   cat("HTTP/1.1 503 Service Unavailable\n")
# }

# Example 3: Prometheus metrics
# metrics <- get_prometheus_metrics(db_pool)
# cat(metrics)

# Example 4: Check for alerts
# alerts <- get_active_alerts(db_pool)
# if (length(alerts) > 0) {
#   # Send to alerting system
#   lapply(alerts, function(alert) {
#     send_alert(alert$severity, alert$message)
#   })
# }
