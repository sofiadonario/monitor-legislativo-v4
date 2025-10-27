# Enhanced Health Check and Monitoring System
# ==========================================
# This module provides comprehensive health monitoring for Railway deployment

library(jsonlite)

# System limits and thresholds
HEALTH_CONFIG <- list(
  memory_warning_threshold = 80,    # Percentage
  memory_critical_threshold = 90,   # Percentage
  response_time_warning = 5000,     # Milliseconds
  response_time_critical = 10000,   # Milliseconds
  max_memory_mb = as.numeric(Sys.getenv("R_MAX_MEM_SIZE", "2000")),
  health_check_interval = 60        # Seconds
)

# Global health state
HEALTH_STATE <- list(
  last_check = NULL,
  status = "unknown",
  components = list(),
  metrics = list(),
  alerts = list()
)

# Component health checkers
check_memory_health <- function() {
  gc_info <- gc()
  current_memory_mb <- as.numeric(gc_info[2, 2])  # Total memory in MB
  max_memory_mb <- HEALTH_CONFIG$max_memory_mb

  percentage_used <- (current_memory_mb / max_memory_mb) * 100

  status <- if (percentage_used >= HEALTH_CONFIG$memory_critical_threshold) {
    "critical"
  } else if (percentage_used >= HEALTH_CONFIG$memory_warning_threshold) {
    "warning"
  } else {
    "healthy"
  }

  list(
    component = "memory",
    status = status,
    percentage_used = round(percentage_used, 1),
    current_mb = round(current_memory_mb, 1),
    max_mb = max_memory_mb,
    available_mb = round(max_memory_mb - current_memory_mb, 1),
    details = sprintf("Memory usage: %s/%s MB (%.1f%%)",
                     round(current_memory_mb, 1), max_memory_mb, percentage_used)
  )
}

check_database_health <- function() {
  status <- "unknown"
  details <- "Database check not available"
  response_time_ms <- NA
  connection_info <- list()

  tryCatch({
    start_time <- Sys.time()

    # Check if database connection function exists
    if (exists("get_connection_status", envir = .GlobalEnv)) {
      db_status <- get_connection_status()

      end_time <- Sys.time()
      response_time_ms <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000

      if (db_status$status == "connected") {
        status <- "healthy"
        details <- sprintf("Database connected (%s) - %s documents available",
                          db_status$method, format(db_status$document_count, big.mark = ","))

        # Additional Railway-specific health checks
        railway_check <- check_railway_database_specifics()
        if (!is.null(railway_check)) {
          connection_info <- railway_check
          if (railway_check$pool_health == "warning") {
            status <- "warning"
            details <- paste(details, "- Pool health warning")
          }
        }
      } else if (db_status$status == "csv_fallback" || db_status$status == "csv_only") {
        status <- "degraded"
        details <- sprintf("Using CSV fallback mode - %s documents available",
                          format(db_status$document_count, big.mark = ","))
      } else {
        status <- "critical"
        details <- paste("Database connection failed:", db_status$error %||% "Unknown error")
      }
    } else {
      status <- "critical"
      details <- "Database connection functions not loaded"
    }

    # Check environment variable configuration
    env_check <- check_database_environment()
    if (!env_check$configured) {
      if (status == "healthy") {
        status <- "warning"
      }
      details <- paste(details, "-", env_check$message)
    }

  }, error = function(e) {
    status <- "critical"
    details <- paste("Database health check failed:", e$message)
  })

  list(
    component = "database",
    status = status,
    response_time_ms = response_time_ms,
    details = details,
    connection_info = connection_info
  )
}

# Check Railway-specific database health
check_railway_database_specifics <- function() {
  tryCatch({
    # Check if connection pool exists and is healthy
    if (exists("CONNECTION_STATE", envir = .GlobalEnv)) {
      connection_state <- get("CONNECTION_STATE", envir = .GlobalEnv)

      if (!is.null(connection_state$connection_pool)) {
        pool <- connection_state$connection_pool

        # Get pool statistics if available
        pool_info <- list(
          pool_health = "healthy",
          active_connections = NA,
          idle_connections = NA
        )

        # Test a simple query to ensure pool is responsive
        test_result <- tryCatch({
          if (requireNamespace("pool", quietly = TRUE)) {
            pool::dbGetQuery(pool, "SELECT 1 as test, NOW() as server_time")
          } else {
            NULL
          }
        }, error = function(e) {
          pool_info$pool_health <- "warning"
          pool_info$error <- e$message
          NULL
        })

        if (!is.null(test_result)) {
          pool_info$server_time <- test_result$server_time
          pool_info$last_successful_query <- Sys.time()
        }

        return(pool_info)
      }
    }

    return(NULL)
  }, error = function(e) {
    return(list(
      pool_health = "critical",
      error = e$message
    ))
  })
}

# Check database environment configuration
check_database_environment <- function() {
  # Check for Railway database URLs
  database_urls <- c(
    "DATABASE_PUBLIC_URL" = Sys.getenv("DATABASE_PUBLIC_URL"),
    "DATABASE_PRIVATE_URL" = Sys.getenv("DATABASE_PRIVATE_URL"),
    "DATABASE_URL" = Sys.getenv("DATABASE_URL")
  )

  available_urls <- database_urls[database_urls != ""]

  if (length(available_urls) == 0) {
    return(list(
      configured = FALSE,
      message = "No database URLs configured"
    ))
  }

  # Check for Railway-specific patterns
  railway_urls <- available_urls[grepl("railway|rlwy\\.net", available_urls)]

  if (length(railway_urls) == 0) {
    return(list(
      configured = TRUE,
      message = sprintf("Non-Railway database URLs detected (%d URLs)", length(available_urls)),
      warning = TRUE
    ))
  }

  return(list(
    configured = TRUE,
    message = sprintf("Railway database URLs configured (%d URLs)", length(railway_urls)),
    url_count = length(railway_urls)
  ))
}

check_filesystem_health <- function() {
  status <- "healthy"
  details <- "Filesystem accessible"

  tryCatch({
    # Check critical directories
    critical_paths <- c(
      "data_current",
      "R",
      "db"
    )

    missing_paths <- character()
    for (path in critical_paths) {
      if (!dir.exists(path) && !file.exists(path)) {
        missing_paths <- c(missing_paths, path)
      }
    }

    if (length(missing_paths) > 0) {
      status <- "warning"
      details <- paste("Missing paths:", paste(missing_paths, collapse = ", "))
    }

    # Check data files
    data_files <- list.files("data_current", pattern = "\\.(csv|parquet)$", recursive = TRUE)
    if (length(data_files) == 0) {
      status <- "critical"
      details <- "No data files found in data_current directory"
    }

  }, error = function(e) {
    status <- "critical"
    details <- paste("Filesystem check failed:", e$message)
  })

  list(
    component = "filesystem",
    status = status,
    data_files_count = length(data_files %||% 0),
    details = details
  )
}

check_environment_health <- function() {
  status <- "healthy"
  warnings <- character()

  # Check critical environment variables
  critical_vars <- c("PORT")
  optional_vars <- c("DATABASE_URL", "REDIS_URL", "R_CONFIG_ACTIVE")

  for (var in critical_vars) {
    if (Sys.getenv(var) == "") {
      status <- "critical"
      warnings <- c(warnings, paste("Critical variable", var, "not set"))
    }
  }

  missing_optional <- character()
  for (var in optional_vars) {
    if (Sys.getenv(var) == "") {
      missing_optional <- c(missing_optional, var)
    }
  }

  if (isTRUE(length(missing_optional) > 0) && status == "healthy") {
    status <- "warning"
    warnings <- c(warnings, paste("Optional variables not set:", paste(missing_optional, collapse = ", ")))
  }

  details <- if (length(warnings) > 0) {
    paste(warnings, collapse = "; ")
  } else {
    "All environment variables properly configured"
  }

  list(
    component = "environment",
    status = status,
    details = details
  )
}

check_application_health <- function() {
  status <- "healthy"
  details <- "Application components loaded"

  tryCatch({
    # Check if critical functions are loaded
    critical_functions <- c("get_library_documents", "process_document_data")
    missing_functions <- character()

    for (func in critical_functions) {
      if (!exists(func, envir = .GlobalEnv)) {
        missing_functions <- c(missing_functions, func)
      }
    }

    if (length(missing_functions) > 0) {
      status <- "critical"
      details <- paste("Missing critical functions:", paste(missing_functions, collapse = ", "))
    }

    # Check package availability
    critical_packages <- c("shiny", "DT", "plotly")
    missing_packages <- character()

    for (pkg in critical_packages) {
      if (!requireNamespace(pkg, quietly = TRUE)) {
        missing_packages <- c(missing_packages, pkg)
      }
    }

    if (length(missing_packages) > 0) {
      status <- "critical"
      details <- paste(details, "; Missing packages:", paste(missing_packages, collapse = ", "))
    }

  }, error = function(e) {
    status <- "critical"
    details <- paste("Application health check failed:", e$message)
  })

  list(
    component = "application",
    status = status,
    details = details
  )
}

# Comprehensive health check
perform_health_check <- function(include_details = TRUE) {
  start_time <- Sys.time()

  cat("🔍 Performing comprehensive health check...\n")

  # Run all component checks
  component_checks <- list(
    check_memory_health(),
    check_database_health(),
    check_filesystem_health(),
    check_environment_health(),
    check_application_health()
  )

  # Determine overall status
  statuses <- sapply(component_checks, function(x) x$status)
  overall_status <- if (any(statuses == "critical")) {
    "critical"
  } else if (any(statuses == "warning") || any(statuses == "degraded")) {
    "warning"
  } else {
    "healthy"
  }

  end_time <- Sys.time()
  check_duration_ms <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000

  # Update global state
  HEALTH_STATE$last_check <<- end_time
  HEALTH_STATE$status <<- overall_status
  HEALTH_STATE$components <<- component_checks

  # Create health summary
  health_summary <- list(
    timestamp = format(end_time, "%Y-%m-%d %H:%M:%S UTC"),
    overall_status = overall_status,
    check_duration_ms = round(check_duration_ms, 1),
    components = if (include_details) component_checks else length(component_checks)
  )

  # Add component summary
  component_summary <- data.frame(
    component = sapply(component_checks, function(x) x$component),
    status = sapply(component_checks, function(x) x$status),
    stringsAsFactors = FALSE
  )

  health_summary$component_summary <- component_summary

  cat("✅ Health check completed in", round(check_duration_ms, 1), "ms\n")
  cat("📊 Overall status:", overall_status, "\n")

  # Print component statuses
  for (comp in component_checks) {
    status_icon <- switch(comp$status,
                         "healthy" = "✅",
                         "warning" = "⚠️",
                         "degraded" = "🔶",
                         "critical" = "❌",
                         "❓")
    cat(sprintf("%s %s: %s\n", status_icon, comp$component, comp$status))
  }

  return(health_summary)
}

# Create health endpoint for Railway
create_health_endpoint <- function() {
  health_check <- perform_health_check(include_details = FALSE)

  # Format for HTTP health check
  http_status <- switch(health_check$overall_status,
                       "healthy" = 200,
                       "warning" = 200,
                       "degraded" = 200,
                       "critical" = 503,
                       503)

  response <- list(
    status = health_check$overall_status,
    timestamp = health_check$timestamp,
    components = nrow(health_check$component_summary),
    healthy_components = sum(health_check$component_summary$status == "healthy"),
    warning_components = sum(health_check$component_summary$status %in% c("warning", "degraded")),
    critical_components = sum(health_check$component_summary$status == "critical")
  )

  list(
    status_code = http_status,
    body = toJSON(response, auto_unbox = TRUE)
  )
}

# Memory monitoring with alerts
monitor_memory_continuously <- function() {
  memory_check <- check_memory_health()

  if (memory_check$status == "critical") {
    cat("🚨 CRITICAL: Memory usage at", memory_check$percentage_used, "%\n")
    cat("🔄 Forcing aggressive garbage collection\n")

    # Aggressive cleanup
    gc()
    gc()  # Run twice for better cleanup

    # Re-check after cleanup
    memory_check_after <- check_memory_health()
    cat("💾 Memory after cleanup:", memory_check_after$percentage_used, "%\n")

    if (memory_check_after$percentage_used > 85) {
      cat("⚠️ Memory still high after cleanup - consider reducing data operations\n")
    }
  }

  return(memory_check)
}

# Automatic health monitoring for Railway
start_health_monitoring <- function(interval_seconds = 60) {
  cat("🔄 Starting automatic health monitoring (interval:", interval_seconds, "seconds)\n")

  # Set up periodic checks (this would need to be integrated with Shiny's reactive system)
  cat("ℹ️ Note: Continuous monitoring requires integration with Shiny reactive system\n")
  cat("🔍 Use perform_health_check() manually for immediate health status\n")
}

# Helper function for NULL coalescing
`%||%` <- function(a, b) if (is.null(a)) b else a

# Export functions
list(
  perform_health_check = perform_health_check,
  create_health_endpoint = create_health_endpoint,
  monitor_memory_continuously = monitor_memory_continuously,
  start_health_monitoring = start_health_monitoring,
  HEALTH_CONFIG = HEALTH_CONFIG
)