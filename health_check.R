# HEALTH CHECK ENDPOINT FOR RAILWAY DEPLOYMENT
# ============================================
# Production-ready health check system for monitoring and Railway platform

library(jsonlite)

# Source monitoring components if available
if (file.exists("monitoring/app_monitor.R")) {
  source("monitoring/app_monitor.R")
}

if (file.exists("monitoring/logger.R")) {
  source("monitoring/logger.R")
}

# Health check configuration
HEALTH_CONFIG <- list(
  timeout_seconds = 30,
  include_details = Sys.getenv("HEALTH_CHECK_DETAILED", "true") == "true",
  check_database = TRUE,
  check_memory = TRUE,
  check_disk = TRUE
)

# Perform comprehensive health check
perform_health_check <- function(detailed = HEALTH_CONFIG$include_details) {
  start_time <- Sys.time()
  
  tryCatch({
    health_status <- list(
      status = "healthy",
      timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC"),
      service = "monitor-legislativo-v4",
      version = "1.0.0",
      checks = list(),
      uptime_seconds = NA
    )
    
    # Check if monitoring system is available
    monitoring_available <- exists("perform_health_check", mode = "function", envir = .GlobalEnv) &&
                           exists("MONITOR_STATE", envir = .GlobalEnv)
    
    if (monitoring_available && detailed) {
      # Use monitoring system health check
      monitoring_health <- get("perform_health_check", envir = .GlobalEnv)()
      
      if (!is.null(monitoring_health) && is.list(monitoring_health)) {
        health_status$status <- monitoring_health$status
        health_status$checks <- monitoring_health$checks
        health_status$metrics <- monitoring_health$metrics
        
        # Add uptime calculation
        if (exists("MONITOR_STATE", envir = .GlobalEnv)) {
          monitor_state <- get("MONITOR_STATE", envir = .GlobalEnv)
          if (!is.null(monitor_state$uptime_start)) {
            health_status$uptime_seconds <- as.numeric(difftime(Sys.time(), monitor_state$uptime_start, units = "secs"))
          }
        }
      }
    } else {
      # Basic health checks without monitoring system
      
      # Memory check
      memory_mb <- tryCatch({
        if (exists("memory.size", mode = "function")) {
          memory.size()
        } else {
          gc_info <- gc()
          sum(gc_info[, 2]) * 8 / 1024 / 1024  # Convert to MB
        }
      }, error = function(e) 0)
      
      health_status$checks$memory <- list(
        status = if (memory_mb > 0 && memory_mb < 1000) "ok" else "warning",
        value = memory_mb,
        unit = "MB"
      )
      
      # Database connection check (if available)
      if (HEALTH_CONFIG$check_database) {
        db_status <- "unknown"
        if (exists("get_connection_status", mode = "function")) {
          tryCatch({
            conn_status <- get_connection_status()
            db_status <- if (conn_status$status == "connected") "ok" else "error"
          }, error = function(e) {
            db_status <- "error"
          })
        }
        
        health_status$checks$database <- list(
          status = db_status
        )
        
        if (db_status == "error") {
          health_status$status <- "degraded"
        }
      }
      
      # Basic R system check
      health_status$checks$r_system <- list(
        status = "ok",
        version = R.version.string
      )
      
      # Environment check
      health_status$checks$environment <- list(
        status = "ok",
        railway_service = Sys.getenv("RAILWAY_SERVICE_NAME", "unknown"),
        railway_environment = Sys.getenv("RAILWAY_ENVIRONMENT_NAME", "unknown")
      )
    }
    
    # Calculate response time
    duration_ms <- as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000
    health_status$response_time_ms <- round(duration_ms, 2)
    
    # Set overall status based on checks
    if (detailed && !is.null(health_status$checks)) {
      has_errors <- any(sapply(health_status$checks, function(check) {
        if (is.list(check) && "status" %in% names(check)) {
          check$status == "error"
        } else {
          FALSE
        }
      }))
      
      has_warnings <- any(sapply(health_status$checks, function(check) {
        if (is.list(check) && "status" %in% names(check)) {
          check$status == "warning"
        } else {
          FALSE
        }
      }))
      
      if (has_errors) {
        health_status$status <- "unhealthy"
      } else if (has_warnings) {
        health_status$status <- "degraded"
      }
    }
    
    return(health_status)
    
  }, error = function(e) {
    return(list(
      status = "error",
      timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC"),
      service = "monitor-legislativo-v4",
      version = "1.0.0",
      error = as.character(e),
      response_time_ms = as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000
    ))
  })
}

# Liveness probe - basic check that the application is running
liveness_check <- function() {
  list(
    status = "alive",
    timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC"),
    service = "monitor-legislativo-v4"
  )
}

# Readiness probe - check that the application is ready to serve traffic
readiness_check <- function() {
  tryCatch({
    # Check if core functions are available
    core_ready <- TRUE
    
    # Check if essential packages are loaded
    required_packages <- c("shiny", "shinydashboard", "DT", "plotly", "dplyr")
    for (pkg in required_packages) {
      if (!requireNamespace(pkg, quietly = TRUE)) {
        core_ready <- FALSE
        break
      }
    }
    
    # Check database connection if required
    db_ready <- TRUE
    if (exists("get_connection_status", mode = "function")) {
      tryCatch({
        status <- get_connection_status()
        db_ready <- (status$status == "connected")
      }, error = function(e) {
        db_ready <- FALSE
      })
    }
    
    overall_ready <- core_ready && db_ready
    
    return(list(
      status = if (overall_ready) "ready" else "not_ready",
      timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC"),
      service = "monitor-legislativo-v4",
      checks = list(
        core_packages = if (core_ready) "ready" else "not_ready",
        database = if (db_ready) "ready" else "not_ready"
      )
    ))
    
  }, error = function(e) {
    return(list(
      status = "error",
      timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC"),
      service = "monitor-legislativo-v4",
      error = as.character(e)
    ))
  })
}

# HTTP endpoint handlers for Railway
handle_health_request <- function(path = "/health") {
  switch(path,
         "/health" = perform_health_check(),
         "/health/live" = liveness_check(),
         "/health/ready" = readiness_check(),
         list(
           status = "not_found",
           message = paste("Health check endpoint not found:", path),
           available_endpoints = c("/health", "/health/live", "/health/ready")
         )
  )
}

# Export health check function for use in main application
if (!exists("get_health_status", mode = "function", envir = .GlobalEnv)) {
  assign("get_health_status", perform_health_check, envir = .GlobalEnv)
}

# Export for direct use
list(
  health_check = perform_health_check,
  liveness_check = liveness_check,
  readiness_check = readiness_check,
  handle_request = handle_health_request
)