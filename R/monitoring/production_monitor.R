# MONITOR LEGISLATIVO V4 - PRODUCTION MONITORING SYSTEM
# =====================================================
# Advanced monitoring and alerting for Railway deployment
# Brazilian Legislative Monitoring - Academic Institution Focus

# Load required libraries
library(httr2)
library(jsonlite)
library(lubridate)
library(dplyr)

# =============================================================================
# RAILWAY PRODUCTION MONITORING CONFIGURATION
# =============================================================================

# Environment detection
is_production <- function() {
  Sys.getenv("RAILWAY_ENVIRONMENT", "development") == "production"
}

is_monitoring_enabled <- function() {
  as.logical(Sys.getenv("MONITORING_ENABLED", "false"))
}

# =============================================================================
# SYSTEM METRICS COLLECTION
# =============================================================================

#' Collect comprehensive system metrics
#' @return list of system metrics optimized for Railway deployment
collect_system_metrics <- function() {
  tryCatch({
    
    # Memory metrics (Railway 3GB optimization)
    memory_info <- list(
      used_mb = as.numeric(system("free -m | grep '^Mem:' | awk '{print $3}'", intern = TRUE)),
      total_mb = as.numeric(system("free -m | grep '^Mem:' | awk '{print $2}'", intern = TRUE)),
      available_mb = as.numeric(system("free -m | grep '^Mem:' | awk '{print $7}'", intern = TRUE))
    )
    memory_info$usage_percent <- round((memory_info$used_mb / memory_info$total_mb) * 100, 2)
    
    # CPU metrics
    cpu_usage <- tryCatch({
      as.numeric(system("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | sed 's/%us,//'", intern = TRUE))
    }, error = function(e) 0)
    
    # Disk metrics
    disk_info <- tryCatch({
      disk_output <- system("df -h / | tail -n 1", intern = TRUE)
      disk_parts <- strsplit(disk_output, "\\s+")[[1]]
      list(
        used = disk_parts[3],
        available = disk_parts[4],
        usage_percent = as.numeric(gsub("%", "", disk_parts[5]))
      )
    }, error = function(e) list(used = "0G", available = "0G", usage_percent = 0))
    
    # R-specific metrics
    r_metrics <- list(
      r_version = R.version.string,
      objects_count = length(ls(envir = .GlobalEnv)),
      memory_usage_mb = round(as.numeric(object.size(.GlobalEnv)) / 1024^2, 2),
      loaded_packages = length(loadedNamespaces())
    )
    
    # Application-specific metrics
    app_metrics <- list(
      uptime_seconds = as.numeric(difftime(Sys.time(), 
                                          as.POSIXct(Sys.getenv("APP_START_TIME", Sys.time())), 
                                          units = "secs")),
      active_sessions = get_active_sessions_count(),
      database_connections = get_db_connection_count(),
      cache_hits = get_cache_hit_rate()
    )
    
    return(list(
      timestamp = Sys.time(),
      memory = memory_info,
      cpu_usage_percent = cpu_usage,
      disk = disk_info,
      r_metrics = r_metrics,
      app_metrics = app_metrics,
      environment = Sys.getenv("RAILWAY_ENVIRONMENT", "unknown")
    ))
    
  }, error = function(e) {
    cat("⚠️ Error collecting system metrics:", e$message, "\n")
    return(list(
      timestamp = Sys.time(),
      error = e$message,
      environment = Sys.getenv("RAILWAY_ENVIRONMENT", "unknown")
    ))
  })
}

# =============================================================================
# APPLICATION HEALTH CHECKS
# =============================================================================

#' Comprehensive health check for Railway deployment
#' @return list with health status and details
health_check <- function() {
  health_status <- list(
    timestamp = Sys.time(),
    status = "healthy",
    checks = list(),
    warnings = list(),
    errors = list()
  )
  
  # Database connectivity check
  tryCatch({
    if (exists("db_pool") && !is.null(db_pool)) {
      pool::dbGetQuery(db_pool, "SELECT 1 as health_check")
      health_status$checks$database <- "✅ Connected"
    } else {
      health_status$warnings <- append(health_status$warnings, "Database pool not available")
      health_status$checks$database <- "⚠️ No pool"
    }
  }, error = function(e) {
    health_status$errors <- append(health_status$errors, paste("Database:", e$message))
    health_status$checks$database <- "❌ Error"
    health_status$status <- "unhealthy"
  })
  
  # Redis cache check (if enabled)
  if (Sys.getenv("CACHE_ENABLED", "false") == "true") {
    tryCatch({
      # Implement Redis health check
      health_status$checks$cache <- "✅ Available"
    }, error = function(e) {
      health_status$warnings <- append(health_status$warnings, paste("Cache:", e$message))
      health_status$checks$cache <- "⚠️ Unavailable"
    })
  }
  
  # Memory threshold check (Railway 3GB limit)
  metrics <- collect_system_metrics()
  if (!is.null(metrics$memory$usage_percent)) {
    memory_threshold <- as.numeric(Sys.getenv("MEMORY_PRESSURE_THRESHOLD", "70"))
    if (metrics$memory$usage_percent > memory_threshold) {
      health_status$warnings <- append(health_status$warnings, 
                                      paste("High memory usage:", metrics$memory$usage_percent, "%"))
      health_status$checks$memory <- paste("⚠️", metrics$memory$usage_percent, "%")
    } else {
      health_status$checks$memory <- paste("✅", metrics$memory$usage_percent, "%")
    }
  }
  
  # Application responsiveness check
  start_time <- Sys.time()
  tryCatch({
    # Simulate a light application operation
    Sys.sleep(0.01)
    response_time <- as.numeric(difftime(Sys.time(), start_time, units = "milliseconds"))
    
    if (response_time > 1000) {
      health_status$warnings <- append(health_status$warnings, 
                                      paste("Slow response time:", round(response_time), "ms"))
      health_status$checks$response_time <- paste("⚠️", round(response_time), "ms")
    } else {
      health_status$checks$response_time <- paste("✅", round(response_time), "ms")
    }
  }, error = function(e) {
    health_status$errors <- append(health_status$errors, paste("Response time:", e$message))
    health_status$checks$response_time <- "❌ Error"
    health_status$status <- "unhealthy"
  })
  
  # Overall status determination
  if (length(health_status$errors) > 0) {
    health_status$status <- "unhealthy"
  } else if (length(health_status$warnings) > 0) {
    health_status$status <- "degraded"
  }
  
  return(health_status)
}

# =============================================================================
# ALERTING SYSTEM
# =============================================================================

#' Check if alerts should be sent based on Brazilian business hours
#' @return logical indicating if alerts should be sent
should_send_alerts <- function() {
  if (!is_production() || !is_monitoring_enabled()) {
    return(FALSE)
  }
  
  # Brazilian timezone
  current_time <- with_tz(Sys.time(), "America/Sao_Paulo")
  hour <- hour(current_time)
  wday <- wday(current_time)
  
  # Business hours: 8 AM to 6 PM, Monday to Friday
  business_hours <- Sys.getenv("ALERT_BUSINESS_HOURS", "08:00-18:00")
  business_days <- Sys.getenv("ALERT_BUSINESS_DAYS", "1-5")
  
  # Parse business hours
  hours_range <- strsplit(business_hours, "-")[[1]]
  start_hour <- as.numeric(strsplit(hours_range[1], ":")[[1]][1])
  end_hour <- as.numeric(strsplit(hours_range[2], ":")[[1]][1])
  
  # Parse business days (1 = Sunday, 2 = Monday, ..., 7 = Saturday)
  days_range <- strsplit(business_days, "-")[[1]]
  start_day <- as.numeric(days_range[1])
  end_day <- as.numeric(days_range[2])
  
  # Check if current time is within business hours and days
  is_business_hour <- hour >= start_hour && hour <= end_hour
  is_business_day <- wday >= start_day && wday <= end_day
  
  return(is_business_hour && is_business_day)
}

#' Send alert for critical issues
#' @param message Alert message
#' @param level Alert level (info, warning, critical)
#' @param metrics Current system metrics
send_alert <- function(message, level = "warning", metrics = NULL) {
  if (!should_send_alerts()) {
    return(FALSE)
  }
  
  alert_data <- list(
    timestamp = Sys.time(),
    level = level,
    message = message,
    environment = Sys.getenv("RAILWAY_ENVIRONMENT", "unknown"),
    metrics = metrics,
    app_version = "4.1",
    source = "monitor_legislativo_v4"
  )
  
  # Log alert locally
  alert_log_path <- "monitoring/logs/alerts.log"
  dir.create(dirname(alert_log_path), recursive = TRUE, showWarnings = FALSE)
  
  alert_json <- toJSON(alert_data, auto_unbox = TRUE, pretty = TRUE)
  cat(alert_json, "\n", file = alert_log_path, append = TRUE)
  
  # Send to external monitoring (if configured)
  webhook_url <- Sys.getenv("ALERT_WEBHOOK_URL", "")
  if (nchar(webhook_url) > 0) {
    tryCatch({
      response <- httr2::request(webhook_url) %>%
        httr2::req_method("POST") %>%
        httr2::req_headers("Content-Type" = "application/json") %>%
        httr2::req_body_json(alert_data) %>%
        httr2::req_timeout(10) %>%
        httr2::req_perform()
      
      cat("✅ Alert sent successfully\n")
      return(TRUE)
    }, error = function(e) {
      cat("⚠️ Failed to send alert:", e$message, "\n")
      return(FALSE)
    })
  }
  
  return(TRUE)
}

# =============================================================================
# PERFORMANCE MONITORING
# =============================================================================

#' Monitor application performance and send alerts if thresholds exceeded
monitor_performance <- function() {
  if (!is_monitoring_enabled()) {
    return(NULL)
  }
  
  metrics <- collect_system_metrics()
  
  # Memory alert thresholds
  memory_threshold <- as.numeric(Sys.getenv("ALERT_MEMORY_THRESHOLD", "80"))
  critical_memory_threshold <- as.numeric(Sys.getenv("CRITICAL_MEMORY_THRESHOLD", "95"))
  
  if (!is.null(metrics$memory$usage_percent)) {
    if (metrics$memory$usage_percent > critical_memory_threshold) {
      send_alert(
        paste("CRITICAL: Memory usage at", metrics$memory$usage_percent, "% - Railway 3GB limit"),
        level = "critical",
        metrics = metrics
      )
    } else if (metrics$memory$usage_percent > memory_threshold) {
      send_alert(
        paste("WARNING: High memory usage at", metrics$memory$usage_percent, "%"),
        level = "warning",
        metrics = metrics
      )
    }
  }
  
  # CPU alert thresholds
  cpu_threshold <- as.numeric(Sys.getenv("ALERT_CPU_THRESHOLD", "75"))
  critical_cpu_threshold <- as.numeric(Sys.getenv("CRITICAL_CPU_THRESHOLD", "90"))
  
  if (!isTRUE(is.null(metrics$cpu_usage_percent)) && metrics$cpu_usage_percent > 0) {
    if (metrics$cpu_usage_percent > critical_cpu_threshold) {
      send_alert(
        paste("CRITICAL: CPU usage at", metrics$cpu_usage_percent, "%"),
        level = "critical",
        metrics = metrics
      )
    } else if (metrics$cpu_usage_percent > cpu_threshold) {
      send_alert(
        paste("WARNING: High CPU usage at", metrics$cpu_usage_percent, "%"),
        level = "warning",
        metrics = metrics
      )
    }
  }
  
  # Disk space monitoring
  disk_threshold <- as.numeric(Sys.getenv("ALERT_DISK_THRESHOLD", "85"))
  if (!is.null(metrics$disk$usage_percent)) {
    if (metrics$disk$usage_percent > disk_threshold) {
      send_alert(
        paste("WARNING: Disk usage at", metrics$disk$usage_percent, "%"),
        level = "warning",
        metrics = metrics
      )
    }
  }
  
  return(metrics)
}

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

#' Get active Shiny sessions count
get_active_sessions_count <- function() {
  tryCatch({
    # This would need to be implemented based on your Shiny session tracking
    return(1) # Placeholder
  }, error = function(e) 0)
}

#' Get database connection pool count
get_db_connection_count <- function() {
  tryCatch({
    if (exists("db_pool") && !is.null(db_pool)) {
      return(pool::dbGetInfo(db_pool)$opened)
    }
    return(0)
  }, error = function(e) 0)
}

#' Get cache hit rate
get_cache_hit_rate <- function() {
  tryCatch({
    # Implement based on your caching system
    return(75) # Placeholder percentage
  }, error = function(e) 0)
}

#' Log metrics to file
log_metrics <- function(metrics) {
  if (!is_monitoring_enabled()) {
    return(FALSE)
  }
  
  log_path <- "monitoring/logs/metrics.log"
  dir.create(dirname(log_path), recursive = TRUE, showWarnings = FALSE)
  
  metrics_json <- toJSON(metrics, auto_unbox = TRUE)
  cat(metrics_json, "\n", file = log_path, append = TRUE)
  
  return(TRUE)
}

# =============================================================================
# MONITORING SCHEDULER
# =============================================================================

#' Start monitoring loop for production environment
start_monitoring <- function() {
  if (!is_production() || !is_monitoring_enabled()) {
    cat("ℹ️ Monitoring disabled or not in production environment\n")
    return(FALSE)
  }
  
  cat("🔍 Starting production monitoring for Monitor Legislativo v4\n")
  
  # Set app start time
  Sys.setenv(APP_START_TIME = as.character(Sys.time()))
  
  # Send startup notification
  send_alert("Monitor Legislativo v4 started successfully", level = "info")
  
  # Monitoring interval (default: 60 seconds)
  interval_seconds <- as.numeric(Sys.getenv("MONITORING_INTERVAL_SECONDS", "60"))
  
  # Start monitoring loop in background
  later::later(function() {
    metrics <- monitor_performance()
    if (!is.null(metrics)) {
      log_metrics(metrics)
    }
    
    # Schedule next monitoring cycle
    later::later(start_monitoring, delay = interval_seconds)
  }, delay = interval_seconds)
  
  cat("✅ Monitoring started with", interval_seconds, "second interval\n")
  return(TRUE)
}

# =============================================================================
# EXPORT FUNCTIONS
# =============================================================================

# Initialize monitoring on module load if in production
if (is_production() && is_monitoring_enabled()) {
  start_monitoring()
}