# APPLICATION MONITORING SYSTEM FOR R SHINY RAILWAY DEPLOYMENT
# =============================================================
# Production-ready application performance monitoring
# Memory, sessions, database, and health metrics tracking

library(shiny)

# Source logger
source("monitoring/logger.R")

# Monitoring Configuration
MONITOR_CONFIG <- list(
  enabled = TRUE,
  collection_interval = as.numeric(Sys.getenv("MONITOR_INTERVAL", "30")), # seconds
  memory_threshold_mb = as.numeric(Sys.getenv("MEMORY_THRESHOLD_MB", "512")),
  cpu_threshold_percent = as.numeric(Sys.getenv("CPU_THRESHOLD_PERCENT", "80")),
  session_timeout_minutes = as.numeric(Sys.getenv("SESSION_TIMEOUT_MIN", "30")),
  max_concurrent_sessions = as.numeric(Sys.getenv("MAX_SESSIONS", "100")),
  db_connection_timeout = as.numeric(Sys.getenv("DB_TIMEOUT_SEC", "10")),
  alert_thresholds = list(
    high_memory = 0.8,      # 80% of threshold
    high_cpu = 0.75,        # 75% of threshold  
    low_disk = 0.9,         # 90% disk usage
    high_response_time = 5  # 5 seconds
  )
)

# Global monitoring state (non-reactive for stability)
MONITOR_STATE <- list(
  active_sessions = 0,
  peak_sessions = 0,
  total_requests = 0,
  error_count = 0,
  last_health_check = NULL,
  memory_usage_mb = 0,
  cpu_usage_percent = 0,
  disk_usage_percent = 0,
  db_connections = 0,
  response_times = numeric(0),
  uptime_start = Sys.time(),
  alerts = list(),
  performance_metrics = data.frame(
    timestamp = character(0),
    memory_mb = numeric(0),
    cpu_percent = numeric(0),
    active_sessions = numeric(0),
    response_time_ms = numeric(0),
    stringsAsFactors = FALSE
  )
)

# System metrics collection functions
get_memory_usage <- function() {
  tryCatch({
    # Get R process memory usage
    if (exists("memory.size", mode = "function")) {
      # Windows
      return(memory.size())
    } else {
      # Unix-like systems
      gc_info <- gc()
      used_mb <- sum(gc_info[, 2]) * 8 / 1024 / 1024  # Convert to MB
      return(used_mb)
    }
  }, error = function(e) {
    log_warn("Failed to get memory usage", list(error = as.character(e)))
    return(0)
  })
}

get_cpu_usage <- function() {
  tryCatch({
    # Simple CPU usage estimation based on R process
    # This is approximate since R doesn't have built-in CPU monitoring
    proc_time <- proc.time()
    if (exists(".last_proc_time", envir = .GlobalEnv)) {
      last_time <- get(".last_proc_time", envir = .GlobalEnv)
      elapsed <- proc_time[3] - last_time[3]
      cpu_time <- (proc_time[1] + proc_time[2]) - (last_time[1] + last_time[2])
      cpu_percent <- if (elapsed > 0) min(100, (cpu_time / elapsed) * 100) else 0
    } else {
      cpu_percent <- 0
    }
    assign(".last_proc_time", proc_time, envir = .GlobalEnv)
    return(cpu_percent)
  }, error = function(e) {
    log_warn("Failed to get CPU usage", list(error = as.character(e)))
    return(0)
  })
}

get_disk_usage <- function() {
  tryCatch({
    # Check available disk space
    if (.Platform$OS.type == "windows") {
      # Windows - use system command
      result <- system("dir", intern = TRUE, ignore.stderr = TRUE)
      return(0) # Simplified for Windows
    } else {
      # Unix-like - use df command
      result <- system("df -h .", intern = TRUE, ignore.stderr = TRUE)
      if (length(result) > 1) {
        # Parse df output
        line <- result[2]
        parts <- strsplit(trimws(line), "\\s+")[[1]]
        if (length(parts) >= 5) {
          usage_str <- parts[5]
          usage_percent <- as.numeric(gsub("%", "", usage_str))
          return(usage_percent)
        }
      }
    }
    return(0)
  }, error = function(e) {
    log_warn("Failed to get disk usage", list(error = as.character(e)))
    return(0)
  })
}

# Database connection monitoring
monitor_database_connections <- function() {
  tryCatch({
    if (exists("get_connection_status") && is.function(get_connection_status)) {
      status <- get_connection_status()
      
      context <- list(
        db_status = status$status,
        connection_method = status$connection_method,
        document_count = status$document_count,
        ssl_enabled = status$ssl_enabled
      )
      
      if (status$status == "connected") {
        log_debug("Database connection healthy", context)
        return(1)
      } else {
        log_warn("Database connection issue", c(context, list(error = status$error)))
        return(0)
      }
    } else {
      log_warn("Database connection functions not available")
      return(0)
    }
  }, error = function(e) {
    log_error("Database monitoring failed", list(error = as.character(e)))
    return(0)
  })
}

# Session monitoring functions
increment_session_count <- function() {
  MONITOR_STATE$active_sessions <- MONITOR_STATE$active_sessions + 1
  MONITOR_STATE$peak_sessions <- max(MONITOR_STATE$peak_sessions, MONITOR_STATE$active_sessions)
  
  log_info("New session started", list(
    active_sessions = MONITOR_STATE$active_sessions,
    peak_sessions = MONITOR_STATE$peak_sessions
  ))
  
  check_session_limits()
}

decrement_session_count <- function() {
  MONITOR_STATE$active_sessions <- max(0, MONITOR_STATE$active_sessions - 1)
  
  log_info("Session ended", list(
    active_sessions = MONITOR_STATE$active_sessions
  ))
}

check_session_limits <- function() {
  if (MONITOR_STATE$active_sessions > MONITOR_CONFIG$max_concurrent_sessions) {
    alert <- list(
      type = "session_limit_exceeded",
      severity = "ERROR",
      message = paste("Session limit exceeded:", MONITOR_STATE$active_sessions, ">", MONITOR_CONFIG$max_concurrent_sessions),
      timestamp = Sys.time()
    )
    
    MONITOR_STATE$alerts <- append(MONITOR_STATE$alerts, list(alert))
    log_error(alert$message, list(current_sessions = MONITOR_STATE$active_sessions))
  }
}

# Request monitoring
track_request <- function(session = NULL, route = NULL, method = "GET") {
  MONITOR_STATE$total_requests <- MONITOR_STATE$total_requests + 1
  
  context <- list(
    total_requests = MONITOR_STATE$total_requests,
    route = route,
    method = method
  )
  
  log_debug("Request tracked", context, session)
}

track_error <- function(error_message, session = NULL, context = list()) {
  MONITOR_STATE$error_count <- MONITOR_STATE$error_count + 1
  
  error_context <- c(list(
    total_errors = MONITOR_STATE$error_count,
    error_rate = MONITOR_STATE$error_count / max(1, MONITOR_STATE$total_requests)
  ), context)
  
  log_error(paste("Application error:", error_message), error_context, session)
}

# Performance tracking
track_response_time <- function(duration_ms, operation = "unknown") {
  MONITOR_STATE$response_times <- c(MONITOR_STATE$response_times, duration_ms)
  
  # Keep only last 1000 response times
  if (length(MONITOR_STATE$response_times) > 1000) {
    MONITOR_STATE$response_times <- tail(MONITOR_STATE$response_times, 1000)
  }
  
  # Check if response time exceeds threshold
  if (duration_ms > MONITOR_CONFIG$alert_thresholds$high_response_time * 1000) {
    alert <- list(
      type = "slow_response",
      severity = "WARN",
      message = paste("Slow response time:", round(duration_ms, 2), "ms for", operation),
      timestamp = Sys.time()
    )
    
    MONITOR_STATE$alerts <- append(MONITOR_STATE$alerts, list(alert))
    log_warn(alert$message, list(duration_ms = duration_ms, operation = operation))
  }
}

# Health check function
perform_health_check <- function() {
  start_time <- Sys.time()
  
  tryCatch({
    health_status <- list(
      timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC"),
      status = "healthy",
      checks = list(),
      metrics = list()
    )
    
    # Memory check
    memory_mb <- get_memory_usage()
    MONITOR_STATE$memory_usage_mb <- memory_mb
    memory_status <- "ok"
    
    if (memory_mb > MONITOR_CONFIG$memory_threshold_mb * MONITOR_CONFIG$alert_thresholds$high_memory) {
      memory_status <- "warning"
      health_status$status <- "degraded"
    }
    
    health_status$checks$memory <- list(
      status = memory_status,
      value = memory_mb,
      threshold = MONITOR_CONFIG$memory_threshold_mb,
      unit = "MB"
    )
    
    # CPU check
    cpu_percent <- get_cpu_usage()
    MONITOR_STATE$cpu_usage_percent <- cpu_percent
    cpu_status <- "ok"
    
    if (cpu_percent > MONITOR_CONFIG$cpu_threshold_percent * MONITOR_CONFIG$alert_thresholds$high_cpu) {
      cpu_status <- "warning"
      health_status$status <- "degraded"
    }
    
    health_status$checks$cpu <- list(
      status = cpu_status,
      value = cpu_percent,
      threshold = MONITOR_CONFIG$cpu_threshold_percent,
      unit = "percent"
    )
    
    # Disk check
    disk_percent <- get_disk_usage()
    MONITOR_STATE$disk_usage_percent <- disk_percent
    disk_status <- "ok"
    
    if (disk_percent > MONITOR_CONFIG$alert_thresholds$low_disk * 100) {
      disk_status <- "warning"
      health_status$status <- "degraded"
    }
    
    health_status$checks$disk <- list(
      status = disk_status,
      value = disk_percent,
      unit = "percent"
    )
    
    # Database check
    db_connections <- monitor_database_connections()
    MONITOR_STATE$db_connections <- db_connections
    
    health_status$checks$database <- list(
      status = if (db_connections > 0) "ok" else "error",
      connections = db_connections
    )
    
    if (db_connections == 0) {
      health_status$status <- "unhealthy"
    }
    
    # Response time metrics
    if (length(MONITOR_STATE$response_times) > 0) {
      health_status$metrics$response_time <- list(
        avg_ms = mean(MONITOR_STATE$response_times),
        p95_ms = quantile(MONITOR_STATE$response_times, 0.95),
        p99_ms = quantile(MONITOR_STATE$response_times, 0.99)
      )
    }
    
    # Session metrics
    health_status$metrics$sessions <- list(
      active = MONITOR_STATE$active_sessions,
      peak = MONITOR_STATE$peak_sessions,
      total_requests = MONITOR_STATE$total_requests,
      error_count = MONITOR_STATE$error_count,
      error_rate = MONITOR_STATE$error_count / max(1, MONITOR_STATE$total_requests)
    )
    
    # Uptime
    uptime_seconds <- as.numeric(difftime(Sys.time(), MONITOR_STATE$uptime_start, units = "secs"))
    health_status$metrics$uptime <- list(
      seconds = uptime_seconds,
      human = format_duration(uptime_seconds)
    )
    
    MONITOR_STATE$last_health_check <- health_status
    
    # Store performance metrics
    new_metric <- data.frame(
      timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC"),
      memory_mb = memory_mb,
      cpu_percent = cpu_percent,
      active_sessions = MONITOR_STATE$active_sessions,
      response_time_ms = if (length(MONITOR_STATE$response_times) > 0) mean(tail(MONITOR_STATE$response_times, 10)) else 0,
      stringsAsFactors = FALSE
    )
    
    MONITOR_STATE$performance_metrics <- rbind(MONITOR_STATE$performance_metrics, new_metric)
    
    # Keep only last 1440 records (24 hours at 1-minute intervals)
    if (!is.null(MONITOR_STATE$performance_metrics) && is.data.frame(MONITOR_STATE$performance_metrics) && nrow(MONITOR_STATE$performance_metrics) > 1440) {
      MONITOR_STATE$performance_metrics <- tail(MONITOR_STATE$performance_metrics, 1440)
    }
    
    duration_ms <- as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000
    
    log_info("Health check completed", list(
      status = health_status$status,
      duration_ms = round(duration_ms, 2),
      memory_mb = memory_mb,
      cpu_percent = cpu_percent,
      active_sessions = MONITOR_STATE$active_sessions
    ))
    
    return(health_status)
    
  }, error = function(e) {
    log_error("Health check failed", list(error = as.character(e)))
    return(list(
      timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC"),
      status = "error",
      error = as.character(e)
    ))
  })
}

# Utility functions
format_duration <- function(seconds) {
  if (seconds < 60) {
    return(paste(round(seconds, 1), "seconds"))
  } else if (seconds < 3600) {
    return(paste(round(seconds / 60, 1), "minutes"))
  } else if (seconds < 86400) {
    return(paste(round(seconds / 3600, 1), "hours"))
  } else {
    return(paste(round(seconds / 86400, 1), "days"))
  }
}

# Alert management
get_active_alerts <- function() {
  # Remove old alerts (older than 1 hour)
  current_time <- Sys.time()
  MONITOR_STATE$alerts <- Filter(function(alert) {
    difftime(current_time, alert$timestamp, units = "hours") < 1
  }, MONITOR_STATE$alerts)
  
  return(MONITOR_STATE$alerts)
}

clear_alerts <- function() {
  MONITOR_STATE$alerts <- list()
  log_info("Alerts cleared")
}

# Monitoring timer setup
start_monitoring <- function() {
  if (!MONITOR_CONFIG$enabled) {
    log_info("Monitoring disabled")
    return(invisible(NULL))
  }
  
  log_info("Starting application monitoring", list(
    interval_seconds = MONITOR_CONFIG$collection_interval,
    thresholds = MONITOR_CONFIG$alert_thresholds
  ))
  
  # Perform initial health check
  perform_health_check()
  
  # Set up recurring health checks
  observe({
    invalidateLater(MONITOR_CONFIG$collection_interval * 1000)
    perform_health_check()
  })
  
  invisible(TRUE)
}

# Get current metrics
get_current_metrics <- function() {
  return(list(
    active_sessions = MONITOR_STATE$active_sessions,
    peak_sessions = MONITOR_STATE$peak_sessions,
    total_requests = MONITOR_STATE$total_requests,
    error_count = MONITOR_STATE$error_count,
    memory_usage_mb = MONITOR_STATE$memory_usage_mb,
    cpu_usage_percent = MONITOR_STATE$cpu_usage_percent,
    disk_usage_percent = MONITOR_STATE$disk_usage_percent,
    db_connections = MONITOR_STATE$db_connections,
    uptime_seconds = as.numeric(difftime(Sys.time(), MONITOR_STATE$uptime_start, units = "secs")),
    last_health_check = MONITOR_STATE$last_health_check,
    performance_history = MONITOR_STATE$performance_metrics
  ))
}

# Export monitoring functions
list(
  # Core monitoring
  start_monitoring = start_monitoring,
  perform_health_check = perform_health_check,
  get_current_metrics = get_current_metrics,
  
  # Session tracking
  increment_session_count = increment_session_count,
  decrement_session_count = decrement_session_count,
  
  # Request/error tracking
  track_request = track_request,
  track_error = track_error,
  track_response_time = track_response_time,
  
  # Alert management
  get_active_alerts = get_active_alerts,
  clear_alerts = clear_alerts,
  
  # State access
  MONITOR_STATE = MONITOR_STATE,
  MONITOR_CONFIG = MONITOR_CONFIG
)