# =============================================================================
# PRODUCTION MONITORING SYSTEM - Monitor Legislativo v4
# Comprehensive monitoring, alerting, and health check system for Railway
# =============================================================================

library(jsonlite)
library(httr)

# Global monitoring configuration
MONITORING_CONFIG <- list(
  enabled = as.logical(Sys.getenv("MONITORING_ENABLED", "true")),
  interval_seconds = as.numeric(Sys.getenv("MONITORING_INTERVAL_SECONDS", "60")),
  alert_threshold_error_rate = as.numeric(Sys.getenv("ALERT_ERROR_RATE_THRESHOLD", "5")),
  alert_threshold_response_time = as.numeric(Sys.getenv("ALERT_RESPONSE_TIME_THRESHOLD", "5000")),
  alert_threshold_memory = as.numeric(Sys.getenv("ALERT_MEMORY_THRESHOLD", "85")),
  alert_threshold_cpu = as.numeric(Sys.getenv("ALERT_CPU_THRESHOLD", "80")),
  uptime_target = as.numeric(Sys.getenv("UPTIME_TARGET_PERCENT", "99.9")),
  enable_alerts = as.logical(Sys.getenv("PERFORMANCE_ALERTS", "true")),
  slack_webhook = Sys.getenv("SLACK_WEBHOOK_URL", ""),
  email_alerts = as.logical(Sys.getenv("EMAIL_ALERTS_ENABLED", "false"))
)

# Monitoring state storage
MONITORING_STATE <- list(
  start_time = Sys.time(),
  last_check = NULL,
  error_count = 0,
  warning_count = 0,
  total_requests = 0,
  successful_requests = 0,
  failed_requests = 0,
  response_times = numeric(0),
  memory_usage_history = numeric(0),
  cpu_usage_history = numeric(0),
  alerts_sent = list(),
  health_status = "unknown",
  last_error = NULL,
  uptime_percentage = 100
)

# Initialize monitoring system
init_monitoring <- function() {
  cat("=== Production Monitoring System Initialization ===\n")
  
  if (!MONITORING_CONFIG$enabled) {
    cat("Monitoring disabled by configuration\n")
    return(FALSE)
  }
  
  MONITORING_STATE$start_time <<- Sys.time()
  MONITORING_STATE$last_check <<- Sys.time()
  
  cat("Monitoring system initialized successfully\n")
  cat(sprintf("Monitoring interval: %d seconds\n", MONITORING_CONFIG$interval_seconds))
  cat(sprintf("Alert thresholds: Error rate: %g%%, Response time: %gms, Memory: %g%%, CPU: %g%%\n",
              MONITORING_CONFIG$alert_threshold_error_rate,
              MONITORING_CONFIG$alert_threshold_response_time,
              MONITORING_CONFIG$alert_threshold_memory,
              MONITORING_CONFIG$alert_threshold_cpu))
  
  return(TRUE)
}

# System metrics collection
collect_system_metrics <- function() {
  metrics <- list(
    timestamp = Sys.time(),
    memory = list(),
    performance = list(),
    database = list(),
    application = list()
  )
  
  # Memory metrics
  tryCatch({
    gc_info <- gc()
    memory_used <- sum(gc_info[, 2])  # Used memory in MB
    memory_limit <- as.numeric(Sys.getenv("MEMORY_LIMIT", "2048"))
    
    metrics$memory <- list(
      used_mb = memory_used,
      limit_mb = memory_limit,
      usage_percent = round((memory_used / memory_limit) * 100, 2),
      gc_collections = list(
        node_count = gc_info[1, 1],
        vector_count = gc_info[2, 1]
      )
    )
    
    # Store for trend analysis
    MONITORING_STATE$memory_usage_history <<- c(
      tail(MONITORING_STATE$memory_usage_history, 99),  # Keep last 100 readings
      metrics$memory$usage_percent
    )
    
  }, error = function(e) {
    metrics$memory$error <- e$message
  })
  
  # Application performance metrics
  tryCatch({
    uptime_seconds <- as.numeric(difftime(Sys.time(), MONITORING_STATE$start_time, units = "secs"))
    
    # Calculate error rate
    total_requests <- MONITORING_STATE$total_requests
    error_rate <- if (total_requests > 0) {
      (MONITORING_STATE$failed_requests / total_requests) * 100
    } else {
      0
    }
    
    # Calculate average response time
    avg_response_time <- if (length(MONITORING_STATE$response_times) > 0) {
      mean(tail(MONITORING_STATE$response_times, 100))  # Last 100 requests
    } else {
      0
    }
    
    metrics$performance <- list(
      uptime_seconds = uptime_seconds,
      total_requests = total_requests,
      successful_requests = MONITORING_STATE$successful_requests,
      failed_requests = MONITORING_STATE$failed_requests,
      error_rate_percent = round(error_rate, 2),
      avg_response_time_ms = round(avg_response_time, 2),
      uptime_percentage = MONITORING_STATE$uptime_percentage
    )
    
  }, error = function(e) {
    metrics$performance$error <- e$message
  })
  
  # Database connectivity check
  tryCatch({
    if (exists("dbPool") && !is.null(get("dbPool"))) {
      # Test database connection
      start_time <- Sys.time()
      db_test <- DBI::dbGetQuery(get("dbPool"), "SELECT 1 as test")
      db_response_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs")) * 1000
      
      metrics$database <- list(
        connected = !isTRUE(is.null(db_test)) && nrow(db_test) > 0,
        response_time_ms = round(db_response_time, 2),
        pool_info = if (exists("dbPool")) {
          list(
            valid = pool::dbPool_valid(get("dbPool")),
            size = "unknown"  # Pool size not easily accessible
          )
        } else {
          NULL
        }
      )
    } else {
      metrics$database <- list(
        connected = FALSE,
        error = "Database pool not available"
      )
    }
  }, error = function(e) {
    metrics$database <- list(
      connected = FALSE,
      error = e$message
    )
  })
  
  # Application-specific metrics
  tryCatch({
    # Cache performance if available
    cache_metrics <- list()
    if (exists("CACHE_STATS")) {
      cache_stats <- get("CACHE_STATS")
      cache_metrics <- list(
        hit_rate = cache_stats$hit_rate,
        total_requests = cache_stats$total_requests,
        cache_size_mb = cache_stats$size_mb
      )
    }
    
    metrics$application <- list(
      cache = cache_metrics,
      active_sessions = if (exists("SESSION_COUNT")) get("SESSION_COUNT") else 0,
      last_error = MONITORING_STATE$last_error
    )
    
  }, error = function(e) {
    metrics$application$error <- e$message
  })
  
  return(metrics)
}

# Alert system
send_alert <- function(type, message, severity = "warning", metrics = NULL) {
  if (!MONITORING_CONFIG$enable_alerts) {
    return(FALSE)
  }
  
  alert_key <- paste0(type, "_", format(Sys.time(), "%Y%m%d_%H"))
  
  # Prevent duplicate alerts within the same hour
  if (alert_key %in% names(MONITORING_STATE$alerts_sent)) {
    last_sent <- MONITORING_STATE$alerts_sent[[alert_key]]
    if (difftime(Sys.time(), last_sent, units = "hours") < 1) {
      return(FALSE)  # Don't send duplicate alert
    }
  }
  
  alert_data <- list(
    timestamp = format(Sys.time(), "%Y-%m-%d %H:%M:%S UTC"),
    service = "Monitor Legislativo v4",
    type = type,
    severity = severity,
    message = message,
    environment = "production",
    metrics = metrics
  )
  
  # Log alert
  cat(sprintf("[ALERT] %s: %s\n", toupper(severity), message))
  
  # Send to Slack if configured
  if (nchar(MONITORING_CONFIG$slack_webhook) > 0) {
    send_slack_alert(alert_data)
  }
  
  # Send email if configured (placeholder)
  if (MONITORING_CONFIG$email_alerts) {
    # send_email_alert(alert_data)  # Implement based on your email service
  }
  
  # Record alert sent
  MONITORING_STATE$alerts_sent[[alert_key]] <<- Sys.time()
  
  return(TRUE)
}

# Slack notification
send_slack_alert <- function(alert_data) {
  tryCatch({
    color <- switch(alert_data$severity,
                   "critical" = "danger",
                   "warning" = "warning", 
                   "info" = "good",
                   "#808080")
    
    payload <- list(
      text = sprintf("🚨 %s Alert: %s", alert_data$service, alert_data$message),
      attachments = list(
        list(
          color = color,
          fields = list(
            list(title = "Service", value = alert_data$service, short = TRUE),
            list(title = "Environment", value = alert_data$environment, short = TRUE),
            list(title = "Type", value = alert_data$type, short = TRUE),
            list(title = "Severity", value = alert_data$severity, short = TRUE),
            list(title = "Timestamp", value = alert_data$timestamp, short = FALSE)
          )
        )
      )
    )
    
    if (!is.null(alert_data$metrics)) {
      metrics_text <- paste0("Memory: ", alert_data$metrics$memory$usage_percent, "% | ",
                            "Uptime: ", round(alert_data$metrics$performance$uptime_seconds/3600, 1), "h | ",
                            "Error Rate: ", alert_data$metrics$performance$error_rate_percent, "%")
      payload$attachments[[1]]$fields <- c(payload$attachments[[1]]$fields,
                                           list(list(title = "Current Metrics", value = metrics_text, short = FALSE)))
    }
    
    response <- httr::POST(
      MONITORING_CONFIG$slack_webhook,
      body = jsonlite::toJSON(payload, auto_unbox = TRUE),
      httr::content_type("application/json")
    )
    
    if (httr::status_code(response) != 200) {
      cat("Failed to send Slack alert:", httr::content(response, "text"), "\n")
    }
    
  }, error = function(e) {
    cat("Error sending Slack alert:", e$message, "\n")
  })
}

# Check system health and trigger alerts
check_health_and_alert <- function() {
  metrics <- collect_system_metrics()
  alerts_triggered <- 0
  
  # Memory usage alert
  if (!isTRUE(is.null(metrics$memory$usage_percent)) && 
      metrics$memory$usage_percent > MONITORING_CONFIG$alert_threshold_memory) {
    send_alert(
      "high_memory_usage",
      sprintf("High memory usage: %g%% (threshold: %g%%)", 
              metrics$memory$usage_percent, 
              MONITORING_CONFIG$alert_threshold_memory),
      "warning",
      metrics
    )
    alerts_triggered <- alerts_triggered + 1
  }
  
  # Error rate alert
  if (!isTRUE(is.null(metrics$performance$error_rate_percent)) &&
      metrics$performance$error_rate_percent > MONITORING_CONFIG$alert_threshold_error_rate) {
    send_alert(
      "high_error_rate",
      sprintf("High error rate: %g%% (threshold: %g%%)",
              metrics$performance$error_rate_percent,
              MONITORING_CONFIG$alert_threshold_error_rate),
      "critical",
      metrics
    )
    alerts_triggered <- alerts_triggered + 1
  }
  
  # Response time alert
  if (!isTRUE(is.null(metrics$performance$avg_response_time_ms)) &&
      metrics$performance$avg_response_time_ms > MONITORING_CONFIG$alert_threshold_response_time) {
    send_alert(
      "slow_response_time",
      sprintf("Slow response time: %gms (threshold: %gms)",
              metrics$performance$avg_response_time_ms,
              MONITORING_CONFIG$alert_threshold_response_time),
      "warning",
      metrics
    )
    alerts_triggered <- alerts_triggered + 1
  }
  
  # Database connectivity alert
  if (!isTRUE(is.null(metrics$database$connected)) && !metrics$database$connected) {
    send_alert(
      "database_connectivity",
      "Database connection failed",
      "critical",
      metrics
    )
    alerts_triggered <- alerts_triggered + 1
  }
  
  # Uptime alert
  uptime_percentage <- metrics$performance$uptime_percentage
  if (!isTRUE(is.null(uptime_percentage)) && uptime_percentage < MONITORING_CONFIG$uptime_target) {
    send_alert(
      "low_uptime",
      sprintf("Uptime below target: %g%% (target: %g%%)",
              uptime_percentage,
              MONITORING_CONFIG$uptime_target),
      "warning",
      metrics
    )
    alerts_triggered <- alerts_triggered + 1
  }
  
  return(list(
    metrics = metrics,
    alerts_triggered = alerts_triggered,
    status = if (alerts_triggered == 0) "healthy" else "degraded"
  ))
}

# Comprehensive health check for Railway
perform_health_check <- function() {
  health_result <- check_health_and_alert()
  
  MONITORING_STATE$last_check <<- Sys.time()
  MONITORING_STATE$health_status <<- health_result$status
  
  # Basic health response
  health_response <- list(
    status = if (health_result$alerts_triggered == 0) "healthy" else "degraded",
    timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC"),
    service = "monitor-legislativo-v4",
    version = "1.0.0",
    uptime_seconds = as.numeric(difftime(Sys.time(), MONITORING_STATE$start_time, units = "secs")),
    checks = list(
      database = if (!is.null(health_result$metrics$database$connected)) {
        health_result$metrics$database$connected
      } else { FALSE },
      memory = if (!is.null(health_result$metrics$memory$usage_percent)) {
        health_result$metrics$memory$usage_percent < MONITORING_CONFIG$alert_threshold_memory
      } else { TRUE },
      application = TRUE  # If we got this far, application is running
    )
  )
  
  # Add detailed metrics if requested
  if (Sys.getenv("HEALTH_CHECK_DETAILED", "true") == "true") {
    health_response$metrics <- health_result$metrics
    health_response$alerts_triggered <- health_result$alerts_triggered
  }
  
  return(health_response)
}

# Record request metrics (to be called by application)
record_request <- function(success = TRUE, response_time_ms = NULL, error = NULL) {
  MONITORING_STATE$total_requests <<- MONITORING_STATE$total_requests + 1
  
  if (success) {
    MONITORING_STATE$successful_requests <<- MONITORING_STATE$successful_requests + 1
  } else {
    MONITORING_STATE$failed_requests <<- MONITORING_STATE$failed_requests + 1
    if (!is.null(error)) {
      MONITORING_STATE$last_error <<- list(
        timestamp = Sys.time(),
        message = error
      )
    }
  }
  
  if (!is.null(response_time_ms)) {
    MONITORING_STATE$response_times <<- c(
      tail(MONITORING_STATE$response_times, 999),  # Keep last 1000 response times
      response_time_ms
    )
  }
  
  # Update uptime percentage
  total <- MONITORING_STATE$total_requests
  if (total > 0) {
    MONITORING_STATE$uptime_percentage <<- (MONITORING_STATE$successful_requests / total) * 100
  }
}

# Start monitoring background process (for production)
start_monitoring_loop <- function() {
  if (!MONITORING_CONFIG$enabled) {
    return(FALSE)
  }
  
  cat("Starting monitoring loop...\n")
  
  # This would typically run in a separate process or thread
  # For R/Shiny, we'll integrate it into the server logic
  
  return(TRUE)
}

# Export monitoring functions for use in main application
list(
  init = init_monitoring,
  health_check = perform_health_check,
  record_request = record_request,
  collect_metrics = collect_system_metrics,
  get_state = function() MONITORING_STATE,
  get_config = function() MONITORING_CONFIG
)