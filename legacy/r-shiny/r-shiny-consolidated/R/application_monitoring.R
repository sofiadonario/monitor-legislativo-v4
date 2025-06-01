# Application Monitoring for Monitor Legislativo v4
# Performance monitoring, health checks, alerting, and automated scaling

library(shiny)
library(jsonlite)
library(lubridate)
library(httr)
library(future)
library(promises)

# Monitoring configuration
MONITORING_CONFIG <- list(
  health_checks = list(
    enabled = TRUE,
    interval_seconds = 30,
    timeout_seconds = 10,
    endpoints = list(
      database = list(enabled = TRUE, critical = TRUE),
      redis = list(enabled = TRUE, critical = FALSE),
      lexml_api = list(enabled = TRUE, critical = FALSE),
      external_apis = list(enabled = TRUE, critical = FALSE)
    ),
    failure_threshold = 3,
    recovery_threshold = 2
  ),
  
  performance_monitoring = list(
    enabled = TRUE,
    track_response_times = TRUE,
    track_memory_usage = TRUE,
    track_error_rates = TRUE,
    track_user_sessions = TRUE,
    collection_interval_seconds = 60,
    retention_hours = 168  # 7 days
  ),
  
  alerting = list(
    enabled = TRUE,
    channels = list(
      log = list(enabled = TRUE, level = "WARN"),
      email = list(enabled = FALSE, recipients = c()),
      webhook = list(enabled = FALSE, url = "")
    ),
    thresholds = list(
      response_time_ms = 5000,
      error_rate_percent = 5,
      memory_usage_mb = 1500,
      disk_usage_percent = 85,
      concurrent_users = 150
    ),
    cooldown_minutes = 15
  ),
  
  scaling = list(
    enabled = FALSE,  # Manual scaling by default
    auto_scale_triggers = list(
      cpu_percent = 80,
      memory_percent = 85,
      response_time_ms = 3000,
      concurrent_users = 100
    ),
    scale_up_actions = list(
      increase_workers = TRUE,
      optimize_queries = TRUE,
      clear_cache = TRUE
    )
  ),
  
  metrics_collection = list(
    business_metrics = TRUE,
    system_metrics = TRUE,
    custom_metrics = TRUE,
    export_format = "json",
    aggregation_window_minutes = 5
  )
)

# Global monitoring state
monitoring_state <- list(
  health_status = list(),
  performance_metrics = list(),
  alerts = list(),
  last_health_check = NULL,
  uptime_start = Sys.time(),
  alert_cooldowns = list()
)

#' Initialize application monitoring system
#' @param config Optional configuration override
#' @return Initialization status
initialize_monitoring <- function(config = NULL) {
  if (!is.null(config)) {
    MONITORING_CONFIG <<- modifyList(MONITORING_CONFIG, config)
  }
  
  log_event("Initializing application monitoring system...", "INFO")
  
  # Initialize monitoring state
  monitoring_state$uptime_start <<- Sys.time()
  monitoring_state$health_status <<- list()
  monitoring_state$performance_metrics <<- list()
  monitoring_state$alerts <<- list()
  monitoring_state$alert_cooldowns <<- list()
  
  # Start health check scheduler if enabled
  if (MONITORING_CONFIG$health_checks$enabled) {
    start_health_check_scheduler()
  }
  
  # Start performance monitoring if enabled
  if (MONITORING_CONFIG$performance_monitoring$enabled) {
    start_performance_monitoring()
  }
  
  log_event("Application monitoring system initialized", "INFO")
  
  return(list(
    status = "success",
    health_checks_enabled = MONITORING_CONFIG$health_checks$enabled,
    performance_monitoring_enabled = MONITORING_CONFIG$performance_monitoring$enabled,
    alerting_enabled = MONITORING_CONFIG$alerting$enabled
  ))
}

#' Start health check scheduler
start_health_check_scheduler <- function() {
  # Schedule periodic health checks
  future({
    while (TRUE) {
      Sys.sleep(MONITORING_CONFIG$health_checks$interval_seconds)
      
      tryCatch({
        perform_health_checks()
      }, error = function(e) {
        log_event(paste("Health check scheduler error:", e$message), "ERROR")
      })
    }
  })
  
  log_event("Health check scheduler started", "INFO")
}

#' Start performance monitoring
start_performance_monitoring <- function() {
  # Schedule periodic performance collection
  future({
    while (TRUE) {
      Sys.sleep(MONITORING_CONFIG$performance_monitoring$collection_interval_seconds)
      
      tryCatch({
        collect_performance_metrics()
      }, error = function(e) {
        log_event(paste("Performance monitoring error:", e$message), "ERROR")
      })
    }
  })
  
  log_event("Performance monitoring started", "INFO")
}

#' Perform comprehensive health checks
#' @return Health check results
perform_health_checks <- function() {
  start_time <- Sys.time()
  results <- list()
  
  # Database health check
  if (MONITORING_CONFIG$health_checks$endpoints$database$enabled) {
    results$database <- check_database_health()
  }
  
  # Redis health check
  if (MONITORING_CONFIG$health_checks$endpoints$redis$enabled) {
    results$redis <- check_redis_health()
  }
  
  # LexML API health check
  if (MONITORING_CONFIG$health_checks$endpoints$lexml_api$enabled) {
    results$lexml_api <- check_lexml_api_health()
  }
  
  # External APIs health check
  if (MONITORING_CONFIG$health_checks$endpoints$external_apis$enabled) {
    results$external_apis <- check_external_apis_health()
  }
  
  # Calculate overall health
  overall_health <- calculate_overall_health(results)
  
  # Update monitoring state
  health_check_result <- list(
    timestamp = start_time,
    duration_ms = as.numeric(Sys.time() - start_time, units = "secs") * 1000,
    overall_status = overall_health$status,
    components = results,
    healthy_components = overall_health$healthy_count,
    total_components = overall_health$total_count
  )
  
  monitoring_state$health_status <<- health_check_result
  monitoring_state$last_health_check <<- Sys.time()
  
  # Check for alerts
  check_health_alerts(health_check_result)
  
  return(health_check_result)
}

#' Check database health
#' @return Database health status
check_database_health <- function() {
  start_time <- Sys.time()
  
  tryCatch({
    # Test database connection
    if (!is.null(perf_state$connection_pool)) {
      test_query <- "SELECT 1 as health_check"
      result <- execute_optimized_query(test_query, use_cache = FALSE)
      
      if (!is.null(result) && nrow(result) == 1) {
        response_time <- as.numeric(Sys.time() - start_time, units = "secs") * 1000
        
        return(list(
          status = "healthy",
          response_time_ms = response_time,
          message = "Database connection successful",
          timestamp = start_time
        ))
      }
    }
    
    return(list(
      status = "unhealthy",
      response_time_ms = as.numeric(Sys.time() - start_time, units = "secs") * 1000,
      message = "Database connection failed",
      timestamp = start_time
    ))
    
  }, error = function(e) {
    return(list(
      status = "unhealthy",
      response_time_ms = as.numeric(Sys.time() - start_time, units = "secs") * 1000,
      message = paste("Database error:", e$message),
      timestamp = start_time
    ))
  })
}

#' Check Redis health
#' @return Redis health status
check_redis_health <- function() {
  start_time <- Sys.time()
  
  tryCatch({
    # Test Redis connection
    if (!is.null(redis_connection)) {
      ping_result <- redis_connection$PING()
      
      if (!is.null(ping_result)) {
        response_time <- as.numeric(Sys.time() - start_time, units = "secs") * 1000
        
        return(list(
          status = "healthy",
          response_time_ms = response_time,
          message = "Redis connection successful",
          timestamp = start_time
        ))
      }
    }
    
    return(list(
      status = "unhealthy",
      response_time_ms = as.numeric(Sys.time() - start_time, units = "secs") * 1000,
      message = "Redis connection failed",
      timestamp = start_time
    ))
    
  }, error = function(e) {
    return(list(
      status = "unhealthy",
      response_time_ms = as.numeric(Sys.time() - start_time, units = "secs") * 1000,
      message = paste("Redis error:", e$message),
      timestamp = start_time
    ))
  })
}

#' Check LexML API health
#' @return LexML API health status
check_lexml_api_health <- function() {
  start_time <- Sys.time()
  
  tryCatch({
    # Test LexML API endpoint
    test_url <- "https://www.lexml.gov.br/urn/urn:lex:br:federal:constituicao:1988-10-05;1988"
    
    response <- httr::GET(
      test_url,
      httr::timeout(MONITORING_CONFIG$health_checks$timeout_seconds)
    )
    
    response_time <- as.numeric(Sys.time() - start_time, units = "secs") * 1000
    
    if (httr::status_code(response) == 200) {
      return(list(
        status = "healthy",
        response_time_ms = response_time,
        message = "LexML API accessible",
        timestamp = start_time
      ))
    } else {
      return(list(
        status = "unhealthy",
        response_time_ms = response_time,
        message = paste("LexML API returned status:", httr::status_code(response)),
        timestamp = start_time
      ))
    }
    
  }, error = function(e) {
    return(list(
      status = "unhealthy",
      response_time_ms = as.numeric(Sys.time() - start_time, units = "secs") * 1000,
      message = paste("LexML API error:", e$message),
      timestamp = start_time
    ))
  })
}

#' Check external APIs health
#' @return External APIs health status
check_external_apis_health <- function() {
  start_time <- Sys.time()
  apis_status <- list()
  
  # Test Câmara dos Deputados API
  apis_status$camara <- tryCatch({
    response <- httr::GET(
      "https://dadosabertos.camara.leg.br/api/v2/proposicoes?ordem=DESC&ordenarPor=id&pagina=1&itens=1",
      httr::timeout(MONITORING_CONFIG$health_checks$timeout_seconds)
    )
    
    if (httr::status_code(response) == 200) {
      list(status = "healthy", message = "Câmara API accessible")
    } else {
      list(status = "unhealthy", message = paste("Câmara API status:", httr::status_code(response)))
    }
  }, error = function(e) {
    list(status = "unhealthy", message = paste("Câmara API error:", e$message))
  })
  
  # Test Senado Federal API
  apis_status$senado <- tryCatch({
    response <- httr::GET(
      "https://legis.senado.leg.br/dadosabertos/materia/pesquisa/lista?v=4",
      httr::timeout(MONITORING_CONFIG$health_checks$timeout_seconds)
    )
    
    if (httr::status_code(response) == 200) {
      list(status = "healthy", message = "Senado API accessible")
    } else {
      list(status = "unhealthy", message = paste("Senado API status:", httr::status_code(response)))
    }
  }, error = function(e) {
    list(status = "unhealthy", message = paste("Senado API error:", e$message))
  })
  
  # Calculate overall external APIs status
  healthy_apis <- sum(sapply(apis_status, function(x) x$status == "healthy"))
  total_apis <- length(apis_status)
  
  overall_status <- if (healthy_apis == total_apis) {
    "healthy"
  } else if (healthy_apis > 0) {
    "degraded"
  } else {
    "unhealthy"
  }
  
  return(list(
    status = overall_status,
    response_time_ms = as.numeric(Sys.time() - start_time, units = "secs") * 1000,
    message = paste(healthy_apis, "of", total_apis, "external APIs healthy"),
    details = apis_status,
    timestamp = start_time
  ))
}

#' Calculate overall health status
#' @param component_results Individual component health results
#' @return Overall health assessment
calculate_overall_health <- function(component_results) {
  if (length(component_results) == 0) {
    return(list(status = "unknown", healthy_count = 0, total_count = 0))
  }
  
  # Count healthy components
  healthy_count <- sum(sapply(component_results, function(x) x$status == "healthy"))
  degraded_count <- sum(sapply(component_results, function(x) x$status == "degraded"))
  total_count <- length(component_results)
  
  # Check for critical component failures
  critical_failures <- 0
  for (component_name in names(component_results)) {
    if (component_results[[component_name]]$status == "unhealthy") {
      endpoint_config <- MONITORING_CONFIG$health_checks$endpoints[[component_name]]
      if (!is.null(endpoint_config) && endpoint_config$critical) {
        critical_failures <- critical_failures + 1
      }
    }
  }
  
  # Determine overall status
  overall_status <- if (critical_failures > 0) {
    "unhealthy"
  } else if (healthy_count == total_count) {
    "healthy"
  } else if (healthy_count + degraded_count == total_count) {
    "degraded"
  } else {
    "unhealthy"
  }
  
  return(list(
    status = overall_status,
    healthy_count = healthy_count,
    degraded_count = degraded_count,
    total_count = total_count,
    critical_failures = critical_failures
  ))
}

#' Collect performance metrics
collect_performance_metrics <- function() {
  timestamp <- Sys.time()
  
  # Collect system metrics
  metrics <- list(
    timestamp = timestamp,
    system = collect_system_metrics(),
    application = collect_application_metrics(),
    business = collect_business_metrics()
  )
  
  # Store metrics
  monitoring_state$performance_metrics <<- append(
    monitoring_state$performance_metrics,
    list(metrics),
    after = 0
  )
  
  # Limit metrics history
  max_metrics <- MONITORING_CONFIG$performance_monitoring$retention_hours * 
                 (3600 / MONITORING_CONFIG$performance_monitoring$collection_interval_seconds)
  
  if (length(monitoring_state$performance_metrics) > max_metrics) {
    monitoring_state$performance_metrics <<- head(monitoring_state$performance_metrics, max_metrics)
  }
  
  # Check for performance alerts
  check_performance_alerts(metrics)
  
  return(metrics)
}

#' Collect system metrics
#' @return System performance metrics
collect_system_metrics <- function() {
  metrics <- list()
  
  # Memory usage
  if (MONITORING_CONFIG$performance_monitoring$track_memory_usage) {
    memory_info <- get_memory_usage()
    metrics$memory_used_mb <- memory_info$used_mb
    metrics$memory_max_mb <- memory_info$max_mb
  }
  
  # Cache statistics
  if (exists("get_cache_statistics")) {
    cache_stats <- get_cache_statistics()
    metrics$cache_hit_rate <- cache_stats$search_results$hit_rate %||% 0
    metrics$redis_memory <- cache_stats$redis_memory_used %||% "unknown"
  }
  
  # Database performance
  if (exists("get_performance_stats")) {
    perf_stats <- get_performance_stats()
    metrics$avg_query_time_ms <- perf_stats$query_performance$avg_time_ms %||% 0
    metrics$query_cache_size <- perf_stats$query_cache$size %||% 0
  }
  
  return(metrics)
}

#' Collect application metrics
#' @return Application performance metrics
collect_application_metrics <- function() {
  metrics <- list()
  
  # Uptime
  uptime_seconds <- as.numeric(Sys.time() - monitoring_state$uptime_start, units = "secs")
  metrics$uptime_hours <- round(uptime_seconds / 3600, 2)
  
  # Error rates (would be tracked by actual error handling)
  metrics$error_rate_percent <- 0  # Placeholder
  
  # Session information (would be tracked by Shiny)
  metrics$active_sessions <- 0  # Placeholder
  
  return(metrics)
}

#' Collect business metrics
#' @return Business performance metrics
collect_business_metrics <- function() {
  if (!MONITORING_CONFIG$metrics_collection$business_metrics) {
    return(list())
  }
  
  metrics <- list()
  
  # Search metrics (would be tracked by search system)
  metrics$total_searches_today <- 0  # Placeholder
  metrics$avg_search_time_ms <- 0    # Placeholder
  
  # Document metrics
  metrics$documents_processed_today <- 0  # Placeholder
  
  # User metrics
  metrics$unique_users_today <- 0  # Placeholder
  
  return(metrics)
}

#' Check for health-based alerts
#' @param health_result Health check result
check_health_alerts <- function(health_result) {
  if (!MONITORING_CONFIG$alerting$enabled) {
    return()
  }
  
  # Check overall health status
  if (health_result$overall_status %in% c("unhealthy", "degraded")) {
    trigger_alert(
      type = "health",
      severity = if (health_result$overall_status == "unhealthy") "critical" else "warning",
      message = paste("System health is", health_result$overall_status),
      details = health_result
    )
  }
  
  # Check individual component response times
  for (component_name in names(health_result$components)) {
    component <- health_result$components[[component_name]]
    
    if (component$response_time_ms > MONITORING_CONFIG$alerting$thresholds$response_time_ms) {
      trigger_alert(
        type = "performance",
        severity = "warning",
        message = paste(component_name, "response time is high:", component$response_time_ms, "ms"),
        details = component
      )
    }
  }
}

#' Check for performance-based alerts
#' @param metrics Performance metrics
check_performance_alerts <- function(metrics) {
  if (!MONITORING_CONFIG$alerting$enabled) {
    return()
  }
  
  # Memory usage alert
  if (!is.null(metrics$system$memory_used_mb)) {
    if (metrics$system$memory_used_mb > MONITORING_CONFIG$alerting$thresholds$memory_usage_mb) {
      trigger_alert(
        type = "memory",
        severity = "warning",
        message = paste("High memory usage:", metrics$system$memory_used_mb, "MB"),
        details = metrics$system
      )
    }
  }
  
  # Query performance alert
  if (!is.null(metrics$system$avg_query_time_ms)) {
    if (metrics$system$avg_query_time_ms > MONITORING_CONFIG$alerting$thresholds$response_time_ms) {
      trigger_alert(
        type = "performance",
        severity = "warning",
        message = paste("Slow query performance:", metrics$system$avg_query_time_ms, "ms"),
        details = metrics$system
      )
    }
  }
}

#' Trigger an alert
#' @param type Alert type
#' @param severity Alert severity
#' @param message Alert message
#' @param details Additional details
trigger_alert <- function(type, severity, message, details = NULL) {
  # Check cooldown period
  cooldown_key <- paste(type, severity, sep = "_")
  last_alert <- monitoring_state$alert_cooldowns[[cooldown_key]]
  
  if (!is.null(last_alert)) {
    minutes_since <- as.numeric(Sys.time() - last_alert, units = "mins")
    if (minutes_since < MONITORING_CONFIG$alerting$cooldown_minutes) {
      return()  # Still in cooldown period
    }
  }
  
  # Create alert
  alert <- list(
    timestamp = Sys.time(),
    type = type,
    severity = severity,
    message = message,
    details = details,
    id = generate_alert_id()
  )
  
  # Store alert
  monitoring_state$alerts <<- append(monitoring_state$alerts, list(alert), after = 0)
  
  # Limit alert history
  if (length(monitoring_state$alerts) > 100) {
    monitoring_state$alerts <<- head(monitoring_state$alerts, 100)
  }
  
  # Send alert through configured channels
  send_alert(alert)
  
  # Update cooldown
  monitoring_state$alert_cooldowns[[cooldown_key]] <<- Sys.time()
  
  return(alert)
}

#' Send alert through configured channels
#' @param alert Alert object
send_alert <- function(alert) {
  # Log alert
  if (MONITORING_CONFIG$alerting$channels$log$enabled) {
    log_level <- switch(alert$severity,
      "critical" = "ERROR",
      "warning" = "WARN", 
      "info" = "INFO"
    )
    
    log_event(paste("ALERT:", alert$message), log_level)
  }
  
  # Email alert (placeholder)
  if (MONITORING_CONFIG$alerting$channels$email$enabled) {
    # Would send email notification
  }
  
  # Webhook alert (placeholder)
  if (MONITORING_CONFIG$alerting$channels$webhook$enabled) {
    # Would send webhook notification
  }
}

#' Generate unique alert ID
#' @return Alert ID string
generate_alert_id <- function() {
  paste0("alert_", format(Sys.time(), "%Y%m%d_%H%M%S"), "_", sample(1000:9999, 1))
}

#' Get current monitoring status
#' @return Monitoring status summary
get_monitoring_status <- function() {
  status <- list(
    timestamp = Sys.time(),
    uptime_hours = as.numeric(Sys.time() - monitoring_state$uptime_start, units = "hours"),
    health_check = monitoring_state$health_status,
    recent_alerts = head(monitoring_state$alerts, 10),
    system_metrics = NULL
  )
  
  # Get latest performance metrics
  if (length(monitoring_state$performance_metrics) > 0) {
    status$system_metrics <- monitoring_state$performance_metrics[[1]]
  }
  
  return(status)
}

#' Get monitoring dashboard data
#' @param hours_back Number of hours of data to return
#' @return Dashboard data
get_monitoring_dashboard_data <- function(hours_back = 24) {
  cutoff_time <- Sys.time() - hours(hours_back)
  
  # Filter metrics by time
  recent_metrics <- Filter(function(x) x$timestamp > cutoff_time, monitoring_state$performance_metrics)
  recent_alerts <- Filter(function(x) x$timestamp > cutoff_time, monitoring_state$alerts)
  
  dashboard_data <- list(
    summary = list(
      uptime_hours = as.numeric(Sys.time() - monitoring_state$uptime_start, units = "hours"),
      health_status = monitoring_state$health_status$overall_status %||% "unknown",
      total_alerts = length(recent_alerts),
      critical_alerts = sum(sapply(recent_alerts, function(x) x$severity == "critical"))
    ),
    
    metrics_timeline = recent_metrics,
    recent_alerts = recent_alerts,
    health_components = monitoring_state$health_status$components %||% list()
  )
  
  return(dashboard_data)
}

#' Export monitoring data
#' @param format Export format (json, csv)
#' @param hours_back Number of hours of data
#' @return Exported data
export_monitoring_data <- function(format = "json", hours_back = 168) {
  data <- get_monitoring_dashboard_data(hours_back)
  
  if (format == "json") {
    return(toJSON(data, pretty = TRUE, auto_unbox = TRUE))
  } else if (format == "csv") {
    # Convert to CSV format (simplified)
    if (length(data$metrics_timeline) > 0) {
      metrics_df <- do.call(rbind, lapply(data$metrics_timeline, function(x) {
        data.frame(
          timestamp = x$timestamp,
          memory_mb = x$system$memory_used_mb %||% NA,
          query_time_ms = x$system$avg_query_time_ms %||% NA,
          cache_hit_rate = x$system$cache_hit_rate %||% NA,
          stringsAsFactors = FALSE
        )
      }))
      return(metrics_df)
    }
  }
  
  return(NULL)
}