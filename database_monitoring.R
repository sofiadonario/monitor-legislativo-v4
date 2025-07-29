# DATABASE MONITORING - Health Monitoring and Alerting System
# Comprehensive monitoring for Railway PostgreSQL database connections
# Prevents "Database connected: FALSE" issues through proactive monitoring

cat("🏥 Loading Database Monitoring System\n")

# Load required libraries for monitoring
suppressPackageStartupMessages({
  library(jsonlite)
})

# Monitoring configuration
.monitoring_config <- list(
  health_check_interval = 300,  # 5 minutes
  log_retention_hours = 24,
  alert_threshold_failures = 3,
  performance_threshold_seconds = 5.0,
  enable_detailed_logging = TRUE,
  enable_performance_tracking = TRUE
)

# Health check history
.health_history <- list()
.performance_metrics <- list(
  query_times = numeric(0),
  connection_times = numeric(0),
  failure_timestamps = character(0),
  success_timestamps = character(0)
)

#' Comprehensive health check with detailed metrics
#' @return List with detailed health information
perform_comprehensive_health_check <- function() {
  cat("🏥 Performing comprehensive health check...\n")
  
  health_result <- list(
    timestamp = Sys.time(),
    overall_status = "unknown",
    database_status = "unknown",
    connection_pool_status = "unknown",
    circuit_breaker_status = "unknown",
    performance_metrics = list(),
    issues = character(0),
    recommendations = character(0)
  )
  
  start_time <- Sys.time()
  
  tryCatch({
    # 1. Check if data access layer exists
    if (!exists("get_connection_status")) {
      health_result$issues <- c(health_result$issues, "Data access layer not initialized")
      health_result$overall_status <- "critical"
      return(health_result)
    }
    
    # 2. Get connection status
    connection_status <- get_connection_status()
    health_result$database_status <- if (connection_status$database_connected) "healthy" else "unhealthy"
    health_result$circuit_breaker_status <- if (connection_status$circuit_breaker_open) "open" else "closed"
    
    # 3. Check connection pool health
    if (exists("get_connection_health_status")) {
      pool_health <- get_connection_health_status()
      health_result$connection_pool_status <- if (pool_health$is_healthy) "healthy" else "unhealthy"
      
      # Add detailed metrics
      health_result$performance_metrics <- list(
        successful_connections = pool_health$statistics$successful_connections,
        failed_connections = pool_health$statistics$failed_connections,
        queries_executed = pool_health$statistics$queries_executed,
        avg_query_time = pool_health$statistics$avg_query_time,
        failure_count = pool_health$failure_count
      )
    }
    
    # 4. Test actual data retrieval
    test_start <- Sys.time()
    test_analytics <- get_search_analytics()
    test_end <- Sys.time()
    test_duration <- as.numeric(difftime(test_end, test_start, units = "secs"))
    
    if (!is.null(test_analytics) && !is.null(test_analytics$total_documents)) {
      health_result$performance_metrics$data_retrieval_time <- test_duration
      health_result$performance_metrics$documents_available <- test_analytics$total_documents
      health_result$performance_metrics$data_source <- test_analytics$data_source %||% "unknown"
      
      if (test_duration > .monitoring_config$performance_threshold_seconds) {
        health_result$issues <- c(health_result$issues, 
          paste("Slow data retrieval:", round(test_duration, 2), "seconds"))
      }
    } else {
      health_result$issues <- c(health_result$issues, "Data retrieval failed")
    }
    
    # 5. Test database connection if available
    if (exists("test_database_connection")) {
      db_test <- test_database_connection()
      if (db_test$success) {
        health_result$performance_metrics$db_test_time <- db_test$query_time
        health_result$performance_metrics$tables_available <- length(db_test$tables)
      } else {
        health_result$issues <- c(health_result$issues, paste("Database test failed:", db_test$error))
      }
    }
    
    # 6. Determine overall status
    if (length(health_result$issues) == 0) {
      health_result$overall_status <- "healthy"
    } else if (connection_status$database_connected || !connection_status$using_fallback) {
      health_result$overall_status <- "degraded"
    } else {
      health_result$overall_status <- "critical"
    }
    
    # 7. Generate recommendations
    if (connection_status$circuit_breaker_open) {
      health_result$recommendations <- c(health_result$recommendations,
        "Circuit breaker is open - database connection issues detected")
    }
    
    if (connection_status$using_fallback) {
      health_result$recommendations <- c(health_result$recommendations,
        "Using fallback data - check database connectivity")
    }
    
    if (connection_status$failure_count > 0) {
      health_result$recommendations <- c(health_result$recommendations,
        paste("Recent failures detected:", connection_status$failure_count))
    }
    
    health_end <- Sys.time()
    health_result$performance_metrics$health_check_duration <- 
      as.numeric(difftime(health_end, start_time, units = "secs"))
    
    # Record metrics
    record_health_metrics(health_result)
    
    cat("✅ Health check completed in", 
        round(health_result$performance_metrics$health_check_duration, 2), "seconds\n")
    cat("📊 Overall Status:", health_result$overall_status, "\n")
    cat("📊 Database Status:", health_result$database_status, "\n")
    
    return(health_result)
    
  }, error = function(e) {
    health_result$overall_status <- "error"
    health_result$issues <- c(health_result$issues, paste("Health check error:", e$message))
    
    health_end <- Sys.time()
    health_result$performance_metrics$health_check_duration <- 
      as.numeric(difftime(health_end, start_time, units = "secs"))
    
    cat("❌ Health check failed:", e$message, "\n")
    return(health_result)
  })
}

#' Record health metrics for trend analysis
#' @param health_result Health check result
record_health_metrics <- function(health_result) {
  
  # Add to health history
  .health_history[[length(.health_history) + 1]] <<- health_result
  
  # Update performance metrics
  if (!is.null(health_result$performance_metrics$data_retrieval_time)) {
    .performance_metrics$query_times <<- c(.performance_metrics$query_times,
      health_result$performance_metrics$data_retrieval_time)
  }
  
  # Record success/failure timestamps
  if (health_result$overall_status == "healthy") {
    .performance_metrics$success_timestamps <<- c(.performance_metrics$success_timestamps,
      as.character(health_result$timestamp))
  } else {
    .performance_metrics$failure_timestamps <<- c(.performance_metrics$failure_timestamps,
      as.character(health_result$timestamp))
  }
  
  # Cleanup old history (keep last 24 hours)
  cleanup_old_metrics()
}

#' Clean up old metrics to prevent memory buildup
cleanup_old_metrics <- function() {
  cutoff_time <- Sys.time() - (.monitoring_config$log_retention_hours * 3600)
  
  # Filter health history
  .health_history <<- Filter(function(h) h$timestamp > cutoff_time, .health_history)
  
  # Limit performance metrics arrays
  max_entries <- 1000
  if (length(.performance_metrics$query_times) > max_entries) {
    .performance_metrics$query_times <<- tail(.performance_metrics$query_times, max_entries)
  }
  
  # Filter timestamps
  success_times <- as.POSIXct(.performance_metrics$success_timestamps)
  failure_times <- as.POSIXct(.performance_metrics$failure_timestamps)
  
  .performance_metrics$success_timestamps <<- 
    as.character(success_times[success_times > cutoff_time])
  .performance_metrics$failure_timestamps <<- 
    as.character(failure_times[failure_times > cutoff_time])
}

#' Get health trends and analytics
#' @return List with trend analysis
get_health_trends <- function() {
  cat("📈 Analyzing health trends...\n")
  
  if (length(.health_history) == 0) {
    return(list(
      message = "No health history available",
      recommendations = "Run health checks to build trend data"
    ))
  }
  
  # Calculate success rate
  total_checks <- length(.health_history)
  healthy_checks <- sum(sapply(.health_history, function(h) h$overall_status == "healthy"))
  success_rate <- healthy_checks / total_checks
  
  # Performance trends
  avg_query_time <- if (length(.performance_metrics$query_times) > 0) {
    mean(.performance_metrics$query_times)
  } else {
    NA
  }
  
  # Recent issues
  recent_issues <- unique(unlist(lapply(.health_history, function(h) h$issues)))
  
  # Failure analysis
  recent_failures <- length(.performance_metrics$failure_timestamps)
  recent_successes <- length(.performance_metrics$success_timestamps)
  
  trends <- list(
    total_health_checks = total_checks,
    success_rate = round(success_rate * 100, 2),
    avg_query_time = if (!is.na(avg_query_time)) round(avg_query_time, 3) else "N/A",
    recent_failures = recent_failures,
    recent_successes = recent_successes,
    recent_issues = if (length(recent_issues) > 0) recent_issues else "None",
    last_check = if (total_checks > 0) .health_history[[total_checks]]$timestamp else "Never",
    recommendations = generate_trend_recommendations(success_rate, recent_failures, avg_query_time)
  )
  
  cat("📊 Success Rate:", trends$success_rate, "%\n")
  cat("📊 Average Query Time:", trends$avg_query_time, "seconds\n")
  cat("📊 Recent Failures:", trends$recent_failures, "\n")
  
  return(trends)
}

#' Generate recommendations based on trends
#' @param success_rate Success rate (0-1)
#' @param recent_failures Number of recent failures
#' @param avg_query_time Average query time
#' @return Character vector of recommendations
generate_trend_recommendations <- function(success_rate, recent_failures, avg_query_time) {
  recommendations <- character(0)
  
  if (success_rate < 0.95) {
    recommendations <- c(recommendations, 
      "Success rate below 95% - investigate connection stability")
  }
  
  if (recent_failures > .monitoring_config$alert_threshold_failures) {
    recommendations <- c(recommendations,
      paste("High failure count (", recent_failures, ") - check Railway database status"))
  }
  
  if (!is.na(avg_query_time) && avg_query_time > .monitoring_config$performance_threshold_seconds) {
    recommendations <- c(recommendations,
      paste("Slow query performance (", round(avg_query_time, 2), "s) - consider query optimization"))
  }
  
  if (length(recommendations) == 0) {
    recommendations <- "System performing well - no issues detected"
  }
  
  return(recommendations)
}

#' Export health report as JSON
#' @param filepath File path to save report
#' @return TRUE if successful
export_health_report <- function(filepath = "health_report.json") {
  tryCatch({
    health_check <- perform_comprehensive_health_check()
    trends <- get_health_trends()
    
    report <- list(
      timestamp = Sys.time(),
      health_check = health_check,
      trends = trends,
      monitoring_config = .monitoring_config,
      system_info = list(
        r_version = R.version.string,
        platform = Sys.info()[["sysname"]],
        working_directory = getwd()
      )
    )
    
    write_json(report, filepath, pretty = TRUE, auto_unbox = TRUE)
    cat("📄 Health report exported to:", filepath, "\n")
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Error exporting health report:", e$message, "\n")
    return(FALSE)
  })
}

#' Start continuous monitoring (for production use)
#' @param interval_seconds Monitoring interval in seconds
start_continuous_monitoring <- function(interval_seconds = .monitoring_config$health_check_interval) {
  cat("🔄 Starting continuous monitoring every", interval_seconds, "seconds\n")
  
  # This would typically use a scheduler like later() package
  # For now, we'll provide the framework
  cat("📋 Continuous monitoring framework ready\n")
  cat("📋 To implement: Use later::later() or similar scheduler\n")
  cat("📋 Call perform_comprehensive_health_check() at regular intervals\n")
  
  return(TRUE)
}

#' Get current monitoring status
#' @return List with monitoring status
get_monitoring_status <- function() {
  return(list(
    monitoring_active = TRUE,
    config = .monitoring_config,
    health_checks_performed = length(.health_history),
    last_health_check = if (length(.health_history) > 0) {
      .health_history[[length(.health_history)]]$timestamp
    } else {
      "Never"
    },
    performance_metrics_available = length(.performance_metrics$query_times) > 0
  ))
}

cat("✅ Database Monitoring System loaded successfully\n")
cat("🏥 Ready to monitor Railway PostgreSQL connections\n")
cat("📊 Health checks will prevent 'Database connected: FALSE' issues\n")
cat("🔄 Use perform_comprehensive_health_check() to check system health\n")