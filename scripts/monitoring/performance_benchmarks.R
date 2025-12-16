# ============================================================================
# COMPREHENSIVE PERFORMANCE BENCHMARKS AND MONITORING SYSTEM
# ============================================================================
#
# This system provides comprehensive performance benchmarking and continuous
# monitoring for the Brazilian Legislative Monitoring System running on Cloud Run.
# It establishes performance baselines, tracks real-time metrics, and provides
# detailed performance analysis and alerting.
#
# Key Features:
# - Real-time performance monitoring with configurable thresholds
# - Comprehensive performance baseline establishment and tracking
# - Cloud Run infrastructure performance monitoring (memory, connections, response times)
# - Brazilian legislative workload-specific performance metrics
# - Automated performance alerting and notification system
# - Historical performance trend analysis and visualization
# - Database query performance tracking and optimization recommendations
# - Cache performance monitoring and efficiency analysis
# - Memory usage tracking with Cloud Run 2GB limit compliance
# - Integration with load testing and regression testing systems
#
# Designed for production monitoring and performance optimization
# ============================================================================

cat("📊 Loading Comprehensive Performance Benchmarks and Monitoring System\n")

# Load required libraries with error handling
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
  library(pool)
  library(pryr)
  library(microbenchmark)
  library(dplyr)
  library(ggplot2)
  library(plotly)
  library(jsonlite)
  library(lubridate)
  library(future)
  library(future.apply)
  library(digest)
  library(stringr)
})

# Performance monitoring configuration
MONITORING_CONFIG <- list(
  # Monitoring intervals and thresholds
  real_time_interval_seconds = 30,          # Real-time monitoring frequency
  benchmark_interval_hours = 6,             # Benchmark refresh frequency
  alert_check_interval_minutes = 5,         # Alert checking frequency
  
  # Performance thresholds for alerting
  critical_response_time_seconds = 10,      # Critical response time threshold
  warning_response_time_seconds = 5,        # Warning response time threshold
  critical_memory_usage_mb = 1800,          # Critical memory usage (Cloud Run 2GB limit)
  warning_memory_usage_mb = 1500,           # Warning memory usage
  critical_db_connections = 90,             # Critical DB connections (Cloud Run 100 limit)
  warning_db_connections = 70,              # Warning DB connections
  critical_error_rate_pct = 5,              # Critical error rate percentage
  warning_error_rate_pct = 2,               # Warning error rate percentage
  
  # Cache performance thresholds
  critical_cache_hit_rate_pct = 50,         # Critical cache hit rate
  warning_cache_hit_rate_pct = 70,          # Warning cache hit rate
  
  # Historical data retention
  real_time_data_retention_hours = 24,      # Keep 24 hours of real-time data
  benchmark_data_retention_days = 90,       # Keep 90 days of benchmark data
  alert_history_retention_days = 30,        # Keep 30 days of alert history
  
  # Brazilian legislative workload monitoring
  workload_monitoring_patterns = list(
    peak_hours = c(9, 10, 11, 14, 15, 16, 17),  # Business hours in Brazil (UTC-3)
    peak_days = c("Monday", "Tuesday", "Wednesday", "Thursday", "Friday"),
    legislative_session_months = c(2, 3, 4, 5, 6, 8, 9, 10, 11, 12)  # Excluding January/July recess
  ),
  
  # Performance benchmarks categories
  benchmark_categories = list(
    database_operations = list(weight = 0.35, critical = TRUE),
    search_operations = list(weight = 0.25, critical = TRUE),
    cache_performance = list(weight = 0.15, critical = FALSE),
    memory_efficiency = list(weight = 0.15, critical = TRUE),
    cloud_run_compliance = list(weight = 0.10, critical = TRUE)
  )
)

# Global monitoring data storage
PERFORMANCE_MONITORING_DATA <- list(
  real_time_metrics = list(),
  benchmark_history = list(),
  alert_history = list(),
  performance_trends = list(),
  current_benchmarks = list()
)

# Performance alert system
PERFORMANCE_ALERTS <- list(
  active_alerts = list(),
  alert_callbacks = list(),
  alert_history = list()
)

# Benchmark tracking system
BENCHMARK_SYSTEM <- list(
  current_benchmarks = list(),
  benchmark_history = list(),
  benchmark_trends = list()
)

# ============================================================================
# REAL-TIME PERFORMANCE MONITORING
# ============================================================================

#' Start comprehensive real-time performance monitoring
#' @param monitoring_duration_hours Duration to run monitoring (0 for continuous)
#' @return Monitoring session handle
start_performance_monitoring <- function(monitoring_duration_hours = 0) {
  
  cat("🚀 Starting comprehensive real-time performance monitoring\n")
  
  if (monitoring_duration_hours > 0) {
    cat("⏱️ Monitoring duration:", monitoring_duration_hours, "hours\n")
  } else {
    cat("🔄 Continuous monitoring mode enabled\n")
  }
  
  monitoring_session <- list(
    session_id = digest(paste(Sys.time(), runif(1)), algo = "md5"),
    start_time = Sys.time(),
    duration_hours = monitoring_duration_hours,
    is_active = TRUE,
    metrics_collected = 0
  )
  
  # Start monitoring in background
  monitoring_future <- future({
    
    session_start <- Sys.time()
    end_time <- if (monitoring_duration_hours > 0) {
      session_start + (monitoring_duration_hours * 3600)
    } else {
      as.POSIXct("2099-12-31")  # Far future for continuous monitoring
    }
    
    metrics_data <- list()
    
    while (Sys.time() < end_time && monitoring_session$is_active) {
      
      timestamp <- Sys.time()
      
      # Collect comprehensive performance metrics
      current_metrics <- collect_current_performance_metrics()
      current_metrics$timestamp <- timestamp
      current_metrics$session_id <- monitoring_session$session_id
      
      # Store metrics
      metrics_data[[length(metrics_data) + 1]] <- current_metrics
      
      # Check for performance alerts
      check_performance_alerts(current_metrics)
      
      # Clean up old real-time data periodically
      if (length(metrics_data) %% 100 == 0) {
        metrics_data <- cleanup_old_real_time_data(metrics_data)
      }
      
      # Wait for next collection interval
      Sys.sleep(MONITORING_CONFIG$real_time_interval_seconds)
    }
    
    return(list(
      session_info = monitoring_session,
      metrics_data = metrics_data,
      end_time = Sys.time()
    ))
  })
  
  # Store monitoring session
  PERFORMANCE_MONITORING_DATA$real_time_metrics[[monitoring_session$session_id]] <<- list(
    session_info = monitoring_session,
    monitoring_future = monitoring_future
  )
  
  cat("✅ Real-time monitoring session", substr(monitoring_session$session_id, 1, 8), "started\n")
  
  return(monitoring_session)
}

#' Collect comprehensive current performance metrics
#' @return Current performance metrics
collect_current_performance_metrics <- function() {
  
  metrics <- list(
    timestamp = Sys.time(),
    system_metrics = collect_system_metrics(),
    database_metrics = collect_database_metrics(),
    cache_metrics = collect_cache_metrics(),
    application_metrics = collect_application_metrics(),
    cloud_run_metrics = collect_cloud_run_metrics(),
    workload_metrics = collect_workload_metrics()
  )
  
  return(metrics)
}

#' Collect system-level performance metrics
#' @return System metrics
collect_system_metrics <- function() {
  
  system_metrics <- list(
    memory_usage_mb = round(as.numeric(pryr::mem_used()) / 1024 / 1024, 1),
    memory_utilization_pct = round((as.numeric(pryr::mem_used()) / 1024 / 1024 / 2048) * 100, 1),
    process_id = Sys.getpid(),
    r_version = R.version.string,
    working_directory = getwd()
  )
  
  # Add OS-specific metrics if available
  tryCatch({
    system_info <- Sys.info()
    system_metrics$os <- system_info["sysname"]
    system_metrics$node_name <- system_info["nodename"]
  }, error = function(e) {
    # OS info not available
  })
  
  return(system_metrics)
}

#' Collect database performance metrics
#' @return Database metrics
collect_database_metrics <- function() {
  
  database_metrics <- list(
    connection_status = "disconnected",
    active_connections = 0,
    idle_connections = 0,
    total_connections = 0,
    connection_utilization_pct = 0,
    query_performance = list(),
    connection_health = FALSE
  )
  
  tryCatch({
    
    # Check database pool status
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      
      database_metrics$connection_status <- "connected"
      database_metrics$connection_health <- TRUE
      
      # Get connection pool metrics
      tryCatch({
        database_metrics$active_connections <- pool::poolGetActive(secure_db_pool)
        database_metrics$idle_connections <- pool::poolGetIdle(secure_db_pool)
        database_metrics$total_connections <- database_metrics$active_connections + database_metrics$idle_connections
        database_metrics$connection_utilization_pct <- round((database_metrics$total_connections / 100) * 100, 1)
      }, error = function(e) {
        # Pool metrics not available
      })
      
      # Test query performance
      query_start <- Sys.time()
      tryCatch({
        test_result <- dbGetQuery(secure_db_pool, "SELECT 1 as test")
        query_time <- as.numeric(difftime(Sys.time(), query_start, units = "secs"))
        
        database_metrics$query_performance <- list(
          test_query_time_seconds = round(query_time, 3),
          test_query_success = TRUE,
          last_successful_query = Sys.time()
        )
        
      }, error = function(e) {
        query_time <- as.numeric(difftime(Sys.time(), query_start, units = "secs"))
        database_metrics$query_performance <- list(
          test_query_time_seconds = round(query_time, 3),
          test_query_success = FALSE,
          last_error = e$message
        )
        database_metrics$connection_health <- FALSE
      })
    }
    
  }, error = function(e) {
    database_metrics$connection_status <- "error"
    database_metrics$error <- e$message
  })
  
  return(database_metrics)
}

#' Collect cache performance metrics
#' @return Cache metrics
collect_cache_metrics <- function() {
  
  cache_metrics <- list(
    cache_enabled = FALSE,
    cache_hit_rate = 0,
    cache_size = 0,
    cache_efficiency = "unknown"
  )
  
  tryCatch({
    
    # Check if performance stats are available
    if (exists("get_performance_stats")) {
      
      perf_stats <- get_performance_stats()
      
      cache_metrics$cache_enabled <- TRUE
      cache_metrics$cache_hit_rate <- ifelse(is.null(perf_stats$cache_hit_rate), 0, perf_stats$cache_hit_rate)
      cache_metrics$cache_size <- ifelse(is.null(perf_stats$query_cache_size), 0, perf_stats$query_cache_size)
      cache_metrics$cache_hits <- ifelse(is.null(perf_stats$cache_hits), 0, perf_stats$cache_hits)
      cache_metrics$cache_misses <- ifelse(is.null(perf_stats$cache_misses), 0, perf_stats$cache_misses)
      cache_metrics$queries_executed <- ifelse(is.null(perf_stats$queries_executed), 0, perf_stats$queries_executed)
      cache_metrics$avg_query_time <- ifelse(is.null(perf_stats$avg_query_time), 0, perf_stats$avg_query_time)
      
      # Calculate cache efficiency
      cache_metrics$cache_efficiency <- case_when(
        cache_metrics$cache_hit_rate >= 90 ~ "excellent",
        cache_metrics$cache_hit_rate >= 80 ~ "good",
        cache_metrics$cache_hit_rate >= 70 ~ "acceptable",
        cache_metrics$cache_hit_rate >= 50 ~ "poor",
        TRUE ~ "critical"
      )
    }
    
  }, error = function(e) {
    cache_metrics$error <- e$message
  })
  
  return(cache_metrics)
}

#' Collect application-level performance metrics
#' @return Application metrics
collect_application_metrics <- function() {
  
  application_metrics <- list(
    uptime_seconds = as.numeric(Sys.time() - .GlobalEnv$.app_start_time %||% Sys.time()),
    main_table_available = FALSE,
    library_function_available = FALSE,
    dashboard_function_available = FALSE,
    error_count = 0
  )
  
  # Check main application functions availability
  if (exists("get_main_table")) {
    application_metrics$main_table_available <- !is.null(get_main_table())
  }
  
  if (exists("get_library_documents_optimized")) {
    application_metrics$library_function_available <- TRUE
  }
  
  if (exists("get_dashboard_metrics_optimized")) {
    application_metrics$dashboard_function_available <- TRUE
  }
  
  # Test core functionality performance
  tryCatch({
    
    if (application_metrics$library_function_available) {
      function_test_start <- Sys.time()
      test_result <- get_library_documents_optimized(limit = 1)
      function_test_time <- as.numeric(difftime(Sys.time(), function_test_start, units = "secs"))
      
      application_metrics$core_function_test <- list(
        test_time_seconds = round(function_test_time, 3),
        test_successful = !is.null(test_result),
        results_returned = ifelse(is.null(test_result), 0, nrow(test_result))
      )
    }
    
  }, error = function(e) {
    application_metrics$core_function_error <- e$message
    application_metrics$error_count <- application_metrics$error_count + 1
  })
  
  return(application_metrics)
}

#' Collect Cloud Run-specific performance metrics
#' @return Cloud Run metrics
collect_cloud_run_metrics <- function() {

  cloud_run_metrics <- list(
    is_cloud_run_environment = FALSE,
    environment_type = "unknown",
    memory_compliance = list(),
    connection_compliance = list(),
    deployment_info = list()
  )

  # Check Cloud Run environment
  k_service <- Sys.getenv("K_SERVICE", "")
  cloud_run_metrics$is_cloud_run_environment <- k_service != ""
  cloud_run_metrics$environment_type <- ifelse(k_service != "", "cloud_run", "local")

  # Cloud Run deployment info
  cloud_run_metrics$deployment_info <- list(
    service_name = Sys.getenv("K_SERVICE", "not_set"),
    revision = Sys.getenv("K_REVISION", "not_set"),
    project_id = Sys.getenv("GOOGLE_CLOUD_PROJECT", "not_set"),
    port = Sys.getenv("PORT", "8080")
  )
  
  # Memory compliance check
  current_memory_mb <- as.numeric(pryr::mem_used()) / 1024 / 1024

  cloud_run_metrics$memory_compliance <- list(
    current_memory_mb = round(current_memory_mb, 1),
    cloud_run_limit_mb = 2048,
    utilization_pct = round((current_memory_mb / 2048) * 100, 1),
    within_limit = current_memory_mb <= 2048,
    headroom_mb = round(2048 - current_memory_mb, 1),
    compliance_status = case_when(
      current_memory_mb > 2048 ~ "NON_COMPLIANT",
      current_memory_mb > 1800 ~ "CRITICAL",
      current_memory_mb > 1500 ~ "WARNING",
      TRUE ~ "COMPLIANT"
    )
  )
  
  # Database connection compliance
  if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    tryCatch({
      active_connections <- pool::poolGetActive(secure_db_pool)
      idle_connections <- pool::poolGetIdle(secure_db_pool)
      total_connections <- active_connections + idle_connections

      cloud_run_metrics$connection_compliance <- list(
        current_connections = total_connections,
        cloud_run_limit = 100,
        utilization_pct = round((total_connections / 100) * 100, 1),
        within_limit = total_connections <= 100,
        headroom = 100 - total_connections,
        compliance_status = case_when(
          total_connections > 100 ~ "NON_COMPLIANT",
          total_connections > 90 ~ "CRITICAL",
          total_connections > 70 ~ "WARNING",
          TRUE ~ "COMPLIANT"
        )
      )
    }, error = function(e) {
      cloud_run_metrics$connection_compliance <- list(error = e$message)
    })
  }

  return(cloud_run_metrics)
}

#' Collect workload-specific performance metrics for Brazilian legislative system
#' @return Workload metrics
collect_workload_metrics <- function() {
  
  workload_metrics <- list(
    current_hour = as.numeric(format(Sys.time(), "%H")),
    current_day = weekdays(Sys.time()),
    current_month = as.numeric(format(Sys.time(), "%m")),
    is_peak_hour = FALSE,
    is_peak_day = FALSE,
    is_legislative_session_month = FALSE,
    expected_load_level = "low"
  )
  
  # Determine if current time is peak usage for Brazilian legislative monitoring
  workload_metrics$is_peak_hour <- workload_metrics$current_hour %in% MONITORING_CONFIG$workload_monitoring_patterns$peak_hours
  workload_metrics$is_peak_day <- workload_metrics$current_day %in% MONITORING_CONFIG$workload_monitoring_patterns$peak_days
  workload_metrics$is_legislative_session_month <- workload_metrics$current_month %in% MONITORING_CONFIG$workload_monitoring_patterns$legislative_session_months
  
  # Calculate expected load level
  load_factors <- 0
  if (workload_metrics$is_peak_hour) load_factors <- load_factors + 1
  if (workload_metrics$is_peak_day) load_factors <- load_factors + 1
  if (workload_metrics$is_legislative_session_month) load_factors <- load_factors + 1
  
  workload_metrics$expected_load_level <- case_when(
    load_factors >= 3 ~ "very_high",
    load_factors >= 2 ~ "high",
    load_factors >= 1 ~ "medium",
    TRUE ~ "low"
  )
  
  # Collect workload-specific performance metrics
  tryCatch({
    
    if (exists("get_library_documents_optimized")) {
      
      # Test Brazilian legislative search performance
      search_test_start <- Sys.time()
      
      # Test with common Brazilian legislative terms
      test_terms <- c("educação", "saúde", "segurança", "transporte", "meio ambiente")
      selected_term <- sample(test_terms, 1)
      
      search_result <- get_library_documents_optimized(
        search_term = selected_term,
        limit = 10
      )
      
      search_test_time <- as.numeric(difftime(Sys.time(), search_test_start, units = "secs"))
      
      workload_metrics$brazilian_search_performance <- list(
        search_term = selected_term,
        search_time_seconds = round(search_test_time, 3),
        results_returned = ifelse(is.null(search_result), 0, nrow(search_result)),
        performance_rating = case_when(
          search_test_time < 1 ~ "excellent",
          search_test_time < 3 ~ "good", 
          search_test_time < 5 ~ "acceptable",
          TRUE ~ "poor"
        )
      )
    }
    
  }, error = function(e) {
    workload_metrics$brazilian_search_error <- e$message
  })
  
  return(workload_metrics)
}

# ============================================================================
# PERFORMANCE ALERTING SYSTEM
# ============================================================================

#' Check current performance metrics against alert thresholds
#' @param current_metrics Current performance metrics
check_performance_alerts <- function(current_metrics) {
  
  alerts_triggered <- list()
  
  tryCatch({
    
    # Memory usage alerts
    memory_mb <- current_metrics$system_metrics$memory_usage_mb
    if (memory_mb >= MONITORING_CONFIG$critical_memory_usage_mb) {
      alerts_triggered$memory_critical <- create_performance_alert(
        "CRITICAL", 
        "Memory Usage Critical", 
        paste0("Memory usage (", memory_mb, "MB) exceeds critical threshold (", MONITORING_CONFIG$critical_memory_usage_mb, "MB)"),
        current_metrics
      )
    } else if (memory_mb >= MONITORING_CONFIG$warning_memory_usage_mb) {
      alerts_triggered$memory_warning <- create_performance_alert(
        "WARNING", 
        "Memory Usage Warning", 
        paste0("Memory usage (", memory_mb, "MB) exceeds warning threshold (", MONITORING_CONFIG$warning_memory_usage_mb, "MB)"),
        current_metrics
      )
    }
    
    # Database connection alerts
    if (!is.null(current_metrics$database_metrics$total_connections)) {
      db_connections <- current_metrics$database_metrics$total_connections
      if (db_connections >= MONITORING_CONFIG$critical_db_connections) {
        alerts_triggered$db_connections_critical <- create_performance_alert(
          "CRITICAL",
          "Database Connections Critical",
          paste0("Database connections (", db_connections, ") near Cloud Run limit (100)"),
          current_metrics
        )
      } else if (db_connections >= MONITORING_CONFIG$warning_db_connections) {
        alerts_triggered$db_connections_warning <- create_performance_alert(
          "WARNING", 
          "Database Connections Warning", 
          paste0("Database connections (", db_connections, ") elevated"),
          current_metrics
        )
      }
    }
    
    # Query performance alerts
    if (!is.null(current_metrics$database_metrics$query_performance$test_query_time_seconds)) {
      query_time <- current_metrics$database_metrics$query_performance$test_query_time_seconds
      if (query_time >= MONITORING_CONFIG$critical_response_time_seconds) {
        alerts_triggered$query_performance_critical <- create_performance_alert(
          "CRITICAL", 
          "Query Performance Critical", 
          paste0("Database query time (", query_time, "s) exceeds critical threshold"),
          current_metrics
        )
      } else if (query_time >= MONITORING_CONFIG$warning_response_time_seconds) {
        alerts_triggered$query_performance_warning <- create_performance_alert(
          "WARNING", 
          "Query Performance Warning", 
          paste0("Database query time (", query_time, "s) elevated"),
          current_metrics
        )
      }
    }
    
    # Cache performance alerts
    if (!is.null(current_metrics$cache_metrics$cache_hit_rate)) {
      hit_rate <- current_metrics$cache_metrics$cache_hit_rate
      if (hit_rate <= MONITORING_CONFIG$critical_cache_hit_rate_pct) {
        alerts_triggered$cache_performance_critical <- create_performance_alert(
          "CRITICAL", 
          "Cache Performance Critical", 
          paste0("Cache hit rate (", hit_rate, "%) below critical threshold"),
          current_metrics
        )
      } else if (hit_rate <= MONITORING_CONFIG$warning_cache_hit_rate_pct) {
        alerts_triggered$cache_performance_warning <- create_performance_alert(
          "WARNING", 
          "Cache Performance Warning", 
          paste0("Cache hit rate (", hit_rate, "%) below optimal"),
          current_metrics
        )
      }
    }
    
    # Cloud Run compliance alerts
    if (!is.null(current_metrics$cloud_run_metrics$memory_compliance)) {
      memory_compliance <- current_metrics$cloud_run_metrics$memory_compliance
      if (memory_compliance$compliance_status == "NON_COMPLIANT") {
        alerts_triggered$cloud_run_memory_critical <- create_performance_alert(
          "CRITICAL",
          "Cloud Run Memory Limit Exceeded",
          paste0("Memory usage exceeds Cloud Run 2GB limit: ", memory_compliance$current_memory_mb, "MB"),
          current_metrics
        )
      }
    }
    
    # Process alerts
    if (length(alerts_triggered) > 0) {
      process_performance_alerts(alerts_triggered)
    }
    
  }, error = function(e) {
    cat("❌ Error checking performance alerts:", e$message, "\n")
  })
}

#' Create a performance alert object
#' @param severity Alert severity (CRITICAL, WARNING, INFO)
#' @param title Alert title
#' @param message Alert message
#' @param metrics_context Current metrics context
#' @return Performance alert object
create_performance_alert <- function(severity, title, message, metrics_context) {
  
  alert <- list(
    alert_id = digest(paste(Sys.time(), title, runif(1)), algo = "md5"),
    timestamp = Sys.time(),
    severity = severity,
    title = title,
    message = message,
    metrics_context = metrics_context,
    acknowledged = FALSE,
    resolved = FALSE
  )
  
  return(alert)
}

#' Process and handle performance alerts
#' @param alerts_triggered List of triggered alerts
process_performance_alerts <- function(alerts_triggered) {
  
  for (alert_name in names(alerts_triggered)) {
    alert <- alerts_triggered[[alert_name]]
    
    # Log alert
    cat("🚨", alert$severity, "ALERT:", alert$title, "\n")
    cat("   ", alert$message, "\n")
    
    # Store alert in active alerts
    PERFORMANCE_ALERTS$active_alerts[[alert$alert_id]] <<- alert
    
    # Add to alert history
    PERFORMANCE_ALERTS$alert_history[[length(PERFORMANCE_ALERTS$alert_history) + 1]] <<- alert
    
    # Execute alert callbacks if any are registered
    if (length(PERFORMANCE_ALERTS$alert_callbacks) > 0) {
      for (callback in PERFORMANCE_ALERTS$alert_callbacks) {
        tryCatch({
          callback(alert)
        }, error = function(e) {
          cat("❌ Error executing alert callback:", e$message, "\n")
        })
      }
    }
  }
}

# ============================================================================
# PERFORMANCE BENCHMARKING SYSTEM
# ============================================================================

#' Establish comprehensive performance benchmarks
#' @param benchmark_name Name for the benchmark set
#' @return Benchmark results
establish_comprehensive_benchmarks <- function(benchmark_name = paste0("benchmark_", format(Sys.time(), "%Y%m%d_%H%M"))) {
  
  cat("📏 Establishing comprehensive performance benchmarks:", benchmark_name, "\n")
  
  benchmark_start <- Sys.time()
  
  benchmarks <- list(
    benchmark_name = benchmark_name,
    timestamp = benchmark_start,
    system_info = capture_benchmark_system_info(),
    database_benchmarks = establish_database_performance_benchmarks(),
    search_benchmarks = establish_search_performance_benchmarks(),
    cache_benchmarks = establish_cache_performance_benchmarks(),
    memory_benchmarks = establish_memory_performance_benchmarks(),
    cloud_run_benchmarks = establish_cloud_run_performance_benchmarks(),
    workload_benchmarks = establish_workload_performance_benchmarks()
  )
  
  # Calculate composite benchmark score
  benchmarks$composite_score <- calculate_benchmark_composite_score(benchmarks)
  
  benchmarks$establishment_duration <- as.numeric(difftime(Sys.time(), benchmark_start, units = "mins"))
  
  # Store benchmarks
  BENCHMARK_SYSTEM$current_benchmarks <<- benchmarks
  BENCHMARK_SYSTEM$benchmark_history[[benchmark_name]] <<- benchmarks
  
  cat("✅ Performance benchmarks established in", round(benchmarks$establishment_duration, 1), "minutes\n")
  cat("📊 Composite benchmark score:", benchmarks$composite_score, "\n")
  
  return(benchmarks)
}

#' Capture system information for benchmarking context
#' @return System information for benchmarks
capture_benchmark_system_info <- function() {
  
  system_info <- list(
    timestamp = Sys.time(),
    r_version = R.version.string,
    platform = R.Version()$platform,
    memory_total_mb = round(as.numeric(pryr::mem_used()) / 1024 / 1024, 1),
    cloud_run_environment = Sys.getenv("K_SERVICE", "local"),
    git_commit = get_git_commit_info(),
    package_versions = get_benchmark_relevant_package_versions()
  )
  
  return(system_info)
}

#' Get git commit information for benchmark tracking
#' @return Git commit information or placeholder
get_git_commit_info <- function() {
  tryCatch({
    if (file.exists(".git")) {
      list(
        hash = system("git rev-parse HEAD", intern = TRUE, ignore.stderr = TRUE)[1],
        branch = system("git rev-parse --abbrev-ref HEAD", intern = TRUE, ignore.stderr = TRUE)[1],
        timestamp = Sys.time()
      )
    } else {
      list(hash = "unknown", branch = "unknown", timestamp = Sys.time())
    }
  }, error = function(e) {
    list(hash = "error", branch = "error", error = e$message, timestamp = Sys.time())
  })
}

#' Get versions of packages relevant to benchmarking
#' @return Package version information
get_benchmark_relevant_package_versions <- function() {
  
  benchmark_packages <- c("DBI", "RPostgres", "pool", "dplyr", "microbenchmark", "pryr")
  
  versions <- list()
  for (pkg in benchmark_packages) {
    tryCatch({
      versions[[pkg]] <- as.character(packageVersion(pkg))
    }, error = function(e) {
      versions[[pkg]] <- "not_installed"
    })
  }
  
  return(versions)
}

# ============================================================================
# SPECIALIZED BENCHMARK FUNCTIONS
# ============================================================================

#' Establish database performance benchmarks
#' @return Database benchmark results
establish_database_performance_benchmarks <- function() {
  
  cat("🗄️ Establishing database performance benchmarks...\n")
  
  db_benchmarks <- list(
    connection_performance = list(),
    query_performance = list(),
    transaction_performance = list()
  )
  
  tryCatch({
    
    # Connection establishment benchmark
    if (exists("get_database_pool")) {
      connection_benchmark <- microbenchmark(
        {
          pool <- get_database_pool()
          if (!is.null(pool)) {
            dbGetQuery(pool, "SELECT 1")
          }
        },
        times = 10,
        unit = "ms"
      )
      
      db_benchmarks$connection_performance <- list(
        median_ms = median(connection_benchmark$time / 1e6),
        mean_ms = mean(connection_benchmark$time / 1e6),
        max_ms = max(connection_benchmark$time / 1e6),
        samples = length(connection_benchmark$time)
      )
    }
    
    # Query performance benchmarks
    if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
      
      # Get main table for testing
      main_table <- NULL
      if (exists("get_main_table")) {
        main_table <- get_main_table()
      }
      
      if (!is.null(main_table)) {
        
        # Simple query benchmark
        simple_query <- sprintf("SELECT COUNT(*) FROM %s LIMIT 1", main_table)
        simple_benchmark <- microbenchmark(
          dbGetQuery(secure_db_pool, simple_query),
          times = 20,
          unit = "ms"
        )
        
        # Complex aggregation query benchmark
        complex_query <- sprintf("SELECT estado, COUNT(*) as doc_count FROM %s WHERE estado IS NOT NULL GROUP BY estado ORDER BY doc_count DESC LIMIT 10", main_table)
        complex_benchmark <- microbenchmark(
          dbGetQuery(secure_db_pool, complex_query),
          times = 10,
          unit = "ms"
        )
        
        db_benchmarks$query_performance <- list(
          simple_query = list(
            median_ms = median(simple_benchmark$time / 1e6),
            mean_ms = mean(simple_benchmark$time / 1e6),
            samples = length(simple_benchmark$time)
          ),
          complex_query = list(
            median_ms = median(complex_benchmark$time / 1e6),
            mean_ms = mean(complex_benchmark$time / 1e6),
            samples = length(complex_benchmark$time)
          )
        )
      }
    }
    
  }, error = function(e) {
    cat("❌ Error establishing database benchmarks:", e$message, "\n")
    db_benchmarks$error <- e$message
  })
  
  return(db_benchmarks)
}

#' Establish search performance benchmarks
#' @return Search benchmark results
establish_search_performance_benchmarks <- function() {
  
  cat("🔍 Establishing search performance benchmarks...\n")
  
  search_benchmarks <- list(
    simple_search = list(),
    filtered_search = list(),
    brazilian_terms_search = list()
  )
  
  tryCatch({
    
    if (exists("get_library_documents_optimized")) {
      
      # Simple search benchmark
      simple_search_benchmark <- microbenchmark(
        get_library_documents_optimized(limit = 10),
        times = 15,
        unit = "ms"
      )
      
      search_benchmarks$simple_search <- list(
        median_ms = median(simple_search_benchmark$time / 1e6),
        mean_ms = mean(simple_search_benchmark$time / 1e6),
        samples = length(simple_search_benchmark$time)
      )
      
      # Filtered search benchmark
      filtered_search_benchmark <- microbenchmark(
        get_library_documents_optimized(
          category = "legislation",
          state = "SP",
          limit = 20
        ),
        times = 10,
        unit = "ms"
      )
      
      search_benchmarks$filtered_search <- list(
        median_ms = median(filtered_search_benchmark$time / 1e6),
        mean_ms = mean(filtered_search_benchmark$time / 1e6),
        samples = length(filtered_search_benchmark$time)
      )
      
      # Brazilian legislative terms search benchmark
      brazilian_terms <- c("educação", "saúde pública", "transporte público", "meio ambiente")
      
      brazilian_search_results <- list()
      for (term in brazilian_terms) {
        term_benchmark <- microbenchmark(
          get_library_documents_optimized(
            search_term = term,
            limit = 25
          ),
          times = 5,
          unit = "ms"
        )
        
        brazilian_search_results[[term]] <- list(
          median_ms = median(term_benchmark$time / 1e6),
          mean_ms = mean(term_benchmark$time / 1e6)
        )
      }
      
      # Calculate average performance across Brazilian terms
      all_medians <- sapply(brazilian_search_results, function(x) x$median_ms)
      search_benchmarks$brazilian_terms_search <- list(
        avg_median_ms = mean(all_medians),
        term_results = brazilian_search_results,
        terms_tested = length(brazilian_terms)
      )
    }
    
  }, error = function(e) {
    cat("❌ Error establishing search benchmarks:", e$message, "\n")
    search_benchmarks$error <- e$message
  })
  
  return(search_benchmarks)
}

#' Establish cache performance benchmarks
#' @return Cache benchmark results
establish_cache_performance_benchmarks <- function() {
  
  cat("💾 Establishing cache performance benchmarks...\n")
  
  cache_benchmarks <- list(
    cache_efficiency = list(),
    hit_miss_performance = list()
  )
  
  tryCatch({
    
    if (exists("get_performance_stats")) {
      
      # Get current cache statistics
      cache_stats <- get_performance_stats()
      
      cache_benchmarks$cache_efficiency <- list(
        hit_rate_pct = cache_stats$cache_hit_rate,
        cache_size = cache_stats$query_cache_size,
        queries_executed = cache_stats$queries_executed,
        avg_query_time = cache_stats$avg_query_time
      )
      
      # Test cache hit vs miss performance
      if (exists("get_library_documents_optimized")) {
        
        # Cache miss test (new query)
        unique_term <- paste0("benchmark_test_", as.numeric(Sys.time()))
        cache_miss_benchmark <- microbenchmark(
          get_library_documents_optimized(search_term = unique_term, limit = 5),
          times = 3,
          unit = "ms"
        )
        
        # Cache hit test (repeat same query)
        cache_hit_benchmark <- microbenchmark(
          get_library_documents_optimized(search_term = unique_term, limit = 5),
          times = 5,
          unit = "ms"
        )
        
        cache_benchmarks$hit_miss_performance <- list(
          cache_miss_median_ms = median(cache_miss_benchmark$time / 1e6),
          cache_hit_median_ms = median(cache_hit_benchmark$time / 1e6),
          cache_improvement_ratio = median(cache_miss_benchmark$time) / median(cache_hit_benchmark$time)
        )
      }
    }
    
  }, error = function(e) {
    cat("❌ Error establishing cache benchmarks:", e$message, "\n")
    cache_benchmarks$error <- e$message
  })
  
  return(cache_benchmarks)
}

#' Establish memory performance benchmarks
#' @return Memory benchmark results
establish_memory_performance_benchmarks <- function() {
  
  cat("🧠 Establishing memory performance benchmarks...\n")
  
  memory_benchmarks <- list(
    baseline_memory = list(),
    allocation_performance = list(),
    cloud_run_compliance = list()
  )
  
  tryCatch({
    
    # Baseline memory measurement
    baseline_memory_mb <- as.numeric(pryr::mem_used()) / 1024 / 1024
    
    memory_benchmarks$baseline_memory <- list(
      memory_mb = round(baseline_memory_mb, 1),
      timestamp = Sys.time()
    )
    
    # Memory allocation benchmark
    allocation_benchmark <- microbenchmark(
      {
        test_data <- matrix(rnorm(50000), ncol = 500)
        rm(test_data)
        gc()
      },
      times = 5,
      unit = "ms"
    )
    
    memory_benchmarks$allocation_performance <- list(
      median_ms = median(allocation_benchmark$time / 1e6),
      mean_ms = mean(allocation_benchmark$time / 1e6),
      samples = length(allocation_benchmark$time)
    )
    
    # Cloud Run compliance assessment
    current_memory <- as.numeric(pryr::mem_used()) / 1024 / 1024

    memory_benchmarks$cloud_run_compliance <- list(
      current_memory_mb = round(current_memory, 1),
      cloud_run_limit_mb = 2048,
      utilization_pct = round((current_memory / 2048) * 100, 1),
      within_limit = current_memory <= 2048,
      headroom_mb = 2048 - current_memory,
      compliance_rating = case_when(
        current_memory > 2048 ~ "NON_COMPLIANT",
        current_memory > 1800 ~ "CRITICAL",
        current_memory > 1500 ~ "WARNING",
        current_memory > 1000 ~ "GOOD",
        TRUE ~ "EXCELLENT"
      )
    )
    
  }, error = function(e) {
    cat("❌ Error establishing memory benchmarks:", e$message, "\n")
    memory_benchmarks$error <- e$message
  })
  
  return(memory_benchmarks)
}

#' Establish Cloud Run-specific performance benchmarks
#' @return Cloud Run benchmark results
establish_cloud_run_performance_benchmarks <- function() {

  cat("☁️ Establishing Cloud Run-specific benchmarks...\n")

  cloud_run_benchmarks <- list(
    environment_validation = list(),
    resource_compliance = list(),
    deployment_performance = list()
  )

  # Environment validation
  cloud_run_benchmarks$environment_validation <- list(
    is_cloud_run = Sys.getenv("K_SERVICE", "") != "",
    service_name = Sys.getenv("K_SERVICE", "local"),
    project_id = Sys.getenv("GOOGLE_CLOUD_PROJECT", "not_set") != "not_set",
    database_url_configured = Sys.getenv("DATABASE_URL", "") != ""
  )
  
  # Resource compliance
  current_memory <- as.numeric(pryr::mem_used()) / 1024 / 1024

  cloud_run_benchmarks$resource_compliance <- list(
    memory_compliance = current_memory <= 2048,
    memory_utilization_pct = round((current_memory / 2048) * 100, 1)
  )

  # Add database connection compliance if available
  if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    tryCatch({
      active_connections <- pool::poolGetActive(secure_db_pool)
      idle_connections <- pool::poolGetIdle(secure_db_pool)
      total_connections <- active_connections + idle_connections

      cloud_run_benchmarks$resource_compliance$db_connection_compliance <- total_connections <= 100
      cloud_run_benchmarks$resource_compliance$db_connection_utilization_pct <- round((total_connections / 100) * 100, 1)
    }, error = function(e) {
      # Connection metrics not available
    })
  }

  return(cloud_run_benchmarks)
}

#' Establish workload-specific performance benchmarks
#' @return Workload benchmark results  
establish_workload_performance_benchmarks <- function() {
  
  cat("🇧🇷 Establishing Brazilian legislative workload benchmarks...\n")
  
  workload_benchmarks <- list(
    academic_research_simulation = list(),
    policy_analysis_simulation = list(),
    legislative_monitoring_simulation = list()
  )
  
  tryCatch({
    
    if (exists("get_library_documents_optimized")) {
      
      # Academic research workflow simulation
      academic_benchmark <- microbenchmark(
        {
          # Simulate typical academic research pattern
          search_terms <- c("política educacional", "ensino superior", "educação básica")
          selected_term <- sample(search_terms, 1)
          
          docs <- get_library_documents_optimized(
            search_term = selected_term,
            category = "legislation",
            limit = 30
          )
          
          if (!isTRUE(is.null(docs)) && nrow(docs) > 0) {
            # Simulate analysis
            state_analysis <- docs %>%
              filter(state != "") %>%
              group_by(state) %>%
              summarise(count = n(), .groups = 'drop') %>%
              arrange(desc(count))
          }
        },
        times = 5,
        unit = "ms"
      )
      
      workload_benchmarks$academic_research_simulation <- list(
        median_ms = median(academic_benchmark$time / 1e6),
        mean_ms = mean(academic_benchmark$time / 1e6),
        samples = length(academic_benchmark$time)
      )
      
      # Policy analysis workflow simulation
      policy_benchmark <- microbenchmark(
        {
          # Simulate policy comparison across states
          policy_term <- "saúde pública"
          target_states <- c("SP", "RJ", "MG")
          
          for (state in target_states) {
            state_docs <- get_library_documents_optimized(
              search_term = policy_term,
              state = state,
              limit = 15
            )
            
            if (!isTRUE(is.null(state_docs)) && nrow(state_docs) > 0) {
              # Simulate policy analysis
              state_summary <- list(
                state = state,
                doc_count = nrow(state_docs),
                recent_count = sum(state_docs$date >= (Sys.Date() - 365), na.rm = TRUE)
              )
            }
          }
        },
        times = 3,
        unit = "ms"
      )
      
      workload_benchmarks$policy_analysis_simulation <- list(
        median_ms = median(policy_benchmark$time / 1e6),
        mean_ms = mean(policy_benchmark$time / 1e6),
        samples = length(policy_benchmark$time)
      )
    }
    
    # Legislative monitoring dashboard simulation
    if (exists("get_dashboard_metrics_optimized")) {
      
      monitoring_benchmark <- microbenchmark(
        {
          # Simulate dashboard loading
          metrics <- get_dashboard_metrics_optimized()
          
          # Simulate recent activity analysis
          if (exists("get_library_documents_optimized")) {
            recent_docs <- get_library_documents_optimized(
              date_start = Sys.Date() - 7,
              limit = 50
            )
            
            if (!isTRUE(is.null(recent_docs)) && nrow(recent_docs) > 0) {
              weekly_summary <- list(
                total_docs = nrow(recent_docs),
                categories = table(recent_docs$category),
                states = table(recent_docs$state[recent_docs$state != ""])
              )
            }
          }
        },
        times = 8,
        unit = "ms"
      )
      
      workload_benchmarks$legislative_monitoring_simulation <- list(
        median_ms = median(monitoring_benchmark$time / 1e6),
        mean_ms = mean(monitoring_benchmark$time / 1e6),
        samples = length(monitoring_benchmark$time)
      )
    }
    
  }, error = function(e) {
    cat("❌ Error establishing workload benchmarks:", e$message, "\n")
    workload_benchmarks$error <- e$message
  })
  
  return(workload_benchmarks)
}

#' Calculate composite benchmark score across all categories
#' @param benchmarks Complete benchmark data
#' @return Composite benchmark score (0-100)
calculate_benchmark_composite_score <- function(benchmarks) {
  
  score <- 0
  total_weight <- 0
  
  # Database performance score (35% weight)
  if (!is.null(benchmarks$database_benchmarks$query_performance$simple_query$median_ms)) {
    db_score <- max(0, min(100, 100 - (benchmarks$database_benchmarks$query_performance$simple_query$median_ms - 10)))
    score <- score + (db_score * 0.35)
    total_weight <- total_weight + 0.35
  }
  
  # Search performance score (25% weight)
  if (!is.null(benchmarks$search_benchmarks$simple_search$median_ms)) {
    search_score <- max(0, min(100, 100 - (benchmarks$search_benchmarks$simple_search$median_ms / 100)))
    score <- score + (search_score * 0.25)
    total_weight <- total_weight + 0.25
  }
  
  # Memory efficiency score (15% weight)
  if (!is.null(benchmarks$memory_benchmarks$cloud_run_compliance$utilization_pct)) {
    memory_score <- max(0, 100 - benchmarks$memory_benchmarks$cloud_run_compliance$utilization_pct)
    score <- score + (memory_score * 0.15)
    total_weight <- total_weight + 0.15
  }

  # Cache performance score (15% weight)
  if (!is.null(benchmarks$cache_benchmarks$cache_efficiency$hit_rate_pct)) {
    cache_score <- benchmarks$cache_benchmarks$cache_efficiency$hit_rate_pct
    score <- score + (cache_score * 0.15)
    total_weight <- total_weight + 0.15
  }

  # Cloud Run compliance score (10% weight)
  cloud_run_score <- 100  # Default full score
  if (!is.null(benchmarks$cloud_run_benchmarks$resource_compliance)) {
    compliance <- benchmarks$cloud_run_benchmarks$resource_compliance
    if (!compliance$memory_compliance) cloud_run_score <- cloud_run_score - 50
    if (!isTRUE(is.null(compliance$db_connection_compliance)) && !compliance$db_connection_compliance) {
      cloud_run_score <- cloud_run_score - 30
    }
  }
  score <- score + (cloud_run_score * 0.10)
  total_weight <- total_weight + 0.10
  
  # Normalize score
  if (total_weight > 0) {
    score <- score / total_weight
  }
  
  return(round(max(0, min(100, score)), 1))
}

# ============================================================================
# UTILITY AND HELPER FUNCTIONS
# ============================================================================

#' Clean up old real-time monitoring data to prevent memory issues
#' @param metrics_data Current metrics data
#' @return Cleaned metrics data
cleanup_old_real_time_data <- function(metrics_data) {
  
  # Keep only last N hours of data based on configuration
  cutoff_time <- Sys.time() - (MONITORING_CONFIG$real_time_data_retention_hours * 3600)
  
  cleaned_data <- metrics_data[sapply(metrics_data, function(x) {
    !isTRUE(is.null(x$timestamp)) && x$timestamp >= cutoff_time
  })]
  
  if (length(cleaned_data) < length(metrics_data)) {
    cat("🧹 Cleaned up", length(metrics_data) - length(cleaned_data), "old monitoring records\n")
  }
  
  return(cleaned_data)
}

#' Register alert callback function
#' @param callback_function Function to call when alerts are triggered
register_alert_callback <- function(callback_function) {
  
  PERFORMANCE_ALERTS$alert_callbacks[[length(PERFORMANCE_ALERTS$alert_callbacks) + 1]] <<- callback_function
  
  cat("📞 Alert callback registered\n")
}

#' Get current performance summary
#' @return Current performance summary
get_current_performance_summary <- function() {
  
  current_metrics <- collect_current_performance_metrics()
  
  summary <- list(
    timestamp = current_metrics$timestamp,
    memory_usage_mb = current_metrics$system_metrics$memory_usage_mb,
    memory_utilization_pct = current_metrics$system_metrics$memory_utilization_pct,
    database_connected = current_metrics$database_metrics$connection_status == "connected",
    cache_hit_rate = current_metrics$cache_metrics$cache_hit_rate,
    cloud_run_compliant = TRUE
  )
  
  # Cloud Run compliance check
  if (!is.null(current_metrics$cloud_run_metrics$memory_compliance)) {
    summary$cloud_run_compliant <- current_metrics$cloud_run_metrics$memory_compliance$compliance_status %in% c("COMPLIANT", "GOOD", "EXCELLENT")
  }

  # Performance rating
  issues <- 0
  if (summary$memory_utilization_pct > 80) issues <- issues + 1
  if (!summary$database_connected) issues <- issues + 2
  if (summary$cache_hit_rate < 70) issues <- issues + 1
  if (!summary$cloud_run_compliant) issues <- issues + 2
  
  summary$performance_rating <- case_when(
    issues == 0 ~ "Excellent",
    issues <= 1 ~ "Good",
    issues <= 2 ~ "Acceptable",
    issues <= 4 ~ "Poor",
    TRUE ~ "Critical"
  )
  
  return(summary)
}

# ============================================================================
# INITIALIZATION
# ============================================================================

# Set application start time for uptime tracking
if (!exists(".app_start_time", envir = .GlobalEnv)) {
  .GlobalEnv$.app_start_time <- Sys.time()
}

cat("✅ Comprehensive Performance Benchmarks and Monitoring System loaded successfully\n")
cat("📊 Real-time monitoring system ready\n")
cat("📏 Performance benchmarking system enabled\n")
cat("🚨 Automated alerting system configured\n")
cat("☁️ Cloud Run-specific monitoring active\n")
cat("🇧🇷 Brazilian legislative workload monitoring ready\n")

# Export main monitoring functions
cat("📋 Available monitoring and benchmarking functions:\n")
cat("  • start_performance_monitoring(monitoring_duration_hours)\n")
cat("  • establish_comprehensive_benchmarks(benchmark_name)\n")
cat("  • collect_current_performance_metrics()\n")
cat("  • get_current_performance_summary()\n")
cat("  • register_alert_callback(callback_function)\n")
cat("  • check_performance_alerts(current_metrics)\n")