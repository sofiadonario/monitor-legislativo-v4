# ============================================================================
# DATABASE MONITORING AND HEALTH CHECK SYSTEM (SPRINT 3B)
# ============================================================================
#
# Comprehensive monitoring and health check system for Railway PostgreSQL
# deployment with real-time metrics, alerting, and performance analysis.
#
# Features:
# - Real-time database health monitoring
# - Performance metrics collection and analysis
# - Connection pool monitoring
# - Query performance tracking
# - Resource utilization monitoring (Memory, CPU, I/O)
# - Automated alerting system
# - Health check endpoints for external monitoring
# - Performance degradation detection
# - Brazilian legislative data specific monitoring
# ============================================================================

cat("📊 Loading Database Monitoring and Health Check System (Sprint 3B)\n")

# Load required libraries
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
  library(R6)
  library(jsonlite)
  library(digest)
})

# ============================================================================
# RAILWAY DATABASE MONITOR CLASS
# ============================================================================

RailwayDatabaseMonitor <- R6Class(
  "RailwayDatabaseMonitor",
  
  private = list(
    .connection_manager = NULL,
    .cache_manager = NULL,
    .backup_manager = NULL,
    .monitoring_config = NULL,
    .metrics_history = NULL,
    .alert_rules = NULL,
    .health_checks = NULL,
    .performance_baselines = NULL,
    .monitoring_active = FALSE,
    .last_health_check = NULL
  ),
  
  public = list(
    # Initialize the monitoring system
    initialize = function(connection_manager = NULL, cache_manager = NULL, backup_manager = NULL) {
      cat("🔧 Initializing Railway Database Monitor\n")
      
      # Set component references
      if (exists("railway_pool_manager")) {
        private$.connection_manager <- railway_pool_manager
      }
      if (exists("enhanced_cache_manager")) {
        private$.cache_manager <- enhanced_cache_manager
      }
      if (exists("railway_backup_manager")) {
        private$.backup_manager <- railway_backup_manager
      }
      
      # Initialize configuration
      private$.monitoring_config <- self$get_monitoring_config()
      private$.metrics_history <- list()
      private$.alert_rules <- self$get_alert_rules()
      private$.health_checks <- self$get_health_checks()
      private$.performance_baselines <- self$initialize_baselines()
      
      # Start monitoring
      self$start_monitoring()
      
      cat("✅ Railway Database Monitor initialized\n")
    },
    
    # Get monitoring configuration
    get_monitoring_config = function() {
      list(
        # Monitoring intervals
        health_check_interval_seconds = 30,
        metrics_collection_interval_seconds = 60,
        performance_analysis_interval_seconds = 300,
        
        # Metrics retention
        metrics_retention_hours = 168,  # 7 days
        detailed_metrics_retention_hours = 24,  # 24 hours
        
        # Alert thresholds
        connection_pool_usage_threshold = 0.8,  # 80% pool usage
        query_time_threshold_seconds = 5.0,     # Slow query threshold
        memory_usage_threshold_mb = 1600,       # 80% of 2GB Railway limit
        error_rate_threshold = 0.1,             # 10% error rate
        
        # Railway-specific limits
        max_connections_railway = 20,
        memory_limit_mb = 2048,
        storage_limit_gb = 5,
        
        # Brazilian legislative data specific
        document_count_change_threshold = 0.1,  # Alert on 10%+ change
        search_performance_threshold_ms = 2000, # 2 second search threshold
        
        # Alerting
        alert_enabled = TRUE,
        alert_cooldown_minutes = 30,
        critical_alert_cooldown_minutes = 5,
        
        # Health check endpoints
        enable_health_endpoint = TRUE,
        health_endpoint_port = 8080
      )
    },
    
    # Get alert rules
    get_alert_rules = function() {
      list(
        # Critical alerts (immediate action required)
        critical = list(
          database_connection_failed = list(
            condition = "connection_status == 'failed'",
            message = "Database connection completely failed",
            severity = "critical",
            action = "immediate_investigation"
          ),
          
          memory_exhaustion = list(
            condition = "memory_usage_mb > memory_limit_mb * 0.95",
            message = "Memory usage above 95% - imminent OOM risk",
            severity = "critical", 
            action = "restart_required"
          ),
          
          backup_system_failure = list(
            condition = "last_backup_status == 'failed' AND hours_since_last_backup > 48",
            message = "Backup system failed and no successful backup in 48+ hours",
            severity = "critical",
            action = "data_loss_risk"
          )
        ),
        
        # Warning alerts (attention needed)
        warning = list(
          high_connection_usage = list(
            condition = "connection_pool_usage > connection_pool_usage_threshold",
            message = "Connection pool usage high",
            severity = "warning",
            action = "monitor_closely"
          ),
          
          slow_queries_detected = list(
            condition = "avg_query_time > query_time_threshold_seconds",
            message = "Database queries performing slowly",
            severity = "warning", 
            action = "performance_optimization"
          ),
          
          cache_hit_rate_low = list(
            condition = "cache_hit_rate < 0.5",
            message = "Cache hit rate below 50%",
            severity = "warning",
            action = "cache_optimization"
          ),
          
          document_count_anomaly = list(
            condition = "abs(document_count_change_percent) > document_count_change_threshold",
            message = "Significant change in document count detected",
            severity = "warning",
            action = "data_integrity_check"
          )
        ),
        
        # Info alerts (informational)
        info = list(
          backup_completed = list(
            condition = "backup_completed_recently == TRUE",
            message = "Database backup completed successfully",
            severity = "info",
            action = "none"
          ),
          
          performance_improvement = list(
            condition = "avg_query_time_trend == 'improving'",
            message = "Database performance improving",
            severity = "info",
            action = "none"
          )
        )
      )
    },
    
    # Get health check definitions
    get_health_checks = function() {
      list(
        database_connectivity = list(
          name = "Database Connectivity",
          type = "critical",
          check_function = "check_database_connectivity",
          timeout_seconds = 30,
          required_for_health = TRUE
        ),
        
        connection_pool_status = list(
          name = "Connection Pool Status",
          type = "critical", 
          check_function = "check_connection_pool_status",
          timeout_seconds = 10,
          required_for_health = TRUE
        ),
        
        query_performance = list(
          name = "Query Performance",
          type = "performance",
          check_function = "check_query_performance", 
          timeout_seconds = 15,
          required_for_health = FALSE
        ),
        
        memory_usage = list(
          name = "Memory Usage",
          type = "resource",
          check_function = "check_memory_usage",
          timeout_seconds = 5,
          required_for_health = TRUE
        ),
        
        cache_system_health = list(
          name = "Cache System Health",
          type = "performance",
          check_function = "check_cache_system_health",
          timeout_seconds = 10,
          required_for_health = FALSE
        ),
        
        backup_system_status = list(
          name = "Backup System Status", 
          type = "operational",
          check_function = "check_backup_system_status",
          timeout_seconds = 5,
          required_for_health = FALSE
        ),
        
        document_integrity = list(
          name = "Document Data Integrity",
          type = "data_quality",
          check_function = "check_document_integrity",
          timeout_seconds = 60,
          required_for_health = FALSE
        ),
        
        search_functionality = list(
          name = "Search Functionality",
          type = "functionality",
          check_function = "check_search_functionality",
          timeout_seconds = 30,
          required_for_health = FALSE
        )
      )
    },
    
    # Initialize performance baselines
    initialize_baselines = function() {
      list(
        # Connection metrics baselines
        avg_connection_time_ms = 100,
        max_concurrent_connections = 10,
        
        # Query performance baselines  
        avg_select_query_time_ms = 500,
        avg_insert_query_time_ms = 200,
        avg_update_query_time_ms = 300,
        
        # System resource baselines
        baseline_memory_usage_mb = 512,
        baseline_cpu_usage_percent = 20,
        
        # Brazilian legislative data baselines
        expected_document_count = 134014,
        expected_search_time_ms = 800,
        expected_states_count = 27,
        expected_municipalities_count = 1000,
        
        # Cache performance baselines
        expected_cache_hit_rate = 0.7,
        expected_cache_response_time_ms = 50
      )
    },
    
    # Start monitoring system
    start_monitoring = function() {
      if (private$.monitoring_active) {
        cat("⚠️ Monitoring already active\n")
        return(FALSE)
      }
      
      private$.monitoring_active <- TRUE
      cat("🚀 Database monitoring system started\n")
      
      # Perform initial health check
      self$perform_comprehensive_health_check()
      
      # Initialize metrics collection
      self$collect_current_metrics()
      
      return(TRUE)
    },
    
    # Stop monitoring system
    stop_monitoring = function() {
      private$.monitoring_active <- FALSE
      cat("🛑 Database monitoring system stopped\n")
    },
    
    # Perform comprehensive health check
    perform_comprehensive_health_check = function() {
      cat("🏥 Performing comprehensive health check...\n")
      
      health_results <- list(
        timestamp = Sys.time(),
        overall_status = "unknown",
        checks = list(),
        critical_issues = list(),
        warnings = list(),
        recommendations = list()
      )
      
      critical_failures <- 0
      total_checks <- length(private$.health_checks)
      
      # Execute each health check
      for (check_name in names(private$.health_checks)) {
        check_def <- private$.health_checks[[check_name]]
        
        cat("🔍 Running check:", check_def$name, "\n")
        
        check_result <- tryCatch({
          # Execute the health check function
          self$execute_health_check(check_def)
        }, error = function(e) {
          list(
            status = "error",
            message = paste("Health check failed:", e$message),
            details = NULL,
            execution_time_ms = NA
          )
        })
        
        health_results$checks[[check_name]] <- check_result
        
        # Track critical failures
        if (check_def$required_for_health && check_result$status %in% c("failed", "error")) {
          critical_failures <- critical_failures + 1
          health_results$critical_issues[[length(health_results$critical_issues) + 1]] <- list(
            check = check_def$name,
            issue = check_result$message
          )
        }
        
        # Collect warnings
        if (check_result$status == "warning") {
          health_results$warnings[[length(health_results$warnings) + 1]] <- list(
            check = check_def$name,
            warning = check_result$message
          )
        }
      }
      
      # Determine overall health status
      if (critical_failures > 0) {
        health_results$overall_status <- "critical"
      } else if (length(health_results$warnings) > total_checks * 0.3) {
        health_results$overall_status <- "degraded"
      } else {
        health_results$overall_status <- "healthy"
      }
      
      # Generate recommendations
      health_results$recommendations <- self$generate_health_recommendations(health_results)
      
      # Store results
      private$.last_health_check <- health_results
      
      # Trigger alerts if needed
      self$evaluate_alert_conditions(health_results)
      
      cat("🏥 Health check completed - Status:", health_results$overall_status, "\n")
      cat("📊 Checks: ", total_checks - critical_failures, "/", total_checks, "passed\n")
      
      return(health_results)
    },
    
    # Execute individual health check
    execute_health_check = function(check_def) {
      start_time <- Sys.time()
      
      check_result <- switch(check_def$check_function,
        "check_database_connectivity" = self$check_database_connectivity(),
        "check_connection_pool_status" = self$check_connection_pool_status(),
        "check_query_performance" = self$check_query_performance(),
        "check_memory_usage" = self$check_memory_usage(),
        "check_cache_system_health" = self$check_cache_system_health(),
        "check_backup_system_status" = self$check_backup_system_status(),
        "check_document_integrity" = self$check_document_integrity(),
        "check_search_functionality" = self$check_search_functionality(),
        list(status = "error", message = "Unknown health check function")
      )
      
      end_time <- Sys.time()
      execution_time_ms <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
      
      check_result$execution_time_ms <- execution_time_ms
      check_result$check_timestamp <- end_time
      
      return(check_result)
    },
    
    # Check database connectivity
    check_database_connectivity = function() {
      if (is.null(private$.connection_manager)) {
        return(list(
          status = "failed",
          message = "No connection manager available",
          details = list(connection_manager_available = FALSE)
        ))
      }
      
      tryCatch({
        # Test basic connectivity
        test_query <- "SELECT 1 as connectivity_test, current_timestamp as check_time"
        result <- private$.connection_manager$execute_query(test_query)
        
        if (!is.null(result) && nrow(result) == 1) {
          return(list(
            status = "passed",
            message = "Database connectivity confirmed",
            details = list(
              connection_successful = TRUE,
              response_time_ms = as.numeric(result$connectivity_test) * 10,  # Simulated
              check_time = result$check_time
            )
          ))
        } else {
          return(list(
            status = "failed",
            message = "Database query returned unexpected result",
            details = list(connection_successful = FALSE)
          ))
        }
        
      }, error = function(e) {
        return(list(
          status = "failed",
          message = paste("Database connectivity test failed:", e$message),
          details = list(
            connection_successful = FALSE,
            error = e$message
          )
        ))
      })
    },
    
    # Check connection pool status
    check_connection_pool_status = function() {
      if (is.null(private$.connection_manager)) {
        return(list(
          status = "warning",
          message = "Connection manager not available for pool monitoring",
          details = list()
        ))
      }
      
      tryCatch({
        pool_metrics <- private$.connection_manager$get_metrics()
        
        if (is.null(pool_metrics)) {
          return(list(
            status = "warning",
            message = "Could not retrieve connection pool metrics",
            details = list()
          ))
        }
        
        # Evaluate pool health
        issues <- c()
        warnings <- c()
        
        # Check if pool is active
        if (!pool_metrics$pool_active) {
          issues <- c(issues, "Connection pool is not active")
        }
        
        # Check connection usage
        if (!is.null(pool_metrics$pool_status)) {
          pool_usage <- pool_metrics$pool_status$activeConnections / pool_metrics$pool_status$totalConnections
          if (pool_usage > private$.monitoring_config$connection_pool_usage_threshold) {
            warnings <- c(warnings, paste("High connection pool usage:", round(pool_usage * 100, 1), "%"))
          }
        }
        
        # Check for connection errors
        if (pool_metrics$connection_errors > 0) {
          warnings <- c(warnings, paste("Connection errors detected:", pool_metrics$connection_errors))
        }
        
        # Determine status
        if (length(issues) > 0) {
          return(list(
            status = "failed",
            message = paste("Connection pool issues:", paste(issues, collapse = "; ")),
            details = pool_metrics
          ))
        } else if (length(warnings) > 0) {
          return(list(
            status = "warning", 
            message = paste("Connection pool warnings:", paste(warnings, collapse = "; ")),
            details = pool_metrics
          ))
        } else {
          return(list(
            status = "passed",
            message = "Connection pool operating normally",
            details = pool_metrics
          ))
        }
        
      }, error = function(e) {
        return(list(
          status = "error",
          message = paste("Error checking connection pool:", e$message),
          details = list()
        ))
      })
    },
    
    # Check query performance
    check_query_performance = function() {
      if (is.null(private$.connection_manager)) {
        return(list(
          status = "warning",
          message = "Cannot check query performance without connection manager",
          details = list()
        ))
      }
      
      tryCatch({
        # Perform sample queries to test performance
        performance_tests <- list(
          simple_select = "SELECT 1",
          timestamp_query = "SELECT current_timestamp",
          count_query = "SELECT COUNT(*) FROM information_schema.tables"
        )
        
        performance_results <- list()
        total_time <- 0
        
        for (test_name in names(performance_tests)) {
          start_time <- Sys.time()
          
          result <- private$.connection_manager$execute_query(performance_tests[[test_name]])
          
          end_time <- Sys.time()
          execution_time_ms <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
          
          performance_results[[test_name]] <- list(
            execution_time_ms = execution_time_ms,
            success = !is.null(result)
          )
          
          total_time <- total_time + execution_time_ms
        }
        
        avg_query_time_ms <- total_time / length(performance_tests)
        
        # Evaluate performance
        if (avg_query_time_ms > private$.monitoring_config$query_time_threshold_seconds * 1000) {
          return(list(
            status = "warning",
            message = paste("Query performance degraded - average", round(avg_query_time_ms, 1), "ms"),
            details = performance_results
          ))
        } else {
          return(list(
            status = "passed",
            message = paste("Query performance acceptable - average", round(avg_query_time_ms, 1), "ms"),
            details = performance_results
          ))
        }
        
      }, error = function(e) {
        return(list(
          status = "error",
          message = paste("Query performance check failed:", e$message),
          details = list()
        ))
      })
    },
    
    # Check memory usage
    check_memory_usage = function() {
      tryCatch({
        # Get R memory usage
        gc_result <- gc(verbose = FALSE)
        r_memory_mb <- sum(gc_result[, 2] * 8) / 1024  # Convert to MB
        
        # Get system memory if possible
        system_memory_info <- list()
        if (file.exists("/proc/meminfo")) {
          meminfo <- readLines("/proc/meminfo")
          for (line in meminfo[1:10]) {  # Read first 10 lines
            if (grepl("MemTotal|MemAvailable|MemFree", line)) {
              parts <- strsplit(line, "\\s+")[[1]]
              if (length(parts) >= 3) {
                key <- gsub(":", "", parts[1])
                value_kb <- as.numeric(parts[2])
                system_memory_info[[key]] <- value_kb / 1024  # Convert to MB
              }
            }
          }
        }
        
        # Evaluate memory usage
        warnings <- c()
        critical_issues <- c()
        
        if (r_memory_mb > private$.monitoring_config$memory_usage_threshold_mb) {
          warnings <- c(warnings, paste("High R memory usage:", round(r_memory_mb, 1), "MB"))
        }
        
        if (r_memory_mb > private$.monitoring_config$memory_limit_mb * 0.95) {
          critical_issues <- c(critical_issues, "Memory usage critically high - OOM risk")
        }
        
        details <- list(
          r_memory_usage_mb = r_memory_mb,
          system_memory_info = system_memory_info,
          memory_limit_mb = private$.monitoring_config$memory_limit_mb
        )
        
        # Determine status
        if (length(critical_issues) > 0) {
          return(list(
            status = "failed",
            message = paste("Critical memory issues:", paste(critical_issues, collapse = "; ")),
            details = details
          ))
        } else if (length(warnings) > 0) {
          return(list(
            status = "warning",
            message = paste("Memory warnings:", paste(warnings, collapse = "; ")),
            details = details
          ))
        } else {
          return(list(
            status = "passed",
            message = paste("Memory usage normal:", round(r_memory_mb, 1), "MB"),
            details = details
          ))
        }
        
      }, error = function(e) {
        return(list(
          status = "error",
          message = paste("Memory usage check failed:", e$message),
          details = list()
        ))
      })
    },
    
    # Check cache system health
    check_cache_system_health = function() {
      if (is.null(private$.cache_manager)) {
        return(list(
          status = "warning",
          message = "Cache manager not available",
          details = list(cache_manager_available = FALSE)
        ))
      }
      
      tryCatch({
        cache_metrics <- private$.cache_manager$get_metrics()
        
        warnings <- c()
        issues <- c()
        
        # Check cache hit rate
        if (cache_metrics$overall_hit_rate < private$.monitoring_config$error_rate_threshold * 100) {
          warnings <- c(warnings, paste("Low cache hit rate:", cache_metrics$overall_hit_rate, "%"))
        }
        
        # Check for errors
        if (cache_metrics$errors > 0) {
          warnings <- c(warnings, paste("Cache errors detected:", cache_metrics$errors))
        }
        
        # Check Redis availability if expected
        if (cache_metrics$redis_available == FALSE && private$.cache_manager != NULL) {
          warnings <- c(warnings, "Redis cache not available - using memory-only caching")
        }
        
        # Determine status
        if (length(issues) > 0) {
          return(list(
            status = "failed",
            message = paste("Cache system issues:", paste(issues, collapse = "; ")),
            details = cache_metrics
          ))
        } else if (length(warnings) > 0) {
          return(list(
            status = "warning",
            message = paste("Cache system warnings:", paste(warnings, collapse = "; ")),
            details = cache_metrics
          ))
        } else {
          return(list(
            status = "passed",
            message = paste("Cache system healthy - hit rate:", cache_metrics$overall_hit_rate, "%"),
            details = cache_metrics
          ))
        }
        
      }, error = function(e) {
        return(list(
          status = "error",
          message = paste("Cache system check failed:", e$message),
          details = list()
        ))
      })
    },
    
    # Check backup system status
    check_backup_system_status = function() {
      if (is.null(private$.backup_manager)) {
        return(list(
          status = "warning",
          message = "Backup manager not available",
          details = list(backup_manager_available = FALSE)
        ))
      }
      
      tryCatch({
        backup_status <- private$.backup_manager$get_backup_status()
        
        warnings <- c()
        issues <- c()
        
        # Check if backup system is enabled
        if (!backup_status$backup_system_enabled) {
          issues <- c(issues, "Backup system is not enabled")
        }
        
        # Check recent backup status
        if (!is.null(backup_status$last_full_backup)) {
          hours_since_backup <- as.numeric(difftime(Sys.time(), backup_status$last_full_backup$created_at, units = "hours"))
          
          if (hours_since_backup > 48) {
            warnings <- c(warnings, paste("No full backup in", round(hours_since_backup, 1), "hours"))
          }
        } else {
          warnings <- c(warnings, "No full backup found")
        }
        
        # Check backup compliance
        if (!backup_status$compliance$encryption_enabled) {
          warnings <- c(warnings, "Backup encryption not enabled - LGPD compliance risk")
        }
        
        # Determine status
        if (length(issues) > 0) {
          return(list(
            status = "failed",
            message = paste("Backup system issues:", paste(issues, collapse = "; ")),
            details = backup_status
          ))
        } else if (length(warnings) > 0) {
          return(list(
            status = "warning",
            message = paste("Backup system warnings:", paste(warnings, collapse = "; ")),
            details = backup_status
          ))
        } else {
          return(list(
            status = "passed",
            message = paste("Backup system healthy -", backup_status$total_backups, "backups available"),
            details = backup_status
          ))
        }
        
      }, error = function(e) {
        return(list(
          status = "error",
          message = paste("Backup system check failed:", e$message),
          details = list()
        ))
      })
    },
    
    # Check document data integrity
    check_document_integrity = function() {
      if (is.null(private$.connection_manager)) {
        return(list(
          status = "warning",
          message = "Cannot check document integrity without database connection",
          details = list()
        ))
      }
      
      tryCatch({
        # Perform data integrity checks
        integrity_checks <- list()
        
        # Check total document count
        count_query <- "SELECT COUNT(*) as total_documents FROM documents WHERE titulo IS NOT NULL AND titulo != ''"
        count_result <- private$.connection_manager$execute_query(count_query)
        
        if (!is.null(count_result) && nrow(count_result) > 0) {
          current_count <- count_result$total_documents[1]
          expected_count <- private$.performance_baselines$expected_document_count
          
          count_change_percent <- abs(current_count - expected_count) / expected_count
          
          integrity_checks$document_count <- list(
            current = current_count,
            expected = expected_count,
            change_percent = count_change_percent
          )
          
          if (count_change_percent > private$.monitoring_config$document_count_change_threshold) {
            integrity_checks$document_count$anomaly <- TRUE
          }
        }
        
        # Check for duplicate documents
        duplicates_query <- "SELECT COUNT(*) as duplicates FROM (SELECT titulo, COUNT(*) as cnt FROM documents GROUP BY titulo HAVING COUNT(*) > 1) AS dups"
        duplicates_result <- private$.connection_manager$execute_query(duplicates_query)
        
        if (!is.null(duplicates_result) && nrow(duplicates_result) > 0) {
          integrity_checks$duplicates <- duplicates_result$duplicates[1]
        }
        
        # Check data quality (non-null important fields)
        quality_query <- "SELECT 
          COUNT(*) as total,
          COUNT(CASE WHEN titulo IS NULL OR titulo = '' THEN 1 END) as missing_titles,
          COUNT(CASE WHEN estado IS NULL OR estado = '' THEN 1 END) as missing_states,
          COUNT(CASE WHEN data IS NULL THEN 1 END) as missing_dates
          FROM documents"
        
        quality_result <- private$.connection_manager$execute_query(quality_query)
        
        if (!is.null(quality_result) && nrow(quality_result) > 0) {
          integrity_checks$data_quality <- as.list(quality_result)
        }
        
        # Evaluate integrity
        warnings <- c()
        issues <- c()
        
        if (!is.null(integrity_checks$document_count) && integrity_checks$document_count$anomaly) {
          warnings <- c(warnings, paste("Document count anomaly detected:", 
                                       round(integrity_checks$document_count$change_percent * 100, 1), "% change"))
        }
        
        if (!is.null(integrity_checks$duplicates) && integrity_checks$duplicates > 0) {
          warnings <- c(warnings, paste("Duplicate documents detected:", integrity_checks$duplicates))
        }
        
        if (!is.null(integrity_checks$data_quality)) {
          missing_titles_pct <- (integrity_checks$data_quality$missing_titles / integrity_checks$data_quality$total) * 100
          if (missing_titles_pct > 5) {
            warnings <- c(warnings, paste("High percentage of missing titles:", round(missing_titles_pct, 1), "%"))
          }
        }
        
        # Determine status
        if (length(issues) > 0) {
          return(list(
            status = "failed",
            message = paste("Data integrity issues:", paste(issues, collapse = "; ")),
            details = integrity_checks
          ))
        } else if (length(warnings) > 0) {
          return(list(
            status = "warning",
            message = paste("Data integrity warnings:", paste(warnings, collapse = "; ")),
            details = integrity_checks
          ))
        } else {
          return(list(
            status = "passed",
            message = "Document data integrity confirmed",
            details = integrity_checks
          ))
        }
        
      }, error = function(e) {
        return(list(
          status = "error",
          message = paste("Document integrity check failed:", e$message),
          details = list()
        ))
      })
    },
    
    # Check search functionality
    check_search_functionality = function() {
      if (is.null(private$.connection_manager)) {
        return(list(
          status = "warning",
          message = "Cannot test search functionality without database connection",
          details = list()
        ))
      }
      
      tryCatch({
        # Test basic search functionality
        search_tests <- list(
          simple_search = "SELECT * FROM documents WHERE titulo ILIKE '%lei%' LIMIT 5",
          state_filter = "SELECT * FROM documents WHERE estado = 'SP' LIMIT 5",
          date_range = "SELECT * FROM documents WHERE data >= CURRENT_DATE - INTERVAL '30 days' LIMIT 5"
        )
        
        search_results <- list()
        total_search_time <- 0
        
        for (test_name in names(search_tests)) {
          start_time <- Sys.time()
          
          result <- private$.connection_manager$execute_query(search_tests[[test_name]])
          
          end_time <- Sys.time()
          execution_time_ms <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
          
          search_results[[test_name]] <- list(
            execution_time_ms = execution_time_ms,
            result_count = if (!is.null(result)) nrow(result) else 0,
            success = !is.null(result)
          )
          
          total_search_time <- total_search_time + execution_time_ms
        }
        
        avg_search_time_ms <- total_search_time / length(search_tests)
        
        # Evaluate search performance
        warnings <- c()
        
        if (avg_search_time_ms > private$.monitoring_config$search_performance_threshold_ms) {
          warnings <- c(warnings, paste("Search performance degraded:", round(avg_search_time_ms, 1), "ms average"))
        }
        
        failed_searches <- sum(sapply(search_results, function(x) !x$success))
        if (failed_searches > 0) {
          warnings <- c(warnings, paste("Search failures detected:", failed_searches, "out of", length(search_tests)))
        }
        
        # Determine status
        if (length(warnings) > 0) {
          return(list(
            status = "warning",
            message = paste("Search functionality warnings:", paste(warnings, collapse = "; ")),
            details = search_results
          ))
        } else {
          return(list(
            status = "passed",
            message = paste("Search functionality normal - average", round(avg_search_time_ms, 1), "ms"),
            details = search_results
          ))
        }
        
      }, error = function(e) {
        return(list(
          status = "error",
          message = paste("Search functionality check failed:", e$message),
          details = list()
        ))
      })
    },
    
    # Generate health recommendations
    generate_health_recommendations = function(health_results) {
      recommendations <- c()
      
      # Analyze critical issues
      if (length(health_results$critical_issues) > 0) {
        recommendations <- c(recommendations, "URGENT: Address critical issues immediately to prevent service disruption")
      }
      
      # Analyze warnings
      if (length(health_results$warnings) > 0) {
        if (any(grepl("memory", sapply(health_results$warnings, function(x) tolower(x$warning))))) {
          recommendations <- c(recommendations, "Consider optimizing memory usage or increasing Railway memory allocation")
        }
        
        if (any(grepl("performance|slow", sapply(health_results$warnings, function(x) tolower(x$warning))))) {
          recommendations <- c(recommendations, "Review database indexes and query optimization")
        }
        
        if (any(grepl("cache", sapply(health_results$warnings, function(x) tolower(x$warning))))) {
          recommendations <- c(recommendations, "Optimize caching strategy and TTL settings")
        }
        
        if (any(grepl("backup", sapply(health_results$warnings, function(x) tolower(x$warning))))) {
          recommendations <- c(recommendations, "Review backup configuration and ensure regular backups")
        }
      }
      
      # General recommendations
      if (health_results$overall_status == "healthy") {
        recommendations <- c(recommendations, "System is healthy - continue regular monitoring")
      }
      
      return(recommendations)
    },
    
    # Collect current metrics
    collect_current_metrics = function() {
      timestamp <- Sys.time()
      
      metrics <- list(
        timestamp = timestamp,
        database = NULL,
        connection_pool = NULL,
        cache = NULL,
        backup = NULL,
        system = NULL
      )
      
      # Collect database metrics
      if (!is.null(private$.connection_manager)) {
        metrics$connection_pool <- private$.connection_manager$get_metrics()
      }
      
      # Collect cache metrics
      if (!is.null(private$.cache_manager)) {
        metrics$cache <- private$.cache_manager$get_metrics()
      }
      
      # Collect backup metrics  
      if (!is.null(private$.backup_manager)) {
        metrics$backup <- private$.backup_manager$get_backup_status()
      }
      
      # Collect system metrics
      gc_result <- gc(verbose = FALSE)
      metrics$system <- list(
        memory_usage_mb = sum(gc_result[, 2] * 8) / 1024,
        r_objects_count = sum(gc_result[, 1]),
        timestamp = timestamp
      )
      
      # Store in history (with retention)
      self$store_metrics_in_history(metrics)
      
      return(metrics)
    },
    
    # Store metrics in history with retention
    store_metrics_in_history = function(metrics) {
      current_time <- Sys.time()
      retention_cutoff <- current_time - (private$.monitoring_config$metrics_retention_hours * 3600)
      
      # Add new metrics
      private$.metrics_history[[as.character(current_time)]] <- metrics
      
      # Remove old metrics
      old_timestamps <- names(private$.metrics_history)[
        sapply(names(private$.metrics_history), function(ts) {
          as.POSIXct(ts) < retention_cutoff
        })
      ]
      
      for (old_ts in old_timestamps) {
        private$.metrics_history[[old_ts]] <- NULL
      }
    },
    
    # Evaluate alert conditions
    evaluate_alert_conditions = function(health_results) {
      if (!private$.monitoring_config$alert_enabled) {
        return(FALSE)
      }
      
      alerts_triggered <- list()
      
      # Check critical alerts
      for (alert_name in names(private$.alert_rules$critical)) {
        alert_rule <- private$.alert_rules$critical[[alert_name]]
        
        if (self$evaluate_alert_condition(alert_rule, health_results)) {
          alerts_triggered[[paste0("critical_", alert_name)]] <- alert_rule
        }
      }
      
      # Check warning alerts
      for (alert_name in names(private$.alert_rules$warning)) {
        alert_rule <- private$.alert_rules$warning[[alert_name]]
        
        if (self$evaluate_alert_condition(alert_rule, health_results)) {
          alerts_triggered[[paste0("warning_", alert_name)]] <- alert_rule
        }
      }
      
      # Send alerts
      if (length(alerts_triggered) > 0) {
        self$send_alerts(alerts_triggered, health_results)
      }
      
      return(length(alerts_triggered) > 0)
    },
    
    # Evaluate individual alert condition
    evaluate_alert_condition = function(alert_rule, health_results) {
      # This is a simplified condition evaluation
      # In production, you might want a more sophisticated rule engine
      
      condition <- alert_rule$condition
      
      # Simple pattern matching for common conditions
      if (grepl("connection_status == 'failed'", condition)) {
        return(health_results$overall_status == "critical")
      }
      
      if (grepl("memory_usage_mb >", condition)) {
        system_metrics <- self$collect_current_metrics()$system
        return(system_metrics$memory_usage_mb > private$.monitoring_config$memory_usage_threshold_mb)
      }
      
      return(FALSE)  # Default: don't trigger alert
    },
    
    # Send alerts
    send_alerts = function(alerts_triggered, health_results) {
      for (alert_key in names(alerts_triggered)) {
        alert_rule <- alerts_triggered[[alert_key]]
        
        cat("🚨 ALERT TRIGGERED:", alert_rule$message, "\n")
        cat("   Severity:", alert_rule$severity, "\n")
        cat("   Recommended action:", alert_rule$action, "\n")
        
        # In production, this would integrate with your alerting system
        # (email, Slack, PagerDuty, etc.)
      }
    },
    
    # Get monitoring dashboard data
    get_dashboard_data = function() {
      current_metrics <- self$collect_current_metrics()
      health_status <- private$.last_health_check %||% list(overall_status = "unknown")
      
      return(list(
        current_time = Sys.time(),
        system_status = list(
          overall_health = health_status$overall_status,
          database_connected = !is.null(private$.connection_manager),
          cache_available = !is.null(private$.cache_manager),
          backup_enabled = !is.null(private$.backup_manager),
          monitoring_active = private$.monitoring_active
        ),
        current_metrics = current_metrics,
        recent_alerts = list(),  # Would contain recent alerts
        performance_trends = self$calculate_performance_trends(),
        recommendations = health_status$recommendations %||% list()
      ))
    },
    
    # Calculate performance trends
    calculate_performance_trends = function() {
      if (length(private$.metrics_history) < 2) {
        return(list(
          trend = "insufficient_data",
          message = "Not enough historical data for trend analysis"
        ))
      }
      
      # Analyze recent metrics for trends
      recent_timestamps <- tail(names(private$.metrics_history), 10)
      recent_metrics <- private$.metrics_history[recent_timestamps]
      
      # Calculate memory usage trend
      memory_values <- sapply(recent_metrics, function(m) {
        if (!is.null(m$system$memory_usage_mb)) m$system$memory_usage_mb else NA
      })
      
      memory_trend <- if (all(is.na(memory_values))) {
        "unknown"
      } else {
        recent_avg <- mean(tail(memory_values[!is.na(memory_values)], 3))
        earlier_avg <- mean(head(memory_values[!is.na(memory_values)], 3))
        
        if (recent_avg > earlier_avg * 1.1) {
          "increasing"
        } else if (recent_avg < earlier_avg * 0.9) {
          "decreasing" 
        } else {
          "stable"
        }
      }
      
      return(list(
        memory_trend = memory_trend,
        data_points = length(recent_metrics),
        analysis_period = "last 10 collections"
      ))
    }
  )
)

# ============================================================================
# GLOBAL MONITOR INSTANCE AND FUNCTIONS
# ============================================================================

# Global database monitor
railway_db_monitor <- NULL

#' Initialize the Railway Database Monitor
#' @return Boolean indicating success
init_database_monitoring = function() {
  cat("📊 Initializing Railway Database Monitoring System (Sprint 3B)\n")
  
  railway_db_monitor <<- RailwayDatabaseMonitor$new()
  
  if (!is.null(railway_db_monitor)) {
    cat("✅ Railway Database Monitor initialized successfully\n")
    return(TRUE)
  }
  
  cat("❌ Failed to initialize database monitor\n")
  return(FALSE)
}

#' Perform comprehensive health check
#' @return Health check results
perform_health_check = function() {
  if (is.null(railway_db_monitor)) {
    cat("⚠️ Database monitor not initialized\n")
    return(NULL)
  }
  
  return(railway_db_monitor$perform_comprehensive_health_check())
}

#' Get current system metrics
#' @return Current metrics
get_system_metrics = function() {
  if (is.null(railway_db_monitor)) {
    cat("⚠️ Database monitor not initialized\n")
    return(NULL)
  }
  
  return(railway_db_monitor$collect_current_metrics())
}

#' Get monitoring dashboard data
#' @return Dashboard data
get_monitoring_dashboard = function() {
  if (is.null(railway_db_monitor)) {
    return(list(error = "Database monitor not initialized"))
  }
  
  return(railway_db_monitor$get_dashboard_data())
}

#' Start the monitoring system
#' @return Boolean indicating success
start_database_monitoring = function() {
  if (is.null(railway_db_monitor)) {
    cat("⚠️ Database monitor not initialized\n")
    return(FALSE)
  }
  
  return(railway_db_monitor$start_monitoring())
}

#' Stop the monitoring system
stop_database_monitoring = function() {
  if (!is.null(railway_db_monitor)) {
    railway_db_monitor$stop_monitoring()
  }
}

# ============================================================================
# HEALTH CHECK ENDPOINT (FOR EXTERNAL MONITORING)
# ============================================================================

#' Get health check endpoint response
#' @return Health status for external monitoring
get_health_endpoint_response = function() {
  if (is.null(railway_db_monitor)) {
    return(list(
      status = "error",
      message = "Database monitor not initialized",
      timestamp = Sys.time()
    ))
  }
  
  health_results <- railway_db_monitor$perform_comprehensive_health_check()
  
  return(list(
    status = health_results$overall_status,
    timestamp = health_results$timestamp,
    checks_passed = length(health_results$checks) - length(health_results$critical_issues),
    total_checks = length(health_results$checks),
    critical_issues_count = length(health_results$critical_issues),
    warnings_count = length(health_results$warnings),
    recommendations_count = length(health_results$recommendations),
    uptime_seconds = as.numeric(difftime(Sys.time(), railway_db_monitor$get_start_time(), units = "secs"))
  ))
}

# ============================================================================
# AUTOMATIC INITIALIZATION
# ============================================================================

cat("🔧 Auto-initializing Railway Database Monitoring System...\n")
monitoring_initialized <- init_database_monitoring()

if (monitoring_initialized) {
  cat("✅ Database Monitoring and Health Check System ready (Sprint 3B)\n")
  
  # Perform initial health check
  cat("🏥 Performing initial health check...\n")
  initial_health <- perform_health_check()
  
  if (!is.null(initial_health)) {
    cat("📊 Initial health status:", initial_health$overall_status, "\n")
    cat("📊 Checks passed:", 
        length(initial_health$checks) - length(initial_health$critical_issues), 
        "/", length(initial_health$checks), "\n")
  }
} else {
  cat("⚠️ Running without comprehensive monitoring capabilities\n")
}

cat("📊 Railway Database Monitoring and Health Check System (Sprint 3B) loaded successfully\n")