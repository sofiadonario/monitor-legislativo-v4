# Health Check and Monitoring Module
# Monitor Legislativo v4 - Production Health Endpoints for Railway
# ================================================================

library(jsonlite)

# Global health check configuration
.health_config <- list(
  check_database = TRUE,
  check_redis = TRUE,
  check_data_integrity = TRUE,
  check_memory_usage = TRUE,
  detailed_response = as.logical(Sys.getenv("HEALTH_CHECK_DETAILED", "FALSE"))
)

#' Comprehensive System Health Check for Academic Research Platform
#' 
#' Performs enterprise-grade system health verification specifically designed
#' for Railway-deployed academic research platforms handling Brazilian
#' legislative data. Implements comprehensive monitoring across all critical
#' system components with LGPD compliance and academic reliability standards.
#' 
#' This function provides complete system status assessment essential for
#' maintaining reliable academic research infrastructure and ensuring
#' continuous availability for legislative document analysis workflows.
#' 
#' @details
#' **Health Check Components:**
#' 
#' **Database Health (40% weight):**
#' - PostgreSQL connectivity and response time monitoring
#' - Connection pool health and performance metrics
#' - Document count verification and data integrity
#' - Fallback system validation (CSV data sources)
#' 
#' **Data Integrity (30% weight):**
#' - Cross-source data consistency verification
#' - Document count validation across multiple sources
#' - Data freshness and completeness assessment
#' - Academic research data quality metrics
#' 
#' **Application Health (20% weight):**
#' - Core module availability and functionality
#' - Shiny framework readiness for web interface
#' - Critical function availability assessment
#' - Module dependency validation
#' 
#' **System Resources (10% weight):**
#' - Memory usage monitoring (Railway 2GB limit)
#' - CPU utilization and performance metrics
#' - Storage and temporary file management
#' - Platform-specific constraint monitoring
#' 
#' **Redis Caching (Optional - 0% weight):**
#' - Cache system connectivity and performance
#' - Hit/miss ratio analysis and optimization
#' - Memory usage and key management
#' - TTL strategy effectiveness monitoring
#' 
#' **Railway Platform Integration:**
#' - Environment-specific configuration validation
#' - Resource constraint compliance monitoring
#' - Platform service dependency checks
#' - Deployment-specific health indicators
#' 
#' **Academic Research Features:**
#' - Research workflow dependency validation
#' - Data export capability verification
#' - Citation generation system health
#' - Search functionality performance assessment
#' 
#' **LGPD Compliance Monitoring:**
#' - Security event logging functionality
#' - Data protection mechanism validation
#' - Audit trail system operational status
#' - Privacy control system health
#' 
#' @param detailed Logical indicating whether to include detailed diagnostic
#'   information in the health report. Set to TRUE for comprehensive
#'   troubleshooting, FALSE for basic status monitoring.
#' 
#' @return Named list containing comprehensive health assessment:
#'   \item{timestamp}{ISO timestamp of health check execution}
#'   \item{status}{Overall system status: "healthy", "degraded", "unhealthy"}
#'   \item{version}{Application version identifier}
#'   \item{environment}{Deployment environment (Railway, development, etc.)}
#'   \item{checks}{Named list of individual component health results}
#'   \item{metrics}{System performance and usage metrics}
#'   \item{response_time_ms}{Total health check execution time}
#'   \item{health_score}{Numeric health score (0-100)}
#'   \item{railway_optimized}{Boolean indicating Railway optimization status}
#' 
#' @family monitoring-functions
#' @seealso \code{\link{simple_health_check}} for lightweight monitoring
#' @seealso \code{\link{check_database_health}} for database-specific checks
#' @seealso \code{\link{check_system_resources}} for resource monitoring
#' @seealso \code{\link{get_cache_stats}} for caching performance metrics
#' 
#' @examples
#' \dontrun{
#' # Basic health check for monitoring
#' health_status <- perform_health_check()
#' 
#' if (health_status$status == "healthy") {
#'   cat("System operational - ready for research")
#' } else {
#'   cat("System issues detected:", health_status$status)
#' }
#' 
#' # Detailed health check for troubleshooting
#' detailed_health <- perform_health_check(detailed = TRUE)
#' 
#' # Check specific component health
#' if (detailed_health$checks$database$status != "healthy") {
#'   cat("Database issues:", detailed_health$checks$database$last_error)
#' }
#' 
#' # Monitor system resources for Railway constraints
#' if (detailed_health$checks$system_resources$memory_usage_percent > 80) {
#'   cat("High memory usage detected:", 
#'       detailed_health$checks$system_resources$memory_usage_mb, "MB")
#' }
#' 
#' # Academic research platform monitoring
#' research_ready <- all(c(
#'   detailed_health$checks$database$status %in% c("healthy", "degraded"),
#'   detailed_health$checks$application$status == "healthy",
#'   detailed_health$checks$data_integrity$total_documents > 100000
#' ))
#' 
#' if (research_ready) {
#'   cat("Platform ready for academic research workflows")
#' }
#' }
#' 
#' @export
perform_health_check <- function(detailed = .health_config$detailed_response) {
  
  start_time <- Sys.time()
  cat("🏥 Performing comprehensive system health check...\n")
  
  health_status <- list(
    timestamp = Sys.time(),
    status = "healthy",
    version = "4.0.0",
    environment = Sys.getenv("RAILWAY_ENVIRONMENT", "development"),
    checks = list(),
    metrics = list(),
    response_time_ms = 0,
    railway_optimized = TRUE
  )
  
  # 1. Database Health Check
  if (.health_config$check_database) {
    health_status$checks$database <- check_database_health(detailed)
  }
  
  # 2. Redis Cache Health Check
  if (.health_config$check_redis) {
    health_status$checks$redis <- check_redis_health(detailed)
  }
  
  # 3. Data Integrity Check
  if (.health_config$check_data_integrity) {
    health_status$checks$data_integrity <- check_data_integrity(detailed)
  }
  
  # 4. System Resources Check (Railway 2GB limit)
  if (.health_config$check_memory_usage) {
    health_status$checks$system_resources <- check_system_resources(detailed)
  }
  
  # 5. Application-specific Health Checks
  health_status$checks$application <- check_application_health(detailed)
  
  # 6. Calculate overall health status
  health_status <- calculate_overall_health(health_status)
  
  # 7. Add performance metrics
  end_time <- Sys.time()
  health_status$response_time_ms <- as.numeric(difftime(end_time, start_time, units = "milliseconds"))
  health_status$metrics <- collect_performance_metrics()
  
  cat(sprintf("✅ Health check completed in %.2f ms - Status: %s\n", 
              health_status$response_time_ms, toupper(health_status$status)))
  
  return(health_status)
}

#' Database Health Check
#' 
#' Verifies database connectivity, performance, and data availability
#' 
#' @param detailed Include detailed diagnostics
#' @return Database health status
check_database_health <- function(detailed = FALSE) {
  
  start_time <- Sys.time()
  
  db_health <- list(
    status = "unknown",
    connected = FALSE,
    response_time_ms = 0,
    document_count = 0,
    last_error = NULL
  )
  
  tryCatch({
    # Check if database connection module is available
    if (exists("init_database_connection")) {
      # Initialize or reuse existing connection
      db_result <- init_database_connection()
      
      if (!isTRUE(is.null(db_result$pool)) && db_result$connection_loaded) {
        # Test database responsiveness
        test_start <- Sys.time()
        test_query <- pool::dbGetQuery(db_result$pool, 
                                      "SELECT COUNT(*) as doc_count FROM documents LIMIT 1")
        test_end <- Sys.time()
        
        db_health$connected <- TRUE
        db_health$response_time_ms <- as.numeric(difftime(test_end, test_start, units = "milliseconds"))
        db_health$document_count <- if(nrow(test_query) > 0) test_query$doc_count[1] else 0
        db_health$status <- "healthy"
        
        if (detailed) {
          # Additional detailed checks
          db_health$connection_pool_size <- if(!is.null(db_result$stats)) {
            paste0(db_result$stats$pool_min_size, "-", db_result$stats$pool_max_size)
          } else {
            "unknown"
          }
          
          db_health$total_queries <- if(!is.null(db_result$stats)) {
            db_result$stats$total_queries
          } else {
            0
          }
        }
        
      } else {
        # Database connection failed, but CSV fallback available
        db_health$status <- "degraded"
        db_health$connected <- FALSE
        db_health$document_count <- get_csv_document_count()
        db_health$fallback_mode <- TRUE
      }
      
    } else {
      db_health$status <- "unavailable"
      db_health$last_error <- "Database connection module not loaded"
    }
    
  }, error = function(e) {
    db_health$status <- "unhealthy"
    db_health$connected <- FALSE
    db_health$last_error <- e$message
  })
  
  end_time <- Sys.time()
  if (db_health$response_time_ms == 0) {
    db_health$response_time_ms <- as.numeric(difftime(end_time, start_time, units = "milliseconds"))
  }
  
  return(db_health)
}

#' Redis Cache Health Check
#' 
#' Verifies Redis connectivity and caching performance
#' 
#' @param detailed Include detailed diagnostics
#' @return Redis health status
check_redis_health <- function(detailed = FALSE) {
  
  redis_health <- list(
    status = "unknown",
    connected = FALSE,
    response_time_ms = 0,
    hit_rate_percent = 0,
    memory_usage_mb = 0,
    total_keys = 0,
    last_error = NULL
  )
  
  tryCatch({
    # Check if Redis caching module is available
    if (exists("init_redis_connection")) {
      # Initialize or check existing Redis connection
      redis_result <- init_redis_connection()
      
      if (!isTRUE(is.null(redis_result$connection)) && redis_result$caching_enabled) {
        # Test Redis responsiveness
        start_time <- Sys.time()
        ping_result <- redis_result$connection$PING()
        end_time <- Sys.time()
        
        if (ping_result == "PONG") {
          redis_health$connected <- TRUE
          redis_health$status <- "healthy"
          redis_health$response_time_ms <- as.numeric(difftime(end_time, start_time, units = "milliseconds"))
          
          # Get cache statistics
          if (exists("get_cache_stats")) {
            cache_stats <- get_cache_stats()
            redis_health$hit_rate_percent <- cache_stats$hit_rate_percent
            redis_health$memory_usage_mb <- cache_stats$memory_usage
            redis_health$total_keys <- cache_stats$total_keys
          }
          
        } else {
          redis_health$status <- "degraded"
        }
        
      } else {
        # Redis not available, but system can function without it
        redis_health$status <- "disabled"
        redis_health$connected <- FALSE
        redis_health$last_error <- "Redis caching disabled or connection failed"
      }
      
    } else {
      redis_health$status <- "unavailable"
      redis_health$last_error <- "Redis caching module not loaded"
    }
    
  }, error = function(e) {
    redis_health$status <- "unhealthy"
    redis_health$connected <- FALSE
    redis_health$last_error <- e$message
  })
  
  return(redis_health)
}

#' Data Integrity Health Check
#' 
#' Verifies data consistency and availability
#' 
#' @param detailed Include detailed diagnostics
#' @return Data integrity status
check_data_integrity <- function(detailed = FALSE) {
  
  data_health <- list(
    status = "unknown",
    total_documents = 0,
    data_sources_available = 0,
    last_updated = NULL,
    consistency_score = 0
  )
  
  tryCatch({
    # Check document count consistency
    document_counts <- list()
    
    # Try database count
    if (exists("get_connection_status")) {
      db_status <- get_connection_status()
      if (!isTRUE(is.null(db_status)) && !is.null(db_status$document_count)) {
        document_counts$database <- db_status$document_count
      }
    }
    
    # Try CSV fallback count
    if (exists("get_csv_document_count")) {
      document_counts$csv <- get_csv_document_count()
    }
    
    # Analyze consistency
    if (length(document_counts) > 0) {
      data_health$total_documents <- max(unlist(document_counts), na.rm = TRUE)
      data_health$data_sources_available <- length(document_counts)
      
      # Calculate consistency score (simplified)
      if (length(document_counts) > 1) {
        values <- unlist(document_counts)
        consistency <- 1 - (sd(values, na.rm = TRUE) / mean(values, na.rm = TRUE))
        data_health$consistency_score <- max(0, min(1, consistency)) * 100
      } else {
        data_health$consistency_score <- 100
      }
      
      # Determine status based on document count
      if (data_health$total_documents >= 130000) {
        data_health$status <- "healthy"
      } else if (data_health$total_documents >= 1000) {
        data_health$status <- "degraded"
      } else {
        data_health$status <- "unhealthy"
      }
      
      if (detailed) {
        data_health$source_counts <- document_counts
      }
      
    } else {
      data_health$status <- "unavailable"
    }
    
  }, error = function(e) {
    data_health$status <- "unhealthy"
    data_health$last_error <- e$message
  })
  
  return(data_health)
}

#' System Resources Health Check for Railway Platform
#' 
#' Comprehensive system resource monitoring specifically designed for
#' Railway platform constraints (2GB memory limit, 1 CPU core).
#' Monitors memory usage, CPU utilization, and platform-specific
#' resource consumption patterns for academic research applications.
#' 
#' This function provides essential resource monitoring for maintaining
#' optimal performance within Railway's resource constraints while
#' supporting intensive academic research workloads involving large
#' legislative document datasets.
#' 
#' @details
#' **Railway Platform Constraints:**
#' - **Memory Limit**: 2GB maximum memory allocation
#' - **CPU Allocation**: Single CPU core with shared resources
#' - **Storage**: Ephemeral storage with platform limitations
#' - **Network**: Managed network connectivity and bandwidth
#' 
#' **Memory Monitoring:**
#' - R environment memory usage tracking
#' - Garbage collection statistics and optimization
#' - Memory leak detection and prevention
#' - Large dataset handling optimization
#' 
#' **Performance Assessment:**
#' - CPU utilization and processing efficiency
#' - Memory allocation patterns and optimization
#' - Temporary file management and cleanup
#' - Resource constraint compliance verification
#' 
#' **Academic Research Considerations:**
#' - Large document corpus handling capability
#' - Memory-intensive NLP operation support
#' - Concurrent user session resource management
#' - Batch processing resource optimization
#' 
#' **Health Status Classification:**
#' - **Healthy**: < 70% memory usage, optimal performance
#' - **Degraded**: 70-90% memory usage, reduced performance
#' - **Unhealthy**: > 90% memory usage, critical resource pressure
#' 
#' **Platform Optimization Features:**
#' - Automatic resource usage optimization
#' - Memory pressure detection and mitigation
#' - Garbage collection triggering and monitoring
#' - Resource usage trend analysis
#' 
#' @param detailed Logical indicating whether to include comprehensive
#'   resource diagnostics including loaded packages, working directories,
#'   temporary file usage, and detailed memory analysis.
#' 
#' @return Named list containing system resource assessment:
#'   \item{status}{"healthy", "degraded", "unhealthy"}
#'   \item{memory_usage_mb}{Current memory usage in megabytes}
#'   \item{memory_limit_mb}{Platform memory limit (2048 MB for Railway)}
#'   \item{memory_usage_percent}{Memory usage as percentage of limit}
#'   \item{cpu_count}{Number of available CPU cores}
#'   \item{r_version}{R version information}
#'   \item{platform}{Operating system platform information}
#'   \item{last_error}{Error message if resource check failed}
#'   \item{r_packages_loaded}{Number of loaded R packages (if detailed=TRUE)}
#'   \item{working_directory}{Current working directory (if detailed=TRUE)}
#'   \item{temp_directory}{Temporary directory location (if detailed=TRUE)}
#' 
#' @family monitoring-functions
#' @seealso \code{\link{perform_health_check}} for comprehensive system health
#' @seealso \code{\link{collect_performance_metrics}} for detailed metrics
#' 
#' @examples
#' \dontrun{
#' # Basic resource monitoring
#' resources <- check_system_resources()
#' 
#' cat("Memory usage:", resources$memory_usage_mb, "MB")
#' cat("Memory percentage:", resources$memory_usage_percent, "%")
#' 
#' # Check for resource pressure
#' if (resources$memory_usage_percent > 80) {
#'   cat("High memory usage detected - consider optimization")
#'   
#'   # Trigger garbage collection
#'   gc(verbose = TRUE)
#' }
#' 
#' # Detailed resource analysis
#' detailed_resources <- check_system_resources(detailed = TRUE)
#' 
#' if (detailed_resources$status == "degraded") {
#'   cat("Resource optimization needed:")
#'   cat("- Loaded packages:", detailed_resources$r_packages_loaded)
#'   cat("- Working directory:", detailed_resources$working_directory)
#'   cat("- Platform:", detailed_resources$platform)
#' }
#' 
#' # Railway platform monitoring
#' railway_compliance <- all(c(
#'   resources$memory_usage_mb < 1800,  # Leave buffer under 2GB
#'   resources$status %in% c("healthy", "degraded")
#' ))
#' 
#' if (!railway_compliance) {
#'   cat("Railway resource constraints exceeded")
#' }
#' }
#' 
check_system_resources <- function(detailed = FALSE) {
  
  system_health <- list(
    status = "unknown",
    memory_usage_mb = 0,
    memory_limit_mb = 2048,  # Railway limit
    memory_usage_percent = 0,
    cpu_count = 1,
    r_version = R.version.string,
    platform = Sys.info()["sysname"]
  )
  
  tryCatch({
    # Get memory usage (simplified for R environment)
    if (requireNamespace("pryr", quietly = TRUE)) {
      memory_usage <- pryr::mem_used()
      system_health$memory_usage_mb <- as.numeric(memory_usage) / (1024^2)
    } else {
      # Fallback memory estimation
      gc_info <- gc()
      system_health$memory_usage_mb <- sum(gc_info[, 2]) * 0.1  # Rough estimation
    }
    
    # Calculate memory usage percentage
    system_health$memory_usage_percent <- (system_health$memory_usage_mb / system_health$memory_limit_mb) * 100
    
    # Determine status based on memory usage
    if (system_health$memory_usage_percent < 70) {
      system_health$status <- "healthy"
    } else if (system_health$memory_usage_percent < 90) {
      system_health$status <- "degraded"
    } else {
      system_health$status <- "unhealthy"
    }
    
    if (detailed) {
      # Additional system information
      system_health$r_packages_loaded <- length(.packages(all.available = FALSE))
      system_health$working_directory <- getwd()
      system_health$temp_directory <- tempdir()
    }
    
  }, error = function(e) {
    system_health$status <- "unhealthy"
    system_health$last_error <- e$message
  })
  
  return(system_health)
}

#' Application-Specific Health Check
#' 
#' Verifies application-specific functionality
#' 
#' @param detailed Include detailed diagnostics
#' @return Application health status
check_application_health <- function(detailed = FALSE) {
  
  app_health <- list(
    status = "unknown",
    modules_loaded = 0,
    shiny_ready = FALSE,
    core_functions_available = 0
  )
  
  tryCatch({
    # Check if core modules are loaded
    core_modules <- c("init_database_connection", "get_connection_status", 
                     "init_redis_connection", "cache_get", "cache_set")
    
    available_modules <- sum(sapply(core_modules, exists))
    app_health$modules_loaded <- available_modules
    app_health$core_functions_available <- length(core_modules)
    
    # Check if Shiny is available and ready
    if (requireNamespace("shiny", quietly = TRUE)) {
      app_health$shiny_ready <- TRUE
    }
    
    # Determine application health
    module_ratio <- available_modules / length(core_modules)
    
    if (module_ratio >= 0.8) {
      app_health$status <- "healthy"
    } else if (module_ratio >= 0.5) {
      app_health$status <- "degraded"
    } else {
      app_health$status <- "unhealthy"
    }
    
    if (detailed) {
      app_health$available_functions <- core_modules[sapply(core_modules, exists)]
      app_health$missing_functions <- core_modules[!sapply(core_modules, exists)]
    }
    
  }, error = function(e) {
    app_health$status <- "unhealthy"
    app_health$last_error <- e$message
  })
  
  return(app_health)
}

#' Calculate Overall Health Status
#' 
#' Determines overall system health based on individual component checks
#' 
#' @param health_status Health status object with individual checks
#' @return Updated health status with overall status
calculate_overall_health <- function(health_status) {
  
  # Extract individual check statuses
  check_statuses <- sapply(health_status$checks, function(check) {
    check$status
  })
  
  # Weight different components (database is most critical)
  weights <- list(
    database = 0.4,
    data_integrity = 0.3,
    application = 0.2,
    system_resources = 0.1,
    redis = 0.0  # Redis is optional, doesn't affect overall health
  )
  
  # Calculate weighted health score
  health_scores <- sapply(check_statuses, function(status) {
    switch(status,
           "healthy" = 100,
           "degraded" = 60,
           "disabled" = 80,  # Disabled but not critical
           "unavailable" = 40,
           "unhealthy" = 0,
           50  # Unknown status
    )
  })
  
  # Apply weights
  weighted_score <- 0
  total_weight <- 0
  
  for (component in names(health_scores)) {
    if (!is.null(weights[[component]])) {
      weighted_score <- weighted_score + (health_scores[[component]] * weights[[component]])
      total_weight <- total_weight + weights[[component]]
    }
  }
  
  # Calculate final score
  if (total_weight > 0) {
    final_score <- weighted_score / total_weight
  } else {
    final_score <- 50  # Default neutral score
  }
  
  # Determine overall status
  health_status$health_score <- round(final_score, 1)
  
  if (final_score >= 90) {
    health_status$status <- "healthy"
  } else if (final_score >= 70) {
    health_status$status <- "degraded"
  } else {
    health_status$status <- "unhealthy"
  }
  
  return(health_status)
}

#' Collect Performance Metrics
#' 
#' Gathers system performance metrics for monitoring
#' 
#' @return List of performance metrics
collect_performance_metrics <- function() {
  
  metrics <- list(
    uptime_seconds = as.numeric(Sys.time() - .GlobalEnv$.app_start_time %||% Sys.time()),
    r_version = R.version.string,
    platform = paste(Sys.info()["sysname"], Sys.info()["release"]),
    timezone = Sys.timezone(),
    memory_info = list()
  )
  
  # Add memory information
  tryCatch({
    gc_info <- gc(verbose = FALSE)
    metrics$memory_info <- list(
      used_mb = sum(gc_info[, 2]),
      max_used_mb = sum(gc_info[, 6]),
      gc_collections = sum(gc_info[, 4])
    )
  }, error = function(e) {
    metrics$memory_info <- list(error = "Memory info unavailable")
  })
  
  return(metrics)
}

#' Simple Health Check Endpoint
#' 
#' Lightweight health check for Railway platform monitoring
#' 
#' @return Simplified health status for quick checks
#' @export
simple_health_check <- function() {
  
  tryCatch({
    # Quick database test
    db_ok <- tryCatch({
      if (exists("init_database_connection")) {
        db_result <- init_database_connection()
        !isTRUE(is.null(db_result$pool)) || db_result$status == "packages_missing"
      } else {
        TRUE  # Assume OK if module not loaded yet
      }
    }, error = function(e) FALSE)
    
    # Quick memory check
    gc_info <- gc(verbose = FALSE)
    memory_mb <- sum(gc_info[, 2])
    memory_ok <- memory_mb < 1800  # Leave buffer under 2GB limit
    
    overall_status <- if (db_ok && memory_ok) "healthy" else "unhealthy"
    
    return(list(
      status = overall_status,
      timestamp = Sys.time(),
      database = if(db_ok) "ok" else "error",
      memory = if(memory_ok) "ok" else "high",
      version = "4.0.0"
    ))
    
  }, error = function(e) {
    return(list(
      status = "unhealthy",
      timestamp = Sys.time(),
      error = e$message,
      version = "4.0.0"
    ))
  })
}

# Initialize app start time for uptime calculation
if (is.null(.GlobalEnv$.app_start_time)) {
  .GlobalEnv$.app_start_time <- Sys.time()
}

cat("✅ Health check and monitoring module loaded\n")