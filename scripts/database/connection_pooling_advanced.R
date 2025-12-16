# ============================================================================
# SPRINT 6A: ADVANCED CONNECTION POOLING FOR CLOUD RUN POSTGRESQL
# Brazilian Legislative Monitoring System - Performance Optimization
# ============================================================================
#
# CLOUD RUN-OPTIMIZED CONNECTION POOLING STRATEGY
# Purpose: Maximize database performance within Cloud Run's 2GB memory constraints
# 
# KEY OPTIMIZATIONS:
# - Intelligent pool sizing based on Railway infrastructure
# - Connection health monitoring and auto-recovery
# - Query-specific connection routing
# - Memory-efficient connection management
# - Concurrent user load balancing
# - LGPD-compliant connection logging
# 
# PERFORMANCE TARGETS:
# - Support 50+ concurrent users on Cloud Run 2GB
# - Sub-200ms connection acquisition
# - 99%+ connection pool utilization
# - Zero connection leaks
# - Automatic failover and recovery
# ============================================================================

# Load required libraries with enhanced error handling
required_packages <- c("DBI", "RPostgres", "pool", "digest", "jsonlite")
missing_packages <- c()

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing_packages <- c(missing_packages, pkg)
  }
}

if (length(missing_packages) > 0) {
  stop(paste("Missing required packages:", paste(missing_packages, collapse = ", "),
             "\nInstall with: install.packages(c(", paste0("'", missing_packages, "'", collapse = ", "), "))"))
}

suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
  library(pool)
  library(digest)
  library(jsonlite)
})

cat("✅ Advanced connection pooling libraries loaded\n")

# ============================================================================
# GLOBAL CONFIGURATION AND STATE MANAGEMENT
# ============================================================================

# Advanced pooling configuration optimized for Cloud Run
.cloudrun_config <- list(
  # Cloud Run-specific memory constraints
  max_memory_mb = 2048,      # Cloud Run 2GB limit
  pool_memory_limit_mb = 512, # Reserve 25% of memory for connection pools

  # Connection pool settings
  min_pool_size = 2,         # Minimum connections per pool
  max_pool_size = 15,        # Maximum connections per pool (Cloud Run limit ~20-25)
  idle_timeout_ms = 1800000, # 30 minutes idle timeout
  connection_timeout_ms = 30000, # 30 seconds connection timeout
  
  # Pool types and allocation
  primary_pool_size = 8,     # Main query pool
  analytics_pool_size = 4,   # Heavy analytics queries
  maintenance_pool_size = 2,  # Background maintenance
  readonly_pool_size = 6,    # Read-only operations
  
  # Health check settings
  health_check_interval_ms = 60000, # 1 minute health checks
  max_failed_health_checks = 3,     # Max failures before pool reset
  
  # Performance monitoring
  enable_query_logging = TRUE,
  slow_query_threshold_ms = 500,
  enable_performance_metrics = TRUE
)

# Global connection pools storage
.connection_pools <- list(
  primary = NULL,
  analytics = NULL,
  maintenance = NULL,
  readonly = NULL
)

# Connection pool health status
.pool_health <- list(
  primary = list(status = "disconnected", last_check = NULL, failed_checks = 0),
  analytics = list(status = "disconnected", last_check = NULL, failed_checks = 0),
  maintenance = list(status = "disconnected", last_check = NULL, failed_checks = 0),
  readonly = list(status = "disconnected", last_check = NULL, failed_checks = 0)
)

# Performance metrics storage
.pool_metrics <- list(
  connections_created = 0,
  connections_destroyed = 0,
  queries_executed = 0,
  slow_queries = 0,
  pool_exhaustions = 0,
  connection_errors = 0,
  avg_query_time_ms = 0,
  last_reset = Sys.time()
)

# ============================================================================
# CLOUD RUN DATABASE CONFIGURATION DETECTION
# ============================================================================

#' Get optimized database configuration for Cloud Run deployment
#' @return List with connection parameters optimized for Cloud Run
get_cloudrun_database_config <- function() {
  cat("🔍 Detecting Cloud Run database configuration...\n")

  # Priority 1: Cloud Run DATABASE_URL
  database_url <- Sys.getenv("DATABASE_URL", unset = NA)
  if (!isTRUE(is.na(database_url)) && database_url != "") {
    config <- parse_cloudrun_database_url(database_url)
    if (!is.null(config)) {
      cat("✅ Using Cloud Run DATABASE_URL configuration\n")
      return(enhance_cloudrun_config(config))
    }
  }

  # Priority 2: Cloud Run environment variables
  cloudrun_config <- list(
    host = Sys.getenv("PGHOST", "localhost"),
    port = as.integer(Sys.getenv("PGPORT", "5432")),
    dbname = Sys.getenv("PGDATABASE", "postgres"),
    user = Sys.getenv("PGUSER", "postgres"),
    password = Sys.getenv("PGPASSWORD", "")
  )

  # Validate Cloud Run configuration
  if (isTRUE(is.na(cloudrun_config$host)) || cloudrun_config$host == "" ||
      isTRUE(is.na(cloudrun_config$password)) || cloudrun_config$password == "") {
    cat("❌ Cloud Run database configuration incomplete\n")
    return(NULL)
  }

  cat("✅ Using Cloud Run environment variables configuration\n")
  return(enhance_cloudrun_config(cloudrun_config))
}

#' Parse Cloud Run DATABASE_URL with enhanced error handling
#' @param database_url Cloud Run-formatted database URL
#' @return List with parsed connection parameters
parse_cloudrun_database_url <- function(database_url) {
  tryCatch({
    # Support both postgresql:// and postgres:// schemes
    if (!grepl("^postgres(ql)?://", database_url)) {
      cat("⚠️ Invalid DATABASE_URL format for Cloud Run\n")
      return(NULL)
    }

    # Enhanced URL parsing for Cloud Run-specific formats
    url_pattern <- "^postgres(?:ql)?://([^:]+):([^@]+)@([^:]+):(\\d+)/(.+)$"
    matches <- regmatches(database_url, regexec(url_pattern, database_url))

    if (length(matches[[1]]) != 6) {
      cat("⚠️ Could not parse Cloud Run DATABASE_URL\n")
      return(NULL)
    }

    config <- list(
      user = matches[[1]][2],
      password = matches[[1]][3],
      host = matches[[1]][4],
      port = as.integer(matches[[1]][5]),
      dbname = matches[[1]][6]
    )

    # Validate Cloud Run-specific constraints
    if (isTRUE(is.na(config$port)) || config$port <= 0 || config$port > 65535) {
      cat("❌ Invalid port in Cloud Run DATABASE_URL\n")
      return(NULL)
    }

    cat("✅ Cloud Run DATABASE_URL parsed successfully\n")
    return(config)

  }, error = function(e) {
    cat("❌ Error parsing Cloud Run DATABASE_URL:", e$message, "\n")
    return(NULL)
  })
}

#' Enhance database configuration with Cloud Run-specific optimizations
#' @param config Basic database configuration
#' @return Enhanced configuration for Cloud Run deployment
enhance_cloudrun_config <- function(config) {
  enhanced_config <- config

  # Cloud Run-optimized connection parameters
  enhanced_config$cloudrun_optimizations <- list(
    sslmode = "prefer",  # Cloud Run supports SSL
    connect_timeout = 30,
    application_name = "cloudrun_legislative_monitor",
    
    # Memory optimizations for 2GB limit
    work_mem = "4MB",
    maintenance_work_mem = "64MB", 
    shared_buffers = "128MB",
    effective_cache_size = "512MB",
    
    # Cloud Run-specific performance settings
    random_page_cost = 1.1,  # SSD storage
    effective_io_concurrency = 200,
    max_parallel_workers_per_gather = 2,

    # Connection pooling optimizations
    tcp_keepalives_idle = 600,
    tcp_keepalives_interval = 30,
    tcp_keepalives_count = 3,

    # Query optimization
    enable_seqscan = "on",
    enable_indexscan = "on",
    enable_bitmapscan = "on",
    enable_hashjoin = "on"
  )

  cat("✅ Cloud Run database configuration enhanced with performance optimizations\n")
  return(enhanced_config)
}

# ============================================================================
# INTELLIGENT CONNECTION POOL CREATION
# ============================================================================

#' Create specialized connection pool with Cloud Run optimizations
#' @param pool_name Name/type of the pool (primary, analytics, maintenance, readonly)
#' @param config Database configuration
#' @param pool_size Size of the connection pool
#' @return Connection pool object or NULL on failure
create_cloudrun_pool <- function(pool_name, config, pool_size = .cloudrun_config$primary_pool_size) {
  cat("🚀 Creating Cloud Run-optimized connection pool:", pool_name, "\n")
  
  pool_config <- list(
    drv = RPostgres::Postgres(),
    host = config$host,
    port = config$port,
    dbname = config$dbname,
    user = config$user,
    password = config$password,
    
    # Pool-specific settings
    minSize = max(1, floor(pool_size * 0.2)),  # 20% minimum
    maxSize = pool_size,
    idleTimeout = .cloudrun_config$idle_timeout_ms,

    # Cloud Run-optimized connection parameters
    sslmode = config$cloudrun_optimizations$sslmode,
    connect_timeout = .cloudrun_config$connection_timeout_ms / 1000,
    application_name = paste0(config$cloudrun_optimizations$application_name, "_", pool_name),

    # Performance parameters
    options = paste(
      "-c work_mem=" %+% config$cloudrun_optimizations$work_mem,
      "-c maintenance_work_mem=" %+% config$cloudrun_optimizations$maintenance_work_mem,
      "-c random_page_cost=" %+% config$cloudrun_optimizations$random_page_cost,
      "-c effective_io_concurrency=" %+% config$cloudrun_optimizations$effective_io_concurrency,
      "-c tcp_keepalives_idle=" %+% config$cloudrun_optimizations$tcp_keepalives_idle,
      "-c tcp_keepalives_interval=" %+% config$cloudrun_optimizations$tcp_keepalives_interval,
      "-c tcp_keepalives_count=" %+% config$cloudrun_optimizations$tcp_keepalives_count,
      sep = " "
    )
  )
  
  # Adjust pool configuration based on pool type
  pool_config <- adjust_pool_config_by_type(pool_config, pool_name)
  
  max_retries <- 3
  for (attempt in 1:max_retries) {
    tryCatch({
      cat("🔄 Pool creation attempt", attempt, "for", pool_name, "\n")
      
      pool <- do.call(dbPool, pool_config)
      
      # Test the pool immediately
      test_conn <- poolCheckout(pool)
      test_result <- dbGetQuery(test_conn, "SELECT version() as version, current_setting('application_name') as app_name")
      poolReturn(test_conn)

      if (nrow(test_result) == 1) {
        cat("✅ Cloud Run connection pool", pool_name, "created successfully\n")
        cat("📊 Database version:", substr(test_result$version, 1, 30), "...\n")
        cat("🏷️  Application name:", test_result$app_name, "\n")
        
        # Update metrics
        .pool_metrics$connections_created <<- .pool_metrics$connections_created + pool_size
        
        # Update health status
        .pool_health[[pool_name]] <<- list(
          status = "healthy",
          last_check = Sys.time(),
          failed_checks = 0
        )
        
        return(pool)
      }
      
    }, error = function(e) {
      cat("❌ Pool creation attempt", attempt, "failed for", pool_name, ":", e$message, "\n")
      
      if (attempt < max_retries) {
        delay <- 2^attempt  # Exponential backoff
        cat("⏳ Waiting", delay, "seconds before retry...\n")
        Sys.sleep(delay)
      }
    })
  }

  cat("❌ Failed to create Cloud Run connection pool:", pool_name, "\n")
  .pool_metrics$connection_errors <<- .pool_metrics$connection_errors + 1

  # Update health status
  .pool_health[[pool_name]] <<- list(
    status = "failed",
    last_check = Sys.time(),
    failed_checks = .cloudrun_config$max_failed_health_checks
  )
  
  return(NULL)
}

#' Adjust pool configuration based on pool type and usage pattern
#' @param pool_config Base pool configuration
#' @param pool_name Type of pool
#' @return Adjusted pool configuration
adjust_pool_config_by_type <- function(pool_config, pool_name) {
  switch(pool_name,
    "primary" = {
      # Optimized for fast, frequent queries
      pool_config$idleTimeout <- 900000  # 15 minutes
      pool_config$options <- paste(pool_config$options, 
                                  "-c statement_timeout=30s",
                                  "-c idle_in_transaction_session_timeout=60s")
    },
    "analytics" = {
      # Optimized for heavy analytical queries
      pool_config$idleTimeout <- 3600000  # 1 hour
      pool_config$options <- paste(pool_config$options,
                                  "-c work_mem=16MB",
                                  "-c statement_timeout=300s",
                                  "-c idle_in_transaction_session_timeout=300s",
                                  "-c max_parallel_workers_per_gather=4")
    },
    "maintenance" = {
      # Optimized for background maintenance tasks
      pool_config$idleTimeout <- 7200000  # 2 hours
      pool_config$options <- paste(pool_config$options,
                                  "-c maintenance_work_mem=128MB", 
                                  "-c statement_timeout=600s",
                                  "-c lock_timeout=300s")
    },
    "readonly" = {
      # Optimized for read-only operations
      pool_config$idleTimeout <- 1800000  # 30 minutes
      pool_config$options <- paste(pool_config$options,
                                  "-c default_transaction_read_only=on",
                                  "-c statement_timeout=60s")
    }
  )
  
  return(pool_config)
}

# ============================================================================
# INTELLIGENT CONNECTION POOL ROUTING
# ============================================================================

#' Get appropriate connection pool based on query type and load
#' @param query_type Type of query: "select", "analytics", "maintenance", "write"
#' @param priority Priority level: "high", "medium", "low"
#' @return Connection pool object
get_optimal_pool <- function(query_type = "select", priority = "medium") {
  # Route based on query type and current pool health
  pool_name <- route_to_optimal_pool(query_type, priority)
  
  pool <- .connection_pools[[pool_name]]
  
  if (isTRUE(is.null(pool)) || !pool_is_healthy(pool_name)) {
    cat("⚠️ Pool", pool_name, "unavailable, trying fallback...\n")
    pool <- get_fallback_pool(pool_name)
  }
  
  if (is.null(pool)) {
    cat("❌ No healthy connection pools available\n")
    .pool_metrics$pool_exhaustions <<- .pool_metrics$pool_exhaustions + 1
  }
  
  return(pool)
}

#' Route query to optimal pool based on type and system state
#' @param query_type Type of database operation
#' @param priority Priority level
#' @return Name of optimal pool
route_to_optimal_pool <- function(query_type, priority) {
  switch(query_type,
    "select" = if (priority == "high") "primary" else "readonly",
    "analytics" = "analytics", 
    "maintenance" = "maintenance",
    "write" = "primary",
    "dashboard" = "readonly",
    "search" = if (priority == "high") "primary" else "readonly",
    "geographic" = "analytics",
    # Default routing
    "primary"
  )
}

#' Get fallback pool when primary choice is unavailable
#' @param preferred_pool_name Preferred pool that is unavailable
#' @return Fallback connection pool
get_fallback_pool <- function(preferred_pool_name) {
  # Fallback hierarchy based on pool type
  fallback_order <- switch(preferred_pool_name,
    "primary" = c("readonly", "analytics", "maintenance"),
    "analytics" = c("primary", "readonly", "maintenance"), 
    "readonly" = c("primary", "analytics", "maintenance"),
    "maintenance" = c("primary", "analytics", "readonly"),
    c("primary", "readonly", "analytics", "maintenance")
  )
  
  for (pool_name in fallback_order) {
    pool <- .connection_pools[[pool_name]]
    if (!isTRUE(is.null(pool)) && pool_is_healthy(pool_name)) {
      cat("🔄 Using fallback pool:", pool_name, "\n")
      return(pool)
    }
  }
  
  return(NULL)
}

# ============================================================================
# POOL HEALTH MONITORING AND AUTO-RECOVERY
# ============================================================================

#' Check if a connection pool is healthy
#' @param pool_name Name of the pool to check
#' @return Boolean indicating pool health
pool_is_healthy <- function(pool_name) {
  health_info <- .pool_health[[pool_name]]
  
  if (is.null(health_info)) return(FALSE)
  
  # Check health status
  if (health_info$status == "failed") return(FALSE)
  
  # Check if health check is recent enough
  if (!is.null(health_info$last_check)) {
    minutes_since_check <- as.numeric(difftime(Sys.time(), health_info$last_check, units = "mins"))
    if (minutes_since_check > (.cloudrun_config$health_check_interval_ms / 60000)) {
      # Health check is stale, perform new check
      return(perform_pool_health_check(pool_name))
    }
  }

  # Check failed checks count
  if (health_info$failed_checks >= .cloudrun_config$max_failed_health_checks) {
    return(FALSE)
  }
  
  return(health_info$status == "healthy")
}

#' Perform health check on a specific pool
#' @param pool_name Name of the pool to check
#' @return Boolean indicating health check result
perform_pool_health_check <- function(pool_name) {
  pool <- .connection_pools[[pool_name]]
  
  if (is.null(pool)) {
    update_pool_health(pool_name, "failed")
    return(FALSE)
  }
  
  tryCatch({
    start_time <- Sys.time()
    
    # Perform quick health check query
    test_conn <- poolCheckout(pool)
    result <- dbGetQuery(test_conn, "SELECT 1 as health_check")
    poolReturn(test_conn)
    
    end_time <- Sys.time()
    response_time_ms <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
    
    if (nrow(result) == 1 && result$health_check == 1) {
      update_pool_health(pool_name, "healthy")
      
      # Log slow health checks
      if (response_time_ms > 1000) {  # 1 second threshold
        cat("⚠️ Slow health check for pool", pool_name, ":", round(response_time_ms), "ms\n")
      }
      
      return(TRUE)
    } else {
      update_pool_health(pool_name, "unhealthy")
      return(FALSE)
    }
    
  }, error = function(e) {
    cat("❌ Health check failed for pool", pool_name, ":", e$message, "\n")
    update_pool_health(pool_name, "failed")
    return(FALSE)
  })
}

#' Update pool health status
#' @param pool_name Name of the pool
#' @param status New health status
update_pool_health <- function(pool_name, status) {
  current_health <- .pool_health[[pool_name]]
  
  if (status == "healthy") {
    .pool_health[[pool_name]] <<- list(
      status = status,
      last_check = Sys.time(),
      failed_checks = 0
    )
  } else {
    .pool_health[[pool_name]] <<- list(
      status = status,
      last_check = Sys.time(),
      failed_checks = (current_health$failed_checks %||% 0) + 1
    )
  }
}

#' Perform comprehensive health check on all pools
#' @return Data frame with health status of all pools
check_all_pools_health <- function() {
  health_results <- data.frame(
    pool_name = character(0),
    status = character(0),
    last_check = as.POSIXct(character(0)),
    failed_checks = integer(0),
    response_time_ms = numeric(0),
    stringsAsFactors = FALSE
  )
  
  for (pool_name in names(.connection_pools)) {
    start_time <- Sys.time()
    is_healthy <- perform_pool_health_check(pool_name)
    end_time <- Sys.time()
    
    response_time <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
    
    health_info <- .pool_health[[pool_name]]
    
    health_results <- rbind(health_results, data.frame(
      pool_name = pool_name,
      status = health_info$status,
      last_check = health_info$last_check,
      failed_checks = health_info$failed_checks,
      response_time_ms = round(response_time, 1),
      stringsAsFactors = FALSE
    ))
  }
  
  return(health_results)
}

# ============================================================================
# AUTOMATIC POOL RECOVERY AND MAINTENANCE
# ============================================================================

#' Recover failed connection pools
#' @param force_recovery Force recovery even if not needed
#' @return List of recovery results
recover_failed_pools <- function(force_recovery = FALSE) {
  cat("🔧 Starting connection pool recovery process...\n")

  recovery_results <- list()
  config <- get_cloudrun_database_config()

  if (is.null(config)) {
    cat("❌ Cannot recover pools: Database configuration unavailable\n")
    return(list(error = "No database configuration"))
  }

  for (pool_name in names(.connection_pools)) {
    pool_health <- .pool_health[[pool_name]]

    needs_recovery <- force_recovery ||
                     isTRUE(is.null(pool_health)) ||
                     pool_health$status == "failed" ||
                     pool_health$failed_checks >= .cloudrun_config$max_failed_health_checks
    
    if (needs_recovery) {
      cat("🔄 Recovering pool:", pool_name, "\n")
      
      # Close existing pool if it exists
      if (!is.null(.connection_pools[[pool_name]])) {
        tryCatch({
          poolClose(.connection_pools[[pool_name]])
        }, error = function(e) {
          cat("⚠️ Error closing pool", pool_name, ":", e$message, "\n")
        })
      }
      
      # Create new pool
      pool_size <- switch(pool_name,
        "primary" = .cloudrun_config$primary_pool_size,
        "analytics" = .cloudrun_config$analytics_pool_size,
        "maintenance" = .cloudrun_config$maintenance_pool_size,
        "readonly" = .cloudrun_config$readonly_pool_size,
        .cloudrun_config$primary_pool_size
      )

      new_pool <- create_cloudrun_pool(pool_name, config, pool_size)
      
      if (!is.null(new_pool)) {
        .connection_pools[[pool_name]] <<- new_pool
        recovery_results[[pool_name]] <- "SUCCESS"
        cat("✅ Pool", pool_name, "recovered successfully\n")
      } else {
        recovery_results[[pool_name]] <- "FAILED"
        cat("❌ Failed to recover pool:", pool_name, "\n")
      }
    } else {
      recovery_results[[pool_name]] <- "NOT_NEEDED"
    }
  }
  
  return(recovery_results)
}

#' Optimize pool sizes based on usage patterns
#' @return List of optimization results
optimize_pool_sizes <- function() {
  cat("⚡ Optimizing connection pool sizes based on usage...\n")
  
  optimization_results <- list()
  
  # Get current pool usage statistics (would need custom implementation)
  # This is a placeholder for usage-based optimization logic
  for (pool_name in names(.connection_pools)) {
    pool <- .connection_pools[[pool_name]]
    
    if (!is.null(pool)) {
      # Example optimization logic (simplified)
      # In a real implementation, you would analyze:
      # - Average connection utilization
      # - Peak usage periods  
      # - Query queue lengths
      # - Connection wait times
      
      current_size <- pool$maxSize  # This would need to be accessed differently
      recommended_size <- current_size  # Placeholder
      
      optimization_results[[pool_name]] <- list(
        current_size = current_size,
        recommended_size = recommended_size,
        action = "MAINTAIN"  # Could be "INCREASE", "DECREASE", "MAINTAIN"
      )
    }
  }
  
  return(optimization_results)
}

# ============================================================================
# PERFORMANCE MONITORING AND METRICS
# ============================================================================

#' Execute query with performance monitoring
#' @param query SQL query to execute
#' @param params Query parameters
#' @param query_type Type of query for optimal routing
#' @param priority Priority level
#' @return Query result with performance metrics
execute_monitored_query <- function(query, params = NULL, query_type = "select", priority = "medium") {
  start_time <- Sys.time()
  
  pool <- get_optimal_pool(query_type, priority)
  
  if (is.null(pool)) {
    cat("❌ No available connection pool for query execution\n")
    return(NULL)
  }
  
  tryCatch({
    # Execute query
    if (isTRUE(is.null(params)) || length(params) == 0) {
      result <- dbGetQuery(pool, query)
    } else {
      result <- dbGetQuery(pool, query, params = params)
    }
    
    end_time <- Sys.time()
    execution_time_ms <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
    
    # Update performance metrics
    .pool_metrics$queries_executed <<- .pool_metrics$queries_executed + 1
    .pool_metrics$avg_query_time_ms <<- 
      ((.pool_metrics$avg_query_time_ms * (.pool_metrics$queries_executed - 1)) + execution_time_ms) / 
      .pool_metrics$queries_executed
    
    # Log slow queries
    if (execution_time_ms > .railway_config$slow_query_threshold_ms) {
      .pool_metrics$slow_queries <<- .pool_metrics$slow_queries + 1
      
      if (.railway_config$enable_query_logging) {
        cat("🐌 Slow query detected:", round(execution_time_ms), "ms\n")
        cat("📝 Query:", substr(gsub("\\s+", " ", query), 1, 100), "...\n")
      }
    }
    
    # Add performance metadata to result
    if (is.data.frame(result)) {
      attr(result, "performance") <- list(
        execution_time_ms = round(execution_time_ms, 2),
        query_type = query_type,
        priority = priority,
        rows_returned = nrow(result)
      )
    }
    
    return(result)
    
  }, error = function(e) {
    end_time <- Sys.time()
    execution_time_ms <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
    
    .pool_metrics$connection_errors <<- .pool_metrics$connection_errors + 1
    
    cat("❌ Query execution failed after", round(execution_time_ms), "ms:", e$message, "\n")
    return(NULL)
  })
}

#' Get comprehensive performance metrics for all pools
#' @return List with detailed performance statistics
get_pool_performance_metrics <- function() {
  metrics <- list(
    # Overall metrics
    overall = .pool_metrics,
    
    # Pool-specific health
    pool_health = .pool_health,
    
    # Railway resource utilization
    railway_stats = list(
      estimated_memory_usage_mb = calculate_estimated_memory_usage(),
      connection_efficiency = calculate_connection_efficiency(),
      query_throughput = calculate_query_throughput()
    ),
    
    # Performance recommendations
    recommendations = generate_performance_recommendations()
  )
  
  return(metrics)
}

#' Calculate estimated memory usage for connection pools
#' @return Estimated memory usage in MB
calculate_estimated_memory_usage <- function() {
  total_connections <- 0
  
  for (pool_name in names(.connection_pools)) {
    pool <- .connection_pools[[pool_name]]
    if (!is.null(pool)) {
      # Estimate based on pool size (rough calculation)
      pool_size <- switch(pool_name,
        "primary" = .cloudrun_config$primary_pool_size,
        "analytics" = .cloudrun_config$analytics_pool_size,
        "maintenance" = .cloudrun_config$maintenance_pool_size,
        "readonly" = .cloudrun_config$readonly_pool_size,
        5
      )
      total_connections <- total_connections + pool_size
    }
  }

  # Rough estimate: ~10-20MB per connection including buffers
  estimated_mb <- total_connections * 15

  return(min(estimated_mb, .cloudrun_config$pool_memory_limit_mb))
}

#' Calculate connection pool efficiency
#' @return Connection efficiency percentage
calculate_connection_efficiency <- function() {
  if (.pool_metrics$queries_executed == 0) return(0)
  
  success_rate <- (.pool_metrics$queries_executed - .pool_metrics$connection_errors) / 
                  .pool_metrics$queries_executed * 100
  
  return(round(success_rate, 2))
}

#' Calculate query throughput (queries per minute)
#' @return Query throughput rate
calculate_query_throughput <- function() {
  if (is.null(.pool_metrics$last_reset)) return(0)
  
  minutes_elapsed <- as.numeric(difftime(Sys.time(), .pool_metrics$last_reset, units = "mins"))
  if (minutes_elapsed == 0) return(0)
  
  return(round(.pool_metrics$queries_executed / minutes_elapsed, 2))
}

#' Generate performance recommendations based on metrics
#' @return List of performance recommendations
generate_performance_recommendations <- function() {
  recommendations <- c()
  
  # Check slow query rate
  if (.pool_metrics$slow_queries > 0) {
    slow_query_rate <- (.pool_metrics$slow_queries / .pool_metrics$queries_executed) * 100
    if (slow_query_rate > 10) {
      recommendations <- c(recommendations, 
                          paste("High slow query rate:", round(slow_query_rate, 1), "% - Consider query optimization"))
    }
  }
  
  # Check pool exhaustions
  if (.pool_metrics$pool_exhaustions > 0) {
    recommendations <- c(recommendations,
                        "Pool exhaustion detected - Consider increasing pool sizes")
  }
  
  # Check connection efficiency
  efficiency <- calculate_connection_efficiency()
  if (efficiency < 95) {
    recommendations <- c(recommendations,
                        paste("Low connection efficiency:", efficiency, "% - Check error rates"))
  }
  
  # Check memory usage
  memory_usage <- calculate_estimated_memory_usage()
  if (memory_usage > (.cloudrun_config$pool_memory_limit_mb * 0.9)) {
    recommendations <- c(recommendations,
                        "High memory usage - Consider reducing pool sizes")
  }
  
  if (length(recommendations) == 0) {
    recommendations <- "All performance metrics are within optimal ranges"
  }
  
  return(recommendations)
}

# ============================================================================
# MAIN INITIALIZATION FUNCTION
# ============================================================================

#' Initialize all Cloud Run connection pools with advanced configuration
#' @param force_reinit Force re-initialization of existing pools
#' @return Boolean indicating successful initialization
init_cloudrun_connection_pools <- function(force_reinit = FALSE) {
  cat("🚀 Initializing Cloud Run advanced connection pools...\n")

  # Get Cloud Run database configuration
  config <- get_cloudrun_database_config()
  if (is.null(config)) {
    cat("❌ Failed to get Cloud Run database configuration\n")
    return(FALSE)
  }

  # Close existing pools if force reinit
  if (force_reinit) {
    close_all_cloudrun_pools()
  }

  success_count <- 0

  # Initialize primary pool (highest priority)
  if (isTRUE(is.null(.connection_pools$primary)) || force_reinit) {
    .connection_pools$primary <<- create_cloudrun_pool("primary", config, .cloudrun_config$primary_pool_size)
    if (!is.null(.connection_pools$primary)) success_count <- success_count + 1
  }

  # Initialize readonly pool
  if (isTRUE(is.null(.connection_pools$readonly)) || force_reinit) {
    .connection_pools$readonly <<- create_cloudrun_pool("readonly", config, .cloudrun_config$readonly_pool_size)
    if (!is.null(.connection_pools$readonly)) success_count <- success_count + 1
  }

  # Initialize analytics pool
  if (isTRUE(is.null(.connection_pools$analytics)) || force_reinit) {
    .connection_pools$analytics <<- create_cloudrun_pool("analytics", config, .cloudrun_config$analytics_pool_size)
    if (!is.null(.connection_pools$analytics)) success_count <- success_count + 1
  }

  # Initialize maintenance pool
  if (isTRUE(is.null(.connection_pools$maintenance)) || force_reinit) {
    .connection_pools$maintenance <<- create_cloudrun_pool("maintenance", config, .cloudrun_config$maintenance_pool_size)
    if (!is.null(.connection_pools$maintenance)) success_count <- success_count + 1
  }

  # Reset metrics
  .pool_metrics$last_reset <<- Sys.time()

  cat("📊 Cloud Run connection pool initialization summary:\n")
  cat("✅ Successful pools:", success_count, "/", length(.connection_pools), "\n")
  cat("💾 Estimated memory usage:", calculate_estimated_memory_usage(), "MB\n")
  cat("🎯 Target Cloud Run memory limit:", .cloudrun_config$max_memory_mb, "MB\n")

  if (success_count >= 2) {  # At least primary and one backup
    cat("🎉 Cloud Run advanced connection pooling system is ready!\n")
    return(TRUE)
  } else {
    cat("⚠️ Limited connection pool availability - some features may be degraded\n")
    return(FALSE)
  }
}

#' Close all Cloud Run connection pools safely
close_all_cloudrun_pools <- function() {
  cat("🔐 Closing all Cloud Run connection pools...\n")

  for (pool_name in names(.connection_pools)) {
    pool <- .connection_pools[[pool_name]]
    if (!is.null(pool)) {
      tryCatch({
        poolClose(pool)
        cat("✅ Pool", pool_name, "closed successfully\n")
      }, error = function(e) {
        cat("⚠️ Error closing pool", pool_name, ":", e$message, "\n")
      })
      .connection_pools[[pool_name]] <<- NULL
    }
  }

  # Reset health status
  for (pool_name in names(.pool_health)) {
    .pool_health[[pool_name]] <<- list(status = "disconnected", last_check = NULL, failed_checks = 0)
  }

  cat("🎯 All Cloud Run connection pools closed\n")
}

# ============================================================================
# HELPER FUNCTIONS AND UTILITIES
# ============================================================================

# String concatenation operator
`%+%` <- function(a, b) paste0(a, b)

# Null coalescing operator
`%||%` <- function(a, b) if (is.null(a)) b else a

# Export main functions
list(
  # Main initialization
  init_cloudrun_connection_pools = init_cloudrun_connection_pools,
  close_all_cloudrun_pools = close_all_cloudrun_pools,

  # Pool management
  get_optimal_pool = get_optimal_pool,
  recover_failed_pools = recover_failed_pools,
  check_all_pools_health = check_all_pools_health,

  # Query execution
  execute_monitored_query = execute_monitored_query,

  # Performance monitoring
  get_pool_performance_metrics = get_pool_performance_metrics,
  optimize_pool_sizes = optimize_pool_sizes,

  # Configuration
  get_cloudrun_database_config = get_cloudrun_database_config
)

# Auto-initialization on load
cat("🔧 Cloud Run advanced connection pooling system loaded\n")
cat("📋 Run init_cloudrun_connection_pools() to initialize pools\n")
cat("📊 Run get_pool_performance_metrics() to monitor performance\n")
cat("🏥 Run check_all_pools_health() to check pool health\n")

# Set up cleanup on exit
reg.finalizer(globalenv(), function(e) {
  close_all_cloudrun_pools()
}, onexit = TRUE)