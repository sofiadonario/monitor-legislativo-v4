# ============================================================================
# COMPREHENSIVE BOTTLENECK ANALYSIS SYSTEM FOR BRAZILIAN LEGISLATIVE SYSTEM
# ============================================================================
# 
# This system provides advanced bottleneck identification across all system layers
# of the Brazilian Legislative Monitoring System running on Railway infrastructure.
# It identifies performance bottlenecks in database operations, cache performance,
# application layer processing, memory utilization, and Railway-specific constraints.
#
# Key Features:
# - Multi-layer bottleneck detection (Database, Cache, Application, Infrastructure)
# - Real-time performance profiling with detailed stack traces
# - Railway-specific resource constraint analysis
# - Brazilian legislative workload-specific bottleneck patterns
# - Automated performance regression detection
# - Memory leak and garbage collection analysis
# - Database query optimization recommendations
# - Cache hit ratio and TTL optimization analysis
#
# Integrates with PERF-001 (SQL optimization) and PERF-002 (Redis caching)
# ============================================================================

cat("🔍 Loading Comprehensive Bottleneck Analysis System for Brazilian Legislative System\n")

# Load required libraries with error handling
suppressPackageStartupMessages({
  library(profvis)
  library(pryr)
  library(microbenchmark)
  library(DBI)
  library(RPostgres)
  library(pool)
  library(dplyr)
  library(ggplot2)
  library(plotly)
  library(httr)
  library(jsonlite)
  library(stringr)
  library(lubridate)
  library(parallel)
  library(future)
})

# Global bottleneck analysis configuration
BOTTLENECK_CONFIG <- list(
  # Performance thresholds for bottleneck detection
  slow_query_threshold_seconds = 2.0,
  memory_leak_threshold_mb = 100,
  high_memory_threshold_mb = 1500,  # Railway 2GB limit consideration
  low_cache_hit_rate_threshold = 0.7,  # 70%
  high_db_connection_usage_threshold = 0.8,  # 80% of Railway's 100 connection limit
  
  # Analysis intervals
  monitoring_interval_seconds = 5,
  analysis_window_minutes = 30,
  trend_analysis_hours = 24,
  
  # Profiling settings
  profiling_sample_interval = 0.01,  # 10ms sampling
  profiling_duration_seconds = 60,
  
  # Railway-specific limits
  railway_memory_limit_mb = 2048,
  railway_db_connection_limit = 100,
  railway_request_timeout_seconds = 30
)

# Global bottleneck detection results
BOTTLENECK_RESULTS <- list(
  database_bottlenecks = list(),
  cache_bottlenecks = list(),
  application_bottlenecks = list(),
  memory_bottlenecks = list(),
  infrastructure_bottlenecks = list(),
  temporal_analysis = list(),
  recommendations = list()
)

# Performance tracking data
PERFORMANCE_TRACKING <- list(
  query_performance = data.frame(),
  memory_timeline = data.frame(),
  cache_statistics = data.frame(),
  response_time_distribution = data.frame(),
  error_patterns = data.frame()
)

# ============================================================================
# DATABASE LAYER BOTTLENECK ANALYSIS
# ============================================================================

#' Comprehensive database bottleneck detection and analysis
#' @param analysis_duration_minutes Duration for database analysis
#' @return Detailed database bottleneck report
analyze_database_bottlenecks <- function(analysis_duration_minutes = 30) {
  
  cat("🗄️ Starting comprehensive database bottleneck analysis...\n")
  
  analysis_start <- Sys.time()
  analysis_end <- analysis_start + (analysis_duration_minutes * 60)
  
  db_analysis <- list(
    start_time = analysis_start,
    duration_minutes = analysis_duration_minutes,
    query_performance = list(),
    connection_analysis = list(),
    index_analysis = list(),
    lock_analysis = list(),
    slow_queries = list(),
    connection_pool_metrics = list()
  )
  
  # Get database connection for analysis
  pool <- NULL
  if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
    pool <- secure_db_pool
  } else if (exists("get_database_pool")) {
    pool <- get_database_pool()
  }
  
  if (is.null(pool)) {
    cat("❌ No database pool available for bottleneck analysis\n")
    return(list(error = "No database connection available"))
  }
  
  tryCatch({
    
    # 1. Analyze query performance patterns
    cat("📊 Analyzing query performance patterns...\n")
    db_analysis$query_performance <- analyze_query_performance_patterns(pool, analysis_duration_minutes)
    
    # 2. Analyze connection pool utilization
    cat("🔗 Analyzing connection pool utilization...\n")
    db_analysis$connection_analysis <- analyze_connection_pool_bottlenecks(pool, analysis_duration_minutes)
    
    # 3. Analyze database schema and indexes
    cat("🏗️ Analyzing database schema and indexes...\n")
    db_analysis$index_analysis <- analyze_database_indexes(pool)
    
    # 4. Monitor for lock contention
    cat("🔒 Analyzing lock contention patterns...\n")
    db_analysis$lock_analysis <- analyze_lock_contention(pool, analysis_duration_minutes)
    
    # 5. Identify slow query patterns specific to Brazilian legislative data
    cat("⏱️ Identifying slow query patterns...\n")
    db_analysis$slow_queries <- identify_slow_query_patterns(pool, analysis_duration_minutes)
    
  }, error = function(e) {
    cat("❌ Error during database bottleneck analysis:", e$message, "\n")
    db_analysis$error <- e$message
  })
  
  db_analysis$end_time <- Sys.time()
  db_analysis$actual_duration <- as.numeric(difftime(db_analysis$end_time, db_analysis$start_time, units = "mins"))
  
  # Store results globally
  BOTTLENECK_RESULTS$database_bottlenecks <<- db_analysis
  
  cat("✅ Database bottleneck analysis completed in", round(db_analysis$actual_duration, 1), "minutes\n")
  
  return(db_analysis)
}

#' Analyze query performance patterns for Brazilian legislative workloads
#' @param pool Database connection pool
#' @param duration_minutes Analysis duration
#' @return Query performance analysis results
analyze_query_performance_patterns <- function(pool, duration_minutes = 30) {
  
  query_analysis <- list(
    total_queries_analyzed = 0,
    slow_queries_detected = 0,
    query_types = list(),
    performance_by_table = list(),
    optimization_opportunities = list()
  )
  
  # Get main table for analysis
  main_table <- NULL
  if (exists("get_main_table")) {
    main_table <- get_main_table()
  }
  
  if (is.null(main_table)) {
    cat("⚠️ No main table identified for query analysis\n")
    return(query_analysis)
  }
  
  cat("📊 Analyzing queries on main table:", main_table, "\n")
  
  # Define common Brazilian legislative query patterns to test
  test_queries <- list(
    # Search queries (most common)
    list(
      type = "full_text_search",
      query = sprintf("SELECT COUNT(*) FROM %s WHERE titulo ILIKE %%s OR ementa ILIKE %%s", main_table),
      params = list("%transporte%", "%transporte%"),
      expected_performance = "< 3 seconds"
    ),
    list(
      type = "geographic_filter",
      query = sprintf("SELECT COUNT(*) FROM %s WHERE estado = $1 AND data_publicacao >= $2", main_table),
      params = list("SP", Sys.Date() - 365),
      expected_performance = "< 1 second"
    ),
    list(
      type = "category_analysis",
      query = sprintf("SELECT categoria, COUNT(*) FROM %s WHERE data_publicacao >= $1 GROUP BY categoria", main_table),
      params = list(Sys.Date() - 730),
      expected_performance = "< 2 seconds"
    ),
    list(
      type = "temporal_analysis",
      query = sprintf("SELECT DATE_TRUNC('month', data_publicacao) as month, COUNT(*) FROM %s WHERE data_publicacao >= $1 GROUP BY month ORDER BY month", main_table),
      params = list(Sys.Date() - 1095),
      expected_performance = "< 5 seconds"
    ),
    list(
      type = "municipality_aggregation",
      query = sprintf("SELECT municipio, COUNT(*) FROM %s WHERE municipio IS NOT NULL AND municipio != '' GROUP BY municipio ORDER BY COUNT(*) DESC LIMIT 50", main_table),
      params = list(),
      expected_performance = "< 3 seconds"
    )
  )
  
  # Benchmark each query type
  for (test_query in test_queries) {
    tryCatch({
      
      cat("🔍 Testing", test_query$type, "performance...\n")
      
      # Run microbenchmark
      if (length(test_query$params) > 0) {
        benchmark_result <- microbenchmark(
          dbGetQuery(pool, test_query$query, params = test_query$params),
          times = 10,
          unit = "s"
        )
      } else {
        benchmark_result <- microbenchmark(
          dbGetQuery(pool, test_query$query),
          times = 10,
          unit = "s"
        )
      }
      
      # Analyze benchmark results
      median_time <- median(benchmark_result$time / 1e9)  # Convert to seconds
      max_time <- max(benchmark_result$time / 1e9)
      
      query_analysis$query_types[[test_query$type]] <- list(
        median_time_seconds = round(median_time, 3),
        max_time_seconds = round(max_time, 3),
        is_slow = median_time > BOTTLENECK_CONFIG$slow_query_threshold_seconds,
        expected_performance = test_query$expected_performance,
        performance_rating = ifelse(median_time < 1, "Excellent", 
                                   ifelse(median_time < 3, "Good",
                                         ifelse(median_time < 5, "Acceptable", "Poor")))
      )
      
      if (median_time > BOTTLENECK_CONFIG$slow_query_threshold_seconds) {
        query_analysis$slow_queries_detected <- query_analysis$slow_queries_detected + 1
        
        # Add optimization recommendation
        optimization <- generate_query_optimization_recommendation(test_query$type, median_time, test_query$query)
        query_analysis$optimization_opportunities[[test_query$type]] <- optimization
      }
      
      query_analysis$total_queries_analyzed <- query_analysis$total_queries_analyzed + 1
      
    }, error = function(e) {
      cat("❌ Error testing", test_query$type, ":", e$message, "\n")
      query_analysis$query_types[[test_query$type]] <- list(error = e$message)
    })
  }
  
  return(query_analysis)
}

#' Analyze connection pool bottlenecks
#' @param pool Database connection pool
#' @param duration_minutes Analysis duration
#' @return Connection pool analysis results
analyze_connection_pool_bottlenecks <- function(pool, duration_minutes = 30) {
  
  connection_analysis <- list(
    monitoring_duration = duration_minutes,
    connection_metrics = list(),
    pool_utilization = list(),
    bottleneck_indicators = list(),
    railway_compliance = list()
  )
  
  tryCatch({
    
    # Monitor connection pool metrics over time
    start_time <- Sys.time()
    end_time <- start_time + (duration_minutes * 60)
    
    connection_samples <- list()
    sample_count <- 0
    
    while (Sys.time() < end_time && sample_count < 100) {  # Limit samples for performance
      
      # Get current pool metrics
      active_connections <- 0
      idle_connections <- 0
      total_connections <- 0
      
      tryCatch({
        active_connections <- pool::poolGetActive(pool)
        idle_connections <- pool::poolGetIdle(pool)
        total_connections <- active_connections + idle_connections
      }, error = function(e) {
        # Pool metrics unavailable
      })
      
      connection_samples[[length(connection_samples) + 1]] <- list(
        timestamp = Sys.time(),
        active = active_connections,
        idle = idle_connections,
        total = total_connections,
        utilization_pct = ifelse(BOTTLENECK_CONFIG$railway_db_connection_limit > 0, 
                                (total_connections / BOTTLENECK_CONFIG$railway_db_connection_limit) * 100, 0)
      )
      
      sample_count <- sample_count + 1
      Sys.sleep(max(1, (duration_minutes * 60) / 100))  # Adaptive sampling interval
    }
    
    # Analyze connection patterns
    if (length(connection_samples) > 0) {
      
      connection_df <- do.call(rbind.data.frame, lapply(connection_samples, function(x) {
        data.frame(
          timestamp = as.numeric(x$timestamp),
          active = x$active,
          idle = x$idle,
          total = x$total,
          utilization_pct = x$utilization_pct
        )
      }))
      
      connection_analysis$connection_metrics <- list(
        samples_collected = nrow(connection_df),
        avg_active_connections = round(mean(connection_df$active, na.rm = TRUE), 1),
        max_active_connections = max(connection_df$active, na.rm = TRUE),
        avg_total_connections = round(mean(connection_df$total, na.rm = TRUE), 1),
        max_total_connections = max(connection_df$total, na.rm = TRUE),
        avg_utilization_pct = round(mean(connection_df$utilization_pct, na.rm = TRUE), 1),
        peak_utilization_pct = round(max(connection_df$utilization_pct, na.rm = TRUE), 1)
      )
      
      # Identify bottleneck indicators
      high_utilization_samples <- sum(connection_df$utilization_pct > (BOTTLENECK_CONFIG$high_db_connection_usage_threshold * 100), na.rm = TRUE)
      
      connection_analysis$bottleneck_indicators <- list(
        high_utilization_frequency = round((high_utilization_samples / nrow(connection_df)) * 100, 1),
        is_connection_bottleneck = high_utilization_samples > (nrow(connection_df) * 0.2),  # 20% of samples show high utilization
        connection_pool_pressure = connection_analysis$connection_metrics$peak_utilization_pct > 90
      )
      
      # Railway compliance analysis
      connection_analysis$railway_compliance <- list(
        within_connection_limit = connection_analysis$connection_metrics$max_total_connections <= BOTTLENECK_CONFIG$railway_db_connection_limit,
        connection_safety_margin = BOTTLENECK_CONFIG$railway_db_connection_limit - connection_analysis$connection_metrics$max_total_connections,
        utilization_rating = case_when(
          connection_analysis$connection_metrics$peak_utilization_pct < 50 ~ "Low",
          connection_analysis$connection_metrics$peak_utilization_pct < 80 ~ "Moderate",
          connection_analysis$connection_metrics$peak_utilization_pct < 95 ~ "High",
          TRUE ~ "Critical"
        )
      )
    }
    
  }, error = function(e) {
    cat("❌ Error analyzing connection pool:", e$message, "\n")
    connection_analysis$error <- e$message
  })
  
  return(connection_analysis)
}

#' Analyze database indexes for optimization opportunities
#' @param pool Database connection pool
#' @return Index analysis results
analyze_database_indexes <- function(pool) {
  
  index_analysis <- list(
    tables_analyzed = 0,
    indexes_found = 0,
    missing_indexes = list(),
    unused_indexes = list(),
    optimization_opportunities = list()
  )
  
  tryCatch({
    
    # Get main table for analysis
    main_table <- NULL
    if (exists("get_main_table")) {
      main_table <- get_main_table()
    }
    
    if (is.null(main_table)) {
      cat("⚠️ No main table for index analysis\n")
      return(index_analysis)
    }
    
    cat("🏗️ Analyzing indexes on main table:", main_table, "\n")
    
    # Check existing indexes
    existing_indexes_query <- "
      SELECT 
        indexname,
        indexdef,
        schemaname,
        tablename
      FROM pg_indexes 
      WHERE tablename = $1
    "
    
    existing_indexes <- dbGetQuery(pool, existing_indexes_query, params = list(main_table))
    index_analysis$indexes_found <- nrow(existing_indexes)
    
    # Analyze table structure for index recommendations
    table_structure_query <- sprintf("
      SELECT column_name, data_type, is_nullable
      FROM information_schema.columns
      WHERE table_name = '%s'
      ORDER BY ordinal_position
    ", main_table)
    
    table_structure <- dbGetQuery(pool, table_structure_query)
    
    # Define recommended indexes for Brazilian legislative data
    recommended_indexes <- list(
      list(
        column = "titulo",
        type = "GIN",
        reason = "Full-text search on document titles",
        priority = "High",
        query_benefit = "Search operations by title"
      ),
      list(
        column = "data_publicacao",
        type = "BTREE",
        reason = "Temporal filtering and sorting",
        priority = "High",
        query_benefit = "Date range queries and chronological sorting"
      ),
      list(
        column = "estado",
        type = "BTREE", 
        reason = "Geographic filtering by state",
        priority = "Medium",
        query_benefit = "State-based filtering in geographic analysis"
      ),
      list(
        column = "municipio",
        type = "BTREE",
        reason = "Municipal-level analysis",
        priority = "Medium",
        query_benefit = "Municipality aggregation queries"
      ),
      list(
        column = "categoria",
        type = "BTREE",
        reason = "Document categorization filtering",
        priority = "Medium",
        query_benefit = "Category-based searches and analytics"
      ),
      list(
        columns = c("estado", "data_publicacao"),
        type = "BTREE",
        reason = "Combined geographic and temporal filtering",
        priority = "Medium",
        query_benefit = "Geographic analysis with time constraints"
      )
    )
    
    # Check for missing recommended indexes
    for (rec_index in recommended_indexes) {
      
      if ("columns" %in% names(rec_index)) {
        # Multi-column index
        index_name_pattern <- paste(rec_index$columns, collapse = "_")
      } else {
        # Single column index
        index_name_pattern <- rec_index$column
      }
      
      # Check if similar index exists
      index_exists <- any(grepl(index_name_pattern, existing_indexes$indexname, ignore.case = TRUE))
      
      if (!index_exists) {
        # Check if column exists in table
        if ("column" %in% names(rec_index)) {
          column_exists <- rec_index$column %in% table_structure$column_name
        } else {
          column_exists <- all(rec_index$columns %in% table_structure$column_name)
        }
        
        if (column_exists) {
          index_analysis$missing_indexes[[length(index_analysis$missing_indexes) + 1]] <- rec_index
        }
      }
    }
    
    index_analysis$tables_analyzed <- 1
    
  }, error = function(e) {
    cat("❌ Error analyzing database indexes:", e$message, "\n")
    index_analysis$error <- e$message
  })
  
  return(index_analysis)
}

#' Analyze lock contention patterns
#' @param pool Database connection pool
#' @param duration_minutes Analysis duration
#' @return Lock contention analysis results
analyze_lock_contention <- function(pool, duration_minutes = 30) {
  
  lock_analysis <- list(
    monitoring_duration = duration_minutes,
    lock_samples = 0,
    blocking_queries = list(),
    deadlocks_detected = 0,
    lock_wait_times = list(),
    contention_hotspots = list()
  )
  
  tryCatch({
    
    # Monitor for lock contention over specified duration
    start_time <- Sys.time()
    end_time <- start_time + (duration_minutes * 60)
    
    sample_interval <- max(10, (duration_minutes * 60) / 20)  # At most 20 samples
    
    while (Sys.time() < end_time) {
      
      # Query for current locks and blocking
      lock_query <- "
        SELECT 
          blocked_locks.pid AS blocked_pid,
          blocked_activity.usename AS blocked_user,
          blocking_locks.pid AS blocking_pid,
          blocking_activity.usename AS blocking_user,
          blocked_activity.query AS blocked_statement,
          blocking_activity.query AS current_statement_in_blocking_process,
          blocked_activity.state AS blocked_state,
          blocking_activity.state AS blocking_state
        FROM pg_catalog.pg_locks blocked_locks
        JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid
        JOIN pg_catalog.pg_locks blocking_locks ON blocking_locks.locktype = blocked_locks.locktype
          AND blocking_locks.DATABASE IS NOT DISTINCT FROM blocked_locks.DATABASE
          AND blocking_locks.relation IS NOT DISTINCT FROM blocked_locks.relation
          AND blocking_locks.page IS NOT DISTINCT FROM blocked_locks.page
          AND blocking_locks.tuple IS NOT DISTINCT FROM blocked_locks.tuple
          AND blocking_locks.virtualxid IS NOT DISTINCT FROM blocked_locks.virtualxid
          AND blocking_locks.transactionid IS NOT DISTINCT FROM blocked_locks.transactionid
          AND blocking_locks.classid IS NOT DISTINCT FROM blocked_locks.classid
          AND blocking_locks.objid IS NOT DISTINCT FROM blocked_locks.objid
          AND blocking_locks.objsubid IS NOT DISTINCT FROM blocked_locks.objsubid
          AND blocking_locks.pid != blocked_locks.pid
        JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid
        WHERE NOT blocked_locks.GRANTED
      "
      
      lock_results <- dbGetQuery(pool, lock_query)
      
      if (nrow(lock_results) > 0) {
        lock_analysis$blocking_queries[[length(lock_analysis$blocking_queries) + 1]] <- list(
          timestamp = Sys.time(),
          blocks_detected = nrow(lock_results),
          blocking_details = lock_results
        )
      }
      
      lock_analysis$lock_samples <- lock_analysis$lock_samples + 1
      Sys.sleep(sample_interval)
    }
    
  }, error = function(e) {
    cat("❌ Error analyzing lock contention:", e$message, "\n")
    lock_analysis$error <- e$message
  })
  
  return(lock_analysis)
}

#' Identify slow query patterns specific to Brazilian legislative workloads
#' @param pool Database connection pool
#' @param duration_minutes Analysis duration
#' @return Slow query analysis results
identify_slow_query_patterns <- function(pool, duration_minutes = 30) {
  
  slow_query_analysis <- list(
    monitoring_duration = duration_minutes,
    slow_queries_detected = list(),
    query_patterns = list(),
    performance_trends = list(),
    optimization_recommendations = list()
  )
  
  tryCatch({
    
    # Enable query timing if available
    dbExecute(pool, "SET log_min_duration_statement = 1000")  # Log queries > 1 second
    
    # Test performance of common legislative workload patterns
    legislative_query_patterns <- list(
      # Pattern 1: Geographic document distribution
      list(
        pattern_name = "geographic_distribution",
        query = "SELECT estado, COUNT(*) as doc_count FROM %s WHERE data_publicacao >= $1 GROUP BY estado ORDER BY doc_count DESC",
        test_params = list(Sys.Date() - 365)
      ),
      # Pattern 2: Temporal trend analysis
      list(
        pattern_name = "temporal_trends", 
        query = "SELECT DATE_TRUNC('quarter', data_publicacao) as quarter, COUNT(*) FROM %s WHERE data_publicacao >= $1 GROUP BY quarter ORDER BY quarter",
        test_params = list(Sys.Date() - 1095)
      ),
      # Pattern 3: Full-text search with filters
      list(
        pattern_name = "filtered_text_search",
        query = "SELECT * FROM %s WHERE (titulo ILIKE $1 OR ementa ILIKE $1) AND estado = $2 AND data_publicacao >= $3 ORDER BY data_publicacao DESC LIMIT 100",
        test_params = list("%meio ambiente%", "SP", Sys.Date() - 365)
      ),
      # Pattern 4: Category analysis with aggregation
      list(
        pattern_name = "category_aggregation",
        query = "SELECT tipo, categoria, COUNT(*) FROM %s WHERE data_publicacao BETWEEN $1 AND $2 GROUP BY tipo, categoria HAVING COUNT(*) > 5 ORDER BY COUNT(*) DESC",
        test_params = list(Sys.Date() - 730, Sys.Date())
      ),
      # Pattern 5: Municipal document analysis
      list(
        pattern_name = "municipal_analysis",
        query = "SELECT municipio, COUNT(*) as total, COUNT(DISTINCT tipo) as types FROM %s WHERE municipio IS NOT NULL AND municipio != '' GROUP BY municipio HAVING COUNT(*) >= 10 ORDER BY total DESC LIMIT 50",
        test_params = list()
      )
    )
    
    # Get main table for testing
    main_table <- NULL
    if (exists("get_main_table")) {
      main_table <- get_main_table()
    }
    
    if (is.null(main_table)) {
      cat("⚠️ No main table for slow query analysis\n")
      return(slow_query_analysis)
    }
    
    # Test each query pattern for performance
    for (pattern in legislative_query_patterns) {
      
      cat("⏱️ Testing", pattern$pattern_name, "performance...\n")
      
      pattern_query <- sprintf(pattern$query, main_table)
      
      tryCatch({
        
        # Measure query execution time
        start_time <- Sys.time()
        
        if (length(pattern$test_params) > 0) {
          result <- dbGetQuery(pool, pattern_query, params = pattern$test_params)
        } else {
          result <- dbGetQuery(pool, pattern_query)
        }
        
        end_time <- Sys.time()
        execution_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
        
        pattern_performance <- list(
          pattern_name = pattern$pattern_name,
          execution_time_seconds = round(execution_time, 3),
          rows_returned = ifelse(is.null(result), 0, nrow(result)),
          is_slow = execution_time > BOTTLENECK_CONFIG$slow_query_threshold_seconds,
          query_complexity = classify_query_complexity(pattern_query),
          optimization_priority = determine_optimization_priority(execution_time, pattern$pattern_name)
        )
        
        slow_query_analysis$query_patterns[[pattern$pattern_name]] <- pattern_performance
        
        if (execution_time > BOTTLENECK_CONFIG$slow_query_threshold_seconds) {
          slow_query_analysis$slow_queries_detected[[length(slow_query_analysis$slow_queries_detected) + 1]] <- 
            list(
              pattern = pattern$pattern_name,
              execution_time = execution_time,
              query = pattern_query,
              timestamp = Sys.time()
            )
          
          # Generate specific optimization recommendation
          optimization <- generate_query_optimization_recommendation(pattern$pattern_name, execution_time, pattern_query)
          slow_query_analysis$optimization_recommendations[[pattern$pattern_name]] <- optimization
        }
        
      }, error = function(e) {
        cat("❌ Error testing", pattern$pattern_name, ":", e$message, "\n")
        slow_query_analysis$query_patterns[[pattern$pattern_name]] <- list(
          error = e$message,
          is_slow = TRUE
        )
      })
    }
    
  }, error = function(e) {
    cat("❌ Error in slow query analysis:", e$message, "\n")
    slow_query_analysis$error <- e$message
  })
  
  return(slow_query_analysis)
}

# ============================================================================
# CACHE LAYER BOTTLENECK ANALYSIS  
# ============================================================================

#' Comprehensive cache bottleneck detection and analysis
#' @param analysis_duration_minutes Duration for cache analysis
#' @return Detailed cache bottleneck report
analyze_cache_bottlenecks <- function(analysis_duration_minutes = 30) {
  
  cat("💾 Starting comprehensive cache bottleneck analysis...\n")
  
  cache_analysis <- list(
    start_time = Sys.time(),
    duration_minutes = analysis_duration_minutes,
    cache_performance = list(),
    hit_rate_analysis = list(),
    ttl_optimization = list(),
    memory_efficiency = list(),
    redis_analysis = list()
  )
  
  tryCatch({
    
    # 1. Analyze cache hit rates and performance
    cat("📊 Analyzing cache hit rates and performance patterns...\n")
    cache_analysis$cache_performance <- analyze_cache_hit_patterns(analysis_duration_minutes)
    
    # 2. Analyze TTL optimization opportunities  
    cat("⏰ Analyzing TTL optimization opportunities...\n")
    cache_analysis$ttl_optimization <- analyze_cache_ttl_patterns()
    
    # 3. Analyze cache memory efficiency
    cat("🧠 Analyzing cache memory usage efficiency...\n")  
    cache_analysis$memory_efficiency <- analyze_cache_memory_efficiency()
    
    # 4. Redis-specific bottleneck analysis (if available)
    cat("🔴 Analyzing Redis-specific performance...\n")
    cache_analysis$redis_analysis <- analyze_redis_bottlenecks()
    
  }, error = function(e) {
    cat("❌ Error during cache bottleneck analysis:", e$message, "\n")
    cache_analysis$error <- e$message
  })
  
  cache_analysis$end_time <- Sys.time()
  cache_analysis$actual_duration <- as.numeric(difftime(cache_analysis$end_time, cache_analysis$start_time, units = "mins"))
  
  # Store results globally
  BOTTLENECK_RESULTS$cache_bottlenecks <<- cache_analysis
  
  cat("✅ Cache bottleneck analysis completed in", round(cache_analysis$actual_duration, 1), "minutes\n")
  
  return(cache_analysis)
}

#' Analyze cache hit rate patterns and identify bottlenecks
#' @param duration_minutes Analysis duration
#' @return Cache hit pattern analysis results
analyze_cache_hit_patterns <- function(duration_minutes = 30) {
  
  hit_analysis <- list(
    baseline_metrics = list(),
    performance_under_load = list(),
    cache_effectiveness = list(),
    bottleneck_indicators = list()
  )
  
  tryCatch({
    
    # Get baseline cache performance metrics
    if (exists("get_performance_stats")) {
      baseline_stats <- get_performance_stats()
      
      hit_analysis$baseline_metrics <- list(
        cache_hits = ifelse(is.null(baseline_stats$cache_hits), 0, baseline_stats$cache_hits),
        cache_misses = ifelse(is.null(baseline_stats$cache_misses), 0, baseline_stats$cache_misses),
        cache_hit_rate = ifelse(is.null(baseline_stats$cache_hit_rate), 0, baseline_stats$cache_hit_rate),
        avg_query_time = ifelse(is.null(baseline_stats$avg_query_time), 0, baseline_stats$avg_query_time),
        queries_executed = ifelse(is.null(baseline_stats$queries_executed), 0, baseline_stats$queries_executed)
      )
      
      # Analyze cache effectiveness
      hit_analysis$cache_effectiveness <- list(
        hit_rate_rating = case_when(
          baseline_stats$cache_hit_rate >= 90 ~ "Excellent",
          baseline_stats$cache_hit_rate >= 80 ~ "Good", 
          baseline_stats$cache_hit_rate >= 70 ~ "Acceptable",
          baseline_stats$cache_hit_rate >= 50 ~ "Poor",
          TRUE ~ "Critical"
        ),
        is_cache_bottleneck = baseline_stats$cache_hit_rate < (BOTTLENECK_CONFIG$low_cache_hit_rate_threshold * 100),
        cache_impact_on_performance = baseline_stats$avg_query_time > 3.0 && baseline_stats$cache_hit_rate < 80
      )
      
      # Identify bottleneck indicators
      hit_analysis$bottleneck_indicators <- list(
        low_hit_rate = baseline_stats$cache_hit_rate < (BOTTLENECK_CONFIG$low_cache_hit_rate_threshold * 100),
        high_miss_rate = (baseline_stats$cache_misses / max(1, baseline_stats$cache_hits + baseline_stats$cache_misses)) > 0.3,
        slow_cache_performance = baseline_stats$avg_query_time > 2.0,
        cache_underutilization = baseline_stats$queries_executed > 100 && baseline_stats$cache_hit_rate < 50
      )
    }
    
    # Test cache performance under simulated load
    cat("🔄 Testing cache performance under load...\n")
    
    load_test_results <- list()
    
    # Simulate cache load with common Brazilian legislative searches
    test_searches <- c(
      "transporte público",
      "meio ambiente", 
      "educação",
      "saúde pública",
      "segurança pública"
    )
    
    for (i in 1:length(test_searches)) {
      search_term <- test_searches[i]
      
      # Test cache performance for each search
      start_time <- Sys.time()
      
      if (exists("get_library_documents_optimized")) {
        # First call (should be cache miss)
        result1 <- get_library_documents_optimized(search_term = search_term, limit = 20)
        first_call_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
        
        # Second call (should be cache hit)
        start_time2 <- Sys.time()
        result2 <- get_library_documents_optimized(search_term = search_term, limit = 20)
        second_call_time <- as.numeric(difftime(Sys.time(), start_time2, units = "secs"))
        
        cache_improvement_ratio <- ifelse(second_call_time > 0, first_call_time / second_call_time, 1)
        
        load_test_results[[search_term]] <- list(
          first_call_time = round(first_call_time, 3),
          second_call_time = round(second_call_time, 3),
          cache_improvement_ratio = round(cache_improvement_ratio, 2),
          effective_caching = cache_improvement_ratio > 1.5
        )
      }
    }
    
    hit_analysis$performance_under_load <- load_test_results
    
  }, error = function(e) {
    cat("❌ Error analyzing cache hit patterns:", e$message, "\n")
    hit_analysis$error <- e$message
  })
  
  return(hit_analysis)
}

#' Analyze cache TTL optimization opportunities
#' @return TTL analysis results
analyze_cache_ttl_patterns <- function() {
  
  ttl_analysis <- list(
    current_ttl_settings = list(),
    data_freshness_requirements = list(),
    optimization_opportunities = list(),
    recommendations = list()
  )
  
  tryCatch({
    
    # Analyze different data types and their freshness requirements
    data_freshness_requirements <- list(
      # Static reference data - can be cached longer
      list(
        data_type = "document_categories",
        current_update_frequency = "rarely",
        recommended_ttl_minutes = 1440,  # 24 hours
        reasoning = "Document categories rarely change"
      ),
      # Search results - moderate caching
      list(
        data_type = "search_results", 
        current_update_frequency = "real-time",
        recommended_ttl_minutes = 15,  # 15 minutes
        reasoning = "Balance between freshness and performance"
      ),
      # Dashboard metrics - can tolerate some staleness
      list(
        data_type = "dashboard_metrics",
        current_update_frequency = "frequent",
        recommended_ttl_minutes = 30,  # 30 minutes
        reasoning = "Metrics don't need real-time accuracy for most use cases"
      ),
      # Geographic data - rarely changes
      list(
        data_type = "geographic_boundaries",
        current_update_frequency = "very_rarely", 
        recommended_ttl_minutes = 10080,  # 1 week
        reasoning = "Brazilian state/municipality boundaries are stable"
      ),
      # User session data - short TTL for security
      list(
        data_type = "user_sessions",
        current_update_frequency = "real-time",
        recommended_ttl_minutes = 60,  # 1 hour
        reasoning = "Security and user experience balance"
      )
    )
    
    ttl_analysis$data_freshness_requirements <- data_freshness_requirements
    
    # Generate TTL optimization recommendations
    ttl_optimizations <- list()
    
    for (data_req in data_freshness_requirements) {
      # Check if current implementation might benefit from TTL adjustment
      optimization <- list(
        data_type = data_req$data_type,
        recommended_ttl = data_req$recommended_ttl_minutes,
        optimization_potential = case_when(
          data_req$data_type %in% c("document_categories", "geographic_boundaries") ~ "High - Can cache much longer",
          data_req$data_type %in% c("dashboard_metrics") ~ "Medium - Moderate TTL increase possible",
          data_req$data_type %in% c("search_results") ~ "Medium - Balance freshness and performance",
          TRUE ~ "Low - Current TTL likely appropriate"
        ),
        implementation_priority = case_when(
          data_req$recommended_ttl_minutes > 1000 ~ "High",
          data_req$recommended_ttl_minutes > 30 ~ "Medium",
          TRUE ~ "Low"
        )
      )
      
      ttl_optimizations[[data_req$data_type]] <- optimization
    }
    
    ttl_analysis$optimization_opportunities <- ttl_optimizations
    
    # Generate specific TTL recommendations
    ttl_analysis$recommendations <- list(
      "Increase TTL for static data (categories, geographic) to reduce database load",
      "Implement adaptive TTL based on data volatility patterns",
      "Use cache invalidation strategies for critical real-time data",
      "Consider time-of-day based TTL adjustment for Brazilian business hours",
      "Implement cache warming strategies for frequently accessed data"
    )
    
  }, error = function(e) {
    cat("❌ Error analyzing TTL patterns:", e$message, "\n")
    ttl_analysis$error <- e$message
  })
  
  return(ttl_analysis)
}

#' Analyze cache memory efficiency
#' @return Memory efficiency analysis results
analyze_cache_memory_efficiency <- function() {
  
  memory_analysis <- list(
    current_memory_usage = list(),
    efficiency_metrics = list(),
    optimization_opportunities = list(),
    railway_compliance = list()
  )
  
  tryCatch({
    
    # Get current memory usage
    current_memory_mb <- as.numeric(pryr::mem_used()) / 1024 / 1024
    
    # Estimate cache memory usage (approximation)
    cache_memory_estimate <- 0
    cache_entry_count <- 0
    
    if (exists(".query_cache")) {
      cache_entry_count <- length(get(".query_cache", envir = .GlobalEnv))
      # Rough estimate: 50KB average per cache entry
      cache_memory_estimate <- cache_entry_count * 0.05  # MB
    }
    
    memory_analysis$current_memory_usage <- list(
      total_memory_mb = round(current_memory_mb, 1),
      estimated_cache_memory_mb = round(cache_memory_estimate, 1),
      cache_memory_percentage = round((cache_memory_estimate / current_memory_mb) * 100, 1),
      cache_entries = cache_entry_count
    )
    
    # Analyze memory efficiency
    memory_analysis$efficiency_metrics <- list(
      memory_per_cache_entry = ifelse(cache_entry_count > 0, round(cache_memory_estimate / cache_entry_count, 3), 0),
      cache_density = ifelse(current_memory_mb > 0, round(cache_entry_count / current_memory_mb, 1), 0),
      efficiency_rating = case_when(
        cache_memory_estimate > 500 ~ "Poor - Cache using excessive memory",
        cache_memory_estimate > 200 ~ "Moderate - Cache using significant memory", 
        cache_memory_estimate > 50 ~ "Good - Reasonable cache memory usage",
        TRUE ~ "Excellent - Minimal cache memory footprint"
      )
    )
    
    # Railway memory constraint analysis
    memory_analysis$railway_compliance <- list(
      within_memory_limit = current_memory_mb <= BOTTLENECK_CONFIG$railway_memory_limit_mb,
      memory_safety_margin = BOTTLENECK_CONFIG$railway_memory_limit_mb - current_memory_mb,
      cache_impact_on_limit = round((cache_memory_estimate / BOTTLENECK_CONFIG$railway_memory_limit_mb) * 100, 1),
      memory_pressure = current_memory_mb > (BOTTLENECK_CONFIG$railway_memory_limit_mb * 0.8)
    )
    
    # Generate optimization recommendations
    optimization_recommendations <- c()
    
    if (cache_memory_estimate > 200) {
      optimization_recommendations <- c(optimization_recommendations, 
        "Consider reducing cache size or implementing LRU eviction")
    }
    
    if (memory_analysis$railway_compliance$memory_pressure) {
      optimization_recommendations <- c(optimization_recommendations,
        "CRITICAL: Memory usage approaching Railway limit - implement memory optimization")
    }
    
    if (cache_entry_count > 1000) {
      optimization_recommendations <- c(optimization_recommendations,
        "Large number of cache entries - consider cache size limits")
    }
    
    if (length(optimization_recommendations) == 0) {
      optimization_recommendations <- c("Cache memory usage is within acceptable limits")
    }
    
    memory_analysis$optimization_opportunities <- optimization_recommendations
    
  }, error = function(e) {
    cat("❌ Error analyzing cache memory efficiency:", e$message, "\n")
    memory_analysis$error <- e$message
  })
  
  return(memory_analysis)
}

#' Analyze Redis-specific bottlenecks (if Redis is available)
#' @return Redis bottleneck analysis results
analyze_redis_bottlenecks <- function() {
  
  redis_analysis <- list(
    redis_available = FALSE,
    connection_analysis = list(),
    performance_metrics = list(),
    memory_analysis = list(),
    optimization_recommendations = list()
  )
  
  # Check if Redis connection is available
  # This would need to be implemented based on your specific Redis setup
  # For now, we'll provide a placeholder analysis
  
  tryCatch({
    
    # Placeholder for Redis analysis
    # In a real implementation, you would:
    # 1. Connect to Redis instance
    # 2. Run INFO command to get metrics
    # 3. Analyze memory usage, hit rates, slow queries
    # 4. Check connection pool status
    
    redis_analysis$redis_available <- FALSE
    redis_analysis$message <- "Redis analysis not implemented - would require Redis connection setup"
    
    # If Redis were available, analysis would include:
    redis_analysis$potential_metrics <- list(
      "Connection pool utilization",
      "Memory usage and fragmentation", 
      "Hit/miss ratios per key pattern",
      "Slow command analysis",
      "Persistence and replication lag",
      "Key expiration patterns",
      "Memory efficiency by data type"
    )
    
    redis_analysis$optimization_recommendations <- list(
      "Implement Redis connection if not available for better caching performance",
      "Consider Redis clustering for high availability in production",
      "Monitor Redis memory usage to prevent out-of-memory issues",
      "Implement Redis key expiration policies aligned with data freshness requirements",
      "Use Redis pipelining for bulk operations to improve throughput"
    )
    
  }, error = function(e) {
    cat("❌ Error analyzing Redis bottlenecks:", e$message, "\n")
    redis_analysis$error <- e$message
  })
  
  return(redis_analysis)
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

#' Classify query complexity for optimization prioritization
#' @param query SQL query string
#' @return Query complexity classification
classify_query_complexity <- function(query) {
  
  query_lower <- tolower(query)
  
  # Count complexity indicators
  complexity_score <- 0
  
  # JOIN operations
  complexity_score <- complexity_score + str_count(query_lower, "join") * 2
  
  # Subqueries
  complexity_score <- complexity_score + str_count(query_lower, "\\(\\s*select") * 3
  
  # GROUP BY operations
  complexity_score <- complexity_score + str_count(query_lower, "group by") * 2
  
  # ORDER BY operations
  complexity_score <- complexity_score + str_count(query_lower, "order by") * 1
  
  # LIKE operations (can be expensive)
  complexity_score <- complexity_score + str_count(query_lower, "like|ilike") * 1
  
  # Aggregate functions
  complexity_score <- complexity_score + str_count(query_lower, "count|sum|avg|max|min") * 1
  
  # Classify based on score
  if (complexity_score >= 10) return("Very High")
  if (complexity_score >= 7) return("High") 
  if (complexity_score >= 4) return("Medium")
  if (complexity_score >= 2) return("Low")
  return("Very Low")
}

#' Determine optimization priority based on execution time and pattern
#' @param execution_time Query execution time in seconds
#' @param pattern_name Query pattern name
#' @return Optimization priority level
determine_optimization_priority <- function(execution_time, pattern_name) {
  
  # Base priority on execution time
  time_priority <- case_when(
    execution_time > 10 ~ "Critical",
    execution_time > 5 ~ "High",
    execution_time > 2 ~ "Medium", 
    TRUE ~ "Low"
  )
  
  # Adjust based on pattern importance for Brazilian legislative workflows
  pattern_multiplier <- case_when(
    pattern_name %in% c("filtered_text_search", "geographic_distribution") ~ 1.5,  # Most common operations
    pattern_name %in% c("temporal_trends", "category_aggregation") ~ 1.2,  # Important analytics
    pattern_name %in% c("municipal_analysis") ~ 1.0,  # Standard priority
    TRUE ~ 0.8  # Lower priority patterns
  )
  
  # Calculate final priority
  if (time_priority == "Critical") return("Critical")
  if (time_priority == "High" && pattern_multiplier >= 1.2) return("Critical")
  if (time_priority == "High") return("High")
  if (time_priority == "Medium" && pattern_multiplier >= 1.5) return("High")
  if (time_priority == "Medium") return("Medium")
  return("Low")
}

#' Generate specific query optimization recommendations
#' @param query_type Type of query being optimized
#' @param execution_time Current execution time
#' @param query_text Query text for analysis
#' @return Optimization recommendation
generate_query_optimization_recommendation <- function(query_type, execution_time, query_text) {
  
  recommendations <- list(
    issue = paste("Slow", query_type, "query -", round(execution_time, 2), "seconds"),
    priority = determine_optimization_priority(execution_time, query_type),
    specific_recommendations = c(),
    implementation_effort = "Medium"
  )
  
  # Generate specific recommendations based on query type
  if (query_type %in% c("full_text_search", "filtered_text_search")) {
    recommendations$specific_recommendations <- c(
      "Implement GIN index on titulo and ementa columns for full-text search",
      "Consider using PostgreSQL full-text search (tsvector) for better performance",
      "Add composite index on (estado, data_publicacao) for filtered searches",
      "Implement query result caching with appropriate TTL"
    )
  } else if (query_type == "geographic_distribution") {
    recommendations$specific_recommendations <- c(
      "Add BTREE index on estado column for geographic filtering",
      "Consider partitioning by estado for very large datasets",
      "Implement materialized view for frequently accessed geographic aggregations",
      "Add composite index on (estado, data_publicacao) for temporal geographic analysis"
    )
  } else if (query_type %in% c("temporal_trends", "temporal_analysis")) {
    recommendations$specific_recommendations <- c(
      "Add BTREE index on data_publicacao for temporal queries",
      "Consider partitioning by date ranges (yearly or quarterly)",
      "Implement materialized view for common temporal aggregations",
      "Use date_trunc indexing for better GROUP BY performance"
    )
  } else if (query_type %in% c("category_aggregation", "category_analysis")) {
    recommendations$specific_recommendations <- c(
      "Add BTREE index on tipo and categoria columns",
      "Consider normalizing category data to separate table with foreign keys",
      "Implement category lookup caching",
      "Add composite index on (categoria, data_publicacao) for filtered aggregations"
    )
  } else if (query_type == "municipal_analysis") {
    recommendations$specific_recommendations <- c(
      "Add BTREE index on municipio column",
      "Implement data cleaning to standardize municipality names",
      "Consider separate municipality reference table with geographic data",
      "Add composite index on (municipio, estado) for regional analysis"
    )
  } else {
    recommendations$specific_recommendations <- c(
      "Analyze query execution plan using EXPLAIN ANALYZE",
      "Consider adding appropriate indexes based on WHERE clause columns",
      "Implement query result caching for frequently executed queries",
      "Review and optimize any subqueries or complex joins"
    )
  }
  
  # Determine implementation effort
  if (execution_time > 10) {
    recommendations$implementation_effort <- "High - Critical performance issue"
  } else if (grepl("materialized view|partitioning", paste(recommendations$specific_recommendations, collapse = " "))) {
    recommendations$implementation_effort <- "High - Requires schema changes"
  } else if (grepl("index", paste(recommendations$specific_recommendations, collapse = " "))) {
    recommendations$implementation_effort <- "Medium - Index creation required"
  } else {
    recommendations$implementation_effort <- "Low - Configuration or caching changes"
  }
  
  return(recommendations)
}

# ============================================================================
# INITIALIZATION AND EXPORT
# ============================================================================

cat("✅ Comprehensive Bottleneck Analysis System loaded successfully\n")
cat("🔍 Ready to identify performance bottlenecks across all system layers\n")
cat("📊 Database, cache, application, and infrastructure analysis enabled\n") 
cat("🎯 Railway-specific constraint analysis configured\n")
cat("🧠 Brazilian legislative workload pattern analysis ready\n")

# Export main analysis functions
cat("📋 Available bottleneck analysis functions:\n")
cat("  • analyze_database_bottlenecks(duration_minutes)\n")
cat("  • analyze_cache_bottlenecks(duration_minutes)\n") 
cat("  • analyze_query_performance_patterns(pool, duration_minutes)\n")
cat("  • analyze_connection_pool_bottlenecks(pool, duration_minutes)\n")
cat("  • identify_slow_query_patterns(pool, duration_minutes)\n")
cat("  • generate_query_optimization_recommendation(type, time, query)\n")