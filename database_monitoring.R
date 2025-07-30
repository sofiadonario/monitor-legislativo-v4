# Database Performance Monitoring and Query Analysis
# Monitor Legislativo v4 - Phase 2 Enhancement
# PostgreSQL Performance Optimization and Railway Deployment
# Created: 2025-07-29

library(DBI)
library(RPostgres)
library(pool)
library(dplyr)
library(lubridate)
library(jsonlite)
library(ggplot2)
library(plotly)

# Load performance monitoring if available
if (file.exists("performance_monitoring.R")) {
  source("performance_monitoring.R")
}

# Global database monitoring state
.db_monitoring_state <- new.env(parent = emptyenv())
.db_monitoring_state$query_log <- list()
.db_monitoring_state$slow_query_threshold <- 3000 # 3 seconds in ms
.db_monitoring_state$connection_pool_alerts <- TRUE
.db_monitoring_state$index_analysis_enabled <- TRUE

#' Initialize Database Performance Monitoring
#' @return Boolean indicating success
init_database_monitoring <- function() {
  tryCatch({
    cat("🗄️ Initializing Database Performance Monitoring\n")
    
    if (is.null(.db_pool)) {
      log_event("Database monitoring requires active database connection", "WARN")
      return(FALSE)
    }
    
    # Enable PostgreSQL query statistics collection
    enable_pg_stat_statements()
    
    # Create monitoring views for easier access
    create_monitoring_views()
    
    # Set up connection pool monitoring
    setup_connection_pool_monitoring()
    
    # Initialize query performance baselines
    initialize_query_baselines()
    
    log_event("Database performance monitoring initialized successfully")
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Database monitoring initialization error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Enable PostgreSQL Statement Statistics
enable_pg_stat_statements <- function() {
  tryCatch({
    # Check if pg_stat_statements extension is available
    extension_check <- dbGetQuery(.db_pool,
      "SELECT EXISTS(SELECT 1 FROM pg_available_extensions WHERE name = 'pg_stat_statements')")
    
    if (extension_check[[1]]) {
      # Try to create the extension (may already exist)
      tryCatch({
        dbExecute(.db_pool, "CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
        log_event("pg_stat_statements extension enabled")
      }, error = function(e) {
        log_event("pg_stat_statements extension not available - using alternative monitoring", "WARN")
      })
    }
    
  }, error = function(e) {
    log_event(paste("Failed to enable pg_stat_statements:", e$message), "WARN")
  })
}

#' Create Monitoring Views for Performance Analysis
create_monitoring_views <- function() {
  tryCatch({
    # Create view for slow queries analysis
    dbExecute(.db_pool, "
      CREATE OR REPLACE VIEW monitor_slow_queries AS
      SELECT 
        query,
        calls,
        total_exec_time,
        mean_exec_time,
        max_exec_time,
        stddev_exec_time,
        rows,
        100.0 * shared_blks_hit /
          nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
      FROM pg_stat_statements 
      WHERE mean_exec_time > 1000  -- Queries taking more than 1 second on average
      ORDER BY mean_exec_time DESC
    ")
    
    # Create view for database activity
    dbExecute(.db_pool, "
      CREATE OR REPLACE VIEW monitor_database_activity AS
      SELECT 
        datname,
        numbackends,
        xact_commit,
        xact_rollback,
        blks_read,
        blks_hit,
        tup_returned,
        tup_fetched,
        tup_inserted,
        tup_updated,
        tup_deleted,
        conflicts,
        temp_files,
        temp_bytes,
        deadlocks,
        blk_read_time,
        blk_write_time,
        stats_reset
      FROM pg_stat_database 
      WHERE datname = current_database()
    ")
    
    # Create view for connection monitoring
    dbExecute(.db_pool, "
      CREATE OR REPLACE VIEW monitor_connections AS
      SELECT 
        pid,
        usename,
        application_name,
        client_addr,
        backend_start,
        query_start,
        state_change,
        state,
        query,
        wait_event_type,
        wait_event
      FROM pg_stat_activity
      WHERE datname = current_database()
      AND pid != pg_backend_pid()
    ")
    
    # Create view for table statistics
    dbExecute(.db_pool, "
      CREATE OR REPLACE VIEW monitor_table_stats AS
      SELECT 
        schemaname,
        tablename,
        seq_scan,
        seq_tup_read,
        idx_scan,
        idx_tup_fetch,
        n_tup_ins,
        n_tup_upd,
        n_tup_del,
        n_tup_hot_upd,
        n_live_tup,
        n_dead_tup,
        n_mod_since_analyze,
        last_vacuum,
        last_autovacuum,
        last_analyze,
        last_autoanalyze,
        vacuum_count,
        autovacuum_count,
        analyze_count,
        autoanalyze_count
      FROM pg_stat_user_tables
      ORDER BY seq_scan + idx_scan DESC
    ")
    
    # Create view for index usage
    dbExecute(.db_pool, "
      CREATE OR REPLACE VIEW monitor_index_usage AS
      SELECT 
        schemaname,
        tablename,
        indexname,
        idx_scan,
        idx_tup_read,
        idx_tup_fetch,
        pg_size_pretty(pg_relation_size(indexrelid)) as index_size
      FROM pg_stat_user_indexes
      ORDER BY idx_scan DESC
    ")
    
    log_event("Database monitoring views created successfully")
    
  }, error = function(e) {
    log_event(paste("Failed to create monitoring views:", e$message), "ERROR")
  })
}

#' Get Comprehensive Database Performance Analysis
#' @return List with detailed database performance metrics
get_database_performance_analysis <- function() {
  if (is.null(.db_pool)) {
    return(list(error = "Database connection not available"))
  }
  
  tryCatch({
    cat("📊 Analyzing database performance...\n")
    
    analysis <- list()
    
    # 1. Connection Pool Analysis
    analysis$connection_pool <- analyze_connection_pool()
    
    # 2. Query Performance Analysis
    analysis$query_performance <- analyze_query_performance()
    
    # 3. Database Activity Analysis
    analysis$database_activity <- analyze_database_activity()
    
    # 4. Table and Index Analysis
    analysis$table_performance <- analyze_table_performance()
    
    # 5. Cache and Buffer Analysis
    analysis$cache_performance <- analyze_cache_performance()
    
    # 6. Lock and Contention Analysis
    analysis$lock_analysis <- analyze_locks_and_contention()
    
    # 7. Storage and Space Analysis
    analysis$storage_analysis <- analyze_storage_usage()
    
    # 8. Performance Recommendations
    analysis$recommendations <- generate_performance_recommendations(analysis)
    
    # 9. Overall Health Score
    analysis$health_score <- calculate_database_health_score(analysis)
    
    analysis$generated_at <- Sys.time()
    
    return(analysis)
    
  }, error = function(e) {
    log_event(paste("Database performance analysis error:", e$message), "ERROR")
    return(list(error = e$message))
  })
}

#' Analyze Connection Pool Performance
#' @return List with connection pool metrics
analyze_connection_pool <- function() {
  tryCatch({
    # Current connections
    current_connections <- dbGetQuery(.db_pool, "
      SELECT 
        count(*) as total_connections,
        count(*) FILTER (WHERE state = 'active') as active_connections,
        count(*) FILTER (WHERE state = 'idle') as idle_connections,
        count(*) FILTER (WHERE state = 'idle in transaction') as idle_in_transaction,
        count(*) FILTER (WHERE wait_event IS NOT NULL) as waiting_connections
      FROM pg_stat_activity 
      WHERE datname = current_database()
    ")
    
    # Connection limits
    connection_limits <- dbGetQuery(.db_pool, "
      SELECT 
        setting::int as max_connections,
        (SELECT count(*) FROM pg_stat_activity) as current_connections
      FROM pg_settings 
      WHERE name = 'max_connections'
    ")
    
    # Connection duration analysis
    connection_duration <- dbGetQuery(.db_pool, "
      SELECT 
        avg(extract(epoch from (now() - backend_start)))/60 as avg_connection_duration_minutes,
        max(extract(epoch from (now() - backend_start)))/60 as max_connection_duration_minutes
      FROM pg_stat_activity 
      WHERE datname = current_database() AND state = 'active'
    ")
    
    pool_efficiency <- current_connections$active_connections[1] / connection_limits$max_connections[1] * 100
    
    list(
      total_connections = current_connections$total_connections[1],
      active_connections = current_connections$active_connections[1],
      idle_connections = current_connections$idle_connections[1],
      idle_in_transaction = current_connections$idle_in_transaction[1],
      waiting_connections = current_connections$waiting_connections[1],
      max_connections = connection_limits$max_connections[1],
      pool_utilization_percent = pool_efficiency,
      avg_connection_duration_minutes = connection_duration$avg_connection_duration_minutes[1] %||% 0,
      max_connection_duration_minutes = connection_duration$max_connection_duration_minutes[1] %||% 0,
      pool_health = if (pool_efficiency < 80) "healthy" else if (pool_efficiency < 95) "warning" else "critical"
    )
    
  }, error = function(e) {
    log_event(paste("Connection pool analysis error:", e$message), "ERROR")
    return(list(error = e$message))
  })
}

#' Analyze Query Performance
#' @return List with query performance metrics
analyze_query_performance <- function() {
  tryCatch({
    # Check if pg_stat_statements is available
    has_pg_stat_statements <- tryCatch({
      dbGetQuery(.db_pool, "SELECT count(*) FROM pg_stat_statements LIMIT 1")
      TRUE
    }, error = function(e) FALSE)
    
    if (has_pg_stat_statements) {
      # Detailed query analysis with pg_stat_statements
      slow_queries <- dbGetQuery(.db_pool, "
        SELECT 
          left(query, 100) as query_sample,
          calls,
          total_exec_time,
          mean_exec_time,
          max_exec_time,
          stddev_exec_time,
          rows,
          100.0 * shared_blks_hit / nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
        FROM pg_stat_statements 
        WHERE mean_exec_time > $1
        ORDER BY mean_exec_time DESC 
        LIMIT 10
      ", params = list(.db_monitoring_state$slow_query_threshold))
      
      # Query frequency analysis
      frequent_queries <- dbGetQuery(.db_pool, "
        SELECT 
          left(query, 100) as query_sample,
          calls,
          mean_exec_time,
          total_exec_time
        FROM pg_stat_statements 
        ORDER BY calls DESC 
        LIMIT 10
      ")
      
      # Overall statistics
      query_stats <- dbGetQuery(.db_pool, "
        SELECT 
          sum(calls) as total_queries,
          avg(mean_exec_time) as avg_query_time,
          max(max_exec_time) as max_query_time,
          count(*) FILTER (WHERE mean_exec_time > $1) as slow_queries_count
        FROM pg_stat_statements
      ", params = list(.db_monitoring_state$slow_query_threshold))
      
    } else {
      # Fallback analysis without pg_stat_statements
      slow_queries <- data.frame()
      frequent_queries <- data.frame()
      query_stats <- data.frame(
        total_queries = NA,
        avg_query_time = NA,
        max_query_time = NA,
        slow_queries_count = NA
      )
    }
    
    list(
      has_detailed_stats = has_pg_stat_statements,
      slow_queries = slow_queries,
      frequent_queries = frequent_queries,
      total_queries = query_stats$total_queries[1] %||% 0,
      avg_query_time_ms = query_stats$avg_query_time[1] %||% 0,
      max_query_time_ms = query_stats$max_query_time[1] %||% 0,
      slow_queries_count = query_stats$slow_queries_count[1] %||% 0,
      query_performance_health = determine_query_health(query_stats)
    )
    
  }, error = function(e) {
    log_event(paste("Query performance analysis error:", e$message), "ERROR")
    return(list(error = e$message))
  })
}

#' Analyze Database Activity
#' @return List with database activity metrics
analyze_database_activity <- function() {
  tryCatch({
    # Database statistics
    db_stats <- dbGetQuery(.db_pool, "
      SELECT 
        numbackends,
        xact_commit,
        xact_rollback,
        blks_read,
        blks_hit,
        tup_returned,
        tup_fetched,
        tup_inserted,
        tup_updated,
        tup_deleted,
        conflicts,
        deadlocks,
        temp_files,
        temp_bytes
      FROM pg_stat_database 
      WHERE datname = current_database()
    ")
    
    # Calculate ratios and rates
    commit_ratio <- db_stats$xact_commit[1] / (db_stats$xact_commit[1] + db_stats$xact_rollback[1] + 1) * 100
    hit_ratio <- db_stats$blks_hit[1] / (db_stats$blks_hit[1] + db_stats$blks_read[1] + 1) * 100
    
    list(
      active_backends = db_stats$numbackends[1] %||% 0,
      committed_transactions = db_stats$xact_commit[1] %||% 0,
      rolled_back_transactions = db_stats$xact_rollback[1] %||% 0,
      commit_ratio_percent = commit_ratio,
      cache_hit_ratio_percent = hit_ratio,
      tuples_returned = db_stats$tup_returned[1] %||% 0,
      tuples_fetched = db_stats$tup_fetched[1] %||% 0,
      tuples_inserted = db_stats$tup_inserted[1] %||% 0,
      tuples_updated = db_stats$tup_updated[1] %||% 0,
      tuples_deleted = db_stats$tup_deleted[1] %||% 0,
      conflicts = db_stats$conflicts[1] %||% 0,
      deadlocks = db_stats$deadlocks[1] %||% 0,
      temp_files = db_stats$temp_files[1] %||% 0,
      temp_bytes = db_stats$temp_bytes[1] %||% 0,
      activity_health = determine_activity_health(commit_ratio, hit_ratio, db_stats$deadlocks[1] %||% 0)
    )
    
  }, error = function(e) {
    log_event(paste("Database activity analysis error:", e$message), "ERROR")
    return(list(error = e$message))
  })
}

#' Analyze Table Performance
#' @return List with table performance metrics
analyze_table_performance <- function() {
  tryCatch({
    # Table usage statistics
    table_stats <- dbGetQuery(.db_pool, "
      SELECT 
        schemaname,
        tablename,
        seq_scan,
        seq_tup_read,
        idx_scan,
        idx_tup_fetch,
        n_tup_ins + n_tup_upd + n_tup_del as total_modifications,
        n_live_tup,
        n_dead_tup,
        n_dead_tup::float / (n_live_tup + n_dead_tup + 1) * 100 as dead_tuple_percent,
        last_analyze,
        last_autoanalyze
      FROM pg_stat_user_tables
      WHERE schemaname = 'public'
      ORDER BY seq_scan + idx_scan DESC
      LIMIT 10
    ")
    
    # Index usage analysis
    index_stats <- dbGetQuery(.db_pool, "
      SELECT 
        schemaname,
        tablename,
        indexname,
        idx_scan,
        idx_tup_read,
        idx_tup_fetch,
        pg_size_pretty(pg_relation_size(indexrelid)) as index_size
      FROM pg_stat_user_indexes
      WHERE schemaname = 'public'
      ORDER BY idx_scan DESC
      LIMIT 10
    ")
    
    # Unused indexes
    unused_indexes <- dbGetQuery(.db_pool, "
      SELECT 
        schemaname,
        tablename,
        indexname,
        pg_size_pretty(pg_relation_size(indexrelid)) as index_size
      FROM pg_stat_user_indexes
      WHERE schemaname = 'public' AND idx_scan = 0
      ORDER BY pg_relation_size(indexrelid) DESC
    ")
    
    # Table sizes
    table_sizes <- dbGetQuery(.db_pool, "
      SELECT 
        schemaname,
        tablename,
        pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as total_size,
        pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) as table_size,
        pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename) - pg_relation_size(schemaname||'.'||tablename)) as index_size
      FROM pg_tables
      WHERE schemaname = 'public'
      ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
      LIMIT 10
    ")
    
    list(
      table_statistics = table_stats,
      index_usage = index_stats,
      unused_indexes = unused_indexes,
      table_sizes = table_sizes,
      tables_needing_analysis = nrow(table_stats[is.na(table_stats$last_analyze) | 
                                               table_stats$last_analyze < (Sys.Date() - 7), ]),
      table_health = determine_table_health(table_stats)
    )
    
  }, error = function(e) {
    log_event(paste("Table performance analysis error:", e$message), "ERROR")
    return(list(error = e$message))
  })
}

#' Analyze Cache Performance
#' @return List with cache performance metrics
analyze_cache_performance <- function() {
  tryCatch({
    # Buffer cache statistics
    buffer_stats <- dbGetQuery(.db_pool, "
      SELECT 
        sum(heap_blks_read) as heap_read,
        sum(heap_blks_hit) as heap_hit,
        sum(idx_blks_read) as idx_read,
        sum(idx_blks_hit) as idx_hit,
        round(100.0 * sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read) + 1), 2) as heap_hit_ratio,
        round(100.0 * sum(idx_blks_hit) / (sum(idx_blks_hit) + sum(idx_blks_read) + 1), 2) as index_hit_ratio
      FROM pg_statio_user_tables
    ")
    
    # Shared buffer usage
    shared_buffer_stats <- tryCatch({
      dbGetQuery(.db_pool, "
        SELECT 
          count(*) as total_buffers,
          count(*) FILTER (WHERE isdirty) as dirty_buffers,
          count(*) FILTER (WHERE usagecount > 0) as used_buffers
        FROM pg_buffercache
      ")
    }, error = function(e) {
      # pg_buffercache extension not available
      data.frame(total_buffers = NA, dirty_buffers = NA, used_buffers = NA)
    })
    
    list(
      heap_blocks_read = buffer_stats$heap_read[1] %||% 0,
      heap_blocks_hit = buffer_stats$heap_hit[1] %||% 0,
      index_blocks_read = buffer_stats$idx_read[1] %||% 0,
      index_blocks_hit = buffer_stats$idx_hit[1] %||% 0,
      heap_hit_ratio_percent = buffer_stats$heap_hit_ratio[1] %||% 0,
      index_hit_ratio_percent = buffer_stats$index_hit_ratio[1] %||% 0,
      overall_hit_ratio = (buffer_stats$heap_hit_ratio[1] %||% 0 + buffer_stats$index_hit_ratio[1] %||% 0) / 2,
      total_buffers = shared_buffer_stats$total_buffers[1],
      dirty_buffers = shared_buffer_stats$dirty_buffers[1],
      used_buffers = shared_buffer_stats$used_buffers[1],
      cache_health = determine_cache_health(buffer_stats$heap_hit_ratio[1] %||% 0, buffer_stats$index_hit_ratio[1] %||% 0)
    )
    
  }, error = function(e) {
    log_event(paste("Cache performance analysis error:", e$message), "ERROR")
    return(list(error = e$message))
  })
}

#' Analyze Locks and Contention
#' @return List with lock analysis metrics
analyze_locks_and_contention <- function() {
  tryCatch({
    # Current locks
    current_locks <- dbGetQuery(.db_pool, "
      SELECT 
        mode,
        count(*) as lock_count
      FROM pg_locks 
      WHERE database = (SELECT oid FROM pg_database WHERE datname = current_database())
      GROUP BY mode
      ORDER BY count(*) DESC
    ")
    
    # Blocking queries
    blocking_queries <- dbGetQuery(.db_pool, "
      SELECT 
        blocked_locks.pid AS blocked_pid,
        blocked_activity.usename AS blocked_user,
        blocking_locks.pid AS blocking_pid,
        blocking_activity.usename AS blocking_user,
        blocked_activity.query AS blocked_statement,
        blocking_activity.query AS current_statement_in_blocking_process
      FROM pg_catalog.pg_locks blocked_locks
      JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid
      JOIN pg_catalog.pg_locks blocking_locks 
          ON blocking_locks.locktype = blocked_locks.locktype
          AND blocking_locks.database IS NOT DISTINCT FROM blocked_locks.database
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
      WHERE NOT blocked_locks.granted
    ")
    
    # Lock wait analysis
    lock_waits <- dbGetQuery(.db_pool, "
      SELECT 
        count(*) as waiting_processes,
        count(DISTINCT relation) as locked_relations
      FROM pg_locks 
      WHERE NOT granted
    ")
    
    list(
      current_locks = current_locks,
      blocking_queries = blocking_queries,
      waiting_processes = lock_waits$waiting_processes[1] %||% 0,
      locked_relations = lock_waits$locked_relations[1] %||% 0,
      has_blocking_queries = nrow(blocking_queries) > 0,
      lock_contention_health = determine_lock_health(lock_waits$waiting_processes[1] %||% 0, nrow(blocking_queries))
    )
    
  }, error = function(e) {
    log_event(paste("Lock analysis error:", e$message), "ERROR")
    return(list(error = e$message))
  })
}

#' Analyze Storage Usage
#' @return List with storage analysis metrics
analyze_storage_usage <- function() {
  tryCatch({
    # Database size
    db_size <- dbGetQuery(.db_pool, "
      SELECT 
        pg_size_pretty(pg_database_size(current_database())) as database_size,
        pg_database_size(current_database()) as database_size_bytes
    ")
    
    # Largest tables
    largest_tables <- dbGetQuery(.db_pool, "
      SELECT 
        schemaname,
        tablename,
        pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as total_size,
        pg_total_relation_size(schemaname||'.'||tablename) as size_bytes
      FROM pg_tables
      WHERE schemaname = 'public'
      ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
      LIMIT 5
    ")
    
    # Growth analysis (if we have historical data)
    growth_analysis <- analyze_storage_growth()
    
    list(
      database_size = db_size$database_size[1],
      database_size_bytes = db_size$database_size_bytes[1],
      largest_tables = largest_tables,
      growth_analysis = growth_analysis,
      storage_health = determine_storage_health(db_size$database_size_bytes[1])
    )
    
  }, error = function(e) {
    log_event(paste("Storage analysis error:", e$message), "ERROR")
    return(list(error = e$message))
  })
}

#' Analyze Storage Growth Trends
#' @return List with growth analysis
analyze_storage_growth <- function() {
  tryCatch({
    # Get historical database size metrics if available
    growth_data <- dbGetQuery(.db_pool, "
      SELECT 
        timestamp,
        database_size_mb
      FROM database_performance_metrics
      WHERE database_size_mb IS NOT NULL
      AND timestamp > (CURRENT_TIMESTAMP - INTERVAL '7 days')
      ORDER BY timestamp DESC
      LIMIT 100
    ")
    
    if (nrow(growth_data) > 1) {
      # Calculate growth rate
      latest_size <- growth_data$database_size_mb[1]
      oldest_size <- growth_data$database_size_mb[nrow(growth_data)]
      growth_mb <- latest_size - oldest_size
      growth_percent <- (growth_mb / oldest_size) * 100
      
      list(
        has_growth_data = TRUE,
        growth_mb_7days = growth_mb,
        growth_percent_7days = growth_percent,
        projected_monthly_growth_mb = growth_mb * 4.3, # Approximate weeks in month
        growth_trend = if (growth_percent > 20) "high" else if (growth_percent > 5) "moderate" else "low"
      )
    } else {
      list(
        has_growth_data = FALSE,
        growth_trend = "unknown"
      )
    }
    
  }, error = function(e) {
    list(has_growth_data = FALSE, error = e$message)
  })
}

#' Generate Performance Recommendations
#' @param analysis Complete database analysis
#' @return List of recommendations
generate_performance_recommendations <- function(analysis) {
  recommendations <- list()
  
  # Connection pool recommendations
  if (analysis$connection_pool$pool_health == "critical") {
    recommendations <- append(recommendations, 
      "CRITICAL: Connection pool utilization is very high. Consider increasing max_connections or optimizing connection usage.")
  }
  
  # Query performance recommendations
  if (analysis$query_performance$slow_queries_count > 10) {
    recommendations <- append(recommendations,
      paste("WARNING: Found", analysis$query_performance$slow_queries_count, "slow queries. Review and optimize query performance."))
  }
  
  # Cache hit ratio recommendations
  if (analysis$cache_performance$overall_hit_ratio < 90) {
    recommendations <- append(recommendations,
      paste("WARNING: Cache hit ratio is", round(analysis$cache_performance$overall_hit_ratio, 1), "%. Consider increasing shared_buffers."))
  }
  
  # Index recommendations
  if (length(analysis$table_performance$unused_indexes) > 0) {
    recommendations <- append(recommendations,
      paste("INFO: Found", nrow(analysis$table_performance$unused_indexes), "unused indexes. Consider dropping to save space."))
  }
  
  # Lock contention recommendations
  if (analysis$lock_analysis$has_blocking_queries) {
    recommendations <- append(recommendations,
      "WARNING: Blocking queries detected. Review long-running transactions and query optimization.")
  }
  
  # Table maintenance recommendations
  if (analysis$table_performance$tables_needing_analysis > 0) {
    recommendations <- append(recommendations,
      paste("INFO:", analysis$table_performance$tables_needing_analysis, "tables need ANALYZE. Run maintenance tasks."))
  }
  
  if (length(recommendations) == 0) {
    recommendations <- list("GOOD: Database performance looks healthy. Continue monitoring.")
  }
  
  return(recommendations)
}

#' Calculate Overall Database Health Score
#' @param analysis Complete database analysis
#' @return Numeric health score (0-100)
calculate_database_health_score <- function(analysis) {
  tryCatch({
    score <- 100
    
    # Connection pool health (-20 for critical, -10 for warning)
    if (analysis$connection_pool$pool_health == "critical") {
      score <- score - 20
    } else if (analysis$connection_pool$pool_health == "warning") {
      score <- score - 10
    }
    
    # Cache performance (-15 if below 85%, -10 if below 90%)
    cache_ratio <- analysis$cache_performance$overall_hit_ratio
    if (cache_ratio < 85) {
      score <- score - 15
    } else if (cache_ratio < 90) {
      score <- score - 10
    }
    
    # Query performance (-15 for many slow queries)
    if (analysis$query_performance$slow_queries_count > 20) {
      score <- score - 15
    } else if (analysis$query_performance$slow_queries_count > 10) {
      score <- score - 8
    }
    
    # Lock contention (-10 for blocking queries)
    if (analysis$lock_analysis$has_blocking_queries) {
      score <- score - 10
    }
    
    # Deadlocks (-5 if any detected)
    if (analysis$database_activity$deadlocks > 0) {
      score <- score - 5
    }
    
    return(max(0, score))
    
  }, error = function(e) {
    return(50) # Default moderate score on error
  })
}

# Helper functions for health determination
determine_query_health <- function(query_stats) {
  avg_time <- query_stats$avg_query_time[1] %||% 0
  slow_count <- query_stats$slow_queries_count[1] %||% 0
  
  if (avg_time > 2000 || slow_count > 20) {
    return("critical")
  } else if (avg_time > 1000 || slow_count > 10) {
    return("warning")
  } else {
    return("healthy")
  }
}

determine_activity_health <- function(commit_ratio, hit_ratio, deadlocks) {
  if (commit_ratio < 90 || hit_ratio < 85 || deadlocks > 5) {
    return("critical")
  } else if (commit_ratio < 95 || hit_ratio < 90 || deadlocks > 0) {
    return("warning")
  } else {
    return("healthy")
  }
}

determine_table_health <- function(table_stats) {
  if (nrow(table_stats) == 0) return("unknown")
  
  # Check for tables with high dead tuple percentage
  high_dead_tuples <- sum(table_stats$dead_tuple_percent > 20, na.rm = TRUE)
  needs_analysis <- sum(is.na(table_stats$last_analyze) | 
                       table_stats$last_analyze < (Sys.Date() - 7), na.rm = TRUE)
  
  if (high_dead_tuples > 2 || needs_analysis > 3) {
    return("warning")
  } else {
    return("healthy")
  }
}

determine_cache_health <- function(heap_hit_ratio, index_hit_ratio) {
  overall_ratio <- (heap_hit_ratio + index_hit_ratio) / 2
  
  if (overall_ratio < 85) {
    return("critical")
  } else if (overall_ratio < 90) {
    return("warning")
  } else {
    return("healthy")
  }
}

determine_lock_health <- function(waiting_processes, blocking_queries_count) {
  if (waiting_processes > 5 || blocking_queries_count > 0) {
    return("critical")
  } else if (waiting_processes > 0) {
    return("warning")
  } else {
    return("healthy")
  }
}

determine_storage_health <- function(database_size_bytes) {
  # Railway typically has storage limits - assume 1GB as warning threshold
  size_gb <- database_size_bytes / (1024^3)
  
  if (size_gb > 2) {
    return("critical")
  } else if (size_gb > 1) {
    return("warning")
  } else {
    return("healthy")
  }
}

#' Setup Connection Pool Monitoring
setup_connection_pool_monitoring <- function() {
  .db_monitoring_state$pool_monitoring_active <- TRUE
  log_event("Connection pool monitoring setup complete")
}

#' Initialize Query Performance Baselines
initialize_query_baselines <- function() {
  tryCatch({
    # Store initial performance baselines for comparison
    if (!is.null(.db_pool)) {
      baseline <- get_database_performance_analysis()
      .db_monitoring_state$performance_baseline <- baseline
      log_event("Database performance baselines initialized")
    }
  }, error = function(e) {
    log_event(paste("Baseline initialization error:", e$message), "WARN")
  })
}

#' Get Database Health Summary for Dashboard
#' @return List with key health metrics
get_database_health_summary <- function() {
  tryCatch({
    analysis <- get_database_performance_analysis()
    
    list(
      overall_health = analysis$health_score,
      connection_status = if (analysis$connection_pool$pool_health == "healthy") "Connected" else "Issues",
      cache_hit_ratio = round(analysis$cache_performance$overall_hit_ratio, 1),
      slow_queries = analysis$query_performance$slow_queries_count,
      active_connections = analysis$connection_pool$active_connections,
      database_size = analysis$storage_analysis$database_size,
      last_analyzed = Sys.time(),
      recommendations_count = length(analysis$recommendations),
      status_color = if (analysis$health_score >= 90) "green" else if (analysis$health_score >= 70) "yellow" else "red"
    )
    
  }, error = function(e) {
    list(
      overall_health = 0,
      connection_status = "Error",
      error = e$message
    )
  })
}

#' Export Database Performance Report
#' @param format Export format ("json", "csv", "html")
#' @return File path of exported report
export_database_performance_report <- function(format = "json") {
  tryCatch({
    analysis <- get_database_performance_analysis()
    
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    filename <- paste0("database_performance_report_", timestamp)
    
    if (format == "json") {
      filepath <- paste0(filename, ".json")
      writeLines(toJSON(analysis, pretty = TRUE), filepath)
    } else if (format == "html") {
      filepath <- paste0(filename, ".html")
      # Create HTML report (would need additional formatting)
      html_content <- generate_html_report(analysis)
      writeLines(html_content, filepath)
    }
    
    log_event(paste("Database performance report exported:", filepath))
    return(filepath)
    
  }, error = function(e) {
    log_event(paste("Report export error:", e$message), "ERROR")
    return(NULL)
  })
}

# Initialize database monitoring if database is available
if (exists(".db_pool") && !is.null(.db_pool)) {
  init_database_monitoring()
}

log_event("Database Performance Monitoring System loaded successfully")