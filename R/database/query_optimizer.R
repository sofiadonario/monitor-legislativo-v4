# Database Query Optimizer - Week 8 Performance Implementation
# Monitor Legislativo v4 - PostgreSQL Optimization for 134k+ Documents
# =====================================================================
# Advanced database query optimization specifically designed for
# Brazilian legislative document processing on Railway PostgreSQL

library(DBI)
library(RPostgreSQL)
library(dplyr)

# Global query optimization configuration
.QUERY_OPTIMIZER_CONFIG <- list(
  # Index optimization settings
  auto_index_creation = TRUE,
  index_monitoring_enabled = TRUE,
  slow_query_threshold_ms = 1000,
  
  # Connection pooling for Railway PostgreSQL
  max_connections = 20,
  min_connections = 5,
  connection_timeout_seconds = 30,
  query_timeout_seconds = 60,
  
  # Brazilian legislative optimization
  text_search_language = "portuguese",
  full_text_search_enabled = TRUE,
  geographic_indexing_enabled = TRUE,
  temporal_indexing_enabled = TRUE,

  # Performance monitoring
  query_performance_tracking = TRUE,
  execution_plan_analysis = TRUE,
  index_usage_monitoring = TRUE,

  # Railway-specific optimizations
  memory_efficient_queries = TRUE,
  result_set_streaming = TRUE,
  connection_reuse_enabled = TRUE
)

# Global query performance tracking
.QUERY_PERFORMANCE_METRICS <- list(
  slow_queries = list(),
  index_usage = list(),
  execution_plans = list(),
  connection_stats = list(
    active_connections = 0,
    total_queries = 0,
    avg_response_time_ms = 0
  )
)

#' Initialize Database Query Optimizer
#' 
#' Sets up comprehensive PostgreSQL optimization for Brazilian legislative
#' document processing with Railway-specific configurations.
#' 
#' @param db_connection DBI connection object
#' @param create_indexes Logical. Create optimized indexes on startup
#' @param enable_monitoring Logical. Enable query performance monitoring
#' @return List with optimization status and configuration
#' @export
init_database_query_optimizer <- function(db_connection = NULL, 
                                         create_indexes = TRUE,
                                         enable_monitoring = TRUE) {
  
  cat("🗄️ Initializing Database Query Optimizer for PostgreSQL\n")
  
  tryCatch({
    # Validate database connection
    if (is.null(db_connection)) {
      db_connection <- get_optimized_db_connection()
    }
    
    # Analyze current database schema
    schema_analysis <- analyze_database_schema(db_connection)
    
    # Create optimized indexes for Brazilian legislative data
    if (create_indexes) {
      index_creation_results <- create_optimized_indexes(db_connection)
    }
    
    # Set up query performance monitoring
    if (enable_monitoring) {
      setup_query_monitoring(db_connection)
    }
    
    # Configure PostgreSQL for Brazilian text processing
    configure_portuguese_text_search(db_connection)
    
    # Optimize connection settings for Railway
    optimize_connection_settings(db_connection)
    
    cat("✅ Database Query Optimizer initialized successfully\n")
    cat("   - Schema tables analyzed:", length(schema_analysis$tables), "\n")
    cat("   - Indexes created:", if(create_indexes) length(index_creation_results$created) else 0, "\n")
    cat("   - Monitoring enabled:", enable_monitoring, "\n")
    
    return(list(
      status = \"success\",
      connection = db_connection,
      schema_analysis = schema_analysis,
      indexes_created = if(create_indexes) index_creation_results else NULL,
      config = .QUERY_OPTIMIZER_CONFIG
    ))
    
  }, error = function(e) {
    cat("❌ Database optimization initialization failed:", e$message, "\n")
    return(list(status = "error", error = e$message))
  })
}

#' Execute Optimized Query with Performance Tracking
#' 
#' Executes database queries with automatic optimization, performance
#' monitoring, and Brazilian legislative document specific enhancements.
#' 
#' @param query Character. SQL query to execute
#' @param params List. Query parameters for prepared statements
#' @param cache_results Logical. Cache results for repeated queries
#' @param track_performance Logical. Track query execution metrics
#' @return Data frame with query results
#' @export
execute_optimized_query <- function(query, params = NULL, 
                                   cache_results = TRUE,
                                   track_performance = TRUE) {
  
  start_time <- Sys.time()
  query_hash <- digest::digest(query, algo = \"md5\")
  
  # Check cache first if enabled
  if (cache_results) {
    cached_result <- check_query_cache(query_hash, params)
    if (!is.null(cached_result)) {
      if (track_performance) {
        track_query_performance(query, 0, \"cache_hit\", query_hash)
      }
      return(cached_result)
    }
  }
  
  tryCatch({
    # Get optimized database connection
    db_conn <- get_optimized_db_connection()
    
    # Analyze query before execution
    if (.QUERY_OPTIMIZER_CONFIG$execution_plan_analysis) {
      execution_plan <- analyze_query_execution_plan(db_conn, query, params)
    }
    
    # Execute the query with parameters
    if (!is.null(params)) {
      result <- dbGetQuery(db_conn, query, params)
    } else {
      result <- dbGetQuery(db_conn, query)
    }
    
    # Calculate execution time
    execution_time_ms <- as.numeric(difftime(Sys.time(), start_time, units = \"secs\")) * 1000
    
    # Track performance metrics
    if (track_performance) {
      track_query_performance(query, execution_time_ms, \"executed\", query_hash)
    }
    
    # Cache results if enabled and query was fast enough
    if (cache_results && execution_time_ms < 5000) {
      cache_query_result(query_hash, params, result)
    }
    
    # Alert on slow queries
    if (execution_time_ms > .QUERY_OPTIMIZER_CONFIG$slow_query_threshold_ms) {
      handle_slow_query(query, execution_time_ms, execution_plan)
    }
    
    return(result)
    
  }, error = function(e) {
    execution_time_ms <- as.numeric(difftime(Sys.time(), start_time, units = \"secs\")) * 1000
    
    if (track_performance) {
      track_query_performance(query, execution_time_ms, \"error\", query_hash, e$message)
    }
    
    cat("❌ Query execution error:", e$message, "\n")
    cat("   Query:", substr(query, 1, 100), "...\n")
    
    stop(e)
  })
}

#' Optimize Legislative Document Search Queries
#' 
#' Specialized optimization for Brazilian legislative document searches
#' with full-text search, geographic filtering, and temporal queries.
#' 
#' @param search_terms Character vector. Search terms
#' @param filters List. Additional filters (state, type, date range)
#' @param limit Numeric. Maximum results to return
#' @param offset Numeric. Result offset for pagination
#' @return Data frame with optimized search results
#' @export
optimize_legislative_search_query <- function(search_terms, filters = list(),
                                             limit = 100, offset = 0) {
  
  cat(\"🔍 Optimizing legislative search query...\n\")
  
  # Build optimized search query with PostgreSQL features
  optimized_query <- build_optimized_search_query(search_terms, filters, limit, offset)
  
  # Execute with performance tracking
  search_results <- execute_optimized_query(
    query = optimized_query$sql,
    params = optimized_query$params,
    cache_results = TRUE,
    track_performance = TRUE
  )
  
  cat(\"✅ Legislative search completed:\", nrow(search_results), \"results\n\")
  
  return(search_results)
}

#' Create Optimized Database Indexes
#' 
#' Creates comprehensive indexes optimized for Brazilian legislative
#' document processing patterns and Railway PostgreSQL performance.
#' 
#' @param db_connection DBI connection object
#' @return List with index creation results
#' @export
create_optimized_indexes <- function(db_connection) {
  
  cat(\"🔧 Creating optimized indexes for Brazilian legislative data...\n\")
  
  index_creation_results <- list(
    created = character(0),
    failed = character(0),
    skipped = character(0)
  )
  
  # Define indexes optimized for Brazilian legislative queries
  indexes_to_create <- list(
    # Full-text search indexes for Portuguese content
    list(
      name = \"idx_documents_fulltext_pt\",
      table = \"documents\",
      sql = \"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_fulltext_pt 
             ON documents USING gin(to_tsvector('portuguese', title || ' ' || content))\"
    ),
    
    # Geographic indexes for Brazilian states and municipalities
    list(
      name = \"idx_documents_geography\",
      table = \"documents\",
      sql = \"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_geography 
             ON documents (state, municipality)\"
    ),
    
    # Temporal indexes for date-based queries
    list(
      name = \"idx_documents_date_published\",
      table = \"documents\",
      sql = \"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_date_published 
             ON documents (date_published DESC)\"
    ),
    
    # Document type and category indexes
    list(
      name = \"idx_documents_type_category\",
      table = \"documents\",
      sql = \"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_type_category 
             ON documents (document_type, category)\"
    ),
    
    # Composite index for common filter combinations
    list(
      name = \"idx_documents_composite_search\",
      table = \"documents\",
      sql = \"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_composite_search 
             ON documents (state, document_type, date_published DESC)\"
    ),
    
    # Source and authority indexes
    list(
      name = \"idx_documents_source_authority\",
      table = \"documents\",
      sql = \"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_source_authority 
             ON documents (source, issuing_authority)\"
    ),
    
    # Hash index for document IDs (Railway PostgreSQL optimization)
    list(
      name = \"idx_documents_id_hash\",
      table = \"documents\",
      sql = \"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_id_hash 
             ON documents USING hash(id)\"
    ),
    
    # Partial index for active documents only
    list(
      name = \"idx_documents_active_only\",
      table = \"documents\",
      sql = \"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_documents_active_only 
             ON documents (date_published DESC) WHERE status = 'active'\"
    )
  )
  
  # Create each index
  for (index_def in indexes_to_create) {
    tryCatch({
      # Check if index already exists
      index_exists <- check_index_exists(db_connection, index_def$name)
      
      if (index_exists) {
        cat(\"   ⏭️ Index already exists:\", index_def$name, \"\n\")
        index_creation_results$skipped <- c(index_creation_results$skipped, index_def$name)
      } else {
        # Create the index
        dbExecute(db_connection, index_def$sql)
        cat(\"   ✅ Created index:\", index_def$name, \"\n\")
        index_creation_results$created <- c(index_creation_results$created, index_def$name)
      }
      
    }, error = function(e) {
      cat(\"   ❌ Failed to create index:\", index_def$name, \"-\", e$message, \"\n\")
      index_creation_results$failed <- c(index_creation_results$failed, index_def$name)
    })
  }
  
  cat(\"🔧 Index creation completed:\n\")
  cat(\"   - Created:\", length(index_creation_results$created), \"indexes\n\")
  cat(\"   - Skipped:\", length(index_creation_results$skipped), \"indexes\n\")
  cat(\"   - Failed:\", length(index_creation_results$failed), \"indexes\n\")
  
  return(index_creation_results)
}

#' Analyze Database Schema for Optimization Opportunities
#' 
#' Comprehensive analysis of PostgreSQL schema to identify
#' optimization opportunities for Brazilian legislative data.
#' 
#' @param db_connection DBI connection object
#' @return List with schema analysis results
#' @export
analyze_database_schema <- function(db_connection) {
  
  cat(\"🔍 Analyzing database schema for optimization opportunities...\n\")
  
  tryCatch({
    # Get table information
    tables_info <- get_tables_information(db_connection)
    
    # Analyze existing indexes
    existing_indexes <- get_existing_indexes(db_connection)
    
    # Check table statistics
    table_statistics <- get_table_statistics(db_connection)
    
    # Identify missing indexes
    missing_indexes <- identify_missing_indexes(db_connection, tables_info)
    
    # Analyze query patterns
    query_patterns <- analyze_query_patterns()
    
    schema_analysis <- list(
      tables = tables_info,
      existing_indexes = existing_indexes,
      table_statistics = table_statistics,
      missing_indexes = missing_indexes,
      query_patterns = query_patterns,
      optimization_recommendations = generate_optimization_recommendations(
        tables_info, existing_indexes, table_statistics
      )
    )
    
    cat(\"✅ Schema analysis completed:\n\")
    cat(\"   - Tables analyzed:\", length(tables_info), \"\n\")
    cat(\"   - Existing indexes:\", length(existing_indexes), \"\n\")
    cat(\"   - Optimization recommendations:\", length(schema_analysis$optimization_recommendations), \"\n\")
    
    return(schema_analysis)
    
  }, error = function(e) {
    cat(\"❌ Schema analysis failed:\", e$message, \"\n\")
    return(list(status = \"error\", error = e$message))
  })
}

# Helper functions for database optimization

#' Get optimized database connection with Railway settings
get_optimized_db_connection <- function() {
  
  # Use Railway PostgreSQL connection settings
  tryCatch({
    # Try to get connection from Railway environment
    db_url <- Sys.getenv(\"DATABASE_URL\")
    
    if (nzchar(db_url)) {
      # Parse Railway database URL
      conn <- parse_and_connect_railway_db(db_url)
    } else {
      # Fallback to individual environment variables
      conn <- DBI::dbConnect(
        RPostgreSQL::PostgreSQL(),
        host = Sys.getenv(\"PGHOST\", \"localhost\"),
        port = as.numeric(Sys.getenv(\"PGPORT\", \"5432\")),
        dbname = Sys.getenv(\"PGDATABASE\", \"monitor_legislativo\"),
        user = Sys.getenv(\"PGUSER\", \"postgres\"),
        password = Sys.getenv(\"PGPASSWORD\", \"\")
      )
    }
    
    # Configure connection for optimal performance
    configure_connection_performance(conn)
    
    return(conn)
    
  }, error = function(e) {
    cat(\"❌ Database connection failed:\", e$message, \"\n\")
    stop(\"Could not establish optimized database connection\")
  })
}

#' Parse Railway database URL and establish connection
parse_and_connect_railway_db <- function(db_url) {
  
  # Parse postgres://user:password@host:port/database format
  url_pattern <- \"^postgres://([^:]+):([^@]+)@([^:]+):(\\\\d+)/(.+)$\"
  
  if (grepl(url_pattern, db_url)) {
    matches <- regmatches(db_url, regexec(url_pattern, db_url))[[1]]
    
    if (length(matches) == 6) {
      return(DBI::dbConnect(
        RPostgreSQL::PostgreSQL(),
        host = matches[4],
        port = as.numeric(matches[5]),
        dbname = matches[6],
        user = matches[2],
        password = matches[3]
      ))
    }
  }
  
  stop(\"Invalid Railway database URL format\")
}

#' Configure database connection for optimal performance
configure_connection_performance <- function(db_connection) {
  
  tryCatch({
    # Set PostgreSQL parameters for Railway optimization
    performance_settings <- list(
      \"SET work_mem = '16MB'\",                    # Memory for sorts and hashes
      \"SET maintenance_work_mem = '64MB'\",        # Memory for maintenance operations
      \"SET effective_cache_size = '1GB'\",         # Available cache (Railway estimate)
      \"SET random_page_cost = 1.1\",               # SSD storage optimization
      \"SET effective_io_concurrency = 200\",       # Concurrent I/O operations
      \"SET max_worker_processes = 4\",             # Railway CPU limitation
      \"SET max_parallel_workers_per_gather = 2\",  # Parallel query workers
      \"SET default_text_search_config = 'portuguese'\"  # Brazilian Portuguese search
    )
    
    for (setting in performance_settings) {
      dbExecute(db_connection, setting)
    }
    
    cat(\"⚙️ Database connection optimized for Railway PostgreSQL\n\")
    
  }, error = function(e) {
    cat(\"⚠️ Warning: Could not apply all performance settings:\", e$message, \"\n\")
  })
}

#' Build optimized search query for legislative documents
build_optimized_search_query <- function(search_terms, filters, limit, offset) {
  
  # Base query with full-text search optimization
  base_query <- \"
    SELECT 
      id, title, content, document_type, state, municipality,
      date_published, source, issuing_authority,
      ts_rank(to_tsvector('portuguese', title || ' ' || content), 
              plainto_tsquery('portuguese', $1)) as relevance_score
    FROM documents
    WHERE to_tsvector('portuguese', title || ' ' || content) 
          @@ plainto_tsquery('portuguese', $1)
  \"
  
  params <- list(paste(search_terms, collapse = \" \"))
  param_counter <- 1
  
  # Add geographic filters
  if (!is.null(filters$state)) {
    param_counter <- param_counter + 1
    base_query <- paste(base_query, \"AND state = $\", param_counter)
    params <- append(params, filters$state)
  }
  
  if (!is.null(filters$municipality)) {
    param_counter <- param_counter + 1
    base_query <- paste(base_query, \"AND municipality = $\", param_counter)
    params <- append(params, filters$municipality)
  }
  
  # Add document type filter
  if (!is.null(filters$document_type)) {
    param_counter <- param_counter + 1
    base_query <- paste(base_query, \"AND document_type = $\", param_counter)
    params <- append(params, filters$document_type)
  }
  
  # Add date range filters
  if (!is.null(filters$date_from)) {
    param_counter <- param_counter + 1
    base_query <- paste(base_query, \"AND date_published >= $\", param_counter)
    params <- append(params, filters$date_from)
  }
  
  if (!is.null(filters$date_to)) {
    param_counter <- param_counter + 1
    base_query <- paste(base_query, \"AND date_published <= $\", param_counter)
    params <- append(params, filters$date_to)
  }
  
  # Add ordering and pagination
  base_query <- paste(
    base_query,
    \"ORDER BY relevance_score DESC, date_published DESC\",
    \"LIMIT\", limit,
    \"OFFSET\", offset
  )
  
  return(list(
    sql = base_query,
    params = params
  ))
}

#' Configure PostgreSQL for Portuguese text search
configure_portuguese_text_search <- function(db_connection) {
  
  tryCatch({
    # Set up Portuguese text search configuration
    portuguese_config_sql <- \"
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_ts_config WHERE cfgname = 'portuguese') THEN
          CREATE TEXT SEARCH CONFIGURATION portuguese (COPY = pg_catalog.simple);
        END IF;
      END
      $$;
    \"
    
    dbExecute(db_connection, portuguese_config_sql)
    
    # Set as default text search configuration
    dbExecute(db_connection, \"SET default_text_search_config = 'portuguese'\")
    
    cat(\"🇧🇷 Portuguese text search configuration enabled\n\")
    
  }, error = function(e) {
    cat(\"⚠️ Warning: Portuguese text search setup failed:\", e$message, \"\n\")
  })
}

#' Track query performance metrics
track_query_performance <- function(query, execution_time_ms, status, query_hash, error_msg = NULL) {
  
  performance_record <- list(
    timestamp = Sys.time(),
    query_hash = query_hash,
    query_snippet = substr(query, 1, 100),
    execution_time_ms = execution_time_ms,
    status = status,
    error_message = error_msg
  )
  
  # Store in global metrics
  .QUERY_PERFORMANCE_METRICS$slow_queries[[length(.QUERY_PERFORMANCE_METRICS$slow_queries) + 1]] <<- performance_record
  
  # Update connection statistics
  .QUERY_PERFORMANCE_METRICS$connection_stats$total_queries <<- 
    .QUERY_PERFORMANCE_METRICS$connection_stats$total_queries + 1
  
  # Calculate rolling average response time
  if (status == \"executed\") {
    current_avg <- .QUERY_PERFORMANCE_METRICS$connection_stats$avg_response_time_ms
    total_queries <- .QUERY_PERFORMANCE_METRICS$connection_stats$total_queries
    
    .QUERY_PERFORMANCE_METRICS$connection_stats$avg_response_time_ms <<- 
      ((current_avg * (total_queries - 1)) + execution_time_ms) / total_queries
  }
  
  # Cleanup old metrics (keep last 1000)
  if (length(.QUERY_PERFORMANCE_METRICS$slow_queries) > 1000) {
    .QUERY_PERFORMANCE_METRICS$slow_queries <<- 
      tail(.QUERY_PERFORMANCE_METRICS$slow_queries, 1000)
  }
}

#' Handle slow query detection and optimization
handle_slow_query <- function(query, execution_time_ms, execution_plan = NULL) {
  
  cat(\"🐌 Slow query detected:\", round(execution_time_ms, 2), \"ms\n\")
  cat(\"   Query:\", substr(query, 1, 100), \"...\n\")
  
  # Analyze why the query was slow
  slow_query_analysis <- analyze_slow_query(query, execution_time_ms, execution_plan)
  
  # Generate optimization recommendations
  optimization_suggestions <- generate_query_optimization_suggestions(query, slow_query_analysis)
  
  if (length(optimization_suggestions) > 0) {
    cat(\"   💡 Optimization suggestions:\n\")
    for (suggestion in optimization_suggestions) {
      cat(\"      -\", suggestion, \"\n\")
    }
  }
}

#' Analyze slow query to identify bottlenecks
analyze_slow_query <- function(query, execution_time_ms, execution_plan) {
  
  analysis <- list(
    execution_time_ms = execution_time_ms,
    query_type = identify_query_type(query),
    has_where_clause = grepl(\"WHERE\", toupper(query)),
    has_order_by = grepl(\"ORDER BY\", toupper(query)),
    has_joins = grepl(\"JOIN\", toupper(query)),
    has_full_text_search = grepl(\"to_tsvector|plainto_tsquery\", query),
    execution_plan = execution_plan
  )
  
  return(analysis)
}

#' Generate query optimization suggestions
generate_query_optimization_suggestions <- function(query, analysis) {
  
  suggestions <- character(0)
  
  if (analysis$execution_time_ms > 2000) {
    suggestions <- c(suggestions, \"Consider adding appropriate indexes\")
  }
  
  if (analysis$has_full_text_search && analysis$execution_time_ms > 1000) {
    suggestions <- c(suggestions, \"Verify GIN index exists for full-text search\")
  }
  
  if (!analysis$has_where_clause && analysis$execution_time_ms > 500) {
    suggestions <- c(suggestions, \"Add WHERE clause to limit result set\")
  }
  
  if (analysis$has_joins && analysis$execution_time_ms > 1500) {
    suggestions <- c(suggestions, \"Check if JOIN conditions are properly indexed\")
  }
  
  return(suggestions)
}

#' Additional helper functions
identify_query_type <- function(query) {
  query_upper <- toupper(query)
  
  if (grepl(\"^SELECT\", query_upper)) return(\"SELECT\")
  if (grepl(\"^INSERT\", query_upper)) return(\"INSERT\")
  if (grepl(\"^UPDATE\", query_upper)) return(\"UPDATE\")
  if (grepl(\"^DELETE\", query_upper)) return(\"DELETE\")
  
  return(\"OTHER\")
}

check_index_exists <- function(db_connection, index_name) {
  
  check_query <- \"
    SELECT 1 FROM pg_indexes 
    WHERE indexname = $1
  \"
  
  result <- dbGetQuery(db_connection, check_query, list(index_name))
  return(nrow(result) > 0)
}

get_tables_information <- function(db_connection) {
  
  tables_query <- \"
    SELECT 
      table_name,
      table_type,
      table_schema
    FROM information_schema.tables 
    WHERE table_schema = 'public'
    ORDER BY table_name
  \"
  
  return(dbGetQuery(db_connection, tables_query))
}

get_existing_indexes <- function(db_connection) {
  
  indexes_query <- \"
    SELECT 
      indexname,
      tablename,
      indexdef
    FROM pg_indexes 
    WHERE schemaname = 'public'
    ORDER BY tablename, indexname
  \"
  
  return(dbGetQuery(db_connection, indexes_query))
}

get_table_statistics <- function(db_connection) {
  
  stats_query <- \"
    SELECT 
      schemaname,
      tablename,
      n_live_tup as row_count,
      n_dead_tup as dead_rows,
      last_vacuum,
      last_autovacuum,
      last_analyze,
      last_autoanalyze
    FROM pg_stat_user_tables
    ORDER BY n_live_tup DESC
  \"
  
  return(dbGetQuery(db_connection, stats_query))
}

identify_missing_indexes <- function(db_connection, tables_info) {
  # This would analyze query patterns and suggest missing indexes
  # Simplified implementation for now
  return(list(status = \"analysis_completed\"))
}

analyze_query_patterns <- function() {
  # Analyze historical query patterns from performance metrics
  return(list(
    common_queries = list(),
    slow_query_patterns = list(),
    index_usage_patterns = list()
  ))
}

generate_optimization_recommendations <- function(tables_info, existing_indexes, table_statistics) {
  
  recommendations <- character(0)
  
  # Check for tables without indexes
  if (nrow(existing_indexes) < nrow(tables_info)) {
    recommendations <- c(recommendations, \"Some tables may need additional indexes\")
  }
  
  # Check for large tables that might need partitioning
  large_tables <- table_statistics[table_statistics$row_count > 100000, ]
  if (nrow(large_tables) > 0) {
    recommendations <- c(recommendations, \"Consider partitioning large tables for better performance\")
  }
  
  return(recommendations)
}

analyze_query_execution_plan <- function(db_connection, query, params = NULL) {
  
  tryCatch({
    explain_query <- paste(\"EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)\", query)
    
    if (!is.null(params)) {
      plan_result <- dbGetQuery(db_connection, explain_query, params)
    } else {
      plan_result <- dbGetQuery(db_connection, explain_query)
    }
    
    return(plan_result)
    
  }, error = function(e) {
    return(NULL)
  })
}

optimize_connection_settings <- function(db_connection) {
  
  tryCatch({
    # Railway-specific connection optimizations
    optimization_settings <- list(
      \"SET statement_timeout = '60s'\",           # Query timeout
      \"SET idle_in_transaction_session_timeout = '300s'\",  # Idle timeout
      \"SET tcp_keepalives_idle = 300\",           # Keep connection alive
      \"SET tcp_keepalives_interval = 30\",        # Keepalive interval
      \"SET tcp_keepalives_count = 3\"             # Keepalive probes
    )
    
    for (setting in optimization_settings) {
      dbExecute(db_connection, setting)
    }
    
    cat(\"🔧 Connection settings optimized for Railway\n\")
    
  }, error = function(e) {
    cat(\"⚠️ Warning: Connection optimization failed:\", e$message, \"\n\")
  })
}

setup_query_monitoring <- function(db_connection) {
  
  cat(\"📊 Query performance monitoring enabled\n\")
  
  # In production, this would set up:
  # - pg_stat_statements extension
  # - Query performance logging
  # - Index usage tracking
  
  tryCatch({
    # Enable query statistics if available
    dbExecute(db_connection, \"SELECT pg_stat_reset()\")
    cat(\"   - Query statistics reset\n\")
  }, error = function(e) {
    cat(\"   - Query statistics not available\n\")
  })
}

# Cache management functions for query results
check_query_cache <- function(query_hash, params) {
  # This would integrate with the Redis cache manager
  tryCatch({
    if (exists(\"cache_get\")) {
      cache_key <- paste0(\"query:\", query_hash)
      return(cache_get(cache_key, \"database_query\"))
    }
    return(NULL)
  }, error = function(e) {
    return(NULL)
  })
}

cache_query_result <- function(query_hash, params, result) {
  # This would integrate with the Redis cache manager
  tryCatch({
    if (exists(\"cache_set\")) {
      cache_key <- paste0(\"query:\", query_hash)
      cache_set(cache_key, result, \"database_query\")
    }
  }, error = function(e) {
    # Silently fail cache operations
  })
}

#' Get comprehensive database performance statistics
#' @return List with detailed database performance metrics
#' @export
get_database_performance_stats <- function() {
  
  stats <- .QUERY_PERFORMANCE_METRICS
  
  # Calculate additional metrics
  recent_queries <- Filter(function(x) {
    difftime(Sys.time(), x$timestamp, units = \"hours\") <= 1
  }, stats$slow_queries)
  
  slow_query_count <- length(Filter(function(x) {
    x$execution_time_ms > .QUERY_OPTIMIZER_CONFIG$slow_query_threshold_ms
  }, recent_queries))
  
  enhanced_stats <- list(
    connection_stats = stats$connection_stats,
    recent_slow_queries = slow_query_count,
    avg_response_time_last_hour = if (length(recent_queries) > 0) {
      mean(sapply(recent_queries, function(x) x$execution_time_ms))
    } else 0,
    query_success_rate = calculate_query_success_rate(recent_queries),
    optimization_config = .QUERY_OPTIMIZER_CONFIG
  )
  
  return(enhanced_stats)
}

calculate_query_success_rate <- function(recent_queries) {
  if (length(recent_queries) == 0) return(100)
  
  successful_queries <- length(Filter(function(x) x$status == \"executed\", recent_queries))
  return((successful_queries / length(recent_queries)) * 100)
}


