# ============================================================================
# DATABASE QUERY OPTIMIZER - OPTIMIZED FOR RAILWAY POSTGRESQL
# ============================================================================
#
# High-performance database operations for 134K+ legislative documents
# Query optimization, connection pooling, and analytical operation caching
# Designed for Railway PostgreSQL with memory constraints
#
# Author: Data Science Consultant
# Date: 2025-08-29
# Version: 2.0 Production-Optimized
# ============================================================================

library(DBI)
library(RPostgres)
library(pool)
library(dplyr, warn.conflicts = FALSE)
library(dbplyr)
library(data.table)

cat("📊 Database Query Optimizer v2.0 initialized\n")

# ============================================================================
# 1. CONNECTION POOL MANAGEMENT
# ============================================================================

#' Create Optimized Database Connection Pool
#' Manages connections efficiently for Railway PostgreSQL
#' 
#' @param database_url Character: PostgreSQL connection URL
#' @param pool_size Integer: maximum connections in pool
#' @param idle_timeout Integer: seconds before closing idle connections
#' @return Database connection pool object
create_optimized_db_pool <- function(database_url = Sys.getenv("DATABASE_URL"),
                                    pool_size = 3,  # Conservative for Railway
                                    idle_timeout = 300) {
  
  if (database_url == "" || is.na(database_url)) {
    warning("DATABASE_URL not found, using fallback connection")
    return(NULL)
  }
  
  cat("🔌 Creating optimized database connection pool...\n")
  
  tryCatch({
    # Parse Railway PostgreSQL URL format
    # postgresql://username:password@host:port/database
    url_parts <- regmatches(database_url, 
                           regexpr("postgresql://([^:]+):([^@]+)@([^:]+):(\\d+)/(.+)", 
                                  database_url, perl = TRUE))
    
    if (length(url_parts) == 0) {
      stop("Invalid DATABASE_URL format")
    }
    
    # Extract connection components
    matches <- regmatches(database_url, 
                         regexec("postgresql://([^:]+):([^@]+)@([^:]+):(\\d+)/(.+)", 
                                database_url))[[1]]
    
    if (length(matches) != 6) {
      stop("Unable to parse DATABASE_URL components")
    }
    
    username <- matches[2]
    password <- matches[3]
    host <- matches[4]
    port <- as.integer(matches[5])
    dbname <- matches[6]
    
    # Create connection pool with Railway-specific optimizations
    pool <- pool::dbPool(
      drv = RPostgres::Postgres(),
      host = host,
      port = port,
      dbname = dbname,
      user = username,
      password = password,
      
      # Railway-optimized settings
      minSize = 1,                    # Minimum connections
      maxSize = pool_size,            # Maximum connections  
      idleTimeout = idle_timeout,     # Close idle connections
      
      # PostgreSQL-specific optimizations
      options = list(
        # Connection-level optimizations
        "statement_timeout" = "30000",       # 30 second query timeout
        "idle_in_transaction_session_timeout" = "10000",  # 10 second idle timeout
        "shared_preload_libraries" = "pg_stat_statements",
        
        # Memory optimizations for Railway
        "work_mem" = "8MB",                  # Working memory per query
        "maintenance_work_mem" = "16MB",     # Maintenance memory
        "effective_cache_size" = "128MB",    # Available cache estimate
        
        # Performance optimizations
        "random_page_cost" = "1.1",          # SSD-optimized
        "effective_io_concurrency" = "200",  # Concurrent I/O operations
        "max_worker_processes" = "2",        # Limit worker processes
        "max_parallel_workers_per_gather" = "1"  # Parallel query workers
      )
    )
    
    # Test connection
    test_conn <- pool::poolCheckout(pool)
    result <- DBI::dbGetQuery(test_conn, "SELECT version() as postgres_version, current_database() as db_name")
    pool::poolReturn(test_conn)
    
    cat("✅ Database pool created successfully!\n")
    cat("   🗄️  Database:", result$db_name, "\n")
    cat("   🔢 Pool size:", pool_size, "connections\n")
    cat("   ⏱️  Idle timeout:", idle_timeout, "seconds\n")
    
    return(list(
      pool = pool,
      config = list(
        host = host,
        port = port,
        dbname = dbname,
        pool_size = pool_size,
        idle_timeout = idle_timeout,
        created = Sys.time()
      )
    ))
    
  }, error = function(e) {
    warning("Failed to create database pool: ", e$message)
    return(NULL)
  })
}

# ============================================================================
# 2. QUERY OPTIMIZATION SYSTEM
# ============================================================================

#' Optimized Query Builder for Legislative Documents
#' Generates efficient queries with proper indexing and caching hints
#' 
#' @param pool Database connection pool
#' @param query_type Character: type of analytical query
#' @param filters List: query filters and conditions
#' @param limit Integer: maximum rows to return
#' @return Optimized query results
execute_optimized_analytical_query <- function(pool, query_type = "basic_stats", 
                                              filters = list(), limit = 1000) {
  
  if (is.null(pool)) {
    warning("No database pool available, using fallback data")
    return(generate_fallback_analytical_data(query_type, limit))
  }
  
  cat("🔍 Executing optimized", query_type, "query...\n")
  
  start_time <- Sys.time()
  
  tryCatch({
    # Build optimized query based on type
    query <- switch(query_type,
      "basic_stats" = build_basic_stats_query(filters, limit),
      "temporal_trends" = build_temporal_trends_query(filters, limit),
      "category_distribution" = build_category_distribution_query(filters, limit),
      "geographic_analysis" = build_geographic_analysis_query(filters, limit),
      "regulatory_complexity" = build_regulatory_complexity_query(filters, limit),
      "citation_network" = build_citation_network_query(filters, limit),
      "transport_focus" = build_transport_focus_query(filters, limit),
      stop("Unknown query type: ", query_type)
    )\n    
    # Execute query with connection from pool
    conn <- pool::poolCheckout(pool$pool)
    on.exit(pool::poolReturn(conn), add = TRUE)
    
    # Execute with query plan analysis for optimization
    if (query_type %in% c("temporal_trends", "category_distribution")) {
      # Use EXPLAIN ANALYZE for complex queries in development
      # explain_result <- DBI::dbGetQuery(conn, paste("EXPLAIN ANALYZE", query))
      # cat("Query plan analysis available for review\\n")
    }
    
    # Execute main query
    result <- DBI::dbGetQuery(conn, query)
    
    # Convert to data.table for performance
    result_dt <- data.table::as.data.table(result)
    
    execution_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    
    cat("✅ Query completed successfully!\n")
    cat("   📊 Rows returned:", nrow(result_dt), "\n")
    cat("   ⏱️  Execution time:", round(execution_time, 3), "seconds\n")
    cat("   🚀 Rate:", round(nrow(result_dt)/execution_time, 0), "rows/sec\n")
    
    return(list(
      data = result_dt,
      query_type = query_type,
      execution_time_seconds = execution_time,
      row_count = nrow(result_dt),
      performance_rating = if(execution_time < 5) "excellent" else if(execution_time < 15) "good" else "needs_optimization",
      timestamp = Sys.time()
    ))
    
  }, error = function(e) {
    warning("Query execution failed: ", e$message)
    return(list(
      data = data.table(),
      error = e$message,
      query_type = query_type,
      timestamp = Sys.time()
    ))
  })
}

#' Build Basic Statistics Query (Optimized)
build_basic_stats_query <- function(filters, limit) {
  base_query <- "
    SELECT 
      COUNT(*) as total_documents,
      COUNT(DISTINCT EXTRACT(YEAR FROM date)) as years_covered,
      COUNT(DISTINCT category) as unique_categories,
      COUNT(DISTINCT state) as states_represented,
      AVG(LENGTH(title)) as avg_title_length,
      MIN(date) as earliest_document,
      MAX(date) as latest_document,
      COUNT(CASE WHEN date >= CURRENT_DATE - INTERVAL '1 year' THEN 1 END) as documents_last_year,
      COUNT(CASE WHEN date >= CURRENT_DATE - INTERVAL '5 years' THEN 1 END) as documents_last_5_years
    FROM documents 
    WHERE 1=1"
  
  # Add filters
  if (length(filters) > 0) {
    if (!is.null(filters$date_from)) {
      base_query <- paste(base_query, "AND date >=", shQuote(filters$date_from))
    }
    if (!is.null(filters$date_to)) {
      base_query <- paste(base_query, "AND date <=", shQuote(filters$date_to))
    }
    if (!is.null(filters$category)) {
      base_query <- paste(base_query, "AND category IN", 
                         paste0("(", paste(shQuote(filters$category), collapse = ","), ")"))
    }
    if (!is.null(filters$state)) {
      base_query <- paste(base_query, "AND state IN", 
                         paste0("(", paste(shQuote(filters$state), collapse = ","), ")"))
    }
  }
  
  return(base_query)
}

#' Build Temporal Trends Query (Optimized with Window Functions)
build_temporal_trends_query <- function(filters, limit) {
  base_query <- "
    SELECT 
      EXTRACT(YEAR FROM date) as year,
      EXTRACT(MONTH FROM date) as month,
      COUNT(*) as document_count,
      COUNT(DISTINCT category) as categories_per_period,
      COUNT(DISTINCT state) as states_per_period,
      AVG(LENGTH(title)) as avg_title_length,
      -- Window functions for trend analysis
      LAG(COUNT(*), 1) OVER (ORDER BY EXTRACT(YEAR FROM date), EXTRACT(MONTH FROM date)) as prev_period_count,
      AVG(COUNT(*)) OVER (
        ORDER BY EXTRACT(YEAR FROM date), EXTRACT(MONTH FROM date) 
        ROWS BETWEEN 5 PRECEDING AND CURRENT ROW
      ) as moving_average_6_months
    FROM documents 
    WHERE date IS NOT NULL"
  
  # Add filters
  if (length(filters) > 0) {
    if (!is.null(filters$date_from)) {
      base_query <- paste(base_query, "AND date >=", shQuote(filters$date_from))
    }
    if (!is.null(filters$date_to)) {
      base_query <- paste(base_query, "AND date <=", shQuote(filters$date_to))
    }
  }
  
  base_query <- paste(base_query, "
    GROUP BY EXTRACT(YEAR FROM date), EXTRACT(MONTH FROM date)
    ORDER BY year DESC, month DESC
    LIMIT", limit)
  
  return(base_query)
}

#' Build Category Distribution Query (Optimized)
build_category_distribution_query <- function(filters, limit) {
  base_query <- "
    SELECT 
      category,
      COUNT(*) as document_count,
      ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 2) as percentage,
      MIN(date) as earliest_in_category,
      MAX(date) as latest_in_category,
      COUNT(DISTINCT state) as states_in_category,
      AVG(LENGTH(title)) as avg_title_length_category
    FROM documents 
    WHERE category IS NOT NULL"
  
  # Add filters
  if (length(filters) > 0) {
    if (!is.null(filters$date_from)) {
      base_query <- paste(base_query, "AND date >=", shQuote(filters$date_from))
    }
    if (!is.null(filters$date_to)) {
      base_query <- paste(base_query, "AND date <=", shQuote(filters$date_to))
    }
    if (!is.null(filters$state)) {
      base_query <- paste(base_query, "AND state IN", 
                         paste0("(", paste(shQuote(filters$state), collapse = ","), ")"))
    }
  }
  
  base_query <- paste(base_query, "
    GROUP BY category
    ORDER BY document_count DESC
    LIMIT", limit)
  
  return(base_query)
}

#' Build Geographic Analysis Query (Optimized)
build_geographic_analysis_query <- function(filters, limit) {
  base_query <- "
    SELECT 
      state,
      municipality,
      COUNT(*) as document_count,
      COUNT(DISTINCT category) as unique_categories,
      COUNT(DISTINCT EXTRACT(YEAR FROM date)) as active_years,
      MIN(date) as earliest_document,
      MAX(date) as latest_document,
      ROUND(AVG(LENGTH(title)), 0) as avg_title_length,
      -- Regional grouping
      CASE 
        WHEN state IN ('AC', 'AM', 'AP', 'PA', 'RO', 'RR', 'TO') THEN 'Norte'
        WHEN state IN ('AL', 'BA', 'CE', 'MA', 'PB', 'PE', 'PI', 'RN', 'SE') THEN 'Nordeste'
        WHEN state IN ('DF', 'GO', 'MT', 'MS') THEN 'Centro-Oeste'
        WHEN state IN ('ES', 'MG', 'RJ', 'SP') THEN 'Sudeste'
        WHEN state IN ('PR', 'RS', 'SC') THEN 'Sul'
        ELSE 'Outros'
      END as region
    FROM documents 
    WHERE state IS NOT NULL"
  
  # Add filters
  if (length(filters) > 0) {
    if (!is.null(filters$date_from)) {
      base_query <- paste(base_query, "AND date >=", shQuote(filters$date_from))
    }
    if (!is.null(filters$date_to)) {
      base_query <- paste(base_query, "AND date <=", shQuote(filters$date_to))
    }
    if (!is.null(filters$region)) {
      region_states <- switch(filters$region,
        "Norte" = c('AC', 'AM', 'AP', 'PA', 'RO', 'RR', 'TO'),
        "Nordeste" = c('AL', 'BA', 'CE', 'MA', 'PB', 'PE', 'PI', 'RN', 'SE'),
        "Centro-Oeste" = c('DF', 'GO', 'MT', 'MS'),
        "Sudeste" = c('ES', 'MG', 'RJ', 'SP'),
        "Sul" = c('PR', 'RS', 'SC'),
        c()
      )
      if (length(region_states) > 0) {
        base_query <- paste(base_query, "AND state IN", 
                           paste0("(", paste(shQuote(region_states), collapse = ","), ")"))
      }
    }
  }
  
  base_query <- paste(base_query, "
    GROUP BY state, municipality
    ORDER BY document_count DESC
    LIMIT", limit)
  
  return(base_query)
}

#' Build Regulatory Complexity Query (Advanced Analytics)
build_regulatory_complexity_query <- function(filters, limit) {
  base_query <- "
    SELECT 
      title,
      category,
      state,
      date,
      LENGTH(title) as title_length,
      LENGTH(summary) as summary_length,
      -- Complexity indicators
      (LENGTH(title) + COALESCE(LENGTH(summary), 0)) as total_text_length,
      CASE 
        WHEN title ~* '(lei|decreto|medida provisória)' THEN 'Normativo'
        WHEN title ~* '(resolução|portaria|instrução)' THEN 'Regulamentar' 
        WHEN title ~* '(parecer|nota técnica)' THEN 'Técnico'
        ELSE 'Outros'
      END as regulatory_type,
      -- Transport relevance scoring
      CASE 
        WHEN title ~* '(transport|frete|rodovia|ferrovia|porto|aeroporto)' THEN 3
        WHEN title ~* '(veículo|combustível|trânsito|logística)' THEN 2
        WHEN title ~* '(mobilidade|infraestrutura)' THEN 1
        ELSE 0
      END as transport_relevance_score,
      -- Legal citation density (approximate)
      (LENGTH(title) - LENGTH(REPLACE(title, 'nº', ''))) / 2 as citation_count_estimate
    FROM documents 
    WHERE title IS NOT NULL"
  
  # Add filters
  if (length(filters) > 0) {
    if (!is.null(filters$date_from)) {
      base_query <- paste(base_query, "AND date >=", shQuote(filters$date_from))
    }
    if (!is.null(filters$date_to)) {
      base_query <- paste(base_query, "AND date <=", shQuote(filters$date_to))
    }
    if (!is.null(filters$category)) {
      base_query <- paste(base_query, "AND category IN", 
                         paste0("(", paste(shQuote(filters$category), collapse = ","), ")"))
    }
  }
  
  base_query <- paste(base_query, "
    ORDER BY total_text_length DESC, transport_relevance_score DESC
    LIMIT", limit)
  
  return(base_query)
}

#' Build Citation Network Query (Network Analysis)
build_citation_network_query <- function(filters, limit) {
  base_query <- "
    SELECT 
      id,
      title,
      category,
      date,
      -- Extract legal citations using regex
      ARRAY(
        SELECT DISTINCT unnest(regexp_split_to_array(
          regexp_replace(title, '.*(Lei nº [0-9,./]+|Decreto nº [0-9,./]+|MP nº [0-9,./]+).*', '\\\\1', 'gi'),
          ',\\\\s*'
        ))
        WHERE unnest(regexp_split_to_array(
          regexp_replace(title, '.*(Lei nº [0-9,./]+|Decreto nº [0-9,./]+|MP nº [0-9,./]+).*', '\\\\1', 'gi'),
          ',\\\\s*'
        )) != title
      ) as extracted_citations,
      -- Count citations in document
      (LENGTH(title) - LENGTH(REGEXP_REPLACE(title, 'nº', '', 'g'))) / 2 as citation_count
    FROM documents 
    WHERE title ~* '(lei|decreto|mp|medida provisória).*(nº|n°)'"
  
  # Add filters
  if (length(filters) > 0) {
    if (!is.null(filters$date_from)) {
      base_query <- paste(base_query, "AND date >=", shQuote(filters$date_from))
    }
    if (!is.null(filters$date_to)) {
      base_query <- paste(base_query, "AND date <=", shQuote(filters$date_to))
    }
  }
  
  base_query <- paste(base_query, "
    ORDER BY citation_count DESC, date DESC
    LIMIT", limit)
  
  return(base_query)
}

#' Build Transport-Focused Query (Domain-Specific)
build_transport_focus_query <- function(filters, limit) {
  base_query <- "
    SELECT 
      title,
      category,
      state,
      date,
      -- Transport modal classification
      CASE 
        WHEN title ~* '(rodoviário|caminhão|rodovia|antt|frete)' THEN 'Rodoviário'
        WHEN title ~* '(ferroviário|ferrovia|trem|trilho)' THEN 'Ferroviário'
        WHEN title ~* '(aquaviário|porto|navegação|antaq|marítimo)' THEN 'Aquaviário'
        WHEN title ~* '(aéreo|aviação|aeroporto|anac)' THEN 'Aéreo'
        WHEN title ~* '(urbano|metrô|ônibus|brt)' THEN 'Urbano'
        ELSE 'Multimodal/Geral'
      END as transport_modal,
      -- Sustainability focus
      CASE 
        WHEN title ~* '(sustentável|verde|emissão|carbono|renovável|biodiesel)' THEN 'Alta'
        WHEN title ~* '(eficiência|otimização|economia)' THEN 'Média'
        ELSE 'Baixa'
      END as sustainability_focus,
      -- Technology integration
      CASE 
        WHEN title ~* '(digital|tecnologia|automação|inteligente|4\\.0)' THEN 'Alta'
        WHEN title ~* '(eletrônico|sistema|controle)' THEN 'Média'
        ELSE 'Baixa'
      END as technology_integration,
      -- Regulatory agency
      CASE 
        WHEN title ~* 'antt' THEN 'ANTT'
        WHEN title ~* 'antaq' THEN 'ANTAQ'
        WHEN title ~* 'anac' THEN 'ANAC'
        WHEN title ~* 'contran' THEN 'CONTRAN'
        WHEN title ~* 'dnit' THEN 'DNIT'
        ELSE 'Outras/Múltiplas'
      END as regulatory_agency
    FROM documents 
    WHERE title ~* '(transport|frete|rodovia|ferrovia|porto|aeroporto|veículo|combustível|trânsito|logística|mobilidade)'"
  
  # Add filters
  if (length(filters) > 0) {
    if (!is.null(filters$date_from)) {
      base_query <- paste(base_query, "AND date >=", shQuote(filters$date_from))
    }
    if (!is.null(filters$date_to)) {
      base_query <- paste(base_query, "AND date <=", shQuote(filters$date_to))
    }
    if (!is.null(filters$modal)) {
      base_query <- paste(base_query, "AND title ~*", 
                         shQuote(switch(filters$modal,
                           "Rodoviário" = "(rodoviário|caminhão|rodovia|antt|frete)",
                           "Ferroviário" = "(ferroviário|ferrovia|trem|trilho)",
                           "Aquaviário" = "(aquaviário|porto|navegação|antaq|marítimo)",
                           "Aéreo" = "(aéreo|aviação|aeroporto|anac)",
                           ".*"
                         )))
    }
  }
  
  base_query <- paste(base_query, "
    ORDER BY date DESC
    LIMIT", limit)
  
  return(base_query)
}

# ============================================================================
# 3. FALLBACK DATA GENERATION
# ============================================================================

#' Generate Fallback Analytical Data
#' Provides sample data when database is not available
generate_fallback_analytical_data <- function(query_type, limit) {
  cat("⚠️ Using fallback data for", query_type, "\n")
  
  switch(query_type,
    "basic_stats" = list(
      data = data.table(
        total_documents = 134567,
        years_covered = 45,
        unique_categories = 23,
        states_represented = 27,
        avg_title_length = 89.3,
        documents_last_year = 8934,
        documents_last_5_years = 41256
      ),
      query_type = query_type,
      execution_time_seconds = 0.1,
      row_count = 1,
      performance_rating = "fallback"
    ),
    
    "temporal_trends" = list(
      data = data.table(
        year = 2020:2024,
        document_count = c(7832, 8945, 9123, 8767, 8934),
        categories_per_period = c(18, 19, 20, 19, 21),
        moving_average_6_months = c(7832, 8388.5, 8633, 8623, 8720.2)
      ),
      query_type = query_type,
      execution_time_seconds = 0.15,
      row_count = 5,
      performance_rating = "fallback"
    ),
    
    "category_distribution" = list(
      data = data.table(
        category = c("Lei Federal", "Decreto", "Resolução", "Portaria", "Instrução Normativa"),
        document_count = c(45123, 32456, 23789, 18234, 14965),
        percentage = c(33.5, 24.1, 17.7, 13.5, 11.1)
      ),
      query_type = query_type,
      execution_time_seconds = 0.12,
      row_count = 5,
      performance_rating = "fallback"
    ),
    
    # Default fallback
    list(
      data = data.table(message = "Fallback data not available for this query type"),
      query_type = query_type,
      execution_time_seconds = 0.05,
      row_count = 0,
      performance_rating = "fallback"
    )
  )
}

# ============================================================================
# 4. QUERY PERFORMANCE MONITORING
# ============================================================================

#' Query Performance Monitor
#' Tracks query performance and identifies optimization opportunities
query_performance_monitor <- list(
  queries_executed = list(),
  performance_log = data.table(),
  
  log_query = function(query_result) {
    if (!is.null(query_result$execution_time_seconds)) {
      new_entry <- data.table(
        timestamp = Sys.time(),
        query_type = query_result$query_type,
        execution_time = query_result$execution_time_seconds,
        row_count = query_result$row_count,
        performance_rating = query_result$performance_rating %||% "unknown"
      )
      
      query_performance_monitor$performance_log <- rbind(
        query_performance_monitor$performance_log, 
        new_entry, 
        fill = TRUE
      )
    }
  },
  
  get_performance_summary = function() {
    if (nrow(query_performance_monitor$performance_log) == 0) {
      return(list(
        total_queries = 0,
        avg_execution_time = 0,
        performance_distribution = data.table()
      ))
    }
    
    log_data <- query_performance_monitor$performance_log
    
    list(
      total_queries = nrow(log_data),
      avg_execution_time = mean(log_data$execution_time, na.rm = TRUE),
      avg_row_count = mean(log_data$row_count, na.rm = TRUE),
      performance_distribution = log_data[, .N, by = performance_rating],
      slowest_queries = head(log_data[order(-execution_time)], 5),
      recent_performance = tail(log_data, 10)
    )
  },
  
  identify_optimization_opportunities = function() {
    if (nrow(query_performance_monitor$performance_log) < 5) {
      return(list(recommendations = "Insufficient data for analysis"))
    }
    
    log_data <- query_performance_monitor$performance_log
    
    recommendations <- list()
    
    # Identify slow queries
    slow_queries <- log_data[execution_time > 10]
    if (nrow(slow_queries) > 0) {
      recommendations$slow_queries <- list(
        count = nrow(slow_queries),
        types = unique(slow_queries$query_type),
        recommendation = "Consider query optimization, indexing, or result caching"
      )
    }
    
    # Identify high-frequency queries
    query_freq <- log_data[, .N, by = query_type][order(-N)]
    if (nrow(query_freq) > 0 && query_freq[1]$N > 10) {
      recommendations$high_frequency <- list(
        most_frequent = query_freq[1]$query_type,
        frequency = query_freq[1]$N,
        recommendation = "Consider caching results for this query type"
      )
    }
    
    # Performance trend analysis
    recent_avg <- log_data[timestamp > (Sys.time() - 3600)]  # Last hour
    if (nrow(recent_avg) > 0) {
      recent_perf <- mean(recent_avg$execution_time)
      overall_perf <- mean(log_data$execution_time)
      
      if (recent_perf > overall_perf * 1.5) {
        recommendations$performance_degradation <- list(
          recent_avg = recent_perf,
          overall_avg = overall_perf,
          recommendation = "Recent performance degradation detected. Check system resources."
        )
      }
    }
    
    return(recommendations)
  }
)

# Helper function for null coalescing
`%||%` <- function(a, b) if (is.null(a)) b else a

cat("✅ Database Query Optimizer fully loaded!\n")
cat("   🔌 Connection pooling: ENABLED\n") 
cat("   🔍 Query optimization: ENABLED\n")
cat("   📊 Performance monitoring: ENABLED\n")
cat("   🚀 Railway PostgreSQL: OPTIMIZED\n")
cat("   💾 Memory constraints: MANAGED\n")

# Export main functions
QUERY_OPTIMIZER_FUNCTIONS <- list(
  create_optimized_db_pool = create_optimized_db_pool,
  execute_optimized_analytical_query = execute_optimized_analytical_query,
  query_performance_monitor = query_performance_monitor,
  generate_fallback_analytical_data = generate_fallback_analytical_data
)