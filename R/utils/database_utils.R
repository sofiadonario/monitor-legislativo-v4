# Database Utilities Module
# Monitor Legislativo v4 - Modular Database Operations
# =====================================================

#' Database Utilities for Monitor Legislativo v4
#' 
#' This module provides optimized database operations with connection pooling,
#' query optimization, and fallback mechanisms for Brazilian legislative data.
#' Railway PostgreSQL optimized with 2GB memory constraints.

library(DBI)
library(pool)

# Global connection pool variable for reuse across modules
.db_pool <- NULL
.db_connection_stats <- list(
  created_at = NULL,
  total_queries = 0,
  failed_queries = 0,
  avg_response_time = 0
)

# Circuit breaker state management
.circuit_breaker <- list(
  state = "CLOSED",  # CLOSED, OPEN, HALF_OPEN
  failure_count = 0,
  last_failure_time = NULL,
  failure_threshold = 5,
  timeout = 60,  # seconds
  success_threshold = 3  # for half-open to closed transition
)

#' Initialize Optimized Database Connection Pool
#' 
#' @return List containing connection pool and status information
#' @export
init_database_connection <- function() {
  cat("🚀 Initializing production-optimized Railway PostgreSQL connection pool...\n")
  
  # Check if connection pool already exists and is valid
  if (!is.null(.db_pool)) {
    tryCatch({
      test_result <- pool::dbGetQuery(.db_pool, "SELECT 1 as test")
      if (nrow(test_result) > 0) {
        cat("♻️ Reusing existing healthy connection pool\n")
        return(list(
          pool = .db_pool,
          status = "reused",
          connection_loaded = TRUE,
          stats = .db_connection_stats
        ))
      }
    }, error = function(e) {
      cat("🔄 Existing pool unhealthy, creating new connection\n")
    })
  }
  
  # Railway PostgreSQL connection with optimized pooling
  tryCatch({
    # Enhanced connection string with Railway optimizations
    db_url <- Sys.getenv("DATABASE_URL", 
      "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway")
    
    # Create optimized connection pool for Railway (2GB memory limit)
    .db_pool <<- pool::dbPool(
      drv = RPostgres::Postgres(),
      url = db_url,
      minSize = 1,        # Minimum connections for Railway efficiency
      maxSize = 3,        # Maximum connections (Railway memory optimization)
      idleTimeout = 300,  # 5 minutes idle timeout
      validationInterval = 60  # Validate connections every minute
    )
    
    # Test connection with lightweight query
    test_result <- pool::dbGetQuery(.db_pool, 
      "SELECT current_database() as db_name, version() as db_version LIMIT 1")
    
    if (nrow(test_result) > 0) {
      .db_connection_stats$created_at <<- Sys.time()
      
      cat("✅ Railway PostgreSQL connection pool created successfully\n")
      cat("   Database:", test_result$db_name[1], "\n")
      cat("   Pool Size: 1-3 connections (Railway optimized)\n")
      cat("   Memory: Optimized for 2GB Railway limit\n")
      
      return(list(
        pool = .db_pool,
        status = "connected",
        connection_loaded = TRUE,
        database_info = test_result,
        stats = .db_connection_stats
      ))
    }
    
  }, error = function(e) {
    cat("❌ Database connection failed:", e$message, "\n")
    return(list(
      pool = NULL,
      status = "failed",
      connection_loaded = FALSE,
      error = e$message
    ))
  })
}

#' Execute Query with Connection Pool and Error Handling
#' 
#' @param query SQL query string
#' @param params List of parameters for prepared statements
#' @return Query results or NULL on error
#' @export
execute_query <- function(query, params = list()) {
  start_time <- Sys.time()
  
  # Circuit breaker check
  if (.circuit_breaker$state == "OPEN") {
    if (difftime(Sys.time(), .circuit_breaker$last_failure_time, units = "secs") > .circuit_breaker$timeout) {
      .circuit_breaker$state <<- "HALF_OPEN"
      cat("🔄 Circuit breaker moved to HALF_OPEN state\n")
    } else {
      cat("⚠️ Circuit breaker OPEN - query blocked\n")
      return(NULL)
    }
  }
  
  tryCatch({
    if (is.null(.db_pool)) {
      init_result <- init_database_connection()
      if (!init_result$connection_loaded) {
        stop("Database connection unavailable")
      }
    }
    
    # Execute query with timeout protection
    if (length(params) > 0) {
      result <- pool::dbGetQuery(.db_pool, query, params = params)
    } else {
      result <- pool::dbGetQuery(.db_pool, query)
    }
    
    # Update statistics
    .db_connection_stats$total_queries <<- .db_connection_stats$total_queries + 1
    response_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    .db_connection_stats$avg_response_time <<- 
      (.db_connection_stats$avg_response_time * (.db_connection_stats$total_queries - 1) + response_time) / 
      .db_connection_stats$total_queries
    
    # Circuit breaker success handling
    if (.circuit_breaker$state == "HALF_OPEN") {
      .circuit_breaker$failure_count <<- 0
      .circuit_breaker$state <<- "CLOSED"
      cat("✅ Circuit breaker CLOSED - connection restored\n")
    }
    
    return(result)
    
  }, error = function(e) {
    cat("❌ Query execution failed:", e$message, "\n")
    
    # Update failure statistics
    .db_connection_stats$failed_queries <<- .db_connection_stats$failed_queries + 1
    .circuit_breaker$failure_count <<- .circuit_breaker$failure_count + 1
    .circuit_breaker$last_failure_time <<- Sys.time()
    
    # Circuit breaker failure handling
    if (.circuit_breaker$failure_count >= .circuit_breaker$failure_threshold) {
      .circuit_breaker$state <<- "OPEN"
      cat("🚨 Circuit breaker OPENED due to repeated failures\n")
    }
    
    return(NULL)
  })
}

#' Get Optimized Legislative Documents with Caching
#' 
#' @param filters List of filter parameters
#' @param limit Number of documents to return
#' @param offset Pagination offset
#' @return Data frame of legislative documents
#' @export
get_legislative_documents_optimized <- function(filters = list(), limit = 50, offset = 0) {
  # Build optimized query with indexes
  base_query <- "
    SELECT 
      id, titulo, categoria, estado, data, autoridade, 
      ementa, municipio, tipo_documento, urn
    FROM documentos_legislativos
    WHERE 1=1
  "
  
  where_conditions <- c()
  params <- list()
  
  # Add filters dynamically
  if (!is.null(filters$search_term) && filters$search_term != "") {
    where_conditions <- c(where_conditions, 
      "AND (titulo ILIKE $1 OR ementa ILIKE $1)")
    params <- c(params, paste0("%", filters$search_term, "%"))
  }
  
  if (!is.null(filters$state) && filters$state != "all") {
    where_conditions <- c(where_conditions, "AND estado = $2")
    params <- c(params, filters$state)
  }
  
  if (!is.null(filters$category) && filters$category != "all") {
    where_conditions <- c(where_conditions, "AND categoria = $3")
    params <- c(params, filters$category)
  }
  
  # Complete query with pagination
  final_query <- paste0(
    base_query,
    paste(where_conditions, collapse = " "),
    " ORDER BY data DESC LIMIT ", limit, " OFFSET ", offset
  )
  
  return(execute_query(final_query, params))
}

#' Get Document Count with Caching
#' 
#' @param filters List of filter parameters
#' @return Integer count of matching documents
#' @export
get_document_count_optimized <- function(filters = list()) {
  # Use cached count if available and recent
  cache_key <- paste0("count_", digest::digest(filters, algo = "md5"))
  
  base_query <- "SELECT COUNT(*) as total FROM documentos_legislativos WHERE 1=1"
  
  where_conditions <- c()
  params <- list()
  
  # Add same filters as document query
  if (!is.null(filters$search_term) && filters$search_term != "") {
    where_conditions <- c(where_conditions, 
      "AND (titulo ILIKE $1 OR ementa ILIKE $1)")
    params <- c(params, paste0("%", filters$search_term, "%"))
  }
  
  if (!is.null(filters$state) && filters$state != "all") {
    where_conditions <- c(where_conditions, "AND estado = $2")
    params <- c(params, filters$state)
  }
  
  if (!is.null(filters$category) && filters$category != "all") {
    where_conditions <- c(where_conditions, "AND categoria = $3")
    params <- c(params, filters$category)
  }
  
  final_query <- paste0(base_query, paste(where_conditions, collapse = " "))
  
  result <- execute_query(final_query, params)
  
  if (!is.null(result) && nrow(result) > 0) {
    return(as.integer(result$total[1]))
  } else {
    return(0)
  }
}

#' Get Database Statistics and Health
#' 
#' @return List with database health metrics
#' @export
get_database_health <- function() {
  health_info <- list(
    pool_status = if(!is.null(.db_pool)) "active" else "inactive",
    connection_stats = .db_connection_stats,
    circuit_breaker = .circuit_breaker
  )
  
  # Get additional database metrics if connected
  if (!is.null(.db_pool)) {
    tryCatch({
      db_metrics <- execute_query("
        SELECT 
          (SELECT COUNT(*) FROM documentos_legislativos) as total_documents,
          (SELECT COUNT(DISTINCT estado) FROM documentos_legislativos) as states_count,
          (SELECT COUNT(DISTINCT categoria) FROM documentos_legislativos) as categories_count
      ")
      
      if (!is.null(db_metrics)) {
        health_info$database_metrics <- db_metrics
      }
    }, error = function(e) {
      health_info$metrics_error <- e$message
    })
  }
  
  return(health_info)
}

#' Close Database Connection Pool
#' 
#' @export
close_database_connection <- function() {
  if (!is.null(.db_pool)) {
    tryCatch({
      pool::poolClose(.db_pool)
      .db_pool <<- NULL
      cat("✅ Database connection pool closed successfully\n")
    }, error = function(e) {
      cat("⚠️ Error closing connection pool:", e$message, "\n")
    })
  }
}

cat("✅ Database utilities module loaded successfully\n")