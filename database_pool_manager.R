# DATABASE POOL MANAGER - Comprehensive Database Connection Management
# This file provides a robust database connection pool manager for Railway PostgreSQL
# Handles 278,152 documents with optimized connection pooling and health monitoring

cat("🔧 Loading Database Pool Manager for Monitor Legislativo v4\n")

# Load required libraries
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
  library(pool)
  library(dplyr)
  library(config)
})

# Global variables for connection management
.connection_pool <- NULL
.connection_health <- list(
  is_healthy = FALSE,
  last_check = NULL,
  failure_count = 0,
  max_failures = 3,
  retry_delay = 5
)
.connection_stats <- list(
  successful_connections = 0,
  failed_connections = 0,
  queries_executed = 0,
  avg_query_time = 0
)

#' Initialize robust database connection pool with health monitoring
#' @return TRUE if successful, FALSE otherwise
init_robust_database_pool <- function() {
  cat("🚀 Initializing robust database connection pool...\n")
  
  tryCatch({
    # Get database URL from Railway environment
    database_url <- Sys.getenv("DATABASE_URL", "")
    
    if (database_url == "") {
      cat("❌ No DATABASE_URL found in environment\n")
      .connection_health$is_healthy <<- FALSE
      return(FALSE)
    }
    
    cat("📊 Parsing Railway DATABASE_URL...\n")
    
    # Parse DATABASE_URL with improved error handling
    # Format: postgresql://user:password@host:port/dbname
    url_pattern <- "postgresql://([^:]+):([^@]+)@([^:]+):([0-9]+)/(.+)"
    parsed <- regmatches(database_url, regexec(url_pattern, database_url))[[1]]
    
    if (length(parsed) != 6) {
      cat("❌ Failed to parse DATABASE_URL format\n")
      .connection_health$is_healthy <<- FALSE
      return(FALSE)
    }
    
    db_user <- parsed[2]
    db_password <- parsed[3]
    db_host <- parsed[4]
    db_port <- as.numeric(parsed[5])
    db_name <- parsed[6]
    
    cat("📊 Connection details: host=", db_host, ", port=", db_port, ", db=", db_name, "\n")
    
    # Create optimized connection pool for Railway PostgreSQL
    .connection_pool <<- dbPool(
      drv = RPostgres::Postgres(),
      host = db_host,
      port = db_port,
      dbname = db_name,
      user = db_user,
      password = db_password,
      # Optimized pool settings for Railway
      minSize = 1,           # Minimum connections (Railway limitation)
      maxSize = 5,           # Maximum connections (Railway free tier limit)
      idleTimeout = 1800,    # 30 minutes idle timeout
      # Connection validation settings
      validateQuery = "SELECT 1",
      onActivate = function(conn) {
        # Set connection-specific settings
        dbExecute(conn, "SET statement_timeout = '30s'")
        dbExecute(conn, "SET lock_timeout = '10s'")
        dbExecute(conn, "SET idle_in_transaction_session_timeout = '5min'")
      }
    )
    
    # Test initial connection and verify data access
    test_result <- test_database_connection()
    if (test_result$success) {
      .connection_health$is_healthy <<- TRUE
      .connection_health$last_check <<- Sys.time()
      .connection_health$failure_count <<- 0
      .connection_stats$successful_connections <<- .connection_stats$successful_connections + 1
      
      cat("✅ Database pool initialized successfully\n")
      cat("📊 Tables available:", paste(test_result$tables, collapse = ", "), "\n")
      cat("📊 Total documents:", test_result$document_count, "\n")
      
      return(TRUE)
    } else {
      cat("❌ Database connection test failed\n")
      cleanup_connection_pool()
      return(FALSE)
    }
    
  }, error = function(e) {
    cat("❌ Database pool initialization error:", e$message, "\n")
    .connection_health$is_healthy <<- FALSE
    .connection_health$failure_count <<- .connection_health$failure_count + 1
    .connection_stats$failed_connections <<- .connection_stats$failed_connections + 1
    
    cleanup_connection_pool()
    return(FALSE)
  })
}

#' Test database connection and return health status
#' @return List with connection test results
test_database_connection <- function() {
  cat("🔍 Testing database connection health...\n")
  
  if (is.null(.connection_pool)) {
    return(list(success = FALSE, error = "No connection pool available"))
  }
  
  tryCatch({
    start_time <- Sys.time()
    
    # Test basic connectivity
    version_result <- dbGetQuery(.connection_pool, "SELECT version() as version")
    cat("📊 PostgreSQL version:", substr(version_result$version[1], 1, 50), "...\n")
    
    # List available tables
    tables <- dbListTables(.connection_pool)
    cat("📊 Available tables:", length(tables), "tables found\n")
    
    # Test document access
    document_count <- 0
    main_table <- NULL
    
    # Try different table names in order of preference
    table_candidates <- c("lexml_documents", "documents", "lexml_parsed_enhanced_fixed")
    
    for (table_name in table_candidates) {
      if (table_name %in% tables) {
        tryCatch({
          count_result <- dbGetQuery(.connection_pool, paste("SELECT COUNT(*) as count FROM", table_name))
          document_count <- count_result$count[1]
          main_table <- table_name
          cat("📊 Using table '", table_name, "' with", document_count, "documents\n")
          break
        }, error = function(e) {
          cat("⚠️ Error accessing table", table_name, ":", e$message, "\n")
        })
      }
    }
    
    # Test a sample query if we have a main table
    if (!is.null(main_table) && document_count > 0) {
      tryCatch({
        sample_query <- paste("SELECT titulo, tipo, estado FROM", main_table, "LIMIT 3")
        sample_data <- dbGetQuery(.connection_pool, sample_query)
        cat("📊 Sample data retrieved:", nrow(sample_data), "rows\n")
      }, error = function(e) {
        cat("⚠️ Error in sample query:", e$message, "\n")
      })
    }
    
    end_time <- Sys.time()
    query_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
    
    # Update connection statistics
    .connection_stats$queries_executed <<- .connection_stats$queries_executed + 1
    .connection_stats$avg_query_time <<- (.connection_stats$avg_query_time + query_time) / 2
    
    cat("⏱️ Connection test completed in", round(query_time, 2), "seconds\n")
    
    return(list(
      success = TRUE,
      tables = tables,
      main_table = main_table,
      document_count = document_count,
      query_time = query_time,
      test_time = Sys.time()
    ))
    
  }, error = function(e) {
    cat("❌ Database connection test failed:", e$message, "\n")
    .connection_health$failure_count <<- .connection_health$failure_count + 1
    .connection_stats$failed_connections <<- .connection_stats$failed_connections + 1
    
    return(list(
      success = FALSE,
      error = e$message,
      test_time = Sys.time()
    ))
  })
}

#' Execute database query with connection health monitoring and retry logic
#' @param query SQL query to execute
#' @param params Query parameters
#' @param max_retries Maximum number of retry attempts
#' @return Query result or NULL on failure
execute_query_with_retry <- function(query, params = NULL, max_retries = 3) {
  
  for (attempt in 1:max_retries) {
    if (attempt > 1) {
      cat("🔄 Retry attempt", attempt, "of", max_retries, "\n")
      Sys.sleep(.connection_health$retry_delay)
    }
    
    # Check connection health before query
    if (!.connection_health$is_healthy || is.null(.connection_pool)) {
      cat("⚠️ Connection unhealthy, attempting to reconnect...\n")
      if (!init_robust_database_pool()) {
        if (attempt == max_retries) {
          cat("❌ All reconnection attempts failed\n")
          return(NULL)
        }
        next
      }
    }
    
    tryCatch({
      start_time <- Sys.time()
      
      # Execute query with timeout protection
      if (is.null(params)) {
        result <- dbGetQuery(.connection_pool, query)
      } else {
        result <- dbGetQuery(.connection_pool, query, params = params)
      }
      
      end_time <- Sys.time()
      query_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
      
      # Update statistics
      .connection_stats$queries_executed <<- .connection_stats$queries_executed + 1
      .connection_stats$avg_query_time <<- (.connection_stats$avg_query_time + query_time) / 2
      
      # Reset failure count on success
      .connection_health$failure_count <<- 0
      .connection_health$last_check <<- Sys.time()
      
      cat("✅ Query executed successfully in", round(query_time, 2), "seconds\n")
      return(result)
      
    }, error = function(e) {
      cat("❌ Query execution error (attempt", attempt, "):", e$message, "\n")
      
      # Mark connection as unhealthy if error suggests connection issue
      if (grepl("connection|network|timeout|closed", tolower(e$message))) {
        .connection_health$is_healthy <<- FALSE
        .connection_health$failure_count <<- .connection_health$failure_count + 1
      }
      
      if (attempt == max_retries) {
        cat("❌ Query failed after", max_retries, "attempts\n")
        return(NULL)
      }
    })
  }
  
  return(NULL)
}

#' Get connection pool health status and statistics
#' @return List with detailed health information
get_connection_health_status <- function() {
  health_status <- list(
    is_healthy = .connection_health$is_healthy,
    last_check = .connection_health$last_check,
    failure_count = .connection_health$failure_count,
    max_failures = .connection_health$max_failures,
    pool_available = !is.null(.connection_pool),
    statistics = .connection_stats
  )
  
  # Add pool-specific information if available
  if (!is.null(.connection_pool)) {
    pool_info <- poolCheckout(.connection_pool)
    health_status$pool_info <- list(
      valid_connection = dbIsValid(pool_info),
      can_execute_query = tryCatch({
        dbGetQuery(pool_info, "SELECT 1")
        TRUE
      }, error = function(e) FALSE)
    )
    poolReturn(pool_info)
  }
  
  return(health_status)
}

#' Cleanup connection pool and reset health status
cleanup_connection_pool <- function() {
  cat("🧹 Cleaning up database connection pool...\n")
  
  if (!is.null(.connection_pool)) {
    tryCatch({
      poolClose(.connection_pool)
      cat("✅ Connection pool closed successfully\n")
    }, error = function(e) {
      cat("⚠️ Error closing connection pool:", e$message, "\n")
    })
    .connection_pool <<- NULL
  }
  
  .connection_health$is_healthy <<- FALSE
  .connection_health$last_check <<- NULL
}

#' Periodic health check function (to be called by monitoring)
perform_health_check <- function() {
  cat("🏥 Performing periodic health check...\n")
  
  # Skip if last check was recent
  if (!is.null(.connection_health$last_check)) {
    time_since_check <- as.numeric(difftime(Sys.time(), .connection_health$last_check, units = "mins"))
    if (time_since_check < 5) {  # Don't check more than every 5 minutes
      cat("📊 Skipping health check (last check", round(time_since_check, 1), "minutes ago)\n")
      return(.connection_health$is_healthy)
    }
  }
  
  test_result <- test_database_connection()
  
  if (test_result$success) {
    cat("✅ Health check passed\n")
    return(TRUE)
  } else {
    cat("❌ Health check failed, marking connection as unhealthy\n")
    .connection_health$is_healthy <<- FALSE
    
    # Attempt to reinitialize if we've exceeded failure threshold
    if (.connection_health$failure_count >= .connection_health$max_failures) {
      cat("🔄 Attempting to reinitialize connection pool...\n")
      cleanup_connection_pool()
      return(init_robust_database_pool())
    }
    
    return(FALSE)
  }
}

# Export the connection pool for use by other modules
get_database_pool <- function() {
  if (is.null(.connection_pool) || !.connection_health$is_healthy) {
    cat("⚠️ Database pool not available, attempting to initialize...\n")
    if (init_robust_database_pool()) {
      return(.connection_pool)
    } else {
      return(NULL)
    }
  }
  return(.connection_pool)
}

cat("✅ Database Pool Manager loaded successfully\n")
cat("📊 Ready to manage robust database connections for 278,152 documents\n")