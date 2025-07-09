# Private Database Client for R-Shiny
# Connects to private Supabase database instead of external APIs

suppressPackageStartupMessages({
  if (!requireNamespace("RPostgreSQL", quietly = TRUE)) {
    stop("RPostgreSQL package is required. Install with: install.packages('RPostgreSQL')")
  }
  if (!requireNamespace("DBI", quietly = TRUE)) {
    stop("DBI package is required. Install with: install.packages('DBI')")
  }
  if (!requireNamespace("dplyr", quietly = TRUE)) {
    stop("dplyr package is required. Install with: install.packages('dplyr')")
  }
  if (!requireNamespace("httr", quietly = TRUE)) {
    stop("httr package is required. Install with: install.packages('httr')")
  }
  if (!requireNamespace("jsonlite", quietly = TRUE)) {
    stop("jsonlite package is required. Install with: install.packages('jsonlite')")
  }
  
  library(RPostgreSQL)
  library(DBI)
  library(dplyr)
  library(httr)
  library(jsonlite)
})

# Global connection variable
.private_db_connection <- NULL

#' Initialize Private Database Connection
#' @param database_url PostgreSQL connection string
#' @return TRUE if successful, FALSE otherwise
init_private_database <- function(database_url = NULL) {
  if (is.null(database_url)) {
    database_url <- Sys.getenv("DATABASE_URL")
  }
  
  if (database_url == "") {
    warning("DATABASE_URL environment variable not set")
    return(FALSE)
  }
  
  tryCatch({
    # Parse database URL
    url_parts <- parse_database_url(database_url)
    
    # Create connection
    drv <- dbDriver("PostgreSQL")
    .private_db_connection <<- dbConnect(
      drv,
      host = url_parts$host,
      port = url_parts$port,
      dbname = url_parts$dbname,
      user = url_parts$user,
      password = url_parts$password
    )
    
    # Test connection
    test_result <- dbGetQuery(.private_db_connection, "SELECT 1 as test")
    
    if (nrow(test_result) == 1) {
      message("Private database connection established successfully")
      return(TRUE)
    } else {
      warning("Database connection test failed")
      return(FALSE)
    }
    
  }, error = function(e) {
    warning(paste("Failed to connect to private database:", e$message))
    return(FALSE)
  })
}

#' Parse Database URL
#' @param database_url PostgreSQL URL
#' @return List with connection parameters
parse_database_url <- function(database_url) {
  # Remove postgresql:// prefix
  clean_url <- gsub("^postgresql://", "", database_url)
  
  # Split into parts
  parts <- strsplit(clean_url, "/")[[1]]
  auth_host <- parts[1]
  dbname <- parts[2]
  
  # Split auth and host
  auth_parts <- strsplit(auth_host, "@")[[1]]
  auth <- auth_parts[1]
  host_port <- auth_parts[2]
  
  # Split user and password
  user_pass <- strsplit(auth, ":")[[1]]
  user <- user_pass[1]
  password <- user_pass[2]
  
  # Split host and port
  host_port_parts <- strsplit(host_port, ":")[[1]]
  host <- host_port_parts[1]
  port <- as.integer(host_port_parts[2])
  
  return(list(
    host = host,
    port = port,
    dbname = dbname,
    user = user,
    password = password
  ))
}

#' Check if private database is available
#' @return TRUE if connection is active, FALSE otherwise
is_private_database_available <- function() {
  if (is.null(.private_db_connection)) {
    return(FALSE)
  }
  
  tryCatch({
    test_result <- dbGetQuery(.private_db_connection, "SELECT 1")
    return(nrow(test_result) == 1)
  }, error = function(e) {
    return(FALSE)
  })
}

#' Search Private Legislative Database
#' @param query Search query string
#' @param filters List of filters (document_type, state, authority, etc.)
#' @param limit Maximum number of results
#' @param offset Results offset for pagination
#' @return Data frame of search results
search_private_database <- function(query, filters = list(), limit = 50, offset = 0) {
  if (!is_private_database_available()) {
    warning("Private database not available")
    return(data.frame())
  }
  
  tryCatch({
    # Build WHERE conditions
    where_conditions <- c("1=1")
    params <- list()
    
    # Add full-text search condition
    if (!is.null(query) && query != "") {
      where_conditions <- c(where_conditions, 
                           "search_vector @@ plainto_tsquery('portuguese', $1)")
      params <- c(params, query)
    }
    
    # Add filters
    param_index <- length(params) + 1
    
    if (!is.null(filters$document_type) && filters$document_type != "") {
      where_conditions <- c(where_conditions, 
                           paste0("document_type ILIKE $", param_index))
      params <- c(params, paste0("%", filters$document_type, "%"))
      param_index <- param_index + 1
    }
    
    if (!is.null(filters$state) && filters$state != "") {
      where_conditions <- c(where_conditions, 
                           paste0("(state_code = $", param_index, " OR state_name ILIKE $", param_index + 1, ")"))
      params <- c(params, toupper(filters$state), paste0("%", filters$state, "%"))
      param_index <- param_index + 2
    }
    
    if (!is.null(filters$authority) && filters$authority != "") {
      where_conditions <- c(where_conditions, 
                           paste0("authority ILIKE $", param_index))
      params <- c(params, paste0("%", filters$authority, "%"))
      param_index <- param_index + 1
    }
    
    if (!is.null(filters$geographic_level) && filters$geographic_level != "") {
      where_conditions <- c(where_conditions, 
                           paste0("geographic_level = $", param_index))
      params <- c(params, filters$geographic_level)
      param_index <- param_index + 1
    }
    
    # Build final query
    where_clause <- paste(where_conditions, collapse = " AND ")
    
    sql_query <- paste0("
      SELECT 
        id, urn, title, description, document_type, authority, locality,
        event_type, event_date, publication_date, subject_keywords,
        full_text_url, source_url, state_code, state_name, municipality,
        geographic_level, word_count, collected_at,
        CASE WHEN search_vector @@ plainto_tsquery('portuguese', $1) 
             THEN ts_rank(search_vector, plainto_tsquery('portuguese', $1))
             ELSE 0 END as relevance_score
      FROM private_legislative_documents
      WHERE ", where_clause, "
      ORDER BY relevance_score DESC, event_date DESC
      LIMIT ", limit, " OFFSET ", offset
    )
    
    # Execute query
    if (length(params) > 0) {
      result <- dbGetQuery(.private_db_connection, sql_query, params)
    } else {
      # Simple query without parameters
      simple_query <- paste0("
        SELECT 
          id, urn, title, description, document_type, authority, locality,
          event_type, event_date, publication_date, subject_keywords,
          full_text_url, source_url, state_code, state_name, municipality,
          geographic_level, word_count, collected_at,
          0 as relevance_score
        FROM private_legislative_documents
        ORDER BY event_date DESC
        LIMIT ", limit, " OFFSET ", offset
      )
      result <- dbGetQuery(.private_db_connection, simple_query)
    }
    
    return(result)
    
  }, error = function(e) {
    warning(paste("Private database search failed:", e$message))
    return(data.frame())
  })
}

#' Get State Document Density Data
#' @return Data frame with state density information
get_state_density_data <- function() {
  if (!is_private_database_available()) {
    warning("Private database not available")
    return(data.frame())
  }
  
  tryCatch({
    query <- "
      SELECT 
        state_code,
        state_name,
        total_documents,
        documents_last_month,
        documents_last_year,
        last_updated,
        CASE 
          WHEN total_documents > 1000 THEN 'high'
          WHEN total_documents > 100 THEN 'medium'
          ELSE 'low'
        END as density_level
      FROM state_document_density
      WHERE state_code IS NOT NULL
      ORDER BY total_documents DESC
    "
    
    result <- dbGetQuery(.private_db_connection, query)
    return(result)
    
  }, error = function(e) {
    warning(paste("State density query failed:", e$message))
    return(data.frame())
  })
}

#' Get Database Analytics
#' @param days Number of days to analyze (default 30)
#' @return List with analytics data
get_database_analytics <- function(days = 30) {
  if (!is_private_database_available()) {
    warning("Private database not available")
    return(list())
  }
  
  tryCatch({
    # Document statistics
    doc_stats_query <- paste0("
      SELECT 
        COUNT(*) as total_documents,
        COUNT(DISTINCT state_code) as states_covered,
        COUNT(DISTINCT document_type) as document_types,
        COUNT(DISTINCT authority) as authorities,
        COUNT(*) FILTER (WHERE collected_at >= NOW() - INTERVAL '", days, " days') as recent_documents,
        MIN(event_date) as oldest_document_date,
        MAX(event_date) as newest_document_date,
        AVG(word_count) as avg_word_count
      FROM private_legislative_documents
    ")
    
    doc_stats <- dbGetQuery(.private_db_connection, doc_stats_query)
    
    # Collection statistics
    collection_stats_query <- paste0("
      SELECT 
        COUNT(*) as total_executions,
        COUNT(*) FILTER (WHERE status = 'completed') as successful_executions,
        COUNT(*) FILTER (WHERE status = 'failed') as failed_executions,
        SUM(documents_new) as total_new_documents,
        SUM(documents_updated) as total_updated_documents,
        AVG(execution_time_seconds) as avg_execution_time,
        MAX(started_at) as last_collection
      FROM collection_executions
      WHERE started_at >= NOW() - INTERVAL '", days, " days'
    ")
    
    collection_stats <- dbGetQuery(.private_db_connection, collection_stats_query)
    
    # Top document types
    top_types_query <- "
      SELECT 
        document_type,
        COUNT(*) as count,
        ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM private_legislative_documents), 2) as percentage
      FROM private_legislative_documents
      WHERE document_type IS NOT NULL
      GROUP BY document_type
      ORDER BY count DESC
      LIMIT 10
    "
    
    top_types <- dbGetQuery(.private_db_connection, top_types_query)
    
    return(list(
      document_statistics = doc_stats,
      collection_statistics = collection_stats,
      top_document_types = top_types,
      analysis_period_days = days
    ))
    
  }, error = function(e) {
    warning(paste("Analytics query failed:", e$message))
    return(list())
  })
}

#' Get Recent Collection Activity
#' @param limit Number of recent collections to retrieve
#' @return Data frame with recent collection logs
get_recent_collections <- function(limit = 20) {
  if (!is_private_database_available()) {
    warning("Private database not available")
    return(data.frame())
  }
  
  tryCatch({
    query <- paste0("
      SELECT 
        ce.batch_id,
        ce.execution_type,
        ce.status,
        ce.documents_found,
        ce.documents_new,
        ce.documents_updated,
        ce.execution_time_seconds,
        ce.started_at,
        ce.completed_at,
        ce.error_message,
        stc.term_name,
        stc.description
      FROM collection_executions ce
      JOIN search_terms_config stc ON ce.search_term_id = stc.id
      ORDER BY ce.started_at DESC
      LIMIT ", limit
    )
    
    result <- dbGetQuery(.private_db_connection, query)
    return(result)
    
  }, error = function(e) {
    warning(paste("Recent collections query failed:", e$message))
    return(data.frame())
  })
}

#' Get Document Count by Time Period
#' @param period Time period ('day', 'week', 'month')
#' @param days Number of periods to look back
#' @return Data frame with time series data
get_document_timeline <- function(period = "day", days = 30) {
  if (!is_private_database_available()) {
    warning("Private database not available")
    return(data.frame())
  }
  
  tryCatch({
    # Determine date truncation
    date_trunc <- switch(period,
      "day" = "day",
      "week" = "week", 
      "month" = "month",
      "day"  # default
    )
    
    query <- paste0("
      SELECT 
        DATE_TRUNC('", date_trunc, "', collected_at) as time_period,
        COUNT(*) as document_count,
        COUNT(DISTINCT state_code) as states_count,
        COUNT(DISTINCT document_type) as types_count
      FROM private_legislative_documents
      WHERE collected_at >= NOW() - INTERVAL '", days, " days'
      GROUP BY DATE_TRUNC('", date_trunc, "', collected_at)
      ORDER BY time_period DESC
    ")
    
    result <- dbGetQuery(.private_db_connection, query)
    return(result)
    
  }, error = function(e) {
    warning(paste("Timeline query failed:", e$message))
    return(data.frame())
  })
}

#' Close Private Database Connection
#' @return TRUE if successful
close_private_database <- function() {
  if (!is.null(.private_db_connection)) {
    tryCatch({
      dbDisconnect(.private_db_connection)
      .private_db_connection <<- NULL
      message("Private database connection closed")
      return(TRUE)
    }, error = function(e) {
      warning(paste("Error closing database connection:", e$message))
      return(FALSE)
    })
  }
  return(TRUE)
}

# Initialize connection on module load
if (file.exists(".env")) {
  # Load environment variables from .env file if it exists
  env_vars <- readLines(".env")
  for (line in env_vars) {
    if (grepl("^[A-Z_]+=", line)) {
      parts <- strsplit(line, "=", fixed = TRUE)[[1]]
      if (length(parts) >= 2) {
        var_name <- parts[1]
        var_value <- paste(parts[-1], collapse = "=")
        Sys.setenv(setNames(var_value, var_name))
      }
    }
  }
}

# Try to initialize connection
if (Sys.getenv("DATABASE_URL") != "") {
  init_result <- init_private_database()
  if (init_result) {
    message("Private database client initialized successfully")
  } else {
    message("Private database client initialization failed - falling back to external APIs")
  }
} else {
  message("DATABASE_URL not configured - private database features disabled")
} 