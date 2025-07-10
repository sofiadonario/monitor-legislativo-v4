# Database Connection Module for Monitor Legislativo v4
# Connects to Railway PostgreSQL with 889 real documents

library(DBI)
library(RPostgres)
library(pool)
library(dplyr)

# Global connection pool
db_pool <- NULL

#' Initialize database connection pool
#' @return TRUE if successful, FALSE otherwise
init_database <- function() {
  tryCatch({
    # Get DATABASE_URL from environment
    database_url <- Sys.getenv("DATABASE_URL")
    
    cat("Initializing database connection...\n")
    cat("DATABASE_URL present:", nchar(database_url) > 0, "\n")
    
    if (nchar(database_url) == 0) {
      cat("⚠️ DATABASE_URL not found - app will use sample data\n")
      return(FALSE)
    }
    
    # Quick validation of URL format
    if (!grepl("^postgresql://", database_url)) {
      cat("⚠️ DATABASE_URL doesn't appear to be PostgreSQL format - app will use sample data\n")
      return(FALSE)
    }
    
    # Parse DATABASE_URL (format: postgresql://user:password@host:port/database)
    # Railway format: postgresql://postgres:password@host:port/railway
    parsed_url <- parse_database_url(database_url)
    
    if (is.null(parsed_url)) {
      warning("Failed to parse DATABASE_URL")
      return(FALSE)
    }
    
    cat("Connecting to database:\n")
    cat("  Host:", parsed_url$host, "\n")
    cat("  Port:", parsed_url$port, "\n")
    cat("  Database:", parsed_url$database, "\n")
    cat("  User:", parsed_url$user, "\n")
    
    # Create connection pool
    cat("Creating database connection pool...\n")
    db_pool <<- dbPool(
      drv = RPostgres::Postgres(),
      host = parsed_url$host,
      port = parsed_url$port,
      dbname = parsed_url$database,
      user = parsed_url$user,
      password = parsed_url$password,
      minSize = 1,
      maxSize = 3,  # Reduced pool size for faster startup
      idleTimeout = 1800000  # 30 minutes
    )
    
    # Test connection with timeout
    cat("Testing database connection (10 second timeout)...\n")
    test_result <- FALSE
    
    # Use a timeout to prevent hanging
    tryCatch({
      # Set a time limit to prevent hanging (10 seconds for faster startup)
      setTimeLimit(cpu = 10, elapsed = 10, transient = TRUE)
      test_result <- test_database_connection()
      setTimeLimit(cpu = Inf, elapsed = Inf, transient = FALSE)  # Reset limits
      
    }, error = function(e) {
      cat("Database test error:", e$message, "\n")
      test_result <- FALSE
      setTimeLimit(cpu = Inf, elapsed = Inf, transient = FALSE)  # Reset limits
    })
    
    if (test_result) {
      cat("✅ Database connection successful!\n")
      return(TRUE)
    } else {
      cat("❌ Database connection test failed or timed out\n")
      return(FALSE)
    }
    
  }, error = function(e) {
    cat("❌ Database initialization error:", e$message, "\n")
    return(FALSE)
  })
}

#' Parse DATABASE_URL into components
#' @param url The DATABASE_URL string
#' @return List with host, port, database, user, password or NULL if failed
parse_database_url <- function(url) {
  tryCatch({
    # Remove postgresql:// prefix
    url <- gsub("^postgresql://", "", url)
    
    # Split user:password@host:port/database
    if (grepl("@", url)) {
      parts <- strsplit(url, "@")[[1]]
      auth_part <- parts[1]
      host_part <- parts[2]
      
      # Extract user and password
      if (grepl(":", auth_part)) {
        auth_split <- strsplit(auth_part, ":")[[1]]
        user <- auth_split[1]
        password <- auth_split[2]
      } else {
        user <- auth_part
        password <- ""
      }
      
      # Extract host, port, and database
      if (grepl("/", host_part)) {
        host_db_split <- strsplit(host_part, "/")[[1]]
        host_port <- host_db_split[1]
        database <- host_db_split[2]
        
        if (grepl(":", host_port)) {
          host_port_split <- strsplit(host_port, ":")[[1]]
          host <- host_port_split[1]
          port <- as.integer(host_port_split[2])
        } else {
          host <- host_port
          port <- 5432L
        }
      } else {
        host <- host_part
        port <- 5432L
        database <- "postgres"
      }
      
      return(list(
        host = host,
        port = port,
        database = database,
        user = user,
        password = password
      ))
    }
    
    return(NULL)
  }, error = function(e) {
    cat("Error parsing DATABASE_URL:", e$message, "\n")
    return(NULL)
  })
}

#' Test database connection and verify tables
#' @return TRUE if successful, FALSE otherwise
test_database_connection <- function() {
  if (is.null(db_pool)) {
    cat("Database pool is NULL\n")
    return(FALSE)
  }
  
  tryCatch({
    cat("Attempting to checkout connection from pool...\n")
    
    # Test basic connection with faster checkout
    conn <- poolCheckout(db_pool)
    on.exit({
      tryCatch(poolReturn(conn), error = function(e) cat("Error returning connection:", e$message, "\n"))
    })
    
    cat("Connection checked out successfully\n")
    
    # Quick connection test - just check if we can run a simple query
    result <- dbGetQuery(conn, "SELECT 1 as test")
    cat("Basic query test successful\n")
    
    # Check if our tables exist (but don't require all of them)
    tables <- dbListTables(conn)
    cat("Available tables count:", length(tables), "\n")
    
    # Just check if we have at least one of our tables
    required_tables <- c("lexml_parsed_enhanced", "documents", "legislative_data")
    found_tables <- intersect(required_tables, tables)
    
    if (length(found_tables) == 0) {
      cat("⚠️ No required tables found, but connection is working\n")
      return(TRUE)  # Still return TRUE if connection works
    }
    
    # Check row counts
    for (table in required_tables) {
      count <- dbGetQuery(conn, paste("SELECT COUNT(*) as count FROM", table))$count
      cat("  ", table, ":", count, "rows\n")
    }
    
    return(TRUE)
    
  }, error = function(e) {
    cat("Database test error:", e$message, "\n")
    return(FALSE)
  })
}

#' Get all documents from the database
#' @param limit Maximum number of documents to return (default: 100)
#' @return Data frame with documents or NULL if error
get_documents <- function(limit = 100) {
  if (is.null(db_pool)) {
    warning("Database not initialized")
    return(NULL)
  }
  
  tryCatch({
    query <- "
      SELECT 
        id,
        titulo,
        tipo,
        estado,
        data_publicacao,
        url,
        urn
      FROM documents 
      WHERE titulo IS NOT NULL 
      ORDER BY data_publicacao DESC NULLS LAST
      LIMIT $1
    "
    
    result <- dbGetQuery(db_pool, query, params = list(limit))
    
    # Clean up the data
    if (nrow(result) > 0) {
      # Convert dates
      if ("data_publicacao" %in% names(result)) {
        result$data_publicacao <- as.Date(result$data_publicacao)
      }
      
      # Clean up missing values
      result[is.na(result)] <- ""
      
      cat("Retrieved", nrow(result), "documents from database\n")
    }
    
    return(result)
    
  }, error = function(e) {
    cat("Error retrieving documents:", e$message, "\n")
    return(NULL)
  })
}

#' Advanced search documents with filters
#' @param search_text Text to search for
#' @param document_types Vector of document types to filter (optional)
#' @param states Vector of states to filter (optional) 
#' @param date_from Start date for date range (optional)
#' @param date_to End date for date range (optional)
#' @param limit Maximum number of results
#' @return Data frame with search results
search_documents <- function(search_text = "", document_types = NULL, states = NULL, 
                            date_from = NULL, date_to = NULL, limit = 100) {
  if (is.null(db_pool)) {
    warning("Database not initialized")
    return(NULL)
  }
  
  tryCatch({
    # Build dynamic query with ranking
    has_search_text <- nchar(search_text) > 0
    
    if (has_search_text) {
      base_query <- "
        SELECT 
          id,
          titulo,
          tipo,
          estado,
          data_publicacao,
          url,
          urn,
          conteudo,
          CASE 
            WHEN titulo ILIKE $1 THEN 3
            WHEN conteudo ILIKE $1 THEN 1
            ELSE 0
          END as relevance_score
        FROM documents 
        WHERE (titulo ILIKE $1 OR conteudo ILIKE $1)"
      
      params <- list(paste0("%", search_text, "%"))
      param_count <- 1
    } else {
      base_query <- "
        SELECT 
          id,
          titulo,
          tipo,
          estado,
          data_publicacao,
          url,
          urn,
          conteudo,
          0 as relevance_score
        FROM documents 
        WHERE 1=1"
      
      params <- list()
      param_count <- 0
    }
    
    # Add document type filter
    if (!is.null(document_types) && length(document_types) > 0) {
      # Use simple string formatting for IN clauses (safer approach)
      quoted_types <- paste0("'", gsub("'", "''", document_types), "'", collapse = ", ")
      base_query <- paste(base_query, "AND tipo IN (", quoted_types, ")")
    }
    
    # Add state filter
    if (!is.null(states) && length(states) > 0) {
      # Use simple string formatting for IN clauses
      quoted_states <- paste0("'", gsub("'", "''", states), "'", collapse = ", ")
      base_query <- paste(base_query, "AND estado IN (", quoted_states, ")")
    }
    
    # Add date range filter
    if (!is.null(date_from)) {
      param_count <- param_count + 1
      base_query <- paste(base_query, "AND data_publicacao >= $", param_count, sep="")
      params[[param_count]] <- date_from
    }
    
    if (!is.null(date_to)) {
      param_count <- param_count + 1
      base_query <- paste(base_query, "AND data_publicacao <= $", param_count, sep="")
      params[[param_count]] <- date_to
    }
    
    # Add ordering and limit - rank by relevance first, then by date
    param_count <- param_count + 1
    if (has_search_text) {
      base_query <- paste(base_query, "ORDER BY relevance_score DESC, data_publicacao DESC NULLS LAST LIMIT $", param_count, sep="")
    } else {
      base_query <- paste(base_query, "ORDER BY data_publicacao DESC NULLS LAST LIMIT $", param_count, sep="")
    }
    params[[param_count]] <- limit
    
    # Debug: print query for troubleshooting
    cat("DEBUG: Generated query:\n", base_query, "\n")
    cat("DEBUG: Query parameters count:", length(params), "\n")
    for (i in seq_along(params)) {
      cat("  Param", i, ":", as.character(params[[i]]), "\n")
    }
    
    # Execute query with error handling
    result <- tryCatch({
      dbGetQuery(db_pool, base_query, params = params)
    }, error = function(e) {
      cat("ERROR: Query execution failed:", e$message, "\n")
      cat("Query was:", base_query, "\n")
      return(data.frame())  # Return empty data frame on error
    })
    
    # Clean up the data
    if (nrow(result) > 0) {
      if ("data_publicacao" %in% names(result)) {
        result$data_publicacao <- as.Date(result$data_publicacao)
      }
      result[is.na(result)] <- ""
      
      # Remove content and relevance score from display (too long for tables)
      if ("conteudo" %in% names(result)) {
        result$conteudo <- NULL
      }
      if ("relevance_score" %in% names(result)) {
        result$relevance_score <- NULL
      }
      
      search_desc <- paste(
        "text:", ifelse(nchar(search_text) > 0, search_text, "any"),
        "types:", ifelse(is.null(document_types), "any", paste(document_types, collapse=",")),
        "states:", ifelse(is.null(states), "any", paste(states, collapse=",")),
        "dates:", ifelse(is.null(date_from) && is.null(date_to), "any", 
                        paste(date_from, "to", date_to))
      )
      
      cat("Advanced search (", search_desc, ") returned", nrow(result), "documents\n")
    }
    
    return(result)
    
  }, error = function(e) {
    cat("Error in advanced search:", e$message, "\n")
    return(NULL)
  })
}

#' Get available document types for filter
#' @return Vector of document types
get_document_types <- function() {
  if (is.null(db_pool)) {
    return(c("lei", "decreto", "portaria"))
  }
  
  tryCatch({
    result <- dbGetQuery(db_pool, "
      SELECT DISTINCT tipo 
      FROM documents 
      WHERE tipo IS NOT NULL AND tipo != '' 
      ORDER BY tipo
    ")
    
    if (nrow(result) > 0) {
      cat("DEBUG: Found document types:", paste(result$tipo, collapse = ", "), "\n")
      return(result$tipo)
    } else {
      cat("DEBUG: No document types found in database, using defaults\n")
      return(c("lei", "decreto", "portaria"))
    }
    
  }, error = function(e) {
    cat("ERROR getting document types:", e$message, "\n")
    return(c("lei", "decreto", "portaria"))
  })
}

#' Get available states for filter
#' @return Vector of states
get_states <- function() {
  if (is.null(db_pool)) {
    return(c("SP", "RJ", "MG", "RS"))
  }
  
  tryCatch({
    result <- dbGetQuery(db_pool, "
      SELECT DISTINCT estado 
      FROM documents 
      WHERE estado IS NOT NULL AND estado != '' 
      ORDER BY estado
    ")
    
    if (nrow(result) > 0) {
      cat("DEBUG: Found states:", paste(result$estado, collapse = ", "), "\n")
      return(result$estado)
    } else {
      cat("DEBUG: No states found in database, using defaults\n")
      return(c("SP", "RJ", "MG", "RS"))
    }
    
  }, error = function(e) {
    cat("ERROR getting states:", e$message, "\n")
    return(c("SP", "RJ", "MG", "RS"))
  })
}

#' Get document statistics
#' @return List with various statistics
get_document_stats <- function() {
  if (is.null(db_pool)) {
    return(list(
      total_documents = 0,
      document_types = data.frame(),
      states = data.frame(),
      connection_status = "No database connection"
    ))
  }
  
  tryCatch({
    # Total documents
    total <- dbGetQuery(db_pool, "SELECT COUNT(*) as count FROM documents")$count
    
    # Document types
    types <- dbGetQuery(db_pool, "
      SELECT tipo, COUNT(*) as count 
      FROM documents 
      WHERE tipo IS NOT NULL AND tipo != ''
      GROUP BY tipo 
      ORDER BY count DESC 
      LIMIT 10
    ")
    
    # States distribution
    states <- dbGetQuery(db_pool, "
      SELECT estado, COUNT(*) as count 
      FROM documents 
      WHERE estado IS NOT NULL AND estado != ''
      GROUP BY estado 
      ORDER BY count DESC 
      LIMIT 10
    ")
    
    return(list(
      total_documents = total,
      document_types = types,
      states = states,
      connection_status = "Connected"
    ))
    
  }, error = function(e) {
    cat("Error getting statistics:", e$message, "\n")
    return(list(
      total_documents = 0,
      document_types = data.frame(),
      states = data.frame(),
      connection_status = paste("Error:", e$message)
    ))
  })
}

#' Get search analytics and statistics
#' @return List with search-related statistics
get_search_analytics <- function() {
  if (is.null(db_pool)) {
    return(list(
      total_documents = 0,
      documents_by_year = data.frame(),
      documents_by_state = data.frame(),
      documents_by_type = data.frame(),
      recent_documents = data.frame(),
      date_range = list(min = NA, max = NA)
    ))
  }
  
  tryCatch({
    # Total documents
    total <- dbGetQuery(db_pool, "SELECT COUNT(*) as count FROM documents")$count
    
    # Documents by year
    by_year <- dbGetQuery(db_pool, "
      SELECT 
        EXTRACT(YEAR FROM data_publicacao) as year,
        COUNT(*) as count
      FROM documents 
      WHERE data_publicacao IS NOT NULL
      GROUP BY EXTRACT(YEAR FROM data_publicacao)
      ORDER BY year DESC
      LIMIT 10
    ")
    
    # Documents by state (top 10)
    by_state <- dbGetQuery(db_pool, "
      SELECT 
        estado,
        COUNT(*) as count
      FROM documents 
      WHERE estado IS NOT NULL AND estado != ''
      GROUP BY estado
      ORDER BY count DESC
      LIMIT 10
    ")
    
    # Documents by type
    by_type <- dbGetQuery(db_pool, "
      SELECT 
        tipo,
        COUNT(*) as count
      FROM documents 
      WHERE tipo IS NOT NULL AND tipo != ''
      GROUP BY tipo
      ORDER BY count DESC
    ")
    
    # Recent documents (last 30 days)
    recent <- dbGetQuery(db_pool, "
      SELECT 
        titulo,
        tipo,
        estado,
        data_publicacao
      FROM documents 
      WHERE data_publicacao >= CURRENT_DATE - INTERVAL '30 days'
      ORDER BY data_publicacao DESC
      LIMIT 10
    ")
    
    # Date range
    date_range <- dbGetQuery(db_pool, "
      SELECT 
        MIN(data_publicacao) as min_date,
        MAX(data_publicacao) as max_date
      FROM documents 
      WHERE data_publicacao IS NOT NULL
    ")
    
    return(list(
      total_documents = total,
      documents_by_year = by_year,
      documents_by_state = by_state,
      documents_by_type = by_type,
      recent_documents = recent,
      date_range = list(
        min = date_range$min_date,
        max = date_range$max_date
      )
    ))
    
  }, error = function(e) {
    cat("Error getting search analytics:", e$message, "\n")
    return(list(
      total_documents = 0,
      documents_by_year = data.frame(),
      documents_by_state = data.frame(),
      documents_by_type = data.frame(),
      recent_documents = data.frame(),
      date_range = list(min = NA, max = NA)
    ))
  })
}

#' Highlight search terms in text
#' @param text The text to highlight
#' @param search_terms Vector of terms to highlight
#' @return HTML string with highlighted terms
highlight_search_terms <- function(text, search_terms) {
  if (is.null(search_terms) || length(search_terms) == 0 || is.null(text) || nchar(text) == 0) {
    return(text)
  }
  
  result <- text
  for (term in search_terms) {
    if (nchar(term) > 0) {
      # Case-insensitive replacement with HTML highlighting
      pattern <- paste0("(", term, ")")
      replacement <- '<mark style="background-color: #ffff00; padding: 0 2px;">\\1</mark>'
      result <- gsub(pattern, replacement, result, ignore.case = TRUE)
    }
  }
  
  return(result)
}

#' Save a search to history
#' @param search_params List containing search parameters
#' @param session_id Session identifier
#' @return TRUE if successful, FALSE otherwise
save_search_history <- function(search_params, session_id) {
  # Store search history in a local file per session
  history_file <- paste0("search_history_", session_id, ".rds")
  history_path <- file.path("data", history_file)
  
  # Ensure data directory exists
  if (!dir.exists("data")) {
    dir.create("data", showWarnings = FALSE)
  }
  
  tryCatch({
    # Load existing history or create new
    if (file.exists(history_path)) {
      history <- readRDS(history_path)
    } else {
      history <- list()
    }
    
    # Add new search with timestamp
    search_entry <- list(
      timestamp = Sys.time(),
      search_text = search_params$search_text,
      document_types = search_params$document_types,
      states = search_params$states,
      date_from = search_params$date_from,
      date_to = search_params$date_to
    )
    
    # Add to beginning of list
    history <- c(list(search_entry), history)
    
    # Keep only last 20 searches
    if (length(history) > 20) {
      history <- history[1:20]
    }
    
    # Save updated history
    saveRDS(history, history_path)
    
    return(TRUE)
    
  }, error = function(e) {
    cat("Error saving search history:", e$message, "\n")
    return(FALSE)
  })
}

#' Get search history for a session
#' @param session_id Session identifier
#' @return List of search history entries
get_search_history <- function(session_id) {
  history_file <- paste0("search_history_", session_id, ".rds")
  history_path <- file.path("data", history_file)
  
  tryCatch({
    if (file.exists(history_path)) {
      history <- readRDS(history_path)
      return(history)
    } else {
      return(list())
    }
  }, error = function(e) {
    cat("Error loading search history:", e$message, "\n")
    return(list())
  })
}

#' Save a search as favorite/saved search
#' @param search_params List containing search parameters
#' @param search_name Name for the saved search
#' @param session_id Session identifier
#' @return TRUE if successful, FALSE otherwise
save_saved_search <- function(search_params, search_name, session_id) {
  saved_file <- paste0("saved_searches_", session_id, ".rds")
  saved_path <- file.path("data", saved_file)
  
  # Ensure data directory exists
  if (!dir.exists("data")) {
    dir.create("data", showWarnings = FALSE)
  }
  
  tryCatch({
    # Load existing saved searches or create new
    if (file.exists(saved_path)) {
      saved_searches <- readRDS(saved_path)
    } else {
      saved_searches <- list()
    }
    
    # Add new saved search
    saved_entry <- list(
      name = search_name,
      created_at = Sys.time(),
      search_text = search_params$search_text,
      document_types = search_params$document_types,
      states = search_params$states,
      date_from = search_params$date_from,
      date_to = search_params$date_to
    )
    
    # Save with name as key
    saved_searches[[search_name]] <- saved_entry
    
    # Save updated list
    saveRDS(saved_searches, saved_path)
    
    return(TRUE)
    
  }, error = function(e) {
    cat("Error saving saved search:", e$message, "\n")
    return(FALSE)
  })
}

#' Get saved searches for a session
#' @param session_id Session identifier
#' @return List of saved searches
get_saved_searches <- function(session_id) {
  saved_file <- paste0("saved_searches_", session_id, ".rds")
  saved_path <- file.path("data", saved_file)
  
  tryCatch({
    if (file.exists(saved_path)) {
      saved_searches <- readRDS(saved_path)
      return(saved_searches)
    } else {
      return(list())
    }
  }, error = function(e) {
    cat("Error loading saved searches:", e$message, "\n")
    return(list())
  })
}

#' Delete a saved search
#' @param search_name Name of the saved search to delete
#' @param session_id Session identifier
#' @return TRUE if successful, FALSE otherwise
delete_saved_search <- function(search_name, session_id) {
  saved_file <- paste0("saved_searches_", session_id, ".rds")
  saved_path <- file.path("data", saved_file)
  
  tryCatch({
    if (file.exists(saved_path)) {
      saved_searches <- readRDS(saved_path)
      
      # Remove the search
      saved_searches[[search_name]] <- NULL
      
      # Save updated list
      saveRDS(saved_searches, saved_path)
      
      return(TRUE)
    } else {
      return(FALSE)
    }
  }, error = function(e) {
    cat("Error deleting saved search:", e$message, "\n")
    return(FALSE)
  })
}

#' Clear search history for a session
#' @param session_id Session identifier
#' @return TRUE if successful, FALSE otherwise
clear_search_history <- function(session_id) {
  history_file <- paste0("search_history_", session_id, ".rds")
  history_path <- file.path("data", history_file)
  
  tryCatch({
    if (file.exists(history_path)) {
      file.remove(history_path)
    }
    return(TRUE)
  }, error = function(e) {
    cat("Error clearing search history:", e$message, "\n")
    return(FALSE)
  })
}

#' Get document counts by state for map visualization
#' @return Data frame with state codes and document counts
get_state_document_counts <- function() {
  if (is.null(db_pool)) {
    return(data.frame(estado = character(), count = numeric()))
  }
  
  tryCatch({
    result <- dbGetQuery(db_pool, "
      SELECT 
        estado,
        COUNT(*) as count
      FROM documents 
      WHERE estado IS NOT NULL AND estado != ''
      GROUP BY estado
      ORDER BY count DESC
    ")
    
    return(result)
    
  }, error = function(e) {
    cat("Error getting state document counts:", e$message, "\n")
    return(data.frame(estado = character(), count = numeric()))
  })
}

#' Close database connection pool
cleanup_database <- function() {
  if (!is.null(db_pool)) {
    poolClose(db_pool)
    db_pool <<- NULL
    cat("Database connection pool closed\n")
  }
}