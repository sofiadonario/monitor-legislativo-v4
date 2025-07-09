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
      warning("DATABASE_URL not found in environment variables")
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
    db_pool <<- dbPool(
      drv = RPostgres::Postgres(),
      host = parsed_url$host,
      port = parsed_url$port,
      dbname = parsed_url$database,
      user = parsed_url$user,
      password = parsed_url$password,
      minSize = 1,
      maxSize = 5,
      idleTimeout = 3600000  # 1 hour
    )
    
    # Test connection
    test_result <- test_database_connection()
    if (test_result) {
      cat("✅ Database connection successful!\n")
      return(TRUE)
    } else {
      cat("❌ Database connection test failed\n")
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
    return(FALSE)
  }
  
  tryCatch({
    # Test basic connection
    conn <- poolCheckout(db_pool)
    on.exit(poolReturn(conn))
    
    # Check if our tables exist
    tables <- dbListTables(conn)
    cat("Available tables:", paste(tables, collapse = ", "), "\n")
    
    required_tables <- c("lexml_parsed_enhanced", "documents", "legislative_data")
    missing_tables <- setdiff(required_tables, tables)
    
    if (length(missing_tables) > 0) {
      cat("⚠️ Missing tables:", paste(missing_tables, collapse = ", "), "\n")
      return(FALSE)
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

#' Search documents by text
#' @param search_text Text to search for
#' @param limit Maximum number of results
#' @return Data frame with search results
search_documents <- function(search_text = "", limit = 100) {
  if (is.null(db_pool)) {
    warning("Database not initialized")
    return(NULL)
  }
  
  tryCatch({
    if (nchar(search_text) == 0) {
      return(get_documents(limit))
    }
    
    # Simple text search (can be enhanced later)
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
      WHERE (titulo ILIKE $1 OR conteudo ILIKE $1)
      ORDER BY data_publicacao DESC NULLS LAST
      LIMIT $2
    "
    
    search_pattern <- paste0("%", search_text, "%")
    result <- dbGetQuery(db_pool, query, params = list(search_pattern, limit))
    
    # Clean up the data
    if (nrow(result) > 0) {
      if ("data_publicacao" %in% names(result)) {
        result$data_publicacao <- as.Date(result$data_publicacao)
      }
      result[is.na(result)] <- ""
      
      cat("Search for '", search_text, "' returned", nrow(result), "documents\n")
    }
    
    return(result)
    
  }, error = function(e) {
    cat("Error searching documents:", e$message, "\n")
    return(NULL)
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

#' Close database connection pool
cleanup_database <- function() {
  if (!is.null(db_pool)) {
    poolClose(db_pool)
    db_pool <<- NULL
    cat("Database connection pool closed\n")
  }
}