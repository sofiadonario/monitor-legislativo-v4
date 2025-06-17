# Database Module for Caching Legislative Data
# Uses SQLite for local storage and caching

library(DBI)
library(RSQLite)
library(dplyr)
library(futile.logger)

# Global database connection
.db_connection <- new.env()

# Security and validation functions
#' Validate and sanitize database inputs
#' @param input Input value to validate
#' @param type Expected type ('string', 'date', 'numeric', 'list')
#' @param max_length Maximum length for strings
#' @return Validated and sanitized input
validate_db_input <- function(input, type = "string", max_length = 1000) {
  
  if (is.null(input)) {
    return(NULL)
  }
  
  switch(type,
    "string" = {
      if (!is.character(input)) {
        stop("Invalid input: expected character string")
      }
      # Sanitize string input
      sanitized <- gsub("[<>\"'&]", "", input)  # Remove potentially dangerous characters
      if (nchar(sanitized) > max_length) {
        sanitized <- substr(sanitized, 1, max_length)
      }
      return(sanitized)
    },
    "date" = {
      if (!inherits(input, c("Date", "POSIXct", "POSIXt"))) {
        tryCatch({
          return(as.Date(input))
        }, error = function(e) {
          stop("Invalid date format")
        })
      }
      return(input)
    },
    "numeric" = {
      if (!is.numeric(input)) {
        tryCatch({
          return(as.numeric(input))
        }, error = function(e) {
          stop("Invalid numeric input")
        })
      }
      return(input)
    },
    "list" = {
      if (!is.list(input) && !is.vector(input)) {
        stop("Invalid input: expected list or vector")
      }
      # Validate each element
      sanitized_list <- lapply(input, function(x) {
        validate_db_input(x, "string", max_length)
      })
      return(sanitized_list)
    },
    stop("Unknown validation type")
  )
}

#' Check for SQL injection patterns
#' @param input String to check
#' @return TRUE if safe, FALSE if suspicious
is_safe_input <- function(input) {
  if (is.null(input)) return(TRUE)
  
  # Check for common SQL injection patterns
  dangerous_patterns <- c(
    "(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)",
    "(?i)(script|javascript|vbscript)",
    "(?i)(onload|onerror|onclick)",
    "--",
    "/\\*",
    "\\*/"
  )
  
  for (pattern in dangerous_patterns) {
    if (grepl(pattern, input, perl = TRUE)) {
      flog.warn("Suspicious input detected: %s", substr(input, 1, 50))
      return(FALSE)
    }
  }
  
  return(TRUE)
}

#' Initialize database and create tables
#' @param db_path Path to SQLite database file
#' @return TRUE if successful, FALSE otherwise
init_database <- function(db_path = "data/legislative.db") {
  
  flog.info("Initializing database: %s", db_path)
  
  # Ensure data directory exists
  dir.create(dirname(db_path), showWarnings = FALSE, recursive = TRUE)
  
  tryCatch({
    # Create connection
    con <- dbConnect(SQLite(), db_path)
    
    # Enable foreign keys
    dbExecute(con, "PRAGMA foreign_keys = ON")
    
    # Create tables
    create_tables(con)
    
    # Store connection globally
    .db_connection$con <- con
    
    flog.info("Database initialized successfully")
    return(TRUE)
    
  }, error = function(e) {
    flog.error("Error initializing database: %s", e$message)
    return(FALSE)
  })
}

#' Create database tables
#' @param con Database connection
create_tables <- function(con) {
  
  # Main legislative documents table
  legislative_table <- "
  CREATE TABLE IF NOT EXISTS legislative_documents (
    id_unico TEXT PRIMARY KEY,
    titulo TEXT NOT NULL,
    tipo TEXT,
    numero TEXT,
    data DATE,
    ano INTEGER,
    resumo TEXT,
    autor TEXT,
    status TEXT,
    estado TEXT,
    municipio TEXT,
    nivel_governo TEXT,
    fonte_original TEXT,
    url TEXT,
    citacao TEXT,
    palavras_chave TEXT,
    dias_desde_publicacao INTEGER,
    data_processamento TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )"
  
  # API cache table for storing raw API responses
  api_cache_table <- "
  CREATE TABLE IF NOT EXISTS api_cache (
    cache_key TEXT PRIMARY KEY,
    endpoint TEXT NOT NULL,
    params TEXT,
    response_data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    status TEXT DEFAULT 'valid'
  )"
  
  # Data source tracking table
  sources_table <- "
  CREATE TABLE IF NOT EXISTS data_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name TEXT NOT NULL,
    endpoint TEXT,
    last_update TIMESTAMP,
    total_records INTEGER DEFAULT 0,
    success_rate REAL DEFAULT 0.0,
    status TEXT DEFAULT 'active'
  )"
  
  # Search queries log
  search_log_table <- "
  CREATE TABLE IF NOT EXISTS search_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    query_text TEXT,
    filters TEXT,
    results_count INTEGER,
    execution_time REAL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )"
  
  # Export history
  export_history_table <- "
  CREATE TABLE IF NOT EXISTS export_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    format TEXT NOT NULL,
    filename TEXT,
    records_count INTEGER,
    file_size INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )"
  
  # Execute table creation
  dbExecute(con, legislative_table)
  dbExecute(con, api_cache_table)
  dbExecute(con, sources_table)
  dbExecute(con, search_log_table)
  dbExecute(con, export_history_table)
  
  # Create indexes for better performance
  create_indexes(con)
  
  flog.info("Database tables created successfully")
}

#' Create database indexes
#' @param con Database connection
create_indexes <- function(con) {
  
  indexes <- c(
    "CREATE INDEX IF NOT EXISTS idx_legislative_estado ON legislative_documents(estado)",
    "CREATE INDEX IF NOT EXISTS idx_legislative_data ON legislative_documents(data)",
    "CREATE INDEX IF NOT EXISTS idx_legislative_tipo ON legislative_documents(tipo)",
    "CREATE INDEX IF NOT EXISTS idx_legislative_fonte ON legislative_documents(fonte_original)",
    "CREATE INDEX IF NOT EXISTS idx_cache_endpoint ON api_cache(endpoint)",
    "CREATE INDEX IF NOT EXISTS idx_cache_expires ON api_cache(expires_at)"
  )
  
  for (index in indexes) {
    dbExecute(con, index)
  }
  
  flog.info("Database indexes created")
}

#' Save legislative data to database
#' @param data Data frame with legislative documents
#' @param overwrite Whether to overwrite existing records
#' @return Number of records saved
save_legislative_data <- function(data, overwrite = FALSE) {
  
  if (is.null(data) || nrow(data) == 0) {
    flog.warn("No data to save")
    return(0)
  }
  
  if (is.null(.db_connection$con)) {
    flog.error("Database not initialized")
    return(0)
  }
  
  flog.info("Saving %d legislative records to database", nrow(data))
  
  tryCatch({
    con <- .db_connection$con
    
    # Prepare data for insertion
    insert_data <- data %>%
      mutate(
        # Ensure all required columns exist
        id_unico = coalesce(id_unico, paste0("auto_", row_number())),
        data_processamento = coalesce(data_processamento, Sys.time()),
        updated_at = Sys.time()
      ) %>%
      select(
        id_unico, titulo, tipo, numero, data, ano, resumo, autor, status,
        estado, municipio, nivel_governo, fonte_original, url, citacao,
        palavras_chave, dias_desde_publicacao, data_processamento
      )
    
    # Use upsert approach if overwrite is TRUE
    if (overwrite) {
      # Delete existing records with same IDs using parameterized query
      if (nrow(insert_data) > 0) {
        placeholders <- paste(rep("?", nrow(insert_data)), collapse = ",")
        delete_query <- paste0("DELETE FROM legislative_documents WHERE id_unico IN (", placeholders, ")")
        dbExecute(con, delete_query, as.list(insert_data$id_unico))
      }
    }
    
    # Insert new records
    dbWriteTable(con, "legislative_documents", insert_data, append = TRUE)
    
    # Update source tracking
    update_source_tracking(data)
    
    flog.info("Successfully saved %d records", nrow(insert_data))
    return(nrow(insert_data))
    
  }, error = function(e) {
    flog.error("Error saving legislative data: %s", e$message)
    return(0)
  })
}

#' Load legislative data from database
#' @param filters List of filters to apply
#' @param limit Maximum number of records to return
#' @return Data frame with legislative documents
load_legislative_data <- function(filters = list(), limit = NULL) {
  
  if (is.null(.db_connection$con)) {
    flog.error("Database not initialized")
    return(NULL)
  }
  
  # Validate and sanitize all filter inputs
  if (!is.null(filters$estado)) {
    filters$estado <- validate_db_input(filters$estado, "list")
    if (!all(sapply(filters$estado, is_safe_input))) {
      flog.error("Unsafe input detected in estado filter")
      return(NULL)
    }
  }
  
  if (!is.null(filters$tipo)) {
    filters$tipo <- validate_db_input(filters$tipo, "list")
    if (!all(sapply(filters$tipo, is_safe_input))) {
      flog.error("Unsafe input detected in tipo filter")
      return(NULL)
    }
  }
  
  if (!is.null(filters$search_text)) {
    filters$search_text <- validate_db_input(filters$search_text, "string", 500)
    if (!is_safe_input(filters$search_text)) {
      flog.error("Unsafe input detected in search text")
      return(NULL)
    }
  }
  
  if (!is.null(filters$date_from)) {
    filters$date_from <- validate_db_input(filters$date_from, "date")
  }
  
  if (!is.null(filters$date_to)) {
    filters$date_to <- validate_db_input(filters$date_to, "date")
  }
  
  if (!is.null(limit)) {
    limit <- validate_db_input(limit, "numeric")
    if (limit < 1 || limit > 10000) {
      flog.warn("Invalid limit value, using default 1000")
      limit <- 1000
    }
  }
  
  flog.info("Loading legislative data with validated filters")
  
  tryCatch({
    con <- .db_connection$con
    
    # Build query
    query <- "SELECT * FROM legislative_documents WHERE 1=1"
    params <- list()
    
    # Apply filters using parameterized queries
    if (!is.null(filters$estado) && length(filters$estado) > 0) {
      placeholders_estado <- paste(rep("?", length(filters$estado)), collapse = ",")
      query <- paste(query, "AND estado IN (", placeholders_estado, ")")
      params <- append(params, as.list(filters$estado))
    }
    
    if (!is.null(filters$tipo) && length(filters$tipo) > 0) {
      placeholders_tipo <- paste(rep("?", length(filters$tipo)), collapse = ",")
      query <- paste(query, "AND tipo IN (", placeholders_tipo, ")")
      params <- append(params, as.list(filters$tipo))
    }
    
    if (!is.null(filters$date_from)) {
      query <- paste(query, "AND data >= ?")
      params <- append(params, filters$date_from)
    }
    
    if (!is.null(filters$date_to)) {
      query <- paste(query, "AND data <= ?")
      params <- append(params, filters$date_to)
    }
    
    if (!is.null(filters$search_text)) {
      query <- paste(query, "AND (titulo LIKE ? OR resumo LIKE ?)")
      search_term <- paste0("%", filters$search_text, "%")
      params <- append(params, list(search_term, search_term))
    }
    
    # Add ordering and limit
    query <- paste(query, "ORDER BY data DESC")
    
    if (!is.null(limit)) {
      query <- paste(query, "LIMIT", limit)
    }
    
    # Execute query
    if (length(params) > 0) {
      result <- dbGetQuery(con, query, params)
    } else {
      result <- dbGetQuery(con, query)
    }
    
    # Log search query
    log_search_query(filters, nrow(result))
    
    flog.info("Loaded %d records from database", nrow(result))
    return(result)
    
  }, error = function(e) {
    flog.error("Error loading legislative data: %s", e$message)
    return(NULL)
  })
}

#' Cache API response
#' @param endpoint API endpoint
#' @param params Request parameters
#' @param response_data Response data
#' @param expires_hours Hours until cache expires
cache_api_response <- function(endpoint, params, response_data, expires_hours = 24) {
  
  if (is.null(.db_connection$con)) {
    return(FALSE)
  }
  
  tryCatch({
    con <- .db_connection$con
    
    # Create cache key
    cache_key <- create_cache_key(endpoint, params)
    
    # Prepare cache record
    cache_record <- data.frame(
      cache_key = cache_key,
      endpoint = endpoint,
      params = jsonlite::toJSON(params, auto_unbox = TRUE),
      response_data = jsonlite::toJSON(response_data, auto_unbox = TRUE),
      expires_at = Sys.time() + as.difftime(expires_hours, units = "hours"),
      stringsAsFactors = FALSE
    )
    
    # Insert or replace cache record
    dbExecute(con, "DELETE FROM api_cache WHERE cache_key = ?", list(cache_key))
    dbWriteTable(con, "api_cache", cache_record, append = TRUE)
    
    flog.debug("Cached API response for: %s", endpoint)
    return(TRUE)
    
  }, error = function(e) {
    flog.error("Error caching API response: %s", e$message)
    return(FALSE)
  })
}

#' Get cached API response
#' @param endpoint API endpoint
#' @param params Request parameters
#' @return Cached response data or NULL if not found/expired
get_cached_response <- function(endpoint, params) {
  
  if (is.null(.db_connection$con)) {
    return(NULL)
  }
  
  tryCatch({
    con <- .db_connection$con
    
    # Create cache key
    cache_key <- create_cache_key(endpoint, params)
    
    # Query cache
    result <- dbGetQuery(
      con, 
      "SELECT response_data FROM api_cache WHERE cache_key = ? AND expires_at > ? AND status = 'valid'",
      list(cache_key, Sys.time())
    )
    
    if (nrow(result) > 0) {
      flog.debug("Cache hit for: %s", endpoint)
      return(jsonlite::fromJSON(result$response_data[1]))
    } else {
      flog.debug("Cache miss for: %s", endpoint)
      return(NULL)
    }
    
  }, error = function(e) {
    flog.error("Error retrieving cached response: %s", e$message)
    return(NULL)
  })
}

#' Clean expired cache entries
#' @return Number of entries cleaned
clean_cache <- function() {
  
  if (is.null(.db_connection$con)) {
    return(0)
  }
  
  tryCatch({
    con <- .db_connection$con
    
    # Delete expired entries
    result <- dbExecute(con, "DELETE FROM api_cache WHERE expires_at <= ?", list(Sys.time()))
    
    flog.info("Cleaned %d expired cache entries", result)
    return(result)
    
  }, error = function(e) {
    flog.error("Error cleaning cache: %s", e$message)
    return(0)
  })
}

#' Get database statistics
#' @return List with database statistics
get_database_stats <- function() {
  
  if (is.null(.db_connection$con)) {
    return(NULL)
  }
  
  tryCatch({
    con <- .db_connection$con
    
    stats <- list(
      total_documents = dbGetQuery(con, "SELECT COUNT(*) as count FROM legislative_documents")$count,
      unique_states = dbGetQuery(con, "SELECT COUNT(DISTINCT estado) as count FROM legislative_documents WHERE estado IS NOT NULL")$count,
      cache_entries = dbGetQuery(con, "SELECT COUNT(*) as count FROM api_cache WHERE status = 'valid'")$count,
      oldest_document = dbGetQuery(con, "SELECT MIN(data) as date FROM legislative_documents")$date,
      newest_document = dbGetQuery(con, "SELECT MAX(data) as date FROM legislative_documents")$date,
      last_update = dbGetQuery(con, "SELECT MAX(updated_at) as timestamp FROM legislative_documents")$timestamp
    )
    
    return(stats)
    
  }, error = function(e) {
    flog.error("Error getting database stats: %s", e$message)
    return(NULL)
  })
}

#' Helper function to create cache keys
create_cache_key <- function(endpoint, params) {
  key_string <- paste0(endpoint, "_", digest::digest(params))
  return(substr(key_string, 1, 64))  # Limit length
}

#' Update source tracking information
update_source_tracking <- function(data) {
  
  if (is.null(.db_connection$con) || is.null(data)) {
    return(FALSE)
  }
  
  tryCatch({
    con <- .db_connection$con
    
    # Count records by source
    source_counts <- data %>%
      count(fonte_original, name = "records_count")
    
    for (i in 1:nrow(source_counts)) {
      source_name <- source_counts$fonte_original[i]
      record_count <- source_counts$records_count[i]
      
      # Upsert source tracking
      dbExecute(con, "
        INSERT INTO data_sources (source_name, last_update, total_records) 
        VALUES (?, ?, ?)
        ON CONFLICT(source_name) DO UPDATE SET
          last_update = ?,
          total_records = total_records + ?
      ", list(source_name, Sys.time(), record_count, Sys.time(), record_count))
    }
    
    return(TRUE)
    
  }, error = function(e) {
    flog.error("Error updating source tracking: %s", e$message)
    return(FALSE)
  })
}

#' Log search query for analytics
log_search_query <- function(filters, results_count, execution_time = NULL) {
  
  if (is.null(.db_connection$con)) {
    return(FALSE)
  }
  
  tryCatch({
    con <- .db_connection$con
    
    log_record <- data.frame(
      query_text = paste(names(filters), collapse = ","),
      filters = jsonlite::toJSON(filters, auto_unbox = TRUE),
      results_count = results_count,
      execution_time = execution_time %||% NA,
      stringsAsFactors = FALSE
    )
    
    dbWriteTable(con, "search_queries", log_record, append = TRUE)
    return(TRUE)
    
  }, error = function(e) {
    flog.error("Error logging search query: %s", e$message)
    return(FALSE)
  })
}

#' Close database connection
close_database <- function() {
  if (!is.null(.db_connection$con)) {
    dbDisconnect(.db_connection$con)
    .db_connection$con <- NULL
    flog.info("Database connection closed")
  }
}

#' Backup database to file
#' @param backup_path Path for backup file
#' @return TRUE if successful
backup_database <- function(backup_path = NULL) {
  
  if (is.null(backup_path)) {
    timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
    backup_path <- paste0("data/backup_", timestamp, ".db")
  }
  
  if (is.null(.db_connection$con)) {
    return(FALSE)
  }
  
  tryCatch({
    # Simple file copy for SQLite
    current_db <- dbGetInfo(.db_connection$con)$dbname
    file.copy(current_db, backup_path, overwrite = TRUE)
    
    flog.info("Database backed up to: %s", backup_path)
    return(TRUE)
    
  }, error = function(e) {
    flog.error("Error backing up database: %s", e$message)
    return(FALSE)
  })
}