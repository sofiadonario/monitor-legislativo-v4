# Database Functions for Monitor Legislativo v4
# PostgreSQL and Redis integration for R architecture

# Source utility functions
source("utils.R")

library(DBI)
library(RPostgres)
library(pool)
library(dplyr)
library(config)

# Global connection pool
.db_pool <- NULL
.redis_connection <- NULL

#' Initialize database connection pool
#' @return TRUE if successful, FALSE otherwise
init_database <- function() {
  
  tryCatch({
    # Get configuration
    config_env <- Sys.getenv("R_CONFIG_ACTIVE", "default")
    app_config <- config::get(config = config_env)
    
    log_event("Initializing database connection pool")
    
    # Create PostgreSQL connection pool
    .db_pool <<- dbPool(
      drv = RPostgres::Postgres(),
      host = app_config$database$host,
      port = app_config$database$port,
      dbname = app_config$database$name,
      user = app_config$database$user,
      password = app_config$database$password,
      minSize = 2,
      maxSize = app_config$database$pool_size %||% 10,
      idleTimeout = 3600  # 1 hour
      # validationQuery not supported by pool package
    )
    
    # Test connection
    test_query <- dbGetQuery(.db_pool, "SELECT version()")
    log_event(paste("Database connected:", substr(test_query$version[1], 1, 50)))
    
    # Initialize Redis connection if available
    init_redis()
    
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Database initialization failed:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Initialize Redis connection for caching
#' @return TRUE if successful, FALSE otherwise
init_redis <- function() {
  
  # Check if Redis packages are available
  if (!require_package("redux", quiet = TRUE)) {
    log_event("Redis package not available, using memory cache", "WARN")
    return(FALSE)
  }
  
  tryCatch({
    # Get configuration
    config_env <- Sys.getenv("R_CONFIG_ACTIVE", "default")
    app_config <- config::get(config = config_env)
    
    log_event("Initializing Redis connection")
    
    # Create Redis connection
    redis_config <- redux::redis_config(
      host = app_config$cache$host %||% "localhost",
      port = app_config$cache$port %||% 6379,
      password = app_config$cache$password
    )
    
    .redis_connection <<- redux::hiredis(redis_config)
    
    # Test connection
    .redis_connection$PING()
    log_event("Redis connected successfully")
    
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Redis initialization failed:", e$message), "WARN")
    .redis_connection <<- NULL
    return(FALSE)
  })
}

#' Get cached data from Redis or memory
#' @param key Cache key
#' @return Cached data or NULL
get_cache <- function(key) {
  
  if (!is.null(.redis_connection)) {
    tryCatch({
      cached_data <- .redis_connection$GET(key)
      if (!is.null(cached_data)) {
        return(unserialize(cached_data))
      }
    }, error = function(e) {
      log_event(paste("Redis cache read error:", e$message), "WARN")
    })
  }
  
  # Fallback to memory cache
  if (exists(".memory_cache", envir = globalenv())) {
    memory_cache <- get(".memory_cache", envir = globalenv())
    if (key %in% names(memory_cache)) {
      cache_entry <- memory_cache[[key]]
      
      # Check if cache entry is still valid
      if (Sys.time() < cache_entry$expires) {
        return(cache_entry$data)
      } else {
        # Remove expired entry
        memory_cache[[key]] <- NULL
        assign(".memory_cache", memory_cache, envir = globalenv())
      }
    }
  }
  
  return(NULL)
}

#' Set cached data in Redis or memory
#' @param key Cache key
#' @param data Data to cache
#' @param ttl Time to live in seconds
set_cache <- function(key, data, ttl = 3600) {
  
  if (!is.null(.redis_connection)) {
    tryCatch({
      serialized_data <- serialize(data, NULL)
      .redis_connection$SETEX(key, ttl, serialized_data)
      return(TRUE)
    }, error = function(e) {
      log_event(paste("Redis cache write error:", e$message), "WARN")
    })
  }
  
  # Fallback to memory cache
  if (!exists(".memory_cache", envir = globalenv())) {
    assign(".memory_cache", list(), envir = globalenv())
  }
  
  memory_cache <- get(".memory_cache", envir = globalenv())
  memory_cache[[key]] <- list(
    data = data,
    expires = Sys.time() + ttl
  )
  assign(".memory_cache", memory_cache, envir = globalenv())
  
  return(TRUE)
}

#' Clear cache (Redis and memory)
#' @param pattern Optional pattern to match keys (for memory cache only)
clear_cache <- function(pattern = NULL) {
  
  cleared_count <- 0
  
  # Clear Redis cache
  if (!is.null(.redis_connection)) {
    tryCatch({
      if (is.null(pattern)) {
        keys <- .redis_connection$KEYS("monitor_legislativo:*")
      } else {
        keys <- .redis_connection$KEYS(paste0("monitor_legislativo:", pattern, "*"))
      }
      
      if (length(keys) > 0) {
        .redis_connection$DEL(keys)
        cleared_count <- cleared_count + length(keys)
      }
    }, error = function(e) {
      log_event(paste("Redis cache clear error:", e$message), "WARN")
    })
  }
  
  # Clear memory cache
  if (exists(".memory_cache", envir = globalenv())) {
    memory_cache <- get(".memory_cache", envir = globalenv())
    
    if (is.null(pattern)) {
      cleared_count <- cleared_count + length(memory_cache)
      assign(".memory_cache", list(), envir = globalenv())
    } else {
      keys_to_remove <- names(memory_cache)[grepl(pattern, names(memory_cache))]
      for (key in keys_to_remove) {
        memory_cache[[key]] <- NULL
      }
      cleared_count <- cleared_count + length(keys_to_remove)
      assign(".memory_cache", memory_cache, envir = globalenv())
    }
  }
  
  log_event(paste("Cleared", cleared_count, "cache entries"))
  return(cleared_count)
}

#' Load legislative data from database
#' @param filters List of filters to apply
#' @param limit Maximum number of records
#' @return Data frame with legislative data
load_legislative_data <- function(filters = list(), limit = 1000) {
  
  if (is.null(.db_pool)) {
    log_event("Database not initialized", "ERROR")
    return(NULL)
  }
  
  # Create cache key
  cache_key <- paste0("monitor_legislativo:search:", digest::digest(filters))
  
  # Check cache first
  cached_data <- get_cache(cache_key)
  if (!is.null(cached_data)) {
    log_event("Returning cached search results")
    return(cached_data)
  }
  
  tryCatch({
    # Build SQL query
    base_query <- "
      SELECT 
        titulo, tipo, numero, data, estado, municipio, autor, fonte, 
        ementa, url, created_at as data_coleta
      FROM documents 
      WHERE 1=1
    "
    
    params <- list()
    where_clauses <- c()
    
    # Add filters
    if (!is.null(filters$search_text) && filters$search_text != "") {
      where_clauses <- c(where_clauses, 
        "(titulo ILIKE ? OR ementa ILIKE ?)")
      search_pattern <- paste0("%", filters$search_text, "%")
      params <- c(params, search_pattern, search_pattern)
    }
    
    if (!is.null(filters$date_from)) {
      where_clauses <- c(where_clauses, "data >= ?")
      params <- c(params, filters$date_from)
    }
    
    if (!is.null(filters$date_to)) {
      where_clauses <- c(where_clauses, "data <= ?")
      params <- c(params, filters$date_to)
    }
    
    if (!is.null(filters$tipo) && length(filters$tipo) > 0) {
      placeholders <- paste(rep("?", length(filters$tipo)), collapse = ",")
      where_clauses <- c(where_clauses, paste0("tipo IN (", placeholders, ")"))
      params <- c(params, filters$tipo)
    }
    
    if (!is.null(filters$estado) && length(filters$estado) > 0) {
      placeholders <- paste(rep("?", length(filters$estado)), collapse = ",")
      where_clauses <- c(where_clauses, paste0("estado IN (", placeholders, ")"))
      params <- c(params, filters$estado)
    }
    
    # Combine query
    if (length(where_clauses) > 0) {
      final_query <- paste(base_query, "AND", paste(where_clauses, collapse = " AND "))
    } else {
      final_query <- base_query
    }
    
    # Add ordering and limit
    final_query <- paste(final_query, "ORDER BY data DESC LIMIT ?")
    params <- c(params, limit)
    
    # Execute query
    log_event("Executing database query")
    result <- dbGetQuery(.db_pool, final_query, params = params)
    
    if (nrow(result) > 0) {
      # Standardize and validate data
      result <- standardize_columns(result)
      result <- validate_data_quality(result)
      
      # Cache results
      config_env <- Sys.getenv("R_CONFIG_ACTIVE", "default")
      app_config <- config::get(config = config_env)
      ttl <- app_config$cache$ttl_search %||% 1800
      
      set_cache(cache_key, result, ttl)
      
      log_event(paste("Loaded", nrow(result), "documents from database"))
      return(result)
    } else {
      log_event("No documents found in database")
      return(NULL)
    }
    
  }, error = function(e) {
    log_event(paste("Database query error:", e$message), "ERROR")
    return(NULL)
  })
}

#' Save legislative data to database
#' @param data Data frame with legislative data
#' @param table_name Target table name
#' @return TRUE if successful, FALSE otherwise
save_legislative_data <- function(data, table_name = "documents") {
  
  if (is.null(.db_pool) || is.null(data) || nrow(data) == 0) {
    return(FALSE)
  }
  
  tryCatch({
    log_event(paste("Saving", nrow(data), "documents to database"))
    
    # Prepare data for insertion
    data$created_at <- Sys.time()
    data$updated_at <- Sys.time()
    
    # Remove any existing quality_score column for database storage
    if ("quality_score" %in% names(data)) {
      data$quality_score <- NULL
    }
    
    # Use upsert to handle duplicates
    dbWriteTable(.db_pool, table_name, data, 
                append = TRUE, row.names = FALSE)
    
    # Clear related cache
    clear_cache("search:")
    
    log_event("Data saved successfully")
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Database save error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Get database statistics
#' @return List with database statistics
get_database_stats <- function() {
  
  if (is.null(.db_pool)) {
    return(NULL)
  }
  
  # Check cache first
  cache_key <- "monitor_legislativo:stats:database"
  cached_stats <- get_cache(cache_key)
  if (!is.null(cached_stats)) {
    return(cached_stats)
  }
  
  tryCatch({
    # Total documents
    total_docs <- dbGetQuery(.db_pool, "SELECT COUNT(*) as count FROM documents")$count[1]
    
    # Unique states
    unique_states <- dbGetQuery(.db_pool, 
      "SELECT COUNT(DISTINCT estado) as count FROM documents WHERE estado IS NOT NULL")$count[1]
    
    # Unique document types
    unique_types <- dbGetQuery(.db_pool, 
      "SELECT COUNT(DISTINCT tipo) as count FROM documents WHERE tipo IS NOT NULL")$count[1]
    
    # Date range
    date_range <- dbGetQuery(.db_pool, 
      "SELECT MIN(data) as min_date, MAX(data) as max_date FROM documents WHERE data IS NOT NULL")
    
    # Most recent update
    last_update <- dbGetQuery(.db_pool, 
      "SELECT MAX(created_at) as last_update FROM documents")$last_update[1]
    
    stats <- list(
      total_documents = total_docs,
      unique_states = unique_states,
      unique_types = unique_types,
      oldest_document = if (!is.na(date_range$min_date[1])) format(date_range$min_date[1], "%d/%m/%Y") else "N/A",
      newest_document = if (!is.na(date_range$max_date[1])) format(date_range$max_date[1], "%d/%m/%Y") else "N/A",
      last_update = if (!is.na(last_update)) format(last_update, "%d/%m/%Y %H:%M") else "N/A"
    )
    
    # Cache for 5 minutes
    set_cache(cache_key, stats, 300)
    
    return(stats)
    
  }, error = function(e) {
    log_event(paste("Database stats error:", e$message), "ERROR")
    return(NULL)
  })
}

#' Load geographic data for Brazilian states and municipalities
#' @return SF object with geographic boundaries
load_geographic_data <- function() {
  
  # Check cache first
  cache_key <- "monitor_legislativo:geo:brazil"
  cached_geo <- get_cache(cache_key)
  if (!is.null(cached_geo)) {
    return(cached_geo)
  }
  
  tryCatch({
    log_event("Loading Brazilian geographic data")
    
    # Try to load from geobr package if available
    if (require_package("geobr", quiet = TRUE)) {
      
      # Load states
      states_geo <- geobr::read_state(year = 2020, showProgress = FALSE)
      
      # Load municipalities (this can be large, so we might want to load on demand)
      # municipalities_geo <- geobr::read_municipality(year = 2020, showProgress = FALSE)
      
      geo_data <- list(
        states = states_geo,
        # municipalities = municipalities_geo,
        loaded_at = Sys.time()
      )
      
      # Cache for 24 hours
      config_env <- Sys.getenv("R_CONFIG_ACTIVE", "default")
      app_config <- config::get(config = config_env)
      ttl <- app_config$cache$ttl_geo %||% 86400
      
      set_cache(cache_key, geo_data, ttl)
      
      log_event("Geographic data loaded successfully")
      return(geo_data)
      
    } else {
      log_event("geobr package not available", "WARN")
      return(NULL)
    }
    
  }, error = function(e) {
    log_event(paste("Geographic data loading error:", e$message), "ERROR")
    return(NULL)
  })
}

#' Create database tables if they don't exist
#' @return TRUE if successful
setup_database_schema <- function() {
  
  if (is.null(.db_pool)) {
    log_event("Database not initialized", "ERROR")
    return(FALSE)
  }
  
  tryCatch({
    log_event("Setting up database schema")
    
    # Create documents table
    documents_schema <- "
      CREATE TABLE IF NOT EXISTS documents (
        id SERIAL PRIMARY KEY,
        titulo TEXT NOT NULL,
        tipo VARCHAR(100),
        numero VARCHAR(50),
        data DATE,
        estado VARCHAR(2),
        municipio VARCHAR(100),
        autor TEXT,
        fonte VARCHAR(100),
        ementa TEXT,
        url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    "
    
    dbExecute(.db_pool, documents_schema)
    
    # Create indexes for better performance
    indexes <- c(
      "CREATE INDEX IF NOT EXISTS idx_documents_data ON documents(data);",
      "CREATE INDEX IF NOT EXISTS idx_documents_estado ON documents(estado);",
      "CREATE INDEX IF NOT EXISTS idx_documents_tipo ON documents(tipo);",
      "CREATE INDEX IF NOT EXISTS idx_documents_titulo ON documents USING gin(to_tsvector('portuguese', titulo));",
      "CREATE INDEX IF NOT EXISTS idx_documents_ementa ON documents USING gin(to_tsvector('portuguese', ementa));"
    )
    
    for (index_sql in indexes) {
      dbExecute(.db_pool, index_sql)
    }
    
    # Create cache management table
    cache_schema <- "
      CREATE TABLE IF NOT EXISTS cache_entries (
        key VARCHAR(255) PRIMARY KEY,
        data BYTEA,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    "
    
    dbExecute(.db_pool, cache_schema)
    
    log_event("Database schema setup completed")
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Database schema setup error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Close database connections
close_database <- function() {
  
  if (!is.null(.db_pool)) {
    tryCatch({
      poolClose(.db_pool)
      .db_pool <<- NULL
      log_event("Database pool closed")
    }, error = function(e) {
      log_event(paste("Error closing database pool:", e$message), "WARN")
    })
  }
  
  if (!is.null(.redis_connection)) {
    tryCatch({
      .redis_connection$disconnect()
      .redis_connection <<- NULL
      log_event("Redis connection closed")
    }, error = function(e) {
      log_event(paste("Error closing Redis connection:", e$message), "WARN")
    })
  }
}