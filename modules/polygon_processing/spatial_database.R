# SPATIAL DATABASE ENHANCEMENTS - PHASE 1
# Brazilian Legislative Monitoring System - Polygon Processing
# ============================================================================
# 
# Database schema enhancements for municipality-level spatial operations
# Compatible with PostgreSQL and SQLite for Railway deployment
# 
# Features:
# - Municipality spatial association tables
# - Optimized spatial indexes for <2s query response
# - Hierarchical administrative level support (federal/state/municipal)
# - Fallback mechanisms for non-spatial databases
# - Memory-efficient batch operations

library(shiny)
library(dplyr)
library(pool)
library(DBI)
library(dbplyr)

# Load optional spatial database packages
optional_spatial_packages <- c("RPostgreSQL", "RPostgres", "RSQLite")
for (pkg in optional_spatial_packages) {
  tryCatch({
    suppressPackageStartupMessages(library(pkg, character.only = TRUE))
  }, error = function(e) {
    cat("⚠️", pkg, "not available\n")
  })
}

# ============================================================================
# DATABASE SCHEMA DEFINITIONS
# ============================================================================

#' SQL schema for municipality spatial associations
SPATIAL_SCHEMA_SQL <- list(
  
  # Municipality master table
  municipalities = "
    CREATE TABLE IF NOT EXISTS municipalities (
      municipality_code TEXT PRIMARY KEY,
      municipality_name TEXT NOT NULL,
      state_code TEXT NOT NULL,
      region_name TEXT,
      area_km2 REAL,
      population INTEGER,
      latitude REAL,
      longitude REAL,
      geometry TEXT,  -- GeoJSON or WKT format
      ibge_code TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  ",
  
  # Document-municipality spatial associations
  document_municipalities = "
    CREATE TABLE IF NOT EXISTS document_municipalities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      document_id TEXT NOT NULL,
      municipality_code TEXT NOT NULL,
      association_type TEXT DEFAULT 'spatial_join',  -- spatial_join, nearest, manual
      confidence_score REAL DEFAULT 1.0,
      distance_km REAL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (municipality_code) REFERENCES municipalities(municipality_code),
      UNIQUE(document_id, municipality_code)
    );
  ",
  
  # Spatial query cache table
  spatial_query_cache = "
    CREATE TABLE IF NOT EXISTS spatial_query_cache (
      cache_key TEXT PRIMARY KEY,
      query_result TEXT,  -- JSON encoded result
      parameters TEXT,    -- JSON encoded parameters
      result_count INTEGER,
      execution_time_ms INTEGER,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      expires_at TIMESTAMP,
      hit_count INTEGER DEFAULT 0
    );
  ",
  
  # Administrative hierarchy table
  administrative_hierarchy = "
    CREATE TABLE IF NOT EXISTS administrative_hierarchy (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      document_id TEXT NOT NULL,
      federal_level BOOLEAN DEFAULT FALSE,
      state_code TEXT,
      municipality_code TEXT,
      hierarchy_level TEXT CHECK (hierarchy_level IN ('federal', 'state', 'municipal')),
      determined_by TEXT DEFAULT 'automatic',  -- automatic, manual, fallback
      confidence REAL DEFAULT 1.0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  "
)

#' SQL indexes for optimal spatial query performance
SPATIAL_INDEXES_SQL <- list(
  
  # Document-municipality associations
  "CREATE INDEX IF NOT EXISTS idx_document_municipalities_doc_id ON document_municipalities(document_id);",
  "CREATE INDEX IF NOT EXISTS idx_document_municipalities_muni_code ON document_municipalities(municipality_code);",
  "CREATE INDEX IF NOT EXISTS idx_document_municipalities_type ON document_municipalities(association_type);",
  
  # Municipality lookups
  "CREATE INDEX IF NOT EXISTS idx_municipalities_state ON municipalities(state_code);",
  "CREATE INDEX IF NOT EXISTS idx_municipalities_region ON municipalities(region_name);",
  "CREATE INDEX IF NOT EXISTS idx_municipalities_coords ON municipalities(latitude, longitude);",
  
  # Administrative hierarchy
  "CREATE INDEX IF NOT EXISTS idx_admin_hierarchy_doc_id ON administrative_hierarchy(document_id);",
  "CREATE INDEX IF NOT EXISTS idx_admin_hierarchy_level ON administrative_hierarchy(hierarchy_level);",
  "CREATE INDEX IF NOT EXISTS idx_admin_hierarchy_state ON administrative_hierarchy(state_code);",
  
  # Query cache
  "CREATE INDEX IF NOT EXISTS idx_spatial_cache_expires ON spatial_query_cache(expires_at);",
  "CREATE INDEX IF NOT EXISTS idx_spatial_cache_created ON spatial_query_cache(created_at);"
)

# ============================================================================
# DATABASE INITIALIZATION
# ============================================================================

#' Initialize spatial database schema
#' @param pool Database connection pool
#' @param force_recreate Whether to drop and recreate tables
#' @return Boolean indicating success
init_spatial_database <- function(pool, force_recreate = FALSE) {
  tryCatch({
    conn <- poolCheckout(pool)
    on.exit(poolReturn(conn), add = TRUE)
    
    cat("🗄️ Initializing spatial database schema...\n")
    
    # Drop tables if force recreate
    if (force_recreate) {
      drop_tables <- c("document_municipalities", "spatial_query_cache", 
                      "administrative_hierarchy", "municipalities")
      for (table in drop_tables) {
        tryCatch({
          dbExecute(conn, paste("DROP TABLE IF EXISTS", table))
        }, error = function(e) {
          # Ignore drop errors
        })
      }
      cat("🗑️ Existing spatial tables dropped\n")
    }
    
    # Create tables
    for (table_name in names(SPATIAL_SCHEMA_SQL)) {
      sql <- SPATIAL_SCHEMA_SQL[[table_name]]
      tryCatch({
        dbExecute(conn, sql)
        cat("✅ Table created:", table_name, "\n")
      }, error = function(e) {
        cat("❌ Error creating table", table_name, ":", e$message, "\n")
        return(FALSE)
      })
    }
    
    # Create indexes
    for (index_sql in SPATIAL_INDEXES_SQL) {
      tryCatch({
        dbExecute(conn, index_sql)
      }, error = function(e) {
        cat("⚠️ Index creation warning:", e$message, "\n")
      })
    }
    
    cat("✅ Spatial database schema initialized successfully\n")
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Error initializing spatial database:", e$message, "\n")
    return(FALSE)
  })
}

#' Check if spatial database schema exists
#' @param pool Database connection pool
#' @return Boolean indicating if schema exists
check_spatial_schema_exists <- function(pool) {
  tryCatch({
    conn <- poolCheckout(pool)
    on.exit(poolReturn(conn), add = TRUE)
    
    required_tables <- c("municipalities", "document_municipalities", "administrative_hierarchy")
    
    for (table in required_tables) {
      # Check if table exists
      if (inherits(conn, "SQLiteConnection")) {
        result <- dbGetQuery(conn, 
          "SELECT name FROM sqlite_master WHERE type='table' AND name=?", 
          params = list(table))
      } else {
        # PostgreSQL
        result <- dbGetQuery(conn, 
          "SELECT tablename FROM pg_tables WHERE tablename = $1", 
          params = list(table))
      }
      
      if (nrow(result) == 0) {
        return(FALSE)
      }
    }
    
    return(TRUE)
    
  }, error = function(e) {
    cat("⚠️ Error checking spatial schema:", e$message, "\n")
    return(FALSE)
  })
}

# ============================================================================
# MUNICIPALITY DATA MANAGEMENT
# ============================================================================

#' Insert or update municipality data in database
#' @param pool Database connection pool
#' @param municipalities_data Data frame with municipality information
#' @param batch_size Number of municipalities to process at once
#' @return Boolean indicating success
upsert_municipalities <- function(pool, municipalities_data, batch_size = 500) {
  if (nrow(municipalities_data) == 0) {
    cat("⚠️ No municipality data to insert\n")
    return(TRUE)
  }
  
  tryCatch({
    conn <- poolCheckout(pool)
    on.exit(poolReturn(conn), add = TRUE)
    
    # Prepare data with required columns
    prepared_data <- municipalities_data %>%
      mutate(
        municipality_code = as.character(municipality_code %||% paste0(state_code, row_number())),
        municipality_name = as.character(municipality_name %||% "Unknown"),
        state_code = as.character(state_code),
        region_name = as.character(region_name %||% "Unknown"),
        area_km2 = as.numeric(area_km2 %||% 0),
        population = as.integer(population %||% 0),
        latitude = as.numeric(latitude %||% lat %||% 0),
        longitude = as.numeric(longitude %||% lng %||% 0),
        ibge_code = as.character(ibge_code %||% municipality_code),
        geometry = as.character(geometry %||% ""),
        updated_at = Sys.time()
      ) %>%
      select(municipality_code, municipality_name, state_code, region_name,
             area_km2, population, latitude, longitude, geometry, ibge_code, updated_at)
    
    # Process in batches
    total_rows <- nrow(prepared_data)
    batches <- ceiling(total_rows / batch_size)
    
    cat("📊 Upserting", total_rows, "municipalities in", batches, "batches\n")
    
    for (i in 1:batches) {
      start_row <- (i - 1) * batch_size + 1
      end_row <- min(i * batch_size, total_rows)
      batch_data <- prepared_data[start_row:end_row, ]
      
      # Use INSERT OR REPLACE for SQLite, ON CONFLICT for PostgreSQL
      if (inherits(conn, "SQLiteConnection")) {
        sql <- "
          INSERT OR REPLACE INTO municipalities 
          (municipality_code, municipality_name, state_code, region_name, 
           area_km2, population, latitude, longitude, geometry, ibge_code, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "
      } else {
        sql <- "
          INSERT INTO municipalities 
          (municipality_code, municipality_name, state_code, region_name, 
           area_km2, population, latitude, longitude, geometry, ibge_code, updated_at)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
          ON CONFLICT (municipality_code) DO UPDATE SET
            municipality_name = EXCLUDED.municipality_name,
            state_code = EXCLUDED.state_code,
            region_name = EXCLUDED.region_name,
            area_km2 = EXCLUDED.area_km2,
            population = EXCLUDED.population,
            latitude = EXCLUDED.latitude,
            longitude = EXCLUDED.longitude,
            geometry = EXCLUDED.geometry,
            updated_at = EXCLUDED.updated_at
        "
      }
      
      # Execute batch insert
      tryCatch({
        if (inherits(conn, "SQLiteConnection")) {
          # SQLite batch insert
          for (row in 1:nrow(batch_data)) {
            dbExecute(conn, sql, params = as.list(batch_data[row, ]))
          }
        } else {
          # PostgreSQL batch insert (simplified)
          for (row in 1:nrow(batch_data)) {
            dbExecute(conn, sql, params = as.list(batch_data[row, ]))
          }
        }
        
        cat("📈 Batch", i, "/", batches, "completed (", nrow(batch_data), "municipalities)\n")
        
      }, error = function(e) {
        cat("❌ Error processing batch", i, ":", e$message, "\n")
      })
    }
    
    cat("✅ Municipality upsert completed\n")
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Error upserting municipalities:", e$message, "\n")
    return(FALSE)
  })
}

#' Retrieve municipalities by state or region
#' @param pool Database connection pool
#' @param state_codes Vector of state codes to filter by
#' @param region_name Region name to filter by
#' @return Data frame with municipality data
get_municipalities <- function(pool, state_codes = NULL, region_name = NULL) {
  tryCatch({
    conn <- poolCheckout(pool)
    on.exit(poolReturn(conn), add = TRUE)
    
    # Build query with filters
    base_query <- "SELECT * FROM municipalities WHERE 1=1"
    params <- list()
    param_count <- 0
    
    if (!isTRUE(is.null(state_codes)) && length(state_codes) > 0) {
      if (inherits(conn, "SQLiteConnection")) {
        placeholders <- paste(rep("?", length(state_codes)), collapse = ",")
        base_query <- paste(base_query, "AND state_code IN (", placeholders, ")")
        params <- c(params, as.list(state_codes))
      } else {
        # PostgreSQL
        placeholders <- paste0("$", (param_count + 1):(param_count + length(state_codes)), collapse = ",")
        base_query <- paste(base_query, "AND state_code IN (", placeholders, ")")
        params <- c(params, as.list(state_codes))
        param_count <- param_count + length(state_codes)
      }
    }
    
    if (!is.null(region_name)) {
      if (inherits(conn, "SQLiteConnection")) {
        base_query <- paste(base_query, "AND region_name = ?")
      } else {
        param_count <- param_count + 1
        base_query <- paste(base_query, "AND region_name = $", param_count, sep = "")
      }
      params <- c(params, region_name)
    }
    
    # Execute query
    if (length(params) > 0) {
      result <- dbGetQuery(conn, base_query, params = params)
    } else {
      result <- dbGetQuery(conn, base_query)
    }
    
    cat("📍 Retrieved", nrow(result), "municipalities from database\n")
    return(result)
    
  }, error = function(e) {
    cat("❌ Error retrieving municipalities:", e$message, "\n")
    return(data.frame())
  })
}

# ============================================================================
# DOCUMENT-MUNICIPALITY ASSOCIATIONS
# ============================================================================

#' Insert document-municipality spatial associations
#' @param pool Database connection pool
#' @param associations Data frame with document-municipality associations
#' @return Boolean indicating success
insert_document_municipality_associations <- function(pool, associations) {
  if (nrow(associations) == 0) {
    return(TRUE)
  }
  
  tryCatch({
    conn <- poolCheckout(pool)
    on.exit(poolReturn(conn), add = TRUE)
    
    # Prepare data
    prepared_data <- associations %>%
      mutate(
        association_type = as.character(association_type %||% "spatial_join"),
        confidence_score = as.numeric(confidence_score %||% 1.0),
        distance_km = as.numeric(distance_km %||% 0)
      ) %>%
      select(document_id, municipality_code, association_type, confidence_score, distance_km)
    
    # Insert with conflict resolution
    sql <- if (inherits(conn, "SQLiteConnection")) {
      "INSERT OR REPLACE INTO document_municipalities 
       (document_id, municipality_code, association_type, confidence_score, distance_km)
       VALUES (?, ?, ?, ?, ?)"
    } else {
      "INSERT INTO document_municipalities 
       (document_id, municipality_code, association_type, confidence_score, distance_km)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (document_id, municipality_code) DO UPDATE SET
         association_type = EXCLUDED.association_type,
         confidence_score = EXCLUDED.confidence_score,
         distance_km = EXCLUDED.distance_km"
    }
    
    # Execute batch insert
    for (i in 1:nrow(prepared_data)) {
      dbExecute(conn, sql, params = as.list(prepared_data[i, ]))
    }
    
    cat("🔗 Inserted", nrow(prepared_data), "document-municipality associations\n")
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Error inserting associations:", e$message, "\n")
    return(FALSE)
  })
}

#' Get documents with their municipality associations
#' @param pool Database connection pool
#' @param document_ids Vector of document IDs (optional)
#' @param municipality_codes Vector of municipality codes (optional)
#' @return Data frame with document-municipality data
get_documents_with_municipalities <- function(pool, document_ids = NULL, municipality_codes = NULL) {
  tryCatch({
    conn <- poolCheckout(pool)
    on.exit(poolReturn(conn), add = TRUE)
    
    base_query <- "
      SELECT 
        dm.document_id,
        dm.municipality_code,
        dm.association_type,
        dm.confidence_score,
        dm.distance_km,
        m.municipality_name,
        m.state_code,
        m.region_name,
        m.latitude,
        m.longitude
      FROM document_municipalities dm
      JOIN municipalities m ON dm.municipality_code = m.municipality_code
      WHERE 1=1
    "
    
    params <- list()
    
    if (!isTRUE(is.null(document_ids)) && length(document_ids) > 0) {
      placeholders <- paste(rep(if (inherits(conn, "SQLiteConnection")) "?" else paste0("$", 1:length(document_ids)), 
                               length(document_ids)), collapse = ",")
      base_query <- paste(base_query, "AND dm.document_id IN (", placeholders, ")")
      params <- c(params, as.list(document_ids))
    }
    
    if (!isTRUE(is.null(municipality_codes)) && length(municipality_codes) > 0) {
      start_param <- length(params) + 1
      if (inherits(conn, "SQLiteConnection")) {
        placeholders <- paste(rep("?", length(municipality_codes)), collapse = ",")
      } else {
        placeholders <- paste0("$", start_param:(start_param + length(municipality_codes) - 1), collapse = ",")
      }
      base_query <- paste(base_query, "AND dm.municipality_code IN (", placeholders, ")")
      params <- c(params, as.list(municipality_codes))
    }
    
    # Execute query
    if (length(params) > 0) {
      result <- dbGetQuery(conn, base_query, params = params)
    } else {
      result <- dbGetQuery(conn, base_query)
    }
    
    return(result)
    
  }, error = function(e) {
    cat("❌ Error retrieving document-municipality associations:", e$message, "\n")
    return(data.frame())
  })
}

# ============================================================================
# QUERY CACHING SYSTEM
# ============================================================================

#' Cache spatial query results
#' @param pool Database connection pool
#' @param cache_key Unique key for the query
#' @param result_data Query result to cache
#' @param parameters Query parameters
#' @param ttl_minutes Time-to-live in minutes
#' @return Boolean indicating success
cache_spatial_query <- function(pool, cache_key, result_data, parameters = list(), ttl_minutes = 30) {
  tryCatch({
    conn <- poolCheckout(pool)
    on.exit(poolReturn(conn), add = TRUE)
    
    expires_at <- Sys.time() + (ttl_minutes * 60)
    result_json <- jsonlite::toJSON(result_data, auto_unbox = TRUE)
    params_json <- jsonlite::toJSON(parameters, auto_unbox = TRUE)
    
    sql <- if (inherits(conn, "SQLiteConnection")) {
      "INSERT OR REPLACE INTO spatial_query_cache 
       (cache_key, query_result, parameters, result_count, expires_at)
       VALUES (?, ?, ?, ?, ?)"
    } else {
      "INSERT INTO spatial_query_cache 
       (cache_key, query_result, parameters, result_count, expires_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (cache_key) DO UPDATE SET
         query_result = EXCLUDED.query_result,
         parameters = EXCLUDED.parameters,
         result_count = EXCLUDED.result_count,
         expires_at = EXCLUDED.expires_at"
    }
    
    dbExecute(conn, sql, params = list(
      cache_key, result_json, params_json, nrow(result_data), expires_at
    ))
    
    return(TRUE)
    
  }, error = function(e) {
    cat("⚠️ Error caching query:", e$message, "\n")
    return(FALSE)
  })
}

#' Retrieve cached spatial query results
#' @param pool Database connection pool
#' @param cache_key Unique key for the query
#' @return Cached query result or NULL if not found/expired
get_cached_spatial_query <- function(pool, cache_key) {
  tryCatch({
    conn <- poolCheckout(pool)
    on.exit(poolReturn(conn), add = TRUE)
    
    sql <- "SELECT query_result, hit_count FROM spatial_query_cache 
            WHERE cache_key = ? AND expires_at > ? "
    
    if (inherits(conn, "SQLiteConnection")) {
      result <- dbGetQuery(conn, sql, params = list(cache_key, Sys.time()))
    } else {
      sql <- gsub("\\?", "$1", sql)
      sql <- gsub("\\?", "$2", sql)
      result <- dbGetQuery(conn, sql, params = list(cache_key, Sys.time()))
    }
    
    if (nrow(result) > 0) {
      # Update hit count
      update_sql <- if (inherits(conn, "SQLiteConnection")) {
        "UPDATE spatial_query_cache SET hit_count = hit_count + 1 WHERE cache_key = ?"
      } else {
        "UPDATE spatial_query_cache SET hit_count = hit_count + 1 WHERE cache_key = $1"
      }
      
      dbExecute(conn, update_sql, params = list(cache_key))
      
      # Parse JSON result
      cached_data <- jsonlite::fromJSON(result$query_result[1])
      return(cached_data)
    }
    
    return(NULL)
    
  }, error = function(e) {
    cat("⚠️ Error retrieving cached query:", e$message, "\n")
    return(NULL)
  })
}

# ============================================================================
# MODULE EXPORTS
# ============================================================================

spatial_database_exports <- list(
  # Schema management
  init_spatial_database = init_spatial_database,
  check_spatial_schema_exists = check_spatial_schema_exists,
  
  # Municipality data
  upsert_municipalities = upsert_municipalities,
  get_municipalities = get_municipalities,
  
  # Document associations
  insert_document_municipality_associations = insert_document_municipality_associations,
  get_documents_with_municipalities = get_documents_with_municipalities,
  
  # Query caching
  cache_spatial_query = cache_spatial_query,
  get_cached_spatial_query = get_cached_spatial_query,
  
  # Schema definitions
  SPATIAL_SCHEMA_SQL = SPATIAL_SCHEMA_SQL,
  SPATIAL_INDEXES_SQL = SPATIAL_INDEXES_SQL
)

cat("✅ Spatial Database Module loaded successfully\n")
cat("   PostgreSQL support:", exists("RPostgreSQL") || exists("RPostgres"), "\n")
cat("   SQLite support:", exists("RSQLite"), "\n")
cat("   Schema tables: municipalities, document_municipalities, administrative_hierarchy\n")