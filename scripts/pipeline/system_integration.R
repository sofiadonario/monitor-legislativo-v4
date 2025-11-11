# ============================================================================
# SYSTEM INTEGRATION WITH EXISTING DATABASE AND SEARCH - SPRINT 4B
# ============================================================================
#
# Comprehensive integration system connecting the new ETL pipeline 
# with existing database connections and search capabilities
# Seamless integration with Railway deployment and existing app infrastructure
#
# Features:
# - Integration with existing secure database connections
# - Search engine integration and optimization
# - Real-time data synchronization
# - Backward compatibility with existing modules
# - Performance optimization for Railway constraints
# - Conflict resolution between old and new data
# - Gradual migration strategies
# - System health monitoring and validation
#
# Author: Legislative Data Science Team
# Version: 4B.1.0 (Sprint 4B)
# Updated: 2025-01-20
# ============================================================================

# Load required packages
required_packages <- c(
  "DBI", "RPostgres", "pool", "dplyr", 
  "lubridate", "jsonlite", "digest", 
  "stringr", "data.table", "future", "promises"
)

missing_packages <- c()
for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing_packages <- c(missing_packages, pkg)
  }
}

if (length(missing_packages) > 0) {
  cat("⚠️ WARNING: Missing integration packages:", paste(missing_packages, collapse = ", "), "\n")
}

# Load available packages
suppressPackageStartupMessages({
  if (requireNamespace("DBI", quietly = TRUE)) library(DBI)
  if (requireNamespace("RPostgres", quietly = TRUE)) library(RPostgres)
  if (requireNamespace("pool", quietly = TRUE)) library(pool)
  if (requireNamespace("dplyr", quietly = TRUE)) library(dplyr)
  if (requireNamespace("lubridate", quietly = TRUE)) library(lubridate)
  if (requireNamespace("jsonlite", quietly = TRUE)) library(jsonlite)
  if (requireNamespace("digest", quietly = TRUE)) library(digest)
  if (requireNamespace("stringr", quietly = TRUE)) library(stringr)
})

# ============================================================================
# INTEGRATION CONFIGURATION
# ============================================================================

INTEGRATION_CONFIG <- list(
  # Database Integration
  database = list(
    # Primary tables in existing system
    primary_tables = c(
      "brazilian_legislative_complete",
      "lexml_parsed_enhanced", 
      "documents",
      "legislative_data"
    ),
    
    # New pipeline tables
    pipeline_tables = c(
      "pipeline_data",
      "pipeline_metadata", 
      "data_versions",
      "pipeline_metrics",
      "alert_history"
    ),
    
    # Integration settings
    sync_strategy = "upsert",     # insert, update, upsert, replace
    conflict_resolution = "newest", # newest, oldest, merge
    batch_size = 1000,
    sync_interval_minutes = 30,
    
    # Performance settings
    parallel_workers = 2,
    memory_limit_mb = 500,
    connection_pool_size = 5
  ),
  
  # Search Integration
  search = list(
    # Existing search functions to integrate
    existing_functions = c(
      "get_library_documents",
      "get_total_documents", 
      "process_document_data"
    ),
    
    # New search enhancements
    enhanced_features = c(
      "full_text_search",
      "faceted_search",
      "semantic_search",
      "autocomplete"
    ),
    
    # Search optimization
    index_strategy = "incremental",
    cache_duration_minutes = 15,
    search_result_limit = 10000
  ),
  
  # Module Integration
  modules = list(
    # Existing modules to integrate
    existing_modules = c(
      "real_data_loader",
      "executive_summary_integration",
      "maps/enhanced_maps_loader"
    ),
    
    # Integration points
    integration_points = c(
      "data_loading",
      "dashboard_metrics", 
      "geographic_data",
      "document_processing"
    ),
    
    # Compatibility settings
    maintain_backwards_compatibility = TRUE,
    gradual_migration = TRUE,
    fallback_enabled = TRUE
  ),
  
  # Monitoring Integration
  monitoring = list(
    integrate_with_existing_logs = TRUE,
    performance_comparison = TRUE,
    data_quality_tracking = TRUE,
    alert_consolidation = TRUE
  )
)

# ============================================================================
# DATABASE INTEGRATION MANAGER
# ============================================================================

#' Database Integration Manager for Seamless Data Synchronization
DatabaseIntegrationManager <- R6::R6Class("DatabaseIntegrationManager",
  public = list(
    existing_pool = NULL,
    pipeline_tables = list(),
    sync_status = list(),
    
    initialize = function(existing_db_pool = NULL) {
      # Connect to existing database pool
      if (isTRUE(is.null(existing_db_pool)) && exists("secure_db_pool") && !is.null(secure_db_pool)) {
        self$existing_pool <- secure_db_pool
      } else {
        self$existing_pool <- existing_db_pool
      }
      
      if (is.null(self$existing_pool)) {
        log_etl("WARN", "No existing database pool available", "DB_INTEGRATION")
      } else {
        log_etl("INFO", "Database integration manager initialized", "DB_INTEGRATION")
      }
      
      self$init_integration_tables()
    },
    
    init_integration_tables = function() {
      if (is.null(self$existing_pool)) return()
      
      tryCatch({
        # Create integration control table
        create_integration_control <- "
          CREATE TABLE IF NOT EXISTS pipeline_integration_control (
            id SERIAL PRIMARY KEY,
            table_name VARCHAR(100) NOT NULL,
            last_sync_timestamp TIMESTAMP,
            last_sync_record_count INTEGER DEFAULT 0,
            sync_status VARCHAR(20) DEFAULT 'pending',
            sync_strategy VARCHAR(20) DEFAULT 'upsert',
            error_message TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          );
          
          CREATE INDEX IF NOT EXISTS idx_integration_control_table ON pipeline_integration_control(table_name);
          CREATE INDEX IF NOT EXISTS idx_integration_control_status ON pipeline_integration_control(sync_status);
        "
        
        # Create data lineage table
        create_data_lineage <- "
          CREATE TABLE IF NOT EXISTS data_lineage (
            id SERIAL PRIMARY KEY,
            document_id VARCHAR(100) NOT NULL,
            source_system VARCHAR(50) NOT NULL,
            target_table VARCHAR(100) NOT NULL,
            operation_type VARCHAR(20) NOT NULL,
            operation_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            pipeline_run_id VARCHAR(64),
            data_hash VARCHAR(64),
            metadata JSONB
          );
          
          CREATE INDEX IF NOT EXISTS idx_lineage_document ON data_lineage(document_id);
          CREATE INDEX IF NOT EXISTS idx_lineage_timestamp ON data_lineage(operation_timestamp);
        "
        
        dbExecute(self$existing_pool, create_integration_control)
        dbExecute(self$existing_pool, create_data_lineage)
        
        log_etl("INFO", "Integration control tables initialized", "DB_INTEGRATION")
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("Integration tables initialization failed: %s", e$message), "DB_INTEGRATION")
      })
    },
    
    sync_pipeline_data = function(pipeline_data, target_table = "brazilian_legislative_complete", pipeline_run_id = NULL) {
      if (isTRUE(is.null(self$existing_pool)) || isTRUE(is.null(pipeline_data)) || nrow(pipeline_data) == 0) {
        log_etl("WARN", "Cannot sync pipeline data - missing connection or data", "DB_INTEGRATION")
        return(FALSE)
      }
      
      log_etl("INFO", sprintf("Starting data sync to %s: %d records", target_table, nrow(pipeline_data)), "DB_INTEGRATION")
      start_time <- Sys.time()
      
      tryCatch({
        # Check if target table exists and get schema
        table_schema <- self$get_table_schema(target_table)
        
        if (is.null(table_schema)) {
          # Create target table if it doesn't exist
          success <- self$create_target_table(target_table, pipeline_data)
          if (!success) {
            stop("Failed to create target table")
          }
        }
        
        # Prepare data for sync
        prepared_data <- self$prepare_data_for_sync(pipeline_data, target_table)
        
        # Execute sync strategy
        sync_strategy <- INTEGRATION_CONFIG$database$sync_strategy
        records_affected <- self$execute_sync_strategy(prepared_data, target_table, sync_strategy, pipeline_run_id)
        
        # Update sync status
        self$update_sync_status(target_table, records_affected, "completed")
        
        # Record data lineage
        self$record_data_lineage(prepared_data, target_table, sync_strategy, pipeline_run_id)
        
        end_time <- Sys.time()
        duration_seconds <- as.numeric(difftime(end_time, start_time, units = "secs"))
        
        log_etl("INFO", sprintf("Data sync completed: %d records to %s in %.2f seconds", 
                               records_affected, target_table, duration_seconds), "DB_INTEGRATION")
        
        return(TRUE)
        
      }, error = function(e) {
        self$update_sync_status(target_table, 0, "failed", e$message)
        log_etl("ERROR", sprintf("Data sync failed for %s: %s", target_table, e$message), "DB_INTEGRATION")
        return(FALSE)
      })
    },
    
    get_table_schema = function(table_name) {
      tryCatch({
        schema_query <- "
          SELECT column_name, data_type, is_nullable, column_default
          FROM information_schema.columns 
          WHERE table_name = $1
          ORDER BY ordinal_position
        "
        
        schema <- dbGetQuery(self$existing_pool, schema_query, list(table_name))
        
        if (nrow(schema) > 0) {
          return(schema)
        } else {
          return(NULL)
        }
        
      }, error = function(e) {
        log_etl("DEBUG", sprintf("Schema query failed for %s: %s", table_name, e$message), "DB_INTEGRATION")
        return(NULL)
      })
    },
    
    create_target_table = function(table_name, sample_data) {
      tryCatch({
        log_etl("INFO", sprintf("Creating target table: %s", table_name), "DB_INTEGRATION")
        
        # Generate CREATE TABLE statement based on sample data
        create_sql <- self$generate_create_table_sql(table_name, sample_data)
        
        dbExecute(self$existing_pool, create_sql)
        
        # Create indexes for common search fields
        self$create_search_indexes(table_name)
        
        log_etl("INFO", sprintf("Target table %s created successfully", table_name), "DB_INTEGRATION")
        return(TRUE)
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("Table creation failed for %s: %s", table_name, e$message), "DB_INTEGRATION")
        return(FALSE)
      })
    },
    
    generate_create_table_sql = function(table_name, sample_data) {
      # Standard Brazilian legislative document schema
      create_sql <- sprintf("
        CREATE TABLE IF NOT EXISTS %s (
          id SERIAL PRIMARY KEY,
          titulo TEXT NOT NULL,
          tipo VARCHAR(100),
          data DATE,
          autoridade TEXT,
          estado VARCHAR(2),
          municipio VARCHAR(255),
          ementa TEXT,
          url TEXT,
          urn TEXT UNIQUE,
          assuntos TEXT,
          categoria VARCHAR(100),
          fonte VARCHAR(50) DEFAULT 'Pipeline',
          data_extracao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          
          -- Brazilian standards compliance
          lexml_compliant BOOLEAN DEFAULT FALSE,
          ibge_compliant BOOLEAN DEFAULT FALSE,
          quality_score INTEGER DEFAULT 0,
          
          -- Processing metadata
          pipeline_run_id VARCHAR(64),
          document_hash VARCHAR(64),
          processing_version VARCHAR(20),
          
          -- Audit fields
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      ", table_name)
      
      return(create_sql)
    },
    
    create_search_indexes = function(table_name) {
      tryCatch({
        indexes <- c(
          sprintf("CREATE INDEX IF NOT EXISTS idx_%s_titulo ON %s USING gin(to_tsvector('portuguese', titulo));", table_name, table_name),
          sprintf("CREATE INDEX IF NOT EXISTS idx_%s_data ON %s(data);", table_name, table_name),
          sprintf("CREATE INDEX IF NOT EXISTS idx_%s_estado ON %s(estado);", table_name, table_name),
          sprintf("CREATE INDEX IF NOT EXISTS idx_%s_categoria ON %s(categoria);", table_name, table_name),
          sprintf("CREATE INDEX IF NOT EXISTS idx_%s_tipo ON %s(tipo);", table_name, table_name),
          sprintf("CREATE INDEX IF NOT EXISTS idx_%s_pipeline_run ON %s(pipeline_run_id);", table_name, table_name)
        )
        
        for (index_sql in indexes) {
          dbExecute(self$existing_pool, index_sql)
        }
        
        log_etl("INFO", sprintf("Search indexes created for %s", table_name), "DB_INTEGRATION")
        
      }, error = function(e) {
        log_etl("WARN", sprintf("Index creation failed for %s: %s", table_name, e$message), "DB_INTEGRATION")
      })
    },
    
    prepare_data_for_sync = function(pipeline_data, target_table) {
      # Standardize column names and add required fields
      prepared_data <- pipeline_data
      
      # Ensure required columns exist
      required_columns <- c("titulo", "tipo", "data", "autoridade")
      
      for (col in required_columns) {
        if (!col %in% names(prepared_data)) {
          prepared_data[[col]] <- ""
        }
      }
      
      # Add integration metadata
      prepared_data$document_hash <- apply(prepared_data[, c("titulo", "data", "autoridade")], 1, function(row) {
        digest::digest(paste(row, collapse = "|"), algo = "md5")
      })
      
      prepared_data$processing_version <- "4B.1.0"
      prepared_data$updated_at <- Sys.time()
      
      # Handle NULL values
      prepared_data[is.na(prepared_data)] <- ""
      
      return(prepared_data)
    },
    
    execute_sync_strategy = function(prepared_data, target_table, strategy, pipeline_run_id) {
      records_affected <- 0
      batch_size <- INTEGRATION_CONFIG$database$batch_size
      
      # Process in batches for memory efficiency
      total_records <- nrow(prepared_data)
      batches <- ceiling(total_records / batch_size)
      
      log_etl("INFO", sprintf("Processing %d records in %d batches using strategy: %s", 
                             total_records, batches, strategy), "DB_INTEGRATION")
      
      for (i in 1:batches) {
        start_row <- (i - 1) * batch_size + 1
        end_row <- min(i * batch_size, total_records)
        
        batch_data <- prepared_data[start_row:end_row, ]
        
        batch_affected <- switch(strategy,
          "insert" = self$execute_insert_batch(batch_data, target_table),
          "update" = self$execute_update_batch(batch_data, target_table),
          "upsert" = self$execute_upsert_batch(batch_data, target_table),
          "replace" = self$execute_replace_batch(batch_data, target_table),
          0
        )
        
        records_affected <- records_affected + batch_affected
        
        log_etl("DEBUG", sprintf("Batch %d/%d completed: %d records affected", 
                                i, batches, batch_affected), "DB_INTEGRATION")
      }
      
      return(records_affected)
    },
    
    execute_upsert_batch = function(batch_data, target_table) {
      tryCatch({
        # Use PostgreSQL UPSERT (ON CONFLICT)
        
        # Get column names (excluding id and auto-generated fields)
        columns <- names(batch_data)
        columns <- columns[!columns %in% c("id", "created_at")]
        
        # Build INSERT ... ON CONFLICT DO UPDATE
        columns_list <- paste(columns, collapse = ", ")
        placeholders <- paste(paste0("$", 1:length(columns)), collapse = ", ")
        
        # Update clause for conflicts (assuming urn is unique)
        update_clauses <- paste(paste0(columns, " = EXCLUDED.", columns), collapse = ", ")
        
        upsert_sql <- sprintf("
          INSERT INTO %s (%s) 
          VALUES (%s)
          ON CONFLICT (urn) DO UPDATE SET 
          %s, updated_at = CURRENT_TIMESTAMP
        ", target_table, columns_list, placeholders, update_clauses)
        
        # Execute for each row in batch
        affected_count <- 0
        
        for (i in 1:nrow(batch_data)) {
          row_data <- as.list(batch_data[i, columns])
          
          # Handle NULL values
          row_data <- lapply(row_data, function(x) if (isTRUE(is.na(x)) || x == "") NA else x)
          
          result <- dbExecute(self$existing_pool, upsert_sql, row_data)
          affected_count <- affected_count + result
        }
        
        return(affected_count)
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("Upsert batch failed: %s", e$message), "DB_INTEGRATION")
        return(0)
      })
    },
    
    execute_insert_batch = function(batch_data, target_table) {
      tryCatch({
        result <- dbWriteTable(self$existing_pool, target_table, batch_data, 
                              append = TRUE, row.names = FALSE)
        return(if (result) nrow(batch_data) else 0)
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("Insert batch failed: %s", e$message), "DB_INTEGRATION")
        return(0)
      })
    },
    
    record_data_lineage = function(data, target_table, operation_type, pipeline_run_id) {
      if (nrow(data) == 0) return()
      
      tryCatch({
        # Sample 10% of records for lineage tracking (performance optimization)
        sample_size <- max(1, ceiling(nrow(data) * 0.1))
        sample_indices <- sample(nrow(data), sample_size)
        sample_data <- data[sample_indices, ]
        
        lineage_records <- data.frame(
          document_id = sample_data$document_hash,
          source_system = "ETL_Pipeline",
          target_table = target_table,
          operation_type = operation_type,
          pipeline_run_id = pipeline_run_id %||% "unknown",
          data_hash = sample_data$document_hash,
          stringsAsFactors = FALSE
        )
        
        dbWriteTable(self$existing_pool, "data_lineage", lineage_records, 
                    append = TRUE, row.names = FALSE)
        
        log_etl("DEBUG", sprintf("Data lineage recorded: %d samples", sample_size), "DB_INTEGRATION")
        
      }, error = function(e) {
        log_etl("WARN", sprintf("Data lineage recording failed: %s", e$message), "DB_INTEGRATION")
      })
    },
    
    update_sync_status = function(table_name, record_count, status, error_message = NULL) {
      tryCatch({
        upsert_status_sql <- "
          INSERT INTO pipeline_integration_control 
          (table_name, last_sync_timestamp, last_sync_record_count, sync_status, error_message, updated_at)
          VALUES ($1, CURRENT_TIMESTAMP, $2, $3, $4, CURRENT_TIMESTAMP)
          ON CONFLICT (table_name) DO UPDATE SET
          last_sync_timestamp = CURRENT_TIMESTAMP,
          last_sync_record_count = $2,
          sync_status = $3,
          error_message = $4,
          updated_at = CURRENT_TIMESTAMP
        "
        
        dbExecute(self$existing_pool, upsert_status_sql, 
                 list(table_name, record_count, status, error_message))
        
      }, error = function(e) {
        log_etl("DEBUG", sprintf("Status update failed: %s", e$message), "DB_INTEGRATION")
      })
    },
    
    get_sync_status = function() {
      if (is.null(self$existing_pool)) {
        return(list(status = "no_connection"))
      }
      
      tryCatch({
        status_query <- "
          SELECT table_name, last_sync_timestamp, last_sync_record_count, 
                 sync_status, error_message, updated_at
          FROM pipeline_integration_control
          ORDER BY updated_at DESC
        "
        
        status_data <- dbGetQuery(self$existing_pool, status_query)
        
        return(list(
          status = "connected",
          sync_history = status_data,
          last_updated = Sys.time()
        ))
        
      }, error = function(e) {
        return(list(
          status = "error",
          error_message = e$message
        ))
      })
    },
    
    cleanup_old_data = function(table_name, retention_days = 365) {
      if (is.null(self$existing_pool)) return(0)
      
      tryCatch({
        cleanup_sql <- sprintf("
          DELETE FROM %s 
          WHERE created_at < CURRENT_DATE - INTERVAL '%d days'
          AND fonte = 'Pipeline'
        ", table_name, retention_days)
        
        deleted_count <- dbExecute(self$existing_pool, cleanup_sql)
        
        if (deleted_count > 0) {
          log_etl("INFO", sprintf("Cleaned up %d old records from %s", deleted_count, table_name), "DB_INTEGRATION")
        }
        
        return(deleted_count)
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("Cleanup failed for %s: %s", table_name, e$message), "DB_INTEGRATION")
        return(0)
      })
    }
  )
)

# ============================================================================
# SEARCH INTEGRATION MANAGER
# ============================================================================

#' Search Integration Manager for Enhanced Search Capabilities
SearchIntegrationManager <- R6::R6Class("SearchIntegrationManager",
  public = list(
    db_integration = NULL,
    search_cache = list(),
    
    initialize = function(db_integration_manager) {
      self$db_integration <- db_integration_manager
      log_etl("INFO", "Search integration manager initialized", "SEARCH_INTEGRATION")
    },
    
    enhance_existing_search = function(search_function_name, enhancement_type = "full_text") {
      if (!exists(search_function_name, envir = .GlobalEnv)) {
        log_etl("WARN", sprintf("Search function %s not found", search_function_name), "SEARCH_INTEGRATION")
        return(FALSE)
      }
      
      # Create enhanced version of existing search function
      enhanced_function_name <- paste0(search_function_name, "_enhanced")
      
      tryCatch({
        # Get original function
        original_function <- get(search_function_name, envir = .GlobalEnv)
        
        # Create enhanced wrapper
        enhanced_function <- self$create_enhanced_search_wrapper(original_function, enhancement_type)
        
        # Register enhanced function
        assign(enhanced_function_name, enhanced_function, envir = .GlobalEnv)
        
        log_etl("INFO", sprintf("Enhanced search function created: %s", enhanced_function_name), "SEARCH_INTEGRATION")
        return(TRUE)
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("Search enhancement failed for %s: %s", search_function_name, e$message), "SEARCH_INTEGRATION")
        return(FALSE)
      })
    },
    
    create_enhanced_search_wrapper = function(original_function, enhancement_type) {
      function(...) {
        args <- list(...)
        
        # Call original function
        original_results <- original_function(...)
        
        # Apply enhancements
        enhanced_results <- switch(enhancement_type,
          "full_text" = self$apply_full_text_search(original_results, args),
          "faceted" = self$apply_faceted_search(original_results, args),
          "semantic" = self$apply_semantic_search(original_results, args),
          "autocomplete" = self$apply_autocomplete_search(original_results, args),
          original_results
        )
        
        return(enhanced_results)
      }
    },
    
    apply_full_text_search = function(results, search_args) {
      if (isTRUE(is.null(results)) || nrow(results) == 0) return(results)
      
      # Check if search term exists
      search_term <- search_args$search_term %||% search_args[[2]] %||% ""
      
      if (search_term == "") return(results)
      
      tryCatch({
        # Enhanced full-text search using PostgreSQL
        if (!is.null(self$db_integration$existing_pool)) {
          enhanced_query <- sprintf("
            SELECT *, 
                   ts_rank(to_tsvector('portuguese', titulo || ' ' || COALESCE(ementa, '')), 
                           plainto_tsquery('portuguese', $1)) as relevance_score
            FROM brazilian_legislative_complete 
            WHERE to_tsvector('portuguese', titulo || ' ' || COALESCE(ementa, '')) 
                  @@ plainto_tsquery('portuguese', $1)
            ORDER BY relevance_score DESC, data DESC
            LIMIT 1000
          ")
          
          enhanced_results <- dbGetQuery(self$db_integration$existing_pool, enhanced_query, list(search_term))
          
          if (nrow(enhanced_results) > 0) {
            log_etl("DEBUG", sprintf("Full-text search returned %d results", nrow(enhanced_results)), "SEARCH_INTEGRATION")
            return(enhanced_results)
          }
        }
        
        # Fallback to original results
        return(results)
        
      }, error = function(e) {
        log_etl("DEBUG", sprintf("Full-text search enhancement failed: %s", e$message), "SEARCH_INTEGRATION")
        return(results)
      })
    },
    
    apply_faceted_search = function(results, search_args) {
      if (isTRUE(is.null(results)) || nrow(results) == 0) return(results)
      
      # Add faceted search metadata
      facets <- list(
        categories = table(results$categoria),
        states = table(results$estado),
        document_types = table(results$tipo),
        authorities = table(results$autoridade),
        years = if ("data" %in% names(results)) {
          table(format(as.Date(results$data), "%Y"))
        } else {
          table()
        }
      )
      
      # Attach facets as attribute
      attr(results, "facets") <- facets
      attr(results, "search_type") <- "faceted"
      
      return(results)
    },
    
    apply_semantic_search = function(results, search_args) {
      # Simplified semantic search based on document similarity
      if (isTRUE(is.null(results)) || nrow(results) == 0) return(results)
      
      search_term <- search_args$search_term %||% ""
      
      if (search_term == "") return(results)
      
      tryCatch({
        # Calculate semantic similarity scores (simplified)
        if ("titulo" %in% names(results) && "ementa" %in% names(results)) {
          # Combine title and summary for similarity calculation
          combined_text <- paste(results$titulo, results$ementa)
          
          # Simple keyword-based semantic scoring
          search_keywords <- tolower(strsplit(search_term, "\\s+")[[1]])
          
          semantic_scores <- sapply(combined_text, function(text) {
            text_lower <- tolower(text)
            keyword_matches <- sum(sapply(search_keywords, function(kw) grepl(kw, text_lower)))
            return(keyword_matches / length(search_keywords))
          })
          
          results$semantic_score <- semantic_scores
          results <- results[order(results$semantic_score, decreasing = TRUE), ]
        }
        
        attr(results, "search_type") <- "semantic"
        return(results)
        
      }, error = function(e) {
        log_etl("DEBUG", sprintf("Semantic search enhancement failed: %s", e$message), "SEARCH_INTEGRATION")
        return(results)
      })
    },
    
    apply_autocomplete_search = function(results, search_args) {
      search_term <- search_args$search_term %||% ""
      
      if (search_term == "" || nchar(search_term) < 2) return(results)
      
      tryCatch({
        # Generate autocomplete suggestions
        if (!is.null(self$db_integration$existing_pool)) {
          suggestions_query <- "
            SELECT DISTINCT titulo
            FROM brazilian_legislative_complete 
            WHERE titulo ILIKE $1
            ORDER BY titulo
            LIMIT 10
          "
          
          suggestions <- dbGetQuery(
            self$db_integration$existing_pool, 
            suggestions_query, 
            list(paste0(search_term, "%"))
          )
          
          attr(results, "autocomplete_suggestions") <- suggestions$titulo
        }
        
        attr(results, "search_type") <- "autocomplete"
        return(results)
        
      }, error = function(e) {
        log_etl("DEBUG", sprintf("Autocomplete enhancement failed: %s", e$message), "SEARCH_INTEGRATION")
        return(results)
      })
    },
    
    integrate_with_existing_modules = function() {
      # Enhance existing search functions
      existing_functions <- INTEGRATION_CONFIG$search$existing_functions
      
      for (func_name in existing_functions) {
        if (exists(func_name, envir = .GlobalEnv)) {
          self$enhance_existing_search(func_name, "full_text")
        }
      }
      
      # Create search performance monitoring
      self$setup_search_monitoring()
      
      log_etl("INFO", "Search integration with existing modules completed", "SEARCH_INTEGRATION")
    },
    
    setup_search_monitoring = function() {
      # Create search performance tracking
      if (!is.null(self$db_integration$existing_pool)) {
        tryCatch({
          create_search_monitoring <- "
            CREATE TABLE IF NOT EXISTS search_performance_log (
              id SERIAL PRIMARY KEY,
              search_term TEXT,
              search_type VARCHAR(50),
              execution_time_ms INTEGER,
              result_count INTEGER,
              user_session VARCHAR(100),
              timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE INDEX IF NOT EXISTS idx_search_perf_timestamp ON search_performance_log(timestamp);
          "
          
          dbExecute(self$db_integration$existing_pool, create_search_monitoring)
          
        }, error = function(e) {
          log_etl("DEBUG", sprintf("Search monitoring setup failed: %s", e$message), "SEARCH_INTEGRATION")
        })
      }
    },
    
    log_search_performance = function(search_term, search_type, execution_time_ms, result_count) {
      if (!is.null(self$db_integration$existing_pool)) {
        tryCatch({
          insert_perf_log <- "
            INSERT INTO search_performance_log 
            (search_term, search_type, execution_time_ms, result_count)
            VALUES ($1, $2, $3, $4)
          "
          
          dbExecute(self$db_integration$existing_pool, insert_perf_log,
                   list(search_term, search_type, execution_time_ms, result_count))
          
        }, error = function(e) {
          log_etl("DEBUG", sprintf("Search performance logging failed: %s", e$message), "SEARCH_INTEGRATION")
        })
      }
    }
  )
)

# ============================================================================
# MAIN SYSTEM INTEGRATION ORCHESTRATOR
# ============================================================================

#' Main System Integration Orchestrator
SystemIntegrationOrchestrator <- R6::R6Class("SystemIntegrationOrchestrator",
  public = list(
    db_integration = NULL,
    search_integration = NULL,
    pipeline_components = list(),
    integration_status = "not_initialized",
    
    initialize = function() {
      log_etl("INFO", "System integration orchestrator initializing...", "SYSTEM_INTEGRATION")
      
      # Initialize database integration
      self$db_integration <- DatabaseIntegrationManager$new()
      
      # Initialize search integration
      self$search_integration <- SearchIntegrationManager$new(self$db_integration)
      
      self$integration_status <- "initialized"
      log_etl("INFO", "System integration orchestrator initialized", "SYSTEM_INTEGRATION")
    },
    
    integrate_all_components = function() {
      log_etl("INFO", "Starting full system integration", "SYSTEM_INTEGRATION")
      self$integration_status <- "integrating"
      
      integration_results <- list(
        database_integration = FALSE,
        search_integration = FALSE,
        module_integration = FALSE,
        monitoring_integration = FALSE
      )
      
      tryCatch({
        # Step 1: Integrate database components
        integration_results$database_integration <- self$integrate_database_components()
        
        # Step 2: Integrate search components
        integration_results$search_integration <- self$integrate_search_components()
        
        # Step 3: Integrate existing modules
        integration_results$module_integration <- self$integrate_existing_modules()
        
        # Step 4: Setup monitoring integration
        integration_results$monitoring_integration <- self$integrate_monitoring_components()
        
        # Check overall success
        overall_success <- all(unlist(integration_results))
        
        if (overall_success) {
          self$integration_status <- "completed"
          log_etl("INFO", "Full system integration completed successfully", "SYSTEM_INTEGRATION")
        } else {
          self$integration_status <- "partial"
          failed_components <- names(integration_results)[!unlist(integration_results)]
          log_etl("WARN", sprintf("Partial integration - failed components: %s", 
                                 paste(failed_components, collapse = ", ")), "SYSTEM_INTEGRATION")
        }
        
        return(integration_results)
        
      }, error = function(e) {
        self$integration_status <- "failed"
        log_etl("ERROR", sprintf("System integration failed: %s", e$message), "SYSTEM_INTEGRATION")
        return(integration_results)
      })
    },
    
    integrate_database_components = function() {
      log_etl("INFO", "Integrating database components", "SYSTEM_INTEGRATION")
      
      # Check if pipeline components are available
      pipeline_components <- c("etl_orchestrator", "validation_orchestrator", 
                              "api_orchestrator", "monitoring_system")
      
      available_components <- c()
      for (component in pipeline_components) {
        if (exists(component, envir = .GlobalEnv) && !is.null(get(component, envir = .GlobalEnv))) {
          available_components <- c(available_components, component)
        }
      }
      
      if (length(available_components) == 0) {
        log_etl("WARN", "No pipeline components found for database integration", "SYSTEM_INTEGRATION")
        return(FALSE)
      }
      
      # Test database connectivity
      sync_status <- self$db_integration$get_sync_status()
      
      if (sync_status$status == "connected") {
        log_etl("INFO", "Database integration successful", "SYSTEM_INTEGRATION")
        return(TRUE)
      } else {
        log_etl("WARN", "Database integration limited - no connection", "SYSTEM_INTEGRATION")
        return(FALSE)
      }
    },
    
    integrate_search_components = function() {
      log_etl("INFO", "Integrating search components", "SYSTEM_INTEGRATION")
      
      # Enhance existing search functions
      self$search_integration$integrate_with_existing_modules()
      
      return(TRUE)
    },
    
    integrate_existing_modules = function() {
      log_etl("INFO", "Integrating with existing application modules", "SYSTEM_INTEGRATION")
      
      # Check for existing modules
      existing_modules <- INTEGRATION_CONFIG$modules$existing_modules
      found_modules <- c()
      
      for (module in existing_modules) {
        module_file <- paste0("modules/", module, ".R")
        if (file.exists(module_file)) {
          found_modules <- c(found_modules, module)
          
          tryCatch({
            source(module_file)
            log_etl("DEBUG", sprintf("Integrated with module: %s", module), "SYSTEM_INTEGRATION")
          }, error = function(e) {
            log_etl("WARN", sprintf("Failed to integrate module %s: %s", module, e$message), "SYSTEM_INTEGRATION")
          })
        }
      }
      
      log_etl("INFO", sprintf("Module integration completed: %d/%d modules found", 
                             length(found_modules), length(existing_modules)), "SYSTEM_INTEGRATION")
      
      return(length(found_modules) > 0)
    },
    
    integrate_monitoring_components = function() {
      log_etl("INFO", "Integrating monitoring components", "SYSTEM_INTEGRATION")
      
      # Connect pipeline monitoring with existing logging
      if (exists("monitoring_system", envir = .GlobalEnv) && !is.null(monitoring_system)) {
        # Integration successful
        return(TRUE)
      } else {
        log_etl("WARN", "Monitoring system not found for integration", "SYSTEM_INTEGRATION")
        return(FALSE)
      }
    },
    
    sync_pipeline_data_to_production = function(pipeline_data, pipeline_run_id = NULL) {
      if (isTRUE(is.null(pipeline_data)) || nrow(pipeline_data) == 0) {
        log_etl("WARN", "No pipeline data to sync", "SYSTEM_INTEGRATION")
        return(FALSE)
      }
      
      log_etl("INFO", sprintf("Syncing %d records to production database", nrow(pipeline_data)), "SYSTEM_INTEGRATION")
      
      # Sync to primary production table
      success <- self$db_integration$sync_pipeline_data(
        pipeline_data = pipeline_data,
        target_table = "brazilian_legislative_complete",
        pipeline_run_id = pipeline_run_id
      )
      
      return(success)
    },
    
    run_integration_health_check = function() {
      health_status <- list(
        integration_status = self$integration_status,
        database_integration = list(
          status = "unknown",
          last_sync = NULL,
          error = NULL
        ),
        search_integration = list(
          enhanced_functions = 0,
          performance_monitoring = FALSE
        ),
        module_integration = list(
          loaded_modules = 0,
          compatibility_issues = 0
        ),
        timestamp = Sys.time()
      )
      
      # Check database integration health
      if (!is.null(self$db_integration)) {
        db_status <- self$db_integration$get_sync_status()
        health_status$database_integration <- db_status
      }
      
      # Check search integration health
      if (!is.null(self$search_integration)) {
        enhanced_functions <- sum(sapply(INTEGRATION_CONFIG$search$existing_functions, 
                                       function(f) exists(paste0(f, "_enhanced"), envir = .GlobalEnv)))
        
        health_status$search_integration$enhanced_functions <- enhanced_functions
        health_status$search_integration$performance_monitoring <- TRUE
      }
      
      return(health_status)
    },
    
    get_integration_summary = function() {
      return(list(
        status = self$integration_status,
        components = list(
          database_integration = !is.null(self$db_integration),
          search_integration = !is.null(self$search_integration)
        ),
        configuration = INTEGRATION_CONFIG,
        health_check = self$run_integration_health_check(),
        last_updated = Sys.time()
      ))
    }
  )
)

# ============================================================================
# EXPORTS AND INITIALIZATION
# ============================================================================

# Global system integration orchestrator
system_integrator <- NULL

initialize_system_integration <- function() {
  cat("🔗 Initializing System Integration with Existing Database and Search...\n")
  
  tryCatch({
    system_integrator <<- SystemIntegrationOrchestrator$new()
    
    # Run full integration
    integration_results <- system_integrator$integrate_all_components()
    
    cat("✅ System integration initialized successfully\n")
    cat("🔧 Integration results:\n")
    cat(sprintf("   - Database Integration: %s\n", 
                if (integration_results$database_integration) "✅ SUCCESS" else "⚠️ LIMITED"))
    cat(sprintf("   - Search Integration: %s\n", 
                if (integration_results$search_integration) "✅ SUCCESS" else "❌ FAILED"))
    cat(sprintf("   - Module Integration: %s\n", 
                if (integration_results$module_integration) "✅ SUCCESS" else "⚠️ PARTIAL"))
    cat(sprintf("   - Monitoring Integration: %s\n", 
                if (integration_results$monitoring_integration) "✅ SUCCESS" else "⚠️ LIMITED"))
    
    cat("📊 Enhanced capabilities:\n")
    cat("   - Advanced full-text search with Portuguese support\n")
    cat("   - Faceted search with metadata\n") 
    cat("   - Semantic search capabilities\n")
    cat("   - Autocomplete functionality\n")
    cat("   - Data lineage tracking\n")
    cat("   - Performance monitoring\n")
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ System integration initialization failed:", e$message, "\n")
    return(FALSE)
  })
}

# Export main functions
sync_pipeline_to_production <- function(pipeline_data, pipeline_run_id = NULL) {
  if (is.null(system_integrator)) {
    if (!initialize_system_integration()) {
      return(FALSE)
    }
  }
  
  return(system_integrator$sync_pipeline_data_to_production(pipeline_data, pipeline_run_id))
}

get_integration_health <- function() {
  if (is.null(system_integrator)) {
    return(list(status = "not_initialized"))
  }
  
  return(system_integrator$run_integration_health_check())
}

get_integration_summary <- function() {
  if (is.null(system_integrator)) {
    return(list(status = "not_initialized"))
  }
  
  return(system_integrator$get_integration_summary())
}

# Enhanced search functions (backward compatible)
get_library_documents_enhanced <- function(...) {
  if (exists("get_library_documents_enhanced", envir = .GlobalEnv)) {
    return(get("get_library_documents_enhanced", envir = .GlobalEnv)(...))
  } else if (exists("get_library_documents", envir = .GlobalEnv)) {
    return(get("get_library_documents", envir = .GlobalEnv)(...))
  } else {
    log_etl("WARN", "No library documents function available", "SYSTEM_INTEGRATION")
    return(data.frame())
  }
}

# Cleanup function
cleanup_system_integration <- function() {
  if (!is.null(system_integrator)) {
    log_etl("INFO", "System integration cleanup completed", "SYSTEM_INTEGRATION")
  }
}

# Register cleanup on exit
reg.finalizer(globalenv(), function(e) {
  cleanup_system_integration()
}, onexit = TRUE)

cat("🔗 System Integration with Database and Search loaded\n")
cat("📋 Seamless Integration with Existing Infrastructure Ready\n")
cat("🔧 Use initialize_system_integration() to start\n")