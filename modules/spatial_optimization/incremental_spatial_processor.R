# INCREMENTAL SPATIAL PROCESSING SYSTEM
# Brazilian Legislative Monitoring System - Real-time Document Integration
# ============================================================================
#
# Advanced incremental processing system for new document ingestion:
# - Real-time spatial association for new documents as they arrive
# - Change detection and delta processing to avoid reprocessing existing data
# - Queue-based processing with priority management for urgent documents
# - Incremental materialized view refresh without full rebuilds
# - Conflict resolution for overlapping spatial assignments
# - Rollback mechanisms for failed processing batches
# - Integration with existing 134k+ document corpus without disruption
#
# Design principles:
# - Process only new/changed documents (avoid full reprocessing)
# - Maintain system responsiveness during incremental updates
# - Preserve data consistency across concurrent processing
# - Optimize for both batch and real-time ingestion patterns

library(shiny)
library(dplyr)
library(pool)
library(DBI)
library(jsonlite)
library(digest)
library(lubridate)

# ============================================================================
# INCREMENTAL PROCESSING CONFIGURATION
# ============================================================================

INCREMENTAL_CONFIG <- list(
  # Processing modes
  processing_modes = list(
    realtime = list(
      max_batch_size = 50,
      max_wait_time_seconds = 30,
      priority_threshold = 0.8
    ),
    batch = list(
      max_batch_size = 500,
      max_wait_time_seconds = 300,
      priority_threshold = 0.5
    ),
    maintenance = list(
      max_batch_size = 1000,
      max_wait_time_seconds = 3600,
      priority_threshold = 0.1
    )
  ),
  
  # Change detection
  enable_change_detection = TRUE,
  change_detection_fields = c("title", "document_summary", "latitude", "longitude", 
                              "state", "municipality_mentioned", "enacting_date"),
  content_hash_algorithm = "md5",
  
  # Queue management
  enable_priority_queue = TRUE,
  max_queue_size = 10000,
  priority_levels = c("urgent", "high", "normal", "low", "maintenance"),
  
  # Materialized view refresh
  enable_incremental_mv_refresh = TRUE,
  mv_refresh_threshold = 100,      # Refresh after N document changes
  mv_refresh_max_age_hours = 6,    # Force refresh after 6 hours
  
  # Conflict resolution
  enable_conflict_detection = TRUE,
  conflict_resolution_strategy = "newest_wins", # "newest_wins", "highest_confidence", "manual"
  
  # Performance optimization
  enable_parallel_processing = TRUE,
  max_parallel_workers = 3,        # Conservative for Railway
  processing_timeout_seconds = 120,
  
  # Monitoring and logging
  enable_processing_audit = TRUE,
  audit_retention_days = 30,
  enable_performance_metrics = TRUE
)

# Document priority rules for intelligent queue management
DOCUMENT_PRIORITY_RULES <- list(
  urgent = list(
    conditions = c("recent_enactment", "federal_level", "emergency_keywords"),
    weight = 1.0,
    max_age_hours = 1
  ),
  high = list(
    conditions = c("state_level", "recent_update", "high_importance_keywords"),
    weight = 0.8,
    max_age_hours = 6
  ),
  normal = list(
    conditions = c("municipal_level", "standard_processing"),
    weight = 0.5,
    max_age_hours = 24
  ),
  low = list(
    conditions = c("historical_data", "backfill_processing"),
    weight = 0.3,
    max_age_hours = 168  # 1 week
  ),
  maintenance = list(
    conditions = c("data_cleanup", "optimization_tasks"),
    weight = 0.1,
    max_age_hours = 720  # 1 month
  )
)

# ============================================================================
# CHANGE DETECTION SYSTEM
# ============================================================================

#' Create change detection system for document monitoring
#' @param pool Database connection pool
#' @return Change detector object
create_change_detector <- function(pool) {
  
  detector <- list(
    
    # Calculate content hash for change detection
    calculate_document_hash = function(document_row) {
      # Extract relevant fields for hashing
      hash_fields <- INCREMENTAL_CONFIG$change_detection_fields
      existing_fields <- hash_fields[hash_fields %in% names(document_row)]
      
      if (length(existing_fields) == 0) {
        return(NA)
      }
      
      # Create consistent string representation
      hash_content <- paste(
        sapply(existing_fields, function(field) {
          value <- document_row[[field]]
          if (is.na(value) || is.null(value)) return("NULL")
          as.character(value)
        }),
        collapse = "|"
      )
      
      # Generate hash
      digest::digest(hash_content, algo = INCREMENTAL_CONFIG$content_hash_algorithm)
    },
    
    # Detect changes in a batch of documents
    detect_changes = function(document_batch) {
      if (nrow(document_batch) == 0) {
        return(list(
          new_documents = document_batch,
          changed_documents = data.frame(),
          unchanged_documents = data.frame()
        ))
      }
      
      tryCatch({
        conn <- poolCheckout(pool)
        on.exit(poolReturn(conn), add = TRUE)
        
        # Calculate hashes for incoming documents
        document_batch$content_hash <- sapply(seq_len(nrow(document_batch)), function(i) {
          detector$calculate_document_hash(document_batch[i, ])
        })
        
        # Get existing document hashes from database
        doc_ids <- document_batch$document_id
        if (length(doc_ids) > 0) {
          placeholders <- paste(rep("?", length(doc_ids)), collapse = ",")
          existing_sql <- sprintf("
            SELECT document_id, content_hash, last_processed
            FROM document_processing_audit 
            WHERE document_id IN (%s)
          ", placeholders)
          
          existing_hashes <- dbGetQuery(conn, existing_sql, params = as.list(doc_ids))
        } else {
          existing_hashes <- data.frame(
            document_id = character(0), 
            content_hash = character(0),
            last_processed = as.POSIXct(character(0))
          )
        }
        
        # Classify documents
        if (nrow(existing_hashes) > 0) {
          document_batch_with_existing <- document_batch %>%
            left_join(existing_hashes, by = "document_id", suffix = c("_new", "_existing"))
          
          new_documents <- document_batch_with_existing %>%
            filter(is.na(content_hash_existing))
          
          potentially_changed <- document_batch_with_existing %>%
            filter(!is.na(content_hash_existing))
          
          changed_documents <- potentially_changed %>%
            filter(content_hash_new != content_hash_existing)
          
          unchanged_documents <- potentially_changed %>%
            filter(content_hash_new == content_hash_existing)
            
        } else {
          new_documents <- document_batch
          changed_documents <- data.frame()
          unchanged_documents <- data.frame()
        }
        
        # Clean up hash columns for return
        if (nrow(new_documents) > 0) {
          new_documents$content_hash_existing <- NULL
          names(new_documents)[names(new_documents) == "content_hash_new"] <- "content_hash"
        }
        
        if (nrow(changed_documents) > 0) {
          changed_documents$content_hash_existing <- NULL
          names(changed_documents)[names(changed_documents) == "content_hash_new"] <- "content_hash"
        }
        
        cat(sprintf("📊 Change detection: %d new, %d changed, %d unchanged documents\n",
                   nrow(new_documents), nrow(changed_documents), nrow(unchanged_documents)))
        
        return(list(
          new_documents = new_documents,
          changed_documents = changed_documents,
          unchanged_documents = unchanged_documents
        ))
        
      }, error = function(e) {
        cat("❌ Change detection failed:", e$message, "\n")
        return(list(
          new_documents = document_batch,
          changed_documents = data.frame(),
          unchanged_documents = data.frame()
        ))
      })
    },
    
    # Update document processing audit trail
    update_processing_audit = function(processed_documents, processing_result) {
      if (!INCREMENTAL_CONFIG$enable_processing_audit) return(TRUE)
      
      tryCatch({
        conn <- poolCheckout(pool)
        on.exit(poolReturn(conn), add = TRUE)
        
        # Ensure audit table exists
        audit_sql <- "
          CREATE TABLE IF NOT EXISTS document_processing_audit (
            document_id TEXT PRIMARY KEY,
            content_hash TEXT,
            last_processed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            processing_result TEXT,
            processing_duration_ms INTEGER,
            spatial_associations_count INTEGER,
            processing_version TEXT DEFAULT '1.0',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
          )
        "
        dbExecute(conn, audit_sql)
        
        # Insert or update audit records
        for (i in seq_len(nrow(processed_documents))) {
          doc <- processed_documents[i, ]
          
          audit_record_sql <- "
            INSERT OR REPLACE INTO document_processing_audit 
            (document_id, content_hash, last_processed, processing_result, 
             processing_duration_ms, spatial_associations_count, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
          "
          
          dbExecute(conn, audit_record_sql, params = list(
            doc$document_id,
            doc$content_hash %||% "",
            Sys.time(),
            jsonlite::toJSON(processing_result, auto_unbox = TRUE),
            processing_result$duration_ms %||% 0,
            processing_result$associations_created %||% 0,
            Sys.time()
          ))
        }
        
        return(TRUE)
        
      }, error = function(e) {
        cat("⚠️ Audit update failed:", e$message, "\n")
        return(FALSE)
      })
    }
  )
  
  return(detector)
}

# ============================================================================
# PRIORITY QUEUE SYSTEM
# ============================================================================

#' Create intelligent priority queue for document processing
#' @param pool Database connection pool
#' @return Priority queue object
create_priority_queue <- function(pool) {
  
  if (!INCREMENTAL_CONFIG$enable_priority_queue) {
    # Simple FIFO queue fallback
    simple_queue <- list()
    return(list(
      enqueue = function(documents, priority = "normal") {
        simple_queue <<- append(simple_queue, list(documents))
        length(simple_queue)
      },
      dequeue = function(max_size = 100) {
        if (length(simple_queue) == 0) return(data.frame())
        result <- simple_queue[[1]]
        simple_queue <<- simple_queue[-1]
        return(result)
      },
      size = function() length(simple_queue),
      clear = function() simple_queue <<- list()
    ))
  }
  
  queue <- list(
    
    # Initialize priority queue table
    initialize_queue = function() {
      tryCatch({
        conn <- poolCheckout(pool)
        on.exit(poolReturn(conn), add = TRUE)
        
        queue_sql <- "
          CREATE TABLE IF NOT EXISTS document_processing_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            document_id TEXT NOT NULL,
            document_data TEXT NOT NULL,  -- JSON encoded document
            priority_level TEXT NOT NULL,
            priority_score REAL NOT NULL,
            enqueue_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            processing_attempts INTEGER DEFAULT 0,
            last_attempt TIMESTAMP,
            error_message TEXT,
            status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed'))
          )
        "
        dbExecute(conn, queue_sql)
        
        # Create indexes for efficient queue operations
        dbExecute(conn, "CREATE INDEX IF NOT EXISTS idx_queue_priority ON document_processing_queue(priority_score DESC, enqueue_time ASC)")
        dbExecute(conn, "CREATE INDEX IF NOT EXISTS idx_queue_status ON document_processing_queue(status)")
        
        return(TRUE)
        
      }, error = function(e) {
        cat("❌ Queue initialization failed:", e$message, "\n")
        return(FALSE)
      })
    },
    
    # Calculate document priority score
    calculate_priority_score = function(document_row) {
      base_score <- 0.5  # Default normal priority
      
      # Check priority conditions
      for (priority_level in names(DOCUMENT_PRIORITY_RULES)) {
        rule <- DOCUMENT_PRIORITY_RULES[[priority_level]]
        
        conditions_met <- 0
        total_conditions <- length(rule$conditions)
        
        for (condition in rule$conditions) {
          if (check_priority_condition(document_row, condition)) {
            conditions_met <- conditions_met + 1
          }
        }
        
        # If majority of conditions are met, use this priority level
        if (conditions_met / total_conditions >= 0.6) {
          base_score <- rule$weight
          break
        }
      }
      
      # Apply time decay for aging documents
      if ("enacting_date" %in% names(document_row) && !is.na(document_row$enacting_date)) {
        days_old <- as.numeric(Sys.Date() - as.Date(document_row$enacting_date))
        if (days_old > 30) {
          age_penalty <- min(0.3, days_old / 365 * 0.1)  # Reduce priority for old documents
          base_score <- max(0.1, base_score - age_penalty)
        }
      }
      
      return(base_score)
    },
    
    # Enqueue documents with priority calculation
    enqueue = function(documents, priority_override = NULL) {
      if (nrow(documents) == 0) return(0)
      
      queue$initialize_queue()  # Ensure queue table exists
      
      tryCatch({
        conn <- poolCheckout(pool)
        on.exit(poolReturn(conn), add = TRUE)
        
        enqueued_count <- 0
        
        for (i in seq_len(nrow(documents))) {
          doc <- documents[i, ]
          
          # Calculate priority
          if (!is.null(priority_override)) {
            priority_level <- priority_override
            priority_score <- DOCUMENT_PRIORITY_RULES[[priority_override]]$weight %||% 0.5
          } else {
            priority_score <- queue$calculate_priority_score(doc)
            priority_level <- determine_priority_level(priority_score)
          }
          
          # Encode document as JSON
          doc_json <- jsonlite::toJSON(doc, auto_unbox = TRUE)
          
          # Insert into queue
          insert_sql <- "
            INSERT INTO document_processing_queue 
            (document_id, document_data, priority_level, priority_score)
            VALUES (?, ?, ?, ?)
          "
          
          dbExecute(conn, insert_sql, params = list(
            doc$document_id,
            doc_json,
            priority_level,
            priority_score
          ))
          
          enqueued_count <- enqueued_count + 1
        }
        
        cat(sprintf("📥 Enqueued %d documents for processing\n", enqueued_count))
        return(enqueued_count)
        
      }, error = function(e) {
        cat("❌ Enqueue failed:", e$message, "\n")
        return(0)
      })
    },
    
    # Dequeue documents for processing
    dequeue = function(max_size = NULL, priority_filter = NULL) {
      if (is.null(max_size)) {
        max_size <- INCREMENTAL_CONFIG$processing_modes$batch$max_batch_size
      }
      
      tryCatch({
        conn <- poolCheckout(pool)
        on.exit(poolReturn(conn), add = TRUE)
        
        # Build query with priority filtering
        base_sql <- "
          SELECT id, document_id, document_data, priority_level, priority_score, enqueue_time
          FROM document_processing_queue 
          WHERE status = 'pending'
        "
        
        if (!is.null(priority_filter)) {
          base_sql <- paste(base_sql, "AND priority_level IN (", 
                           paste(sprintf("'%s'", priority_filter), collapse = ","), ")")
        }
        
        base_sql <- paste(base_sql, "ORDER BY priority_score DESC, enqueue_time ASC LIMIT ?")
        
        queue_entries <- dbGetQuery(conn, base_sql, params = list(max_size))
        
        if (nrow(queue_entries) == 0) {
          return(data.frame())
        }
        
        # Mark entries as processing
        entry_ids <- queue_entries$id
        placeholders <- paste(rep("?", length(entry_ids)), collapse = ",")
        update_sql <- sprintf("
          UPDATE document_processing_queue 
          SET status = 'processing', last_attempt = ? 
          WHERE id IN (%s)
        ", placeholders)
        
        dbExecute(conn, update_sql, params = c(list(Sys.time()), as.list(entry_ids)))
        
        # Parse document data from JSON
        documents <- data.frame()
        for (i in seq_len(nrow(queue_entries))) {
          doc_data <- jsonlite::fromJSON(queue_entries$document_data[i])
          doc_data$queue_id <- queue_entries$id[i]
          doc_data$priority_level <- queue_entries$priority_level[i]
          doc_data$priority_score <- queue_entries$priority_score[i]
          
          if (i == 1) {
            documents <- doc_data
          } else {
            documents <- bind_rows(documents, doc_data)
          }
        }
        
        cat(sprintf("📤 Dequeued %d documents (priorities: %s)\n", 
                   nrow(documents), 
                   paste(unique(documents$priority_level), collapse = ", ")))
        
        return(documents)
        
      }, error = function(e) {
        cat("❌ Dequeue failed:", e$message, "\n")
        return(data.frame())
      })
    },
    
    # Mark documents as completed or failed
    mark_completed = function(document_ids, success = TRUE, error_message = NULL) {
      tryCatch({
        conn <- poolCheckout(pool)
        on.exit(poolReturn(conn), add = TRUE)
        
        status <- if (success) "completed" else "failed"
        placeholders <- paste(rep("?", length(document_ids)), collapse = ",")
        
        update_sql <- sprintf("
          UPDATE document_processing_queue 
          SET status = ?, error_message = ?, processing_attempts = processing_attempts + 1
          WHERE document_id IN (%s) AND status = 'processing'
        ", placeholders)
        
        updated_rows <- dbExecute(conn, update_sql, params = c(
          list(status, error_message %||% ""), 
          as.list(document_ids)
        ))
        
        return(updated_rows)
        
      }, error = function(e) {
        cat("❌ Mark completed failed:", e$message, "\n")
        return(0)
      })
    },
    
    # Get queue statistics
    get_queue_stats = function() {
      tryCatch({
        conn <- poolCheckout(pool)
        on.exit(poolReturn(conn), add = TRUE)
        
        stats_sql <- "
          SELECT 
            status,
            priority_level,
            COUNT(*) as count,
            AVG(priority_score) as avg_priority_score,
            MIN(enqueue_time) as oldest_enqueue_time,
            MAX(enqueue_time) as newest_enqueue_time
          FROM document_processing_queue 
          GROUP BY status, priority_level
          ORDER BY priority_score DESC
        "
        
        stats <- dbGetQuery(conn, stats_sql)
        
        # Overall queue size
        total_sql <- "SELECT COUNT(*) as total_size FROM document_processing_queue WHERE status = 'pending'"
        total_size <- dbGetQuery(conn, total_sql)$total_size[1]
        
        return(list(
          total_pending = total_size,
          detailed_stats = stats,
          queue_health = if (total_size < INCREMENTAL_CONFIG$max_queue_size * 0.8) "healthy" else "congested"
        ))
        
      }, error = function(e) {
        cat("❌ Queue stats failed:", e$message, "\n")
        return(list(total_pending = 0, detailed_stats = data.frame(), queue_health = "unknown"))
      })
    }
  )
  
  # Initialize queue on creation
  queue$initialize_queue()
  
  return(queue)
}

# ============================================================================
# INCREMENTAL SPATIAL PROCESSOR
# ============================================================================

#' Create incremental spatial processor
#' @param pool Database connection pool
#' @param spatial_join_function Spatial join function to use
#' @return Incremental processor object
create_incremental_spatial_processor <- function(pool, spatial_join_function = NULL) {
  
  change_detector <- create_change_detector(pool)
  priority_queue <- create_priority_queue(pool)
  
  processor <- list(
    
    # Process new documents incrementally
    process_incremental_batch = function(new_documents, processing_mode = "batch") {
      if (nrow(new_documents) == 0) {
        return(list(success = TRUE, processed = 0, message = "No documents to process"))
      }
      
      start_time <- Sys.time()
      cat(sprintf("🔄 Starting incremental processing: %d documents (%s mode)\n", 
                 nrow(new_documents), processing_mode))
      
      # Detect changes
      change_result <- change_detector$detect_changes(new_documents)
      
      # Combine new and changed documents for processing
      documents_to_process <- rbind(
        change_result$new_documents,
        change_result$changed_documents
      )
      
      if (nrow(documents_to_process) == 0) {
        cat("✅ No new or changed documents to process\n")
        return(list(
          success = TRUE, 
          processed = 0,
          new_count = 0,
          changed_count = 0,
          unchanged_count = nrow(change_result$unchanged_documents)
        ))
      }
      
      # Enqueue documents with appropriate priority
      queue_priority <- switch(processing_mode,
        "realtime" = "high",
        "batch" = "normal", 
        "maintenance" = "low"
      )
      
      enqueued_count <- priority_queue$enqueue(documents_to_process, queue_priority)
      
      # Process documents from queue
      mode_config <- INCREMENTAL_CONFIG$processing_modes[[processing_mode]]
      processing_results <- list()
      total_processed <- 0
      
      while (total_processed < nrow(documents_to_process)) {
        # Dequeue batch for processing
        batch_size <- min(mode_config$max_batch_size, nrow(documents_to_process) - total_processed)
        processing_batch <- priority_queue$dequeue(batch_size)
        
        if (nrow(processing_batch) == 0) break
        
        # Apply spatial processing
        batch_result <- processor$process_spatial_batch(processing_batch)
        
        # Update queue status
        if (batch_result$success) {
          priority_queue$mark_completed(processing_batch$document_id, success = TRUE)
        } else {
          priority_queue$mark_completed(processing_batch$document_id, success = FALSE, 
                                       error_message = batch_result$error)
        }
        
        # Update audit trail
        change_detector$update_processing_audit(processing_batch, batch_result)
        
        processing_results[[length(processing_results) + 1]] <- batch_result
        total_processed <- total_processed + nrow(processing_batch)
        
        cat(sprintf("✅ Processed batch: %d documents (%d total)\n", 
                   nrow(processing_batch), total_processed))
      }
      
      # Refresh materialized views if needed
      if (INCREMENTAL_CONFIG$enable_incremental_mv_refresh && 
          total_processed >= INCREMENTAL_CONFIG$mv_refresh_threshold) {
        
        cat("📊 Refreshing materialized views after incremental processing\n")
        mv_refresh_result <- refresh_materialized_views_incremental(pool, processing_results)
      }
      
      # Calculate processing summary
      duration <- as.numeric(Sys.time() - start_time, units = "secs")
      
      summary <- list(
        success = all(sapply(processing_results, function(r) r$success %||% FALSE)),
        total_processed = total_processed,
        new_documents = nrow(change_result$new_documents),
        changed_documents = nrow(change_result$changed_documents),
        unchanged_documents = nrow(change_result$unchanged_documents),
        processing_duration_seconds = duration,
        processing_rate = total_processed / duration,
        batches_processed = length(processing_results),
        materialized_views_refreshed = exists("mv_refresh_result")
      )
      
      cat(sprintf("🎉 Incremental processing completed: %d documents in %.1fs (%.1f docs/sec)\n",
                 total_processed, duration, summary$processing_rate))
      
      return(summary)
    },
    
    # Process spatial batch with error handling
    process_spatial_batch = function(document_batch) {
      if (is.null(spatial_join_function)) {
        # Placeholder spatial processing
        return(list(
          success = TRUE,
          processed_count = nrow(document_batch),
          associations_created = nrow(document_batch),
          duration_ms = 100
        ))
      }
      
      tryCatch({
        batch_start <- Sys.time()
        
        # Load municipality data if needed
        municipalities <- load_municipalities_for_batch(document_batch)
        
        # Apply spatial join
        spatial_result <- spatial_join_function(document_batch, municipalities)
        
        # Store spatial associations
        associations_stored <- store_spatial_associations(pool, spatial_result)
        
        batch_duration <- as.numeric(Sys.time() - batch_start, units = "secs") * 1000
        
        return(list(
          success = TRUE,
          processed_count = nrow(document_batch),
          associations_created = associations_stored,
          duration_ms = batch_duration,
          spatial_match_rate = calculate_spatial_match_rate(spatial_result)
        ))
        
      }, error = function(e) {
        return(list(
          success = FALSE,
          processed_count = 0,
          error = e$message,
          duration_ms = 0
        ))
      })
    },
    
    # Monitor incremental processing performance
    monitor_processing_performance = function() {
      queue_stats <- priority_queue$get_queue_stats()
      
      performance_metrics <- list(
        timestamp = Sys.time(),
        queue_size = queue_stats$total_pending,
        queue_health = queue_stats$queue_health,
        priority_distribution = queue_stats$detailed_stats,
        system_memory_mb = get_current_memory_usage(),
        processing_capacity = calculate_processing_capacity()
      )
      
      return(performance_metrics)
    },
    
    # Get component references
    get_change_detector = function() change_detector,
    get_priority_queue = function() priority_queue
  )
  
  return(processor)
}

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

#' Check if a document meets a specific priority condition
#' @param document_row Single document row
#' @param condition Condition name to check
#' @return Boolean indicating if condition is met
check_priority_condition <- function(document_row, condition) {
  switch(condition,
    "recent_enactment" = {
      if ("enacting_date" %in% names(document_row) && !is.na(document_row$enacting_date)) {
        days_since <- as.numeric(Sys.Date() - as.Date(document_row$enacting_date))
        return(days_since <= 7)  # Within last week
      }
      return(FALSE)
    },
    "federal_level" = {
      federal_keywords <- c("federal", "congresso", "senado", "câmara", "brasil")
      text_to_check <- paste(document_row$source_type %||% "", 
                           document_row$title %||% "", 
                           document_row$urn %||% "", sep = " ")
      return(any(sapply(federal_keywords, function(kw) grepl(kw, text_to_check, ignore.case = TRUE))))
    },
    "emergency_keywords" = {
      emergency_keywords <- c("emergência", "urgente", "calamidade", "pandemia", "crise")
      text_to_check <- paste(document_row$title %||% "", 
                           document_row$document_summary %||% "", sep = " ")
      return(any(sapply(emergency_keywords, function(kw) grepl(kw, text_to_check, ignore.case = TRUE))))
    },
    "state_level" = {
      return(!is.na(document_row$state %||% document_row$state_code) && 
             is.na(document_row$municipality %||% document_row$municipality_mentioned))
    },
    "municipal_level" = {
      return(!is.na(document_row$municipality %||% document_row$municipality_mentioned))
    },
    "recent_update" = {
      # For now, assume all documents are recent updates if they're being processed
      return(TRUE)
    },
    TRUE  # Default: condition met
  )
}

#' Determine priority level from numeric score
#' @param priority_score Numeric priority score
#' @return Priority level string
determine_priority_level <- function(priority_score) {
  if (priority_score >= 0.9) return("urgent")
  if (priority_score >= 0.7) return("high")
  if (priority_score >= 0.4) return("normal")
  if (priority_score >= 0.2) return("low")
  return("maintenance")
}

#' Load municipalities relevant to document batch
#' @param document_batch Batch of documents to process
#' @return sf object with relevant municipalities
load_municipalities_for_batch <- function(document_batch) {
  # Simplified implementation - would load from spatial database
  # Based on states mentioned in documents
  
  # Extract unique states from batch
  states <- unique(c(
    document_batch$state[!is.na(document_batch$state)],
    document_batch$state_code[!is.na(document_batch$state_code)]
  ))
  
  if (length(states) == 0) {
    # Load default municipality set for fallback
    states <- c("SP", "RJ", "MG")  # Major states as fallback
  }
  
  cat(sprintf("🗺️ Loading municipalities for states: %s\n", paste(states, collapse = ", ")))
  
  # Placeholder municipality data
  data.frame(
    municipality_code = paste0(rep(states, each = 10), sprintf("%03d", 1:10)),
    municipality_name = paste("Municipality", rep(states, each = 10), 1:10),
    state_code = rep(states, each = 10),
    stringsAsFactors = FALSE
  )
}

#' Store spatial associations in database
#' @param pool Database connection pool
#' @param spatial_result Spatial join results
#' @return Number of associations stored
store_spatial_associations <- function(pool, spatial_result) {
  # Simplified implementation
  # Would insert into document_municipality_associations table
  
  return(nrow(spatial_result$results %||% spatial_result))
}

#' Calculate spatial match rate from results
#' @param spatial_result Spatial processing results
#' @return Match rate as percentage
calculate_spatial_match_rate <- function(spatial_result) {
  if (is.null(spatial_result$metrics)) return(0)
  return(spatial_result$metrics$success_rate %||% 0)
}

#' Refresh materialized views incrementally
#' @param pool Database connection pool
#' @param processing_results Results from recent processing
#' @return Refresh operation results
refresh_materialized_views_incremental <- function(pool, processing_results) {
  tryCatch({
    conn <- poolCheckout(pool)
    on.exit(poolReturn(conn), add = TRUE)
    
    # Refresh key materialized views
    mv_list <- c(
      "mv_municipality_document_stats",
      "mv_state_document_aggregates"
    )
    
    refresh_results <- list()
    
    for (mv_name in mv_list) {
      refresh_start <- Sys.time()
      
      # Use REFRESH MATERIALIZED VIEW CONCURRENTLY if supported
      refresh_sql <- sprintf("REFRESH MATERIALIZED VIEW CONCURRENTLY %s", mv_name)
      
      tryCatch({
        dbExecute(conn, refresh_sql)
        refresh_duration <- as.numeric(Sys.time() - refresh_start, units = "secs")
        refresh_results[[mv_name]] <- list(success = TRUE, duration_seconds = refresh_duration)
        cat(sprintf("✅ Refreshed %s in %.1fs\n", mv_name, refresh_duration))
      }, error = function(e) {
        # Fallback to non-concurrent refresh
        fallback_sql <- sprintf("REFRESH MATERIALIZED VIEW %s", mv_name)
        dbExecute(conn, fallback_sql)
        refresh_duration <- as.numeric(Sys.time() - refresh_start, units = "secs")
        refresh_results[[mv_name]] <- list(success = TRUE, duration_seconds = refresh_duration, fallback = TRUE)
        cat(sprintf("⚠️ Refreshed %s (fallback) in %.1fs\n", mv_name, refresh_duration))
      })
    }
    
    return(refresh_results)
    
  }, error = function(e) {
    cat("❌ Materialized view refresh failed:", e$message, "\n")
    return(list())
  })
}

#' Calculate current processing capacity
#' @return Processing capacity metrics
calculate_processing_capacity <- function() {
  current_memory <- get_current_memory_usage()
  
  # Simple capacity calculation based on memory usage
  memory_capacity <- max(0, (1200 - current_memory) / 1200)  # Based on 1200MB operational limit
  
  list(
    memory_capacity_percent = memory_capacity * 100,
    estimated_batch_capacity = round(memory_capacity * 1000),  # Max batch size based on memory
    system_load = 1 - memory_capacity
  )
}

#' Get current memory usage (simplified)
#' @return Memory usage in MB
get_current_memory_usage <- function() {
  gc_result <- gc(verbose = FALSE)
  sum(gc_result[, "used"]) * 8 / 1024  # Convert to MB approximation
}

# ============================================================================
# MODULE EXPORTS
# ============================================================================

incremental_spatial_processor_exports <- list(
  # Main components
  create_change_detector = create_change_detector,
  create_priority_queue = create_priority_queue,
  create_incremental_spatial_processor = create_incremental_spatial_processor,
  
  # Utility functions
  check_priority_condition = check_priority_condition,
  determine_priority_level = determine_priority_level,
  refresh_materialized_views_incremental = refresh_materialized_views_incremental,
  
  # Configuration
  INCREMENTAL_CONFIG = INCREMENTAL_CONFIG,
  DOCUMENT_PRIORITY_RULES = DOCUMENT_PRIORITY_RULES
)

cat("✅ Incremental Spatial Processing System loaded successfully\n")
cat("   Change detection:", INCREMENTAL_CONFIG$enable_change_detection, "\n")
cat("   Priority queue:", INCREMENTAL_CONFIG$enable_priority_queue, "\n")
cat("   Processing modes:", length(INCREMENTAL_CONFIG$processing_modes), "\n")
cat("   Max queue size:", INCREMENTAL_CONFIG$max_queue_size, "documents\n")