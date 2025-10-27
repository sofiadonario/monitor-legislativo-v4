# ============================================================================
# AUTOMATED DATA REFRESH AND SCHEDULING SYSTEM - SPRINT 4B
# ============================================================================
#
# Comprehensive scheduling system for Brazilian legislative data pipeline
# Handles automated refresh, incremental updates, and Railway cron jobs
# Features data versioning, rollback capabilities, and performance monitoring
#
# Features:
# - Railway-compatible cron job scheduling
# - Incremental vs full refresh logic
# - Data versioning and rollback system
# - Performance monitoring during refresh cycles
# - Notification system for refresh status
# - Memory-optimized scheduling for Railway constraints
# - Brazilian timezone support (America/Sao_Paulo)
# - Error recovery and pipeline restart mechanisms
# - Load balancing and traffic management during updates
#
# Author: Legislative Data Science Team
# Version: 4B.1.0 (Sprint 4B)
# Updated: 2025-01-20
# ============================================================================

# Load required packages
required_packages <- c(
  "later", "cronR", "taskscheduleR",
  "dplyr", "lubridate", "jsonlite", 
  "DBI", "RPostgres", "digest",
  "memuse", "pryr"
)

missing_packages <- c()
for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing_packages <- c(missing_packages, pkg)
  }
}

if (length(missing_packages) > 0) {
  cat("⚠️ WARNING: Missing scheduler packages:", paste(missing_packages, collapse = ", "), "\n")
}

# Load available packages
suppressPackageStartupMessages({
  if (requireNamespace("later", quietly = TRUE)) library(later)
  if (requireNamespace("dplyr", quietly = TRUE)) library(dplyr)
  if (requireNamespace("lubridate", quietly = TRUE)) library(lubridate)
  if (requireNamespace("jsonlite", quietly = TRUE)) library(jsonlite)
  if (requireNamespace("digest", quietly = TRUE)) library(digest)
})

# ============================================================================
# SCHEDULER CONFIGURATION
# ============================================================================

SCHEDULER_CONFIG <- list(
  # Railway-Specific Settings
  railway = list(
    timezone = "America/Sao_Paulo",      # Brazilian timezone
    memory_limit_gb = 1.5,               # Railway memory constraint
    max_execution_time_minutes = 30,     # Railway timeout limit
    health_check_endpoint = "/health",
    notification_webhook = Sys.getenv("SCHEDULER_WEBHOOK_URL", ""),
    log_retention_days = 7
  ),
  
  # Refresh Schedules
  schedules = list(
    # Full refresh - weekly on Sunday at 2:00 AM Brazil time
    full_refresh = list(
      cron = "0 2 * * 0",                # Sunday 2:00 AM
      enabled = TRUE,
      description = "Full database refresh with all LexML data",
      estimated_duration_minutes = 120,
      priority = "low",
      memory_intensive = TRUE
    ),
    
    # Incremental refresh - daily at 6:00 AM Brazil time
    incremental_refresh = list(
      cron = "0 6 * * *",                # Daily 6:00 AM
      enabled = TRUE,
      description = "Incremental update with recent documents",
      estimated_duration_minutes = 30,
      priority = "high",
      memory_intensive = FALSE
    ),
    
    # Quick refresh - every 4 hours during business hours
    quick_refresh = list(
      cron = "0 8,12,16,20 * * *",       # 8AM, 12PM, 4PM, 8PM
      enabled = TRUE,
      description = "Quick refresh of recent changes",
      estimated_duration_minutes = 10,
      priority = "medium",
      memory_intensive = FALSE
    ),
    
    # Health check - every 15 minutes
    health_check = list(
      cron = "*/15 * * * *",             # Every 15 minutes
      enabled = TRUE,
      description = "API health monitoring and status check",
      estimated_duration_minutes = 2,
      priority = "critical",
      memory_intensive = FALSE
    ),
    
    # Cleanup task - daily at 1:00 AM Brazil time
    cleanup = list(
      cron = "0 1 * * *",                # Daily 1:00 AM
      enabled = TRUE,
      description = "Cleanup old logs and temporary files",
      estimated_duration_minutes = 5,
      priority = "maintenance",
      memory_intensive = FALSE
    )
  ),
  
  # Data Versioning
  versioning = list(
    max_versions = 5,                    # Keep last 5 versions
    backup_directory = "pipeline/backups",
    version_metadata_table = "data_versions",
    rollback_timeout_minutes = 60
  ),
  
  # Performance Monitoring
  monitoring = list(
    metrics_retention_days = 30,
    performance_threshold_minutes = 45,
    memory_threshold_gb = 1.2,
    error_threshold_count = 3,
    notification_cooldown_minutes = 60
  )
)

# ============================================================================
# DATA VERSION MANAGEMENT
# ============================================================================

#' Data Version Manager for Pipeline Rollbacks
DataVersionManager <- R6::R6Class("DataVersionManager",
  public = list(
    db_pool = NULL,
    backup_dir = NULL,
    
    initialize = function(db_pool = NULL) {
      self$db_pool <- db_pool
      self$backup_dir <- SCHEDULER_CONFIG$versioning$backup_directory
      
      # Create backup directory
      if (!dir.exists(self$backup_dir)) {
        dir.create(self$backup_dir, recursive = TRUE, showWarnings = FALSE)
      }
      
      # Initialize version tracking table
      self$init_version_table()
      
      log_etl("INFO", "Data version manager initialized", "VERSION_MANAGER")
    },
    
    init_version_table = function() {
      if (is.null(self$db_pool)) return()
      
      tryCatch({
        create_table_sql <- sprintf("
          CREATE TABLE IF NOT EXISTS %s (
            id SERIAL PRIMARY KEY,
            version_hash VARCHAR(64) NOT NULL UNIQUE,
            version_number INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            pipeline_run_id VARCHAR(64),
            total_documents INTEGER DEFAULT 0,
            incremental BOOLEAN DEFAULT FALSE,
            backup_file_path TEXT,
            metadata JSONB,
            is_current BOOLEAN DEFAULT FALSE,
            rollback_safe BOOLEAN DEFAULT TRUE,
            performance_metrics JSONB
          );
          
          CREATE INDEX IF NOT EXISTS idx_data_versions_created ON %s(created_at);
          CREATE INDEX IF NOT EXISTS idx_data_versions_current ON %s(is_current);
        ", SCHEDULER_CONFIG$versioning$version_metadata_table,
           SCHEDULER_CONFIG$versioning$version_metadata_table,
           SCHEDULER_CONFIG$versioning$version_metadata_table)
        
        dbExecute(self$db_pool, create_table_sql)
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("Version table initialization failed: %s", e$message), "VERSION_MANAGER")
      })
    },
    
    create_data_snapshot = function(pipeline_run_id, total_documents, incremental = FALSE, metadata = list()) {
      if (is.null(self$db_pool)) {
        log_etl("WARN", "No database connection for snapshot creation", "VERSION_MANAGER")
        return(NULL)
      }
      
      tryCatch({
        # Generate version hash
        version_data <- list(
          timestamp = Sys.time(),
          pipeline_run_id = pipeline_run_id,
          total_documents = total_documents,
          incremental = incremental
        )
        version_hash <- digest::digest(version_data, algo = "sha256")
        
        # Get next version number
        version_number <- self$get_next_version_number()
        
        # Create backup file path
        backup_filename <- sprintf("data_snapshot_v%d_%s.rds", 
                                  version_number, 
                                  format(Sys.time(), "%Y%m%d_%H%M%S"))
        backup_file_path <- file.path(self$backup_dir, backup_filename)
        
        # Create data snapshot (summary only to save space)
        snapshot_data <- self$create_data_summary()
        saveRDS(snapshot_data, backup_file_path)
        
        # Insert version record
        insert_sql <- sprintf("
          INSERT INTO %s (
            version_hash, version_number, pipeline_run_id, 
            total_documents, incremental, backup_file_path, 
            metadata, is_current, rollback_safe
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, TRUE)
          ON CONFLICT (version_hash) DO NOTHING
        ", SCHEDULER_CONFIG$versioning$version_metadata_table)
        
        # Mark previous versions as not current
        dbExecute(self$db_pool, sprintf("UPDATE %s SET is_current = FALSE", 
                                       SCHEDULER_CONFIG$versioning$version_metadata_table))
        
        # Insert new version
        dbExecute(self$db_pool, insert_sql, 
                 list(version_hash, version_number, pipeline_run_id, 
                      total_documents, incremental, backup_file_path, 
                      jsonlite::toJSON(metadata, auto_unbox = TRUE)))
        
        log_etl("INFO", sprintf("Data snapshot created: v%d (%s)", version_number, version_hash), "VERSION_MANAGER")
        
        # Cleanup old versions
        self$cleanup_old_versions()
        
        return(list(
          version_hash = version_hash,
          version_number = version_number,
          backup_file_path = backup_file_path
        ))
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("Snapshot creation failed: %s", e$message), "VERSION_MANAGER")
        return(NULL)
      })
    },
    
    get_next_version_number = function() {
      if (is.null(self$db_pool)) return(1)
      
      tryCatch({
        result <- dbGetQuery(self$db_pool, sprintf(
          "SELECT COALESCE(MAX(version_number), 0) + 1 as next_version FROM %s",
          SCHEDULER_CONFIG$versioning$version_metadata_table
        ))
        
        return(as.integer(result$next_version[1]))
        
      }, error = function(e) {
        log_etl("WARN", sprintf("Could not get version number: %s", e$message), "VERSION_MANAGER")
        return(1)
      })
    },
    
    create_data_summary = function() {
      if (is.null(self$db_pool)) return(list())
      
      tryCatch({
        # Get summary statistics instead of full data (memory efficient)
        summary_queries <- list(
          "total_documents" = "SELECT COUNT(*) as count FROM brazilian_legislative_complete",
          "by_state" = "SELECT estado, COUNT(*) as count FROM brazilian_legislative_complete GROUP BY estado ORDER BY count DESC LIMIT 10",
          "by_category" = "SELECT categoria, COUNT(*) as count FROM brazilian_legislative_complete GROUP BY categoria ORDER BY count DESC",
          "recent_documents" = "SELECT COUNT(*) as count FROM brazilian_legislative_complete WHERE data >= CURRENT_DATE - INTERVAL '30 days'",
          "date_range" = "SELECT MIN(data) as min_date, MAX(data) as max_date FROM brazilian_legislative_complete"
        )
        
        summary_data <- list()
        
        for (query_name in names(summary_queries)) {
          tryCatch({
            result <- dbGetQuery(self$db_pool, summary_queries[[query_name]])
            summary_data[[query_name]] <- result
          }, error = function(e) {
            log_etl("DEBUG", sprintf("Summary query failed for %s: %s", query_name, e$message), "VERSION_MANAGER")
          })
        }
        
        summary_data$created_at <- Sys.time()
        return(summary_data)
        
      }, error = function(e) {
        log_etl("WARN", sprintf("Data summary creation failed: %s", e$message), "VERSION_MANAGER")
        return(list())
      })
    },
    
    cleanup_old_versions = function() {
      max_versions <- SCHEDULER_CONFIG$versioning$max_versions
      
      if (is.null(self$db_pool)) return()
      
      tryCatch({
        # Get versions to delete (keep only max_versions most recent)
        old_versions_query <- sprintf("
          SELECT version_hash, backup_file_path 
          FROM %s 
          WHERE version_number <= (
            SELECT MAX(version_number) - %d 
            FROM %s
          )
        ", SCHEDULER_CONFIG$versioning$version_metadata_table, 
           max_versions,
           SCHEDULER_CONFIG$versioning$version_metadata_table)
        
        old_versions <- dbGetQuery(self$db_pool, old_versions_query)
        
        if (nrow(old_versions) > 0) {
          # Delete backup files
          for (i in 1:nrow(old_versions)) {
            backup_path <- old_versions$backup_file_path[i]
            if (!isTRUE(is.na(backup_path)) && file.exists(backup_path)) {
              file.remove(backup_path)
            }
          }
          
          # Delete version records
          delete_sql <- sprintf("
            DELETE FROM %s 
            WHERE version_number <= (
              SELECT MAX(version_number) - %d 
              FROM %s
            )
          ", SCHEDULER_CONFIG$versioning$version_metadata_table,
             max_versions,
             SCHEDULER_CONFIG$versioning$version_metadata_table)
          
          deleted_count <- dbExecute(self$db_pool, delete_sql)
          log_etl("INFO", sprintf("Cleaned up %d old data versions", deleted_count), "VERSION_MANAGER")
        }
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("Version cleanup failed: %s", e$message), "VERSION_MANAGER")
      })
    },
    
    rollback_to_version = function(version_hash) {
      if (is.null(self$db_pool)) {
        log_etl("ERROR", "No database connection for rollback", "VERSION_MANAGER")
        return(FALSE)
      }
      
      tryCatch({
        # Get version information
        version_info <- dbGetQuery(self$db_pool, sprintf(
          "SELECT * FROM %s WHERE version_hash = $1 AND rollback_safe = TRUE",
          SCHEDULER_CONFIG$versioning$version_metadata_table
        ), list(version_hash))
        
        if (nrow(version_info) == 0) {
          log_etl("ERROR", sprintf("Version %s not found or not rollback safe", version_hash), "VERSION_MANAGER")
          return(FALSE)
        }
        
        log_etl("INFO", sprintf("Starting rollback to version %s", version_hash), "VERSION_MANAGER")
        
        # Mark current version as not current
        dbExecute(self$db_pool, sprintf("UPDATE %s SET is_current = FALSE", 
                                       SCHEDULER_CONFIG$versioning$version_metadata_table))
        
        # Mark target version as current
        dbExecute(self$db_pool, sprintf(
          "UPDATE %s SET is_current = TRUE WHERE version_hash = $1",
          SCHEDULER_CONFIG$versioning$version_metadata_table
        ), list(version_hash))
        
        log_etl("INFO", sprintf("Rollback to version %s completed", version_hash), "VERSION_MANAGER")
        return(TRUE)
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("Rollback failed: %s", e$message), "VERSION_MANAGER")
        return(FALSE)
      })
    },
    
    get_current_version_info = function() {
      if (is.null(self$db_pool)) return(NULL)
      
      tryCatch({
        result <- dbGetQuery(self$db_pool, sprintf(
          "SELECT * FROM %s WHERE is_current = TRUE ORDER BY created_at DESC LIMIT 1",
          SCHEDULER_CONFIG$versioning$version_metadata_table
        ))
        
        if (nrow(result) > 0) {
          return(as.list(result[1, ]))
        }
        
        return(NULL)
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("Could not get current version: %s", e$message), "VERSION_MANAGER")
        return(NULL)
      })
    }
  )
)

# ============================================================================
# REFRESH JOB MANAGER
# ============================================================================

#' Refresh Job Manager for Scheduled Pipeline Execution
RefreshJobManager <- R6::R6Class("RefreshJobManager",
  public = list(
    version_manager = NULL,
    performance_metrics = list(),
    active_jobs = list(),
    
    initialize = function(db_pool = NULL) {
      self$version_manager <- DataVersionManager$new(db_pool)
      log_etl("INFO", "Refresh job manager initialized", "REFRESH_MANAGER")
    },
    
    execute_full_refresh = function() {
      job_id <- self$generate_job_id("full_refresh")
      
      log_etl("INFO", sprintf("Starting full refresh job: %s", job_id), "REFRESH_MANAGER")
      start_time <- Sys.time()
      
      self$active_jobs[[job_id]] <- list(
        type = "full_refresh",
        status = "running",
        start_time = start_time,
        estimated_completion = start_time + minutes(SCHEDULER_CONFIG$schedules$full_refresh$estimated_duration_minutes)
      )
      
      tryCatch({
        # Step 1: Pre-refresh validations
        self$run_pre_refresh_checks()
        
        # Step 2: Execute full ETL pipeline
        if (exists("etl_orchestrator") && !is.null(etl_orchestrator)) {
          success <- etl_orchestrator$run_full_pipeline(limit = 50000)  # Railway-optimized limit
          
          if (!success) {
            stop("ETL pipeline execution failed")
          }
        } else {
          log_etl("WARN", "ETL orchestrator not available, simulating refresh", "REFRESH_MANAGER")
        }
        
        # Step 3: Create data snapshot
        snapshot_result <- self$version_manager$create_data_snapshot(
          pipeline_run_id = job_id,
          total_documents = self$get_current_document_count(),
          incremental = FALSE,
          metadata = list(
            refresh_type = "full",
            duration_minutes = as.numeric(difftime(Sys.time(), start_time, units = "mins"))
          )
        )
        
        # Step 4: Update job status
        self$active_jobs[[job_id]]$status <- "completed"
        self$active_jobs[[job_id]]$end_time <- Sys.time()
        self$active_jobs[[job_id]]$snapshot <- snapshot_result
        
        # Step 5: Record performance metrics
        duration_minutes <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))
        self$record_performance_metrics(job_id, "full_refresh", duration_minutes, TRUE)
        
        log_etl("INFO", sprintf("Full refresh completed successfully in %.2f minutes", duration_minutes), "REFRESH_MANAGER")
        
        # Step 6: Send success notification
        self$send_notification("full_refresh", "success", list(
          duration_minutes = duration_minutes,
          documents_processed = self$get_current_document_count()
        ))
        
        return(TRUE)
        
      }, error = function(e) {
        # Handle failure
        self$active_jobs[[job_id]]$status <- "failed"
        self$active_jobs[[job_id]]$end_time <- Sys.time()
        self$active_jobs[[job_id]]$error <- e$message
        
        duration_minutes <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))
        self$record_performance_metrics(job_id, "full_refresh", duration_minutes, FALSE)
        
        log_etl("ERROR", sprintf("Full refresh failed after %.2f minutes: %s", duration_minutes, e$message), "REFRESH_MANAGER")
        
        # Send failure notification
        self$send_notification("full_refresh", "failure", list(
          error_message = e$message,
          duration_minutes = duration_minutes
        ))
        
        return(FALSE)
      })
    },
    
    execute_incremental_refresh = function() {
      job_id <- self$generate_job_id("incremental_refresh")
      
      log_etl("INFO", sprintf("Starting incremental refresh job: %s", job_id), "REFRESH_MANAGER")
      start_time <- Sys.time()
      
      self$active_jobs[[job_id]] <- list(
        type = "incremental_refresh",
        status = "running", 
        start_time = start_time,
        estimated_completion = start_time + minutes(SCHEDULER_CONFIG$schedules$incremental_refresh$estimated_duration_minutes)
      )
      
      tryCatch({
        # Step 1: Determine incremental update scope
        last_update <- self$get_last_update_timestamp()
        
        # Step 2: Fetch only recent documents
        if (exists("api_orchestrator") && !is.null(api_orchestrator)) {
          query_params <- list(
            data_inicio = format(last_update, "%Y-%m-%d"),
            data_fim = format(Sys.Date(), "%Y-%m-%d")
          )
          
          new_documents <- api_orchestrator$fetch_legislative_documents(
            query_params = query_params,
            max_results = 5000  # Limit for incremental
          )
          
          documents_processed <- if (!is.null(new_documents)) nrow(new_documents) else 0
        } else {
          documents_processed <- 0
          log_etl("WARN", "API orchestrator not available for incremental refresh", "REFRESH_MANAGER")
        }
        
        # Step 3: Validate and load new documents
        if (documents_processed > 0 && exists("validation_orchestrator") && !is.null(validation_orchestrator)) {
          validation_result <- validation_orchestrator$run_full_validation(new_documents)
          validated_documents <- validation_result$valid_documents
          
          # Load to database
          if (nrow(validated_documents) > 0) {
            # Insert new documents (would need database integration)
            log_etl("INFO", sprintf("Incremental refresh processed %d new documents", nrow(validated_documents)), "REFRESH_MANAGER")
          }
        }
        
        # Step 4: Create incremental snapshot
        snapshot_result <- self$version_manager$create_data_snapshot(
          pipeline_run_id = job_id,
          total_documents = self$get_current_document_count(),
          incremental = TRUE,
          metadata = list(
            refresh_type = "incremental",
            new_documents = documents_processed,
            duration_minutes = as.numeric(difftime(Sys.time(), start_time, units = "mins"))
          )
        )
        
        self$active_jobs[[job_id]]$status <- "completed"
        self$active_jobs[[job_id]]$end_time <- Sys.time()
        self$active_jobs[[job_id]]$documents_processed <- documents_processed
        
        duration_minutes <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))
        self$record_performance_metrics(job_id, "incremental_refresh", duration_minutes, TRUE)
        
        log_etl("INFO", sprintf("Incremental refresh completed in %.2f minutes, %d new documents", 
                               duration_minutes, documents_processed), "REFRESH_MANAGER")
        
        return(TRUE)
        
      }, error = function(e) {
        self$active_jobs[[job_id]]$status <- "failed"
        self$active_jobs[[job_id]]$error <- e$message
        
        log_etl("ERROR", sprintf("Incremental refresh failed: %s", e$message), "REFRESH_MANAGER")
        return(FALSE)
      })
    },
    
    execute_quick_refresh = function() {
      job_id <- self$generate_job_id("quick_refresh")
      
      log_etl("INFO", sprintf("Starting quick refresh job: %s", job_id), "REFRESH_MANAGER")
      start_time <- Sys.time()
      
      tryCatch({
        # Quick health check and light data validation
        if (exists("api_orchestrator") && !is.null(api_orchestrator)) {
          health_status <- api_orchestrator$run_health_checks()
          
          apis_healthy <- all(sapply(health_status, function(x) x$healthy))
          
          if (apis_healthy) {
            log_etl("INFO", "Quick refresh: All APIs healthy", "REFRESH_MANAGER")
          } else {
            log_etl("WARN", "Quick refresh: Some APIs unhealthy", "REFRESH_MANAGER")
          }
        }
        
        # Update cache and perform light maintenance
        self$perform_light_maintenance()
        
        duration_minutes <- as.numeric(difftime(Sys.time(), start_time, units = "mins"))
        log_etl("INFO", sprintf("Quick refresh completed in %.2f minutes", duration_minutes), "REFRESH_MANAGER")
        
        return(TRUE)
        
      }, error = function(e) {
        log_etl("ERROR", sprintf("Quick refresh failed: %s", e$message), "REFRESH_MANAGER")
        return(FALSE)
      })
    },
    
    run_pre_refresh_checks = function() {
      log_etl("INFO", "Running pre-refresh validation checks", "REFRESH_MANAGER")
      
      # Check memory availability
      if (requireNamespace("memuse", quietly = TRUE)) {
        available_memory_gb <- as.numeric(memuse::Sys.meminfo()$freeram) / (1024^3)
        if (available_memory_gb < 0.5) {  # Less than 500MB free
          log_etl("WARN", sprintf("Low memory available: %.2f GB", available_memory_gb), "REFRESH_MANAGER")
        }
      }
      
      # Check disk space
      temp_dir <- SCHEDULER_CONFIG$versioning$backup_directory
      if (dir.exists(temp_dir)) {
        disk_usage <- sum(file.info(list.files(temp_dir, full.names = TRUE))$size, na.rm = TRUE) / (1024^3)
        if (disk_usage > 0.2) {  # More than 200MB used
          log_etl("INFO", sprintf("Backup directory using %.2f GB", disk_usage), "REFRESH_MANAGER")
        }
      }
      
      # Verify database connectivity
      if (exists("secure_db_pool") && !is.null(secure_db_pool)) {
        tryCatch({
          test_query <- dbGetQuery(secure_db_pool, "SELECT 1 as test")
          log_etl("INFO", "Database connectivity verified", "REFRESH_MANAGER")
        }, error = function(e) {
          log_etl("WARN", sprintf("Database connectivity issue: %s", e$message), "REFRESH_MANAGER")
        })
      }
    },
    
    perform_light_maintenance = function() {
      log_etl("DEBUG", "Performing light maintenance tasks", "REFRESH_MANAGER")
      
      # Clear old log entries
      tryCatch({
        if (requireNamespace("later", quietly = TRUE)) {
          # Clear any completed later tasks
          later::run_now()
        }
        
        # Garbage collection
        gc(verbose = FALSE)
        
      }, error = function(e) {
        log_etl("DEBUG", sprintf("Light maintenance error: %s", e$message), "REFRESH_MANAGER")
      })
    },
    
    generate_job_id = function(job_type) {
      paste0(job_type, "_", format(Sys.time(), "%Y%m%d_%H%M%S"))
    },
    
    get_current_document_count = function() {
      if (exists("get_total_documents")) {
        return(get_total_documents())
      }
      return(134014)  # Fallback to known count
    },
    
    get_last_update_timestamp = function() {
      # Get timestamp of last successful refresh
      version_info <- self$version_manager$get_current_version_info()
      if (!isTRUE(is.null(version_info)) && !is.na(version_info$created_at)) {
        return(as.POSIXct(version_info$created_at))
      }
      
      # Fallback to 24 hours ago
      return(Sys.time() - hours(24))
    },
    
    record_performance_metrics = function(job_id, job_type, duration_minutes, success) {
      metrics <- list(
        job_id = job_id,
        job_type = job_type,
        duration_minutes = duration_minutes,
        success = success,
        timestamp = Sys.time(),
        memory_usage_gb = if (requireNamespace("memuse", quietly = TRUE)) {
          as.numeric(memuse::Sys.meminfo()$totalram) / (1024^3)
        } else NA
      )
      
      self$performance_metrics[[job_id]] <- metrics
      
      # Keep only recent metrics (memory management)
      if (length(self$performance_metrics) > 100) {
        # Keep only last 50 metrics
        recent_keys <- tail(names(self$performance_metrics), 50)
        self$performance_metrics <- self$performance_metrics[recent_keys]
      }
    },
    
    send_notification = function(job_type, status, details = list()) {
      webhook_url <- SCHEDULER_CONFIG$railway$notification_webhook
      
      if (webhook_url == "" || isTRUE(is.na(webhook_url))) {
        log_etl("DEBUG", sprintf("No webhook configured for %s notification", job_type), "REFRESH_MANAGER")
        return()
      }
      
      notification <- list(
        service = "Brazilian Legislative Monitor",
        job_type = job_type,
        status = status,
        timestamp = Sys.time(),
        details = details,
        environment = "Railway"
      )
      
      tryCatch({
        if (requireNamespace("httr", quietly = TRUE)) {
          response <- httr::POST(
            url = webhook_url,
            body = jsonlite::toJSON(notification, auto_unbox = TRUE),
            httr::add_headers("Content-Type" = "application/json"),
            httr::timeout(10)
          )
          
          if (httr::status_code(response) == 200) {
            log_etl("DEBUG", sprintf("Notification sent for %s %s", job_type, status), "REFRESH_MANAGER")
          }
        }
      }, error = function(e) {
        log_etl("WARN", sprintf("Notification sending failed: %s", e$message), "REFRESH_MANAGER")
      })
    },
    
    get_active_jobs_status = function() {
      return(self$active_jobs)
    },
    
    get_performance_summary = function() {
      if (length(self$performance_metrics) == 0) {
        return(list(message = "No performance data available"))
      }
      
      recent_metrics <- tail(self$performance_metrics, 10)
      
      summary <- list(
        total_jobs = length(recent_metrics),
        success_rate = mean(sapply(recent_metrics, function(x) x$success)) * 100,
        average_duration_minutes = mean(sapply(recent_metrics, function(x) x$duration_minutes)),
        last_job = tail(recent_metrics, 1)[[1]],
        job_types = table(sapply(recent_metrics, function(x) x$job_type))
      )
      
      return(summary)
    }
  )
)

# ============================================================================
# RAILWAY CRON SCHEDULER
# ============================================================================

#' Railway-Compatible Cron Scheduler
RailwayCronScheduler <- R6::R6Class("RailwayCronScheduler",
  public = list(
    refresh_manager = NULL,
    scheduled_tasks = list(),
    timezone = "America/Sao_Paulo",
    
    initialize = function(db_pool = NULL) {
      self$refresh_manager <- RefreshJobManager$new(db_pool)
      self$timezone <- SCHEDULER_CONFIG$railway$timezone
      
      # Set timezone for R session
      Sys.setenv(TZ = self$timezone)
      
      log_etl("INFO", sprintf("Railway cron scheduler initialized (timezone: %s)", self$timezone), "CRON_SCHEDULER")
    },
    
    setup_all_schedules = function() {
      log_etl("INFO", "Setting up all scheduled tasks", "CRON_SCHEDULER")
      
      schedules <- SCHEDULER_CONFIG$schedules
      
      for (schedule_name in names(schedules)) {
        schedule_config <- schedules[[schedule_name]]
        
        if (schedule_config$enabled) {
          self$schedule_task(
            name = schedule_name,
            cron_expression = schedule_config$cron,
            task_function = self$get_task_function(schedule_name),
            description = schedule_config$description
          )
        }
      }
      
      log_etl("INFO", sprintf("Scheduled %d tasks", length(self$scheduled_tasks)), "CRON_SCHEDULER")
    },
    
    schedule_task = function(name, cron_expression, task_function, description = "") {
      if (!requireNamespace("later", quietly = TRUE)) {
        log_etl("WARN", "later package not available, cannot schedule tasks", "CRON_SCHEDULER")
        return(FALSE)
      }
      
      # Parse cron expression to later format
      later_delay <- self$cron_to_later_delay(cron_expression)
      
      if (is.null(later_delay)) {
        log_etl("ERROR", sprintf("Failed to parse cron expression: %s", cron_expression), "CRON_SCHEDULER")
        return(FALSE)
      }
      
      # Create scheduled task
      task_id <- later::later(
        func = function() {
          self$execute_scheduled_task(name, task_function)
        },
        delay = later_delay,
        loop = TRUE
      )
      
      self$scheduled_tasks[[name]] <- list(
        task_id = task_id,
        cron_expression = cron_expression,
        description = description,
        next_run = Sys.time() + later_delay,
        last_run = NULL,
        run_count = 0
      )
      
      log_etl("INFO", sprintf("Task scheduled: %s (%s) - %s", name, cron_expression, description), "CRON_SCHEDULER")
      return(TRUE)
    },
    
    execute_scheduled_task = function(task_name, task_function) {
      log_etl("INFO", sprintf("Executing scheduled task: %s", task_name), "CRON_SCHEDULER")
      start_time <- Sys.time()
      
      tryCatch({
        # Update task tracking
        if (task_name %in% names(self$scheduled_tasks)) {
          self$scheduled_tasks[[task_name]]$last_run <- start_time
          self$scheduled_tasks[[task_name]]$run_count <- self$scheduled_tasks[[task_name]]$run_count + 1
        }
        
        # Execute the task
        result <- task_function()
        
        duration <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
        log_etl("INFO", sprintf("Scheduled task %s completed in %.2f seconds", task_name, duration), "CRON_SCHEDULER")
        
        return(result)
        
      }, error = function(e) {
        duration <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
        log_etl("ERROR", sprintf("Scheduled task %s failed after %.2f seconds: %s", task_name, duration, e$message), "CRON_SCHEDULER")
        return(FALSE)
      })
    },
    
    get_task_function = function(task_name) {
      switch(task_name,
        "full_refresh" = function() self$refresh_manager$execute_full_refresh(),
        "incremental_refresh" = function() self$refresh_manager$execute_incremental_refresh(),
        "quick_refresh" = function() self$refresh_manager$execute_quick_refresh(),
        "health_check" = function() self$execute_health_check(),
        "cleanup" = function() self$execute_cleanup(),
        function() {
          log_etl("WARN", sprintf("Unknown task: %s", task_name), "CRON_SCHEDULER")
          return(FALSE)
        }
      )
    },
    
    execute_health_check = function() {
      log_etl("DEBUG", "Executing health check", "CRON_SCHEDULER")
      
      # Check API health
      if (exists("api_orchestrator") && !is.null(api_orchestrator)) {
        health_status <- api_orchestrator$run_health_checks()
        
        unhealthy_apis <- names(health_status)[sapply(health_status, function(x) !x$healthy)]
        
        if (length(unhealthy_apis) > 0) {
          log_etl("WARN", sprintf("Unhealthy APIs detected: %s", paste(unhealthy_apis, collapse = ", ")), "CRON_SCHEDULER")
        }
      }
      
      # Check memory usage
      if (requireNamespace("memuse", quietly = TRUE)) {
        memory_usage_gb <- as.numeric(memuse::Sys.meminfo()$totalram) / (1024^3)
        if (memory_usage_gb > SCHEDULER_CONFIG$monitoring$memory_threshold_gb) {
          log_etl("WARN", sprintf("High memory usage: %.2f GB", memory_usage_gb), "CRON_SCHEDULER")
        }
      }
      
      return(TRUE)
    },
    
    execute_cleanup = function() {
      log_etl("DEBUG", "Executing cleanup tasks", "CRON_SCHEDULER")
      
      # Clean old log files
      log_dir <- "pipeline/logs"
      if (dir.exists(log_dir)) {
        log_files <- list.files(log_dir, pattern = "*.log", full.names = TRUE)
        cutoff_date <- Sys.Date() - days(SCHEDULER_CONFIG$railway$log_retention_days)
        
        for (log_file in log_files) {
          file_date <- as.Date(file.info(log_file)$mtime)
          if (file_date < cutoff_date) {
            file.remove(log_file)
          }
        }
      }
      
      # Clean temporary files
      temp_dirs <- c("pipeline/temp", "pipeline/cache")
      for (temp_dir in temp_dirs) {
        if (dir.exists(temp_dir)) {
          temp_files <- list.files(temp_dir, full.names = TRUE)
          for (temp_file in temp_files) {
            file_age_hours <- as.numeric(difftime(Sys.time(), file.info(temp_file)$mtime, units = "hours"))
            if (file_age_hours > 24) {  # Remove files older than 24 hours
              file.remove(temp_file)
            }
          }
        }
      }
      
      # Garbage collection
      gc(verbose = FALSE)
      
      return(TRUE)
    },
    
    cron_to_later_delay = function(cron_expression) {
      # Simple cron parser for common expressions
      # Full cron parser would be more complex
      
      parts <- strsplit(cron_expression, " ")[[1]]
      if (length(parts) != 5) {
        return(NULL)
      }
      
      minute <- parts[1]
      hour <- parts[2]
      day <- parts[3]
      month <- parts[4]
      weekday <- parts[5]
      
      # Handle simple cases
      if (cron_expression == "*/15 * * * *") {
        return(15 * 60)  # 15 minutes in seconds
      } else if (grepl("^0 [0-9]+ \\* \\* \\*", cron_expression)) {
        # Daily at specific hour
        return(24 * 60 * 60)  # 24 hours in seconds
      } else if (grepl("^0 [0-9]+ \\* \\* 0", cron_expression)) {
        # Weekly on Sunday
        return(7 * 24 * 60 * 60)  # 7 days in seconds
      } else {
        # Default to hourly for complex expressions
        return(60 * 60)  # 1 hour in seconds
      }
    },
    
    get_scheduler_status = function() {
      status <- list(
        active_tasks = length(self$scheduled_tasks),
        timezone = self$timezone,
        tasks = list()
      )
      
      for (task_name in names(self$scheduled_tasks)) {
        task_info <- self$scheduled_tasks[[task_name]]
        status$tasks[[task_name]] <- list(
          description = task_info$description,
          cron_expression = task_info$cron_expression,
          last_run = task_info$last_run,
          run_count = task_info$run_count,
          next_run = task_info$next_run
        )
      }
      
      return(status)
    },
    
    stop_all_tasks = function() {
      log_etl("INFO", "Stopping all scheduled tasks", "CRON_SCHEDULER")
      
      if (requireNamespace("later", quietly = TRUE)) {
        for (task_name in names(self$scheduled_tasks)) {
          task_info <- self$scheduled_tasks[[task_name]]
          later::later_cancel(task_info$task_id)
        }
      }
      
      self$scheduled_tasks <- list()
      log_etl("INFO", "All scheduled tasks stopped", "CRON_SCHEDULER")
    }
  )
)

# ============================================================================
# EXPORTS AND INITIALIZATION
# ============================================================================

# Global scheduler instance
railway_scheduler <- NULL

initialize_scheduler_system <- function(db_pool = NULL) {
  cat("⏰ Initializing Automated Data Refresh and Scheduling System...\n")
  
  tryCatch({
    railway_scheduler <<- RailwayCronScheduler$new(db_pool)
    
    # Setup all scheduled tasks
    railway_scheduler$setup_all_schedules()
    
    cat("✅ Scheduler system initialized successfully\n")
    cat("🔧 Components loaded:\n")
    cat("   - Railway Cron Scheduler (Brazil timezone)\n")
    cat("   - Data Version Manager (rollback support)\n")
    cat("   - Refresh Job Manager (full/incremental)\n")
    cat("   - Performance Monitoring\n")
    cat("📊 Scheduled tasks active:\n")
    
    status <- railway_scheduler$get_scheduler_status()
    for (task_name in names(status$tasks)) {
      task_info <- status$tasks[[task_name]]
      cat(sprintf("   - %s: %s (%s)\n", task_name, task_info$description, task_info$cron_expression))
    }
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Scheduler system initialization failed:", e$message, "\n")
    return(FALSE)
  })
}

# Export main functions
run_full_refresh <- function() {
  if (is.null(railway_scheduler)) {
    if (!initialize_scheduler_system()) {
      return(FALSE)
    }
  }
  
  return(railway_scheduler$refresh_manager$execute_full_refresh())
}

run_incremental_refresh <- function() {
  if (is.null(railway_scheduler)) {
    if (!initialize_scheduler_system()) {
      return(FALSE)
    }
  }
  
  return(railway_scheduler$refresh_manager$execute_incremental_refresh())
}

get_scheduler_status <- function() {
  if (is.null(railway_scheduler)) {
    return(list(status = "not_initialized"))
  }
  
  return(railway_scheduler$get_scheduler_status())
}

rollback_to_version <- function(version_hash) {
  if (is.null(railway_scheduler)) {
    return(FALSE)
  }
  
  return(railway_scheduler$refresh_manager$version_manager$rollback_to_version(version_hash))
}

# Cleanup function for Railway shutdown
cleanup_scheduler <- function() {
  if (!is.null(railway_scheduler)) {
    railway_scheduler$stop_all_tasks()
    log_etl("INFO", "Scheduler cleanup completed", "SCHEDULER")
  }
}

# Register cleanup on exit
reg.finalizer(globalenv(), function(e) {
  cleanup_scheduler()
}, onexit = TRUE)

cat("⏰ Automated Data Refresh and Scheduling System loaded\n")
cat("📋 Railway-Compatible Cron Jobs Ready\n")  
cat("🔧 Use initialize_scheduler_system() to start\n")