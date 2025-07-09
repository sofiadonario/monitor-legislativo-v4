# Batch Operations for Monitor Legislativo v4
# Batch document processing, bulk data import/export, and scheduled processing tasks

library(future)
library(promises)
library(DBI)
library(dplyr)
library(lubridate)
library(jsonlite)
library(digest)

# Batch operations configuration
BATCH_CONFIG <- list(
  processing = list(
    max_batch_size = 1000,
    default_batch_size = 100,
    max_concurrent_batches = 4,
    batch_timeout_minutes = 30,
    enable_progress_tracking = TRUE,
    auto_retry_failed = TRUE,
    max_retry_attempts = 3
  ),
  
  scheduling = list(
    enable_scheduler = TRUE,
    default_schedule = "0 2 * * *",  # Daily at 2 AM
    max_scheduled_jobs = 50,
    job_retention_days = 30
  ),
  
  import_export = list(
    supported_formats = c("csv", "xlsx", "json", "xml"),
    max_file_size_mb = 500,
    chunk_size = 1000,
    enable_validation = TRUE,
    backup_imports = TRUE
  ),
  
  performance = list(
    enable_parallel_processing = TRUE,
    memory_limit_mb = 2000,
    disk_space_limit_gb = 10,
    cleanup_temp_files = TRUE
  ),
  
  monitoring = list(
    track_batch_metrics = TRUE,
    alert_on_failures = TRUE,
    log_batch_operations = TRUE,
    performance_profiling = FALSE
  )
)

# Global batch operations state
batch_state <- list(
  active_batches = list(),
  completed_batches = list(),
  scheduled_jobs = list(),
  batch_metrics = list(),
  job_queue = list()
)

#' Initialize batch operations system
#' @param config Optional configuration override
#' @return Initialization status
initialize_batch_operations <- function(config = NULL) {
  if (!is.null(config)) {
    BATCH_CONFIG <<- modifyList(BATCH_CONFIG, config)
  }
  
  log_event("Initializing batch operations system...", "INFO")
  
  # Initialize batch state
  batch_state$active_batches <<- list()
  batch_state$completed_batches <<- list()
  batch_state$scheduled_jobs <<- list()
  batch_state$batch_metrics <<- list()
  batch_state$job_queue <<- list()
  
  # Set up parallel processing
  if (BATCH_CONFIG$performance$enable_parallel_processing) {
    plan(multisession, workers = BATCH_CONFIG$processing$max_concurrent_batches)
  }
  
  # Start job scheduler if enabled
  if (BATCH_CONFIG$scheduling$enable_scheduler) {
    start_job_scheduler()
  }
  
  log_event("Batch operations system initialized successfully", "INFO")
  
  return(list(
    status = "success",
    max_batch_size = BATCH_CONFIG$processing$max_batch_size,
    parallel_processing = BATCH_CONFIG$performance$enable_parallel_processing,
    scheduler_enabled = BATCH_CONFIG$scheduling$enable_scheduler
  ))
}

#' Process documents in batches
#' @param documents List of documents to process
#' @param processing_function Function to apply to each document
#' @param batch_size Size of each batch
#' @param batch_id Optional batch identifier
#' @return Batch processing result
batch_process_documents <- function(documents, processing_function, batch_size = NULL, batch_id = NULL) {
  batch_size <- batch_size %||% BATCH_CONFIG$processing$default_batch_size
  batch_size <- min(batch_size, BATCH_CONFIG$processing$max_batch_size)
  
  if (is.null(batch_id)) {
    batch_id <- generate_batch_id()
  }
  
  log_event(paste("Starting batch processing:", length(documents), "documents in batches of", batch_size), "INFO")
  
  # Validate inputs
  if (length(documents) == 0) {
    return(list(
      batch_id = batch_id,
      status = "completed",
      message = "No documents to process",
      results = list()
    ))
  }
  
  if (!is.function(processing_function)) {
    return(list(
      batch_id = batch_id,
      status = "error",
      message = "Processing function must be a valid function"
    ))
  }
  
  # Create batch job
  batch_job <- list(
    batch_id = batch_id,
    status = "processing",
    start_time = Sys.time(),
    total_documents = length(documents),
    batch_size = batch_size,
    processed_count = 0,
    success_count = 0,
    error_count = 0,
    results = list(),
    errors = list()
  )
  
  # Add to active batches
  batch_state$active_batches[[batch_id]] <<- batch_job
  
  # Split documents into batches
  document_batches <- split(documents, ceiling(seq_along(documents) / batch_size))
  
  tryCatch({
    # Process batches
    if (BATCH_CONFIG$performance$enable_parallel_processing && length(document_batches) > 1) {
      # Parallel processing
      batch_results <- future_lapply(document_batches, function(batch) {
        process_document_batch(batch, processing_function, batch_id)
      })
    } else {
      # Sequential processing
      batch_results <- lapply(document_batches, function(batch) {
        process_document_batch(batch, processing_function, batch_id)
      })
    }
    
    # Combine results
    all_results <- unlist(batch_results, recursive = FALSE)
    success_count <- sum(sapply(all_results, function(x) x$success))
    error_count <- length(all_results) - success_count
    
    # Update batch job
    batch_job$status <- "completed"
    batch_job$end_time <- Sys.time()
    batch_job$processed_count <- length(all_results)
    batch_job$success_count <- success_count
    batch_job$error_count <- error_count
    batch_job$results <- all_results
    batch_job$duration_seconds <- as.numeric(batch_job$end_time - batch_job$start_time, units = "secs")
    
    # Move to completed batches
    batch_state$completed_batches[[batch_id]] <<- batch_job
    batch_state$active_batches[[batch_id]] <<- NULL
    
    # Record metrics
    record_batch_metrics(batch_job)
    
    log_event(paste("Batch processing completed:", batch_id, "-", success_count, "success,", error_count, "errors"), "INFO")
    
    return(list(
      batch_id = batch_id,
      status = "completed",
      total_documents = length(documents),
      success_count = success_count,
      error_count = error_count,
      duration_seconds = batch_job$duration_seconds,
      results = all_results
    ))
    
  }, error = function(e) {
    # Handle batch processing error
    batch_job$status <- "failed"
    batch_job$end_time <- Sys.time()
    batch_job$error_message <- e$message
    
    batch_state$completed_batches[[batch_id]] <<- batch_job
    batch_state$active_batches[[batch_id]] <<- NULL
    
    log_event(paste("Batch processing failed:", batch_id, "-", e$message), "ERROR")
    
    return(list(
      batch_id = batch_id,
      status = "failed",
      error = e$message
    ))
  })
}

#' Process a single batch of documents
#' @param batch_documents Documents in this batch
#' @param processing_function Processing function
#' @param batch_id Batch identifier
#' @return Batch results
process_document_batch <- function(batch_documents, processing_function, batch_id) {
  batch_results <- list()
  
  for (i in seq_along(batch_documents)) {
    document <- batch_documents[[i]]
    
    result <- tryCatch({
      # Apply processing function
      processed_doc <- processing_function(document)
      
      # Update progress
      update_batch_progress(batch_id, 1, TRUE)
      
      list(
        success = TRUE,
        document_id = document$id %||% i,
        result = processed_doc
      )
      
    }, error = function(e) {
      # Update progress
      update_batch_progress(batch_id, 1, FALSE)
      
      log_event(paste("Document processing error in batch", batch_id, ":", e$message), "WARN")
      
      list(
        success = FALSE,
        document_id = document$id %||% i,
        error = e$message
      )
    })
    
    batch_results[[i]] <- result
    
    # Check memory usage
    if (BATCH_CONFIG$performance$memory_limit_mb > 0) {
      current_memory <- get_memory_usage()$used_mb
      if (current_memory > BATCH_CONFIG$performance$memory_limit_mb) {
        log_event("Memory limit reached during batch processing, forcing garbage collection", "WARN")
        gc()
      }
    }
  }
  
  return(batch_results)
}

#' Bulk import data from file
#' @param file_path Path to import file
#' @param format File format
#' @param validation_function Optional validation function
#' @param chunk_size Number of records per chunk
#' @return Import result
bulk_import_data <- function(file_path, format = "csv", validation_function = NULL, chunk_size = NULL) {
  chunk_size <- chunk_size %||% BATCH_CONFIG$import_export$chunk_size
  
  if (!file.exists(file_path)) {
    return(list(
      status = "error",
      message = "Import file does not exist"
    ))
  }
  
  # Check file size
  file_size_mb <- file.info(file_path)$size / 1024 / 1024
  if (file_size_mb > BATCH_CONFIG$import_export$max_file_size_mb) {
    return(list(
      status = "error",
      message = paste("File size", round(file_size_mb, 2), "MB exceeds limit of", BATCH_CONFIG$import_export$max_file_size_mb, "MB")
    ))
  }
  
  import_id <- generate_import_id()
  log_event(paste("Starting bulk import:", import_id, "from", file_path), "INFO")
  
  tryCatch({
    # Read data based on format
    import_data <- switch(format,
      "csv" = read.csv(file_path, stringsAsFactors = FALSE),
      "xlsx" = readxl::read_excel(file_path),
      "json" = fromJSON(file_path, simplifyDataFrame = TRUE),
      stop(paste("Unsupported import format:", format))
    )
    
    if (nrow(import_data) == 0) {
      return(list(
        import_id = import_id,
        status = "completed",
        message = "No data to import",
        imported_count = 0
      ))
    }
    
    # Backup original file if enabled
    if (BATCH_CONFIG$import_export$backup_imports) {
      backup_path <- create_import_backup(file_path, import_id)
    }
    
    # Validate data if validation function provided
    if (!is.null(validation_function) && BATCH_CONFIG$import_export$enable_validation) {
      validation_result <- validate_import_data(import_data, validation_function)
      if (!validation_result$valid) {
        return(list(
          import_id = import_id,
          status = "error",
          message = paste("Data validation failed:", validation_result$message),
          invalid_rows = validation_result$invalid_rows
        ))
      }
    }
    
    # Process data in chunks
    data_chunks <- split(import_data, ceiling(seq_len(nrow(import_data)) / chunk_size))
    
    total_imported <- 0
    import_errors <- list()
    
    for (chunk_index in seq_along(data_chunks)) {
      chunk <- data_chunks[[chunk_index]]
      
      chunk_result <- tryCatch({
        # Process chunk (this would typically involve database insertion)
        process_import_chunk(chunk, import_id, chunk_index)
        
        list(success = TRUE, count = nrow(chunk))
        
      }, error = function(e) {
        log_event(paste("Import chunk error:", e$message), "ERROR")
        list(success = FALSE, error = e$message)
      })
      
      if (chunk_result$success) {
        total_imported <- total_imported + chunk_result$count
      } else {
        import_errors[[chunk_index]] <- chunk_result$error
      }
    }
    
    import_result <- list(
      import_id = import_id,
      status = if (length(import_errors) == 0) "completed" else "partial",
      total_rows = nrow(import_data),
      imported_count = total_imported,
      error_count = length(import_errors),
      file_path = file_path,
      format = format,
      imported_at = Sys.time()
    )
    
    if (length(import_errors) > 0) {
      import_result$errors <- import_errors
    }
    
    log_event(paste("Bulk import completed:", import_id, "-", total_imported, "rows imported"), "INFO")
    
    return(import_result)
    
  }, error = function(e) {
    log_event(paste("Bulk import failed:", import_id, "-", e$message), "ERROR")
    
    return(list(
      import_id = import_id,
      status = "failed",
      error = e$message
    ))
  })
}

#' Bulk export data to file
#' @param data Data to export
#' @param file_path Export file path
#' @param format Export format
#' @param template Export template
#' @return Export result
bulk_export_data <- function(data, file_path, format = "csv", template = "default") {
  if (is.null(data) || (is.data.frame(data) && nrow(data) == 0)) {
    return(list(
      status = "error",
      message = "No data to export"
    ))
  }
  
  export_id <- generate_export_id()
  log_event(paste("Starting bulk export:", export_id, "to", file_path), "INFO")
  
  tryCatch({
    # Ensure export directory exists
    export_dir <- dirname(file_path)
    if (!dir.exists(export_dir)) {
      dir.create(export_dir, recursive = TRUE)
    }
    
    # Apply template processing if not default
    if (template != "default") {
      data <- apply_export_template(data, template)
    }
    
    # Export data based on format
    export_result <- switch(format,
      "csv" = {
        write.csv(data, file_path, row.names = FALSE, fileEncoding = "UTF-8")
        list(success = TRUE)
      },
      "xlsx" = {
        openxlsx::write.xlsx(data, file_path)
        list(success = TRUE)
      },
      "json" = {
        write(toJSON(data, pretty = TRUE, auto_unbox = TRUE), file_path)
        list(success = TRUE)
      },
      "xml" = {
        xml_content <- convert_to_xml(data)
        write(xml_content, file_path)
        list(success = TRUE)
      },
      list(success = FALSE, error = paste("Unsupported export format:", format))
    )
    
    if (!export_result$success) {
      return(list(
        export_id = export_id,
        status = "error",
        message = export_result$error
      ))
    }
    
    # Get file info
    file_info <- file.info(file_path)
    
    result <- list(
      export_id = export_id,
      status = "completed",
      file_path = file_path,
      format = format,
      template = template,
      row_count = if (is.data.frame(data)) nrow(data) else length(data),
      file_size_mb = round(file_info$size / 1024 / 1024, 2),
      exported_at = Sys.time()
    )
    
    log_event(paste("Bulk export completed:", export_id, "-", result$row_count, "rows,", result$file_size_mb, "MB"), "INFO")
    
    return(result)
    
  }, error = function(e) {
    log_event(paste("Bulk export failed:", export_id, "-", e$message), "ERROR")
    
    return(list(
      export_id = export_id,
      status = "failed",
      error = e$message
    ))
  })
}

#' Schedule batch job
#' @param job_name Job name
#' @param job_function Function to execute
#' @param schedule Cron expression
#' @param job_params Job parameters
#' @return Scheduled job result
schedule_batch_job <- function(job_name, job_function, schedule, job_params = list()) {
  if (!BATCH_CONFIG$scheduling$enable_scheduler) {
    return(list(
      status = "error",
      message = "Job scheduler is disabled"
    ))
  }
  
  job_id <- generate_job_id(job_name)
  
  scheduled_job <- list(
    job_id = job_id,
    job_name = job_name,
    job_function = job_function,
    schedule = schedule,
    job_params = job_params,
    status = "scheduled",
    created_at = Sys.time(),
    last_run = NULL,
    next_run = calculate_next_run(schedule),
    run_count = 0,
    success_count = 0,
    error_count = 0
  )
  
  # Add to scheduled jobs
  batch_state$scheduled_jobs[[job_id]] <<- scheduled_job
  
  log_event(paste("Batch job scheduled:", job_name, "with ID", job_id), "INFO")
  
  return(list(
    status = "success",
    job_id = job_id,
    job_name = job_name,
    next_run = scheduled_job$next_run
  ))
}

#' Start job scheduler
start_job_scheduler <- function() {
  future({
    while (TRUE) {
      Sys.sleep(60)  # Check every minute
      
      tryCatch({
        current_time <- Sys.time()
        
        # Check for jobs to run
        for (job_id in names(batch_state$scheduled_jobs)) {
          job <- batch_state$scheduled_jobs[[job_id]]
          
          if (job$status == "scheduled" && current_time >= job$next_run) {
            execute_scheduled_job(job_id)
          }
        }
        
        # Cleanup old completed jobs
        cleanup_old_jobs()
        
      }, error = function(e) {
        log_event(paste("Job scheduler error:", e$message), "ERROR")
      })
    }
  })
  
  log_event("Batch job scheduler started", "INFO")
}

#' Execute scheduled job
#' @param job_id Job identifier
execute_scheduled_job <- function(job_id) {
  job <- batch_state$scheduled_jobs[[job_id]]
  
  if (is.null(job)) {
    return()
  }
  
  log_event(paste("Executing scheduled job:", job$job_name), "INFO")
  
  # Update job status
  job$status <- "running"
  job$last_run <- Sys.time()
  job$run_count <- job$run_count + 1
  batch_state$scheduled_jobs[[job_id]] <<- job
  
  # Execute job function
  tryCatch({
    result <- do.call(job$job_function, job$job_params)
    
    # Update job with success
    job$status <- "scheduled"
    job$success_count <- job$success_count + 1
    job$next_run <- calculate_next_run(job$schedule, job$last_run)
    job$last_result <- result
    
    log_event(paste("Scheduled job completed successfully:", job$job_name), "INFO")
    
  }, error = function(e) {
    # Update job with error
    job$status <- "scheduled"
    job$error_count <- job$error_count + 1
    job$next_run <- calculate_next_run(job$schedule, job$last_run)
    job$last_error <- e$message
    
    log_event(paste("Scheduled job failed:", job$job_name, "-", e$message), "ERROR")
    
    # Trigger alert if monitoring is available
    if (exists("trigger_alert") && BATCH_CONFIG$monitoring$alert_on_failures) {
      trigger_alert(
        type = "scheduled_job",
        severity = "warning",
        message = paste("Scheduled job failed:", job$job_name),
        details = list(job_id = job_id, error = e$message)
      )
    }
  })
  
  batch_state$scheduled_jobs[[job_id]] <<- job
}

# Helper functions

#' Generate unique batch ID
#' @return Batch ID string
generate_batch_id <- function() {
  paste0("batch_", format(Sys.time(), "%Y%m%d_%H%M%S"), "_", sample(1000:9999, 1))
}

#' Generate unique import ID
#' @return Import ID string
generate_import_id <- function() {
  paste0("import_", format(Sys.time(), "%Y%m%d_%H%M%S"), "_", sample(1000:9999, 1))
}

#' Generate unique job ID
#' @param job_name Job name
#' @return Job ID string
generate_job_id <- function(job_name) {
  clean_name <- gsub("[^a-zA-Z0-9]", "_", job_name)
  paste0("job_", clean_name, "_", format(Sys.time(), "%Y%m%d_%H%M%S"))
}

#' Update batch progress
#' @param batch_id Batch identifier
#' @param increment Progress increment
#' @param success Whether operation was successful
update_batch_progress <- function(batch_id, increment, success) {
  if (!BATCH_CONFIG$processing$enable_progress_tracking) {
    return()
  }
  
  batch_job <- batch_state$active_batches[[batch_id]]
  if (!is.null(batch_job)) {
    batch_job$processed_count <- batch_job$processed_count + increment
    
    if (success) {
      batch_job$success_count <- batch_job$success_count + increment
    } else {
      batch_job$error_count <- batch_job$error_count + increment
    }
    
    batch_state$active_batches[[batch_id]] <<- batch_job
  }
}

#' Record batch metrics
#' @param batch_job Completed batch job
record_batch_metrics <- function(batch_job) {
  if (!BATCH_CONFIG$monitoring$track_batch_metrics) {
    return()
  }
  
  metric <- list(
    timestamp = batch_job$end_time,
    batch_id = batch_job$batch_id,
    total_documents = batch_job$total_documents,
    success_count = batch_job$success_count,
    error_count = batch_job$error_count,
    duration_seconds = batch_job$duration_seconds,
    throughput = batch_job$total_documents / batch_job$duration_seconds
  )
  
  batch_state$batch_metrics <<- append(batch_state$batch_metrics, list(metric), after = 0)
  
  # Limit metrics size
  if (length(batch_state$batch_metrics) > 1000) {
    batch_state$batch_metrics <<- head(batch_state$batch_metrics, 1000)
  }
}

#' Validate import data
#' @param data Data to validate
#' @param validation_function Validation function
#' @return Validation result
validate_import_data <- function(data, validation_function) {
  invalid_rows <- c()
  
  for (i in 1:nrow(data)) {
    row_data <- data[i, ]
    
    tryCatch({
      is_valid <- validation_function(row_data)
      if (!is_valid) {
        invalid_rows <- c(invalid_rows, i)
      }
    }, error = function(e) {
      invalid_rows <<- c(invalid_rows, i)
    })
  }
  
  if (length(invalid_rows) > 0) {
    return(list(
      valid = FALSE,
      message = paste(length(invalid_rows), "rows failed validation"),
      invalid_rows = invalid_rows
    ))
  }
  
  return(list(valid = TRUE))
}

#' Process import chunk
#' @param chunk Data chunk
#' @param import_id Import identifier
#' @param chunk_index Chunk index
process_import_chunk <- function(chunk, import_id, chunk_index) {
  # This would typically involve database operations
  # For now, we'll just simulate processing
  
  log_event(paste("Processing import chunk", chunk_index, "with", nrow(chunk), "rows"), "INFO")
  
  # Simulate processing time
  Sys.sleep(0.1)
  
  return(nrow(chunk))
}

#' Apply export template
#' @param data Data to process
#' @param template Template name
#' @return Processed data
apply_export_template <- function(data, template) {
  # Apply template-specific transformations
  switch(template,
    "academic" = {
      # Add academic formatting
      if ("data" %in% names(data)) {
        data$data_formatted <- format(as.Date(data$data), "%d de %B de %Y")
      }
      data
    },
    "summary" = {
      # Create summary version
      if (nrow(data) > 100) {
        rbind(head(data, 50), tail(data, 50))
      } else {
        data
      }
    },
    data  # Default: return as-is
  )
}

#' Convert data to XML
#' @param data Data to convert
#' @return XML string
convert_to_xml <- function(data) {
  # Simple XML conversion (can be enhanced)
  xml_lines <- c('<?xml version="1.0" encoding="UTF-8"?>', '<documents>')
  
  if (is.data.frame(data)) {
    for (i in 1:nrow(data)) {
      row_data <- data[i, ]
      xml_lines <- c(xml_lines, '  <document>')
      
      for (col_name in names(row_data)) {
        value <- row_data[[col_name]]
        if (!is.na(value)) {
          xml_lines <- c(xml_lines, paste0('    <', col_name, '>', htmlEscape(as.character(value)), '</', col_name, '>'))
        }
      }
      
      xml_lines <- c(xml_lines, '  </document>')
    }
  }
  
  xml_lines <- c(xml_lines, '</documents>')
  
  return(paste(xml_lines, collapse = '\n'))
}

#' HTML escape function
#' @param text Text to escape
#' @return Escaped text
htmlEscape <- function(text) {
  text <- gsub("&", "&amp;", text)
  text <- gsub("<", "&lt;", text)
  text <- gsub(">", "&gt;", text)
  text <- gsub("\"", "&quot;", text)
  text <- gsub("'", "&#39;", text)
  return(text)
}

#' Calculate next run time for scheduled job
#' @param schedule Cron expression
#' @param from_time Base time (default: current time)
#' @return Next run time
calculate_next_run <- function(schedule, from_time = NULL) {
  from_time <- from_time %||% Sys.time()
  
  # Simple scheduling - daily at 2 AM (can be enhanced with proper cron parsing)
  if (schedule == "0 2 * * *") {
    next_run <- as.POSIXct(paste(as.Date(from_time) + 1, "02:00:00"))
    
    # If it's already past 2 AM today, schedule for tomorrow
    if (from_time >= as.POSIXct(paste(as.Date(from_time), "02:00:00"))) {
      next_run <- next_run + days(1)
    }
    
    return(next_run)
  }
  
  # Default: 1 hour from now
  return(from_time + hours(1))
}

#' Cleanup old jobs
cleanup_old_jobs <- function() {
  cutoff_date <- Sys.time() - days(BATCH_CONFIG$scheduling$job_retention_days)
  
  # Remove old completed batches
  old_batch_ids <- names(Filter(function(x) x$end_time < cutoff_date, batch_state$completed_batches))
  for (batch_id in old_batch_ids) {
    batch_state$completed_batches[[batch_id]] <<- NULL
  }
  
  # Clean up old metrics
  batch_state$batch_metrics <<- Filter(function(x) x$timestamp > cutoff_date, batch_state$batch_metrics)
}

#' Create import backup
#' @param file_path Original file path
#' @param import_id Import identifier
#' @return Backup file path
create_import_backup <- function(file_path, import_id) {
  backup_dir <- file.path(dirname(file_path), "backups")
  if (!dir.exists(backup_dir)) {
    dir.create(backup_dir, recursive = TRUE)
  }
  
  file_name <- basename(file_path)
  backup_path <- file.path(backup_dir, paste0(import_id, "_", file_name))
  
  file.copy(file_path, backup_path)
  
  return(backup_path)
}

#' Get batch operations statistics
#' @return Batch statistics
get_batch_statistics <- function() {
  # Active batches
  active_count <- length(batch_state$active_batches)
  
  # Completed batches
  completed_count <- length(batch_state$completed_batches)
  
  # Scheduled jobs
  scheduled_count <- length(batch_state$scheduled_jobs)
  
  # Recent metrics (last 24 hours)
  recent_cutoff <- Sys.time() - hours(24)
  recent_metrics <- Filter(function(x) x$timestamp > recent_cutoff, batch_state$batch_metrics)
  
  # Calculate averages
  avg_throughput <- if (length(recent_metrics) > 0) {
    mean(sapply(recent_metrics, function(x) x$throughput))
  } else {
    0
  }
  
  avg_duration <- if (length(recent_metrics) > 0) {
    mean(sapply(recent_metrics, function(x) x$duration_seconds))
  } else {
    0
  }
  
  return(list(
    active_batches = active_count,
    completed_batches = completed_count,
    scheduled_jobs = scheduled_count,
    recent_batches_24h = length(recent_metrics),
    avg_throughput_docs_per_sec = round(avg_throughput, 2),
    avg_duration_seconds = round(avg_duration, 2),
    total_documents_processed = sum(sapply(batch_state$batch_metrics, function(x) x$total_documents)),
    success_rate = if (length(batch_state$batch_metrics) > 0) {
      total_success <- sum(sapply(batch_state$batch_metrics, function(x) x$success_count))
      total_docs <- sum(sapply(batch_state$batch_metrics, function(x) x$total_documents))
      if (total_docs > 0) total_success / total_docs else 0
    } else {
      0
    }
  ))
}