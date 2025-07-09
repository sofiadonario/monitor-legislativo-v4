# Data Pipeline for Monitor Legislativo v4
# Automated data collection, transformation, validation, and archival

library(future)
library(promises)
library(dplyr)
library(lubridate)
library(jsonlite)
library(digest)
library(DBI)

# Data pipeline configuration
PIPELINE_CONFIG <- list(
  collection = list(
    enable_automated_collection = TRUE,
    collection_interval_hours = 6,
    max_concurrent_sources = 3,
    retry_failed_collections = TRUE,
    max_retry_attempts = 3
  ),
  
  transformation = list(
    enable_data_normalization = TRUE,
    enable_duplicate_detection = TRUE,
    enable_quality_scoring = TRUE,
    duplicate_threshold = 0.9,
    min_quality_score = 60
  ),
  
  validation = list(
    enable_schema_validation = TRUE,
    enable_content_validation = TRUE,
    enable_cross_reference_validation = TRUE,
    validation_rules_file = "validation_rules.json",
    fail_on_validation_errors = FALSE
  ),
  
  archival = list(
    enable_automated_archival = TRUE,
    archive_interval_days = 30,
    retention_period_years = 10,
    compression_enabled = TRUE,
    backup_enabled = TRUE
  ),
  
  monitoring = list(
    track_pipeline_metrics = TRUE,
    alert_on_failures = TRUE,
    performance_profiling = TRUE,
    log_all_operations = TRUE
  ),
  
  sources = list(
    government_apis = list(
      enabled = TRUE,
      priority = 1,
      collection_schedule = "0 */6 * * *"  # Every 6 hours
    ),
    regulatory_agencies = list(
      enabled = TRUE,
      priority = 2,
      collection_schedule = "0 2 * * *"    # Daily at 2 AM
    ),
    lexml_feeds = list(
      enabled = TRUE,
      priority = 1,
      collection_schedule = "0 */3 * * *"  # Every 3 hours
    )
  )
)

# Global pipeline state
pipeline_state <- list(
  active_pipelines = list(),
  completed_runs = list(),
  pipeline_metrics = list(),
  collection_status = list(),
  last_collection = NULL
)

#' Initialize data pipeline system
#' @param config Optional configuration override
#' @return Initialization status
initialize_data_pipeline <- function(config = NULL) {
  if (!is.null(config)) {
    PIPELINE_CONFIG <<- modifyList(PIPELINE_CONFIG, config)
  }
  
  log_event("Initializing data pipeline system...", "INFO")
  
  # Initialize pipeline state
  pipeline_state$active_pipelines <<- list()
  pipeline_state$completed_runs <<- list()
  pipeline_state$pipeline_metrics <<- list()
  pipeline_state$collection_status <<- list()
  
  # Load validation rules
  validation_rules <- load_validation_rules()
  
  # Start automated collection if enabled
  if (PIPELINE_CONFIG$collection$enable_automated_collection) {
    start_automated_collection()
  }
  
  # Start automated archival if enabled
  if (PIPELINE_CONFIG$archival$enable_automated_archival) {
    start_automated_archival()
  }
  
  log_event("Data pipeline system initialized successfully", "INFO")
  
  return(list(
    status = "success",
    automated_collection = PIPELINE_CONFIG$collection$enable_automated_collection,
    automated_archival = PIPELINE_CONFIG$archival$enable_automated_archival,
    validation_rules_loaded = !is.null(validation_rules)
  ))
}

#' Execute complete data pipeline
#' @param pipeline_id Optional pipeline identifier
#' @param source_filter Optional source filter
#' @return Pipeline execution result
execute_data_pipeline <- function(pipeline_id = NULL, source_filter = NULL) {
  if (is.null(pipeline_id)) {
    pipeline_id <- generate_pipeline_id()
  }
  
  log_event(paste("Starting data pipeline execution:", pipeline_id), "INFO")
  
  # Create pipeline run
  pipeline_run <- list(
    pipeline_id = pipeline_id,
    status = "running",
    start_time = Sys.time(),
    source_filter = source_filter,
    stages = list(),
    metrics = list()
  )
  
  # Add to active pipelines
  pipeline_state$active_pipelines[[pipeline_id]] <<- pipeline_run
  
  tryCatch({
    # Stage 1: Data Collection
    collection_result <- execute_collection_stage(pipeline_id, source_filter)
    pipeline_run$stages$collection <- collection_result
    
    if (!collection_result$success) {
      stop("Data collection stage failed")
    }
    
    # Stage 2: Data Transformation
    transformation_result <- execute_transformation_stage(pipeline_id, collection_result$data)
    pipeline_run$stages$transformation <- transformation_result
    
    if (!transformation_result$success) {
      stop("Data transformation stage failed")
    }
    
    # Stage 3: Data Validation
    validation_result <- execute_validation_stage(pipeline_id, transformation_result$data)
    pipeline_run$stages$validation <- validation_result
    
    if (!validation_result$success && PIPELINE_CONFIG$validation$fail_on_validation_errors) {
      stop("Data validation stage failed")
    }
    
    # Stage 4: Data Storage
    storage_result <- execute_storage_stage(pipeline_id, validation_result$data)
    pipeline_run$stages$storage <- storage_result
    
    if (!storage_result$success) {
      stop("Data storage stage failed")
    }
    
    # Complete pipeline run
    pipeline_run$status <- "completed"
    pipeline_run$end_time <- Sys.time()
    pipeline_run$duration_seconds <- as.numeric(pipeline_run$end_time - pipeline_run$start_time, units = "secs")
    pipeline_run$total_documents <- storage_result$stored_count
    
    # Move to completed runs
    pipeline_state$completed_runs[[pipeline_id]] <<- pipeline_run
    pipeline_state$active_pipelines[[pipeline_id]] <<- NULL
    
    # Record metrics
    record_pipeline_metrics(pipeline_run)
    
    log_event(paste("Data pipeline completed successfully:", pipeline_id, "-", pipeline_run$total_documents, "documents"), "INFO")
    
    return(list(
      pipeline_id = pipeline_id,
      status = "completed",
      duration_seconds = pipeline_run$duration_seconds,
      total_documents = pipeline_run$total_documents,
      stages = pipeline_run$stages
    ))
    
  }, error = function(e) {
    # Handle pipeline failure
    pipeline_run$status <- "failed"
    pipeline_run$end_time <- Sys.time()
    pipeline_run$error_message <- e$message
    
    pipeline_state$completed_runs[[pipeline_id]] <<- pipeline_run
    pipeline_state$active_pipelines[[pipeline_id]] <<- NULL
    
    log_event(paste("Data pipeline failed:", pipeline_id, "-", e$message), "ERROR")
    
    # Trigger alert if monitoring is available
    if (exists("trigger_alert") && PIPELINE_CONFIG$monitoring$alert_on_failures) {
      trigger_alert(
        type = "data_pipeline",
        severity = "critical",
        message = paste("Data pipeline failed:", pipeline_id),
        details = list(error = e$message, pipeline_id = pipeline_id)
      )
    }
    
    return(list(
      pipeline_id = pipeline_id,
      status = "failed",
      error = e$message
    ))
  })
}

#' Execute data collection stage
#' @param pipeline_id Pipeline identifier
#' @param source_filter Source filter
#' @return Collection result
execute_collection_stage <- function(pipeline_id, source_filter = NULL) {
  log_event(paste("Executing collection stage for pipeline:", pipeline_id), "INFO")
  
  collection_start <- Sys.time()
  collected_data <- list()
  collection_errors <- list()
  
  # Determine sources to collect from
  sources_to_collect <- if (is.null(source_filter)) {
    names(PIPELINE_CONFIG$sources)[sapply(PIPELINE_CONFIG$sources, function(x) x$enabled)]
  } else {
    source_filter
  }
  
  # Collect from each source
  for (source_name in sources_to_collect) {
    source_result <- tryCatch({
      collect_from_source(source_name, pipeline_id)
    }, error = function(e) {
      log_event(paste("Collection error from", source_name, ":", e$message), "ERROR")
      list(success = FALSE, error = e$message)
    })
    
    if (source_result$success) {
      collected_data[[source_name]] <- source_result$data
    } else {
      collection_errors[[source_name]] <- source_result$error
    }
  }
  
  collection_duration <- as.numeric(Sys.time() - collection_start, units = "secs")
  
  # Combine collected data
  combined_data <- combine_source_data(collected_data)
  
  result <- list(
    success = length(collected_data) > 0,
    duration_seconds = collection_duration,
    sources_collected = length(collected_data),
    sources_failed = length(collection_errors),
    total_documents = if (!is.null(combined_data)) nrow(combined_data) else 0,
    data = combined_data,
    errors = if (length(collection_errors) > 0) collection_errors else NULL
  )
  
  log_event(paste("Collection stage completed:", result$sources_collected, "sources,", result$total_documents, "documents"), "INFO")
  
  return(result)
}

#' Execute data transformation stage
#' @param pipeline_id Pipeline identifier
#' @param raw_data Raw collected data
#' @return Transformation result
execute_transformation_stage <- function(pipeline_id, raw_data) {
  log_event(paste("Executing transformation stage for pipeline:", pipeline_id), "INFO")
  
  if (is.null(raw_data) || nrow(raw_data) == 0) {
    return(list(
      success = FALSE,
      message = "No data to transform",
      data = NULL
    ))
  }
  
  transformation_start <- Sys.time()
  
  tryCatch({
    # Step 1: Data normalization
    normalized_data <- if (PIPELINE_CONFIG$transformation$enable_data_normalization) {
      normalize_document_data(raw_data)
    } else {
      raw_data
    }
    
    # Step 2: Duplicate detection and removal
    deduplicated_data <- if (PIPELINE_CONFIG$transformation$enable_duplicate_detection) {
      remove_duplicate_documents(normalized_data, PIPELINE_CONFIG$transformation$duplicate_threshold)
    } else {
      normalized_data
    }
    
    # Step 3: Quality scoring
    scored_data <- if (PIPELINE_CONFIG$transformation$enable_quality_scoring) {
      score_document_quality(deduplicated_data)
    } else {
      deduplicated_data
    }
    
    # Step 4: Filter by quality score
    filtered_data <- if (PIPELINE_CONFIG$transformation$enable_quality_scoring) {
      scored_data[scored_data$quality_score >= PIPELINE_CONFIG$transformation$min_quality_score, ]
    } else {
      scored_data
    }
    
    transformation_duration <- as.numeric(Sys.time() - transformation_start, units = "secs")
    
    result <- list(
      success = TRUE,
      duration_seconds = transformation_duration,
      input_documents = nrow(raw_data),
      output_documents = nrow(filtered_data),
      duplicates_removed = nrow(normalized_data) - nrow(deduplicated_data),
      quality_filtered = nrow(deduplicated_data) - nrow(filtered_data),
      data = filtered_data
    )
    
    log_event(paste("Transformation stage completed:", result$input_documents, "→", result$output_documents, "documents"), "INFO")
    
    return(result)
    
  }, error = function(e) {
    log_event(paste("Transformation stage error:", e$message), "ERROR")
    
    return(list(
      success = FALSE,
      error = e$message,
      data = raw_data
    ))
  })
}

#' Execute data validation stage
#' @param pipeline_id Pipeline identifier
#' @param transformed_data Transformed data
#' @return Validation result
execute_validation_stage <- function(pipeline_id, transformed_data) {
  log_event(paste("Executing validation stage for pipeline:", pipeline_id), "INFO")
  
  if (is.null(transformed_data) || nrow(transformed_data) == 0) {
    return(list(
      success = FALSE,
      message = "No data to validate",
      data = NULL
    ))
  }
  
  validation_start <- Sys.time()
  validation_errors <- list()
  
  tryCatch({
    # Schema validation
    if (PIPELINE_CONFIG$validation$enable_schema_validation) {
      schema_result <- validate_document_schema(transformed_data)
      if (!schema_result$valid) {
        validation_errors$schema <- schema_result$errors
      }
    }
    
    # Content validation
    if (PIPELINE_CONFIG$validation$enable_content_validation) {
      content_result <- validate_document_content(transformed_data)
      if (!content_result$valid) {
        validation_errors$content <- content_result$errors
      }
    }
    
    # Cross-reference validation
    if (PIPELINE_CONFIG$validation$enable_cross_reference_validation) {
      cross_ref_result <- validate_cross_references(transformed_data)
      if (!cross_ref_result$valid) {
        validation_errors$cross_reference <- cross_ref_result$errors
      }
    }
    
    validation_duration <- as.numeric(Sys.time() - validation_start, units = "secs")
    
    # Mark validation status on each document
    if (length(validation_errors) > 0) {
      transformed_data$validation_status <- "warning"
      transformed_data$validation_errors <- sapply(1:nrow(transformed_data), function(i) {
        toJSON(validation_errors, auto_unbox = TRUE)
      })
    } else {
      transformed_data$validation_status <- "valid"
    }
    
    result <- list(
      success = length(validation_errors) == 0,
      duration_seconds = validation_duration,
      documents_validated = nrow(transformed_data),
      validation_errors = if (length(validation_errors) > 0) validation_errors else NULL,
      data = transformed_data
    )
    
    log_event(paste("Validation stage completed:", result$documents_validated, "documents,", length(validation_errors), "error types"), "INFO")
    
    return(result)
    
  }, error = function(e) {
    log_event(paste("Validation stage error:", e$message), "ERROR")
    
    return(list(
      success = FALSE,
      error = e$message,
      data = transformed_data
    ))
  })
}

#' Execute data storage stage
#' @param pipeline_id Pipeline identifier
#' @param validated_data Validated data
#' @return Storage result
execute_storage_stage <- function(pipeline_id, validated_data) {
  log_event(paste("Executing storage stage for pipeline:", pipeline_id), "INFO")
  
  if (is.null(validated_data) || nrow(validated_data) == 0) {
    return(list(
      success = FALSE,
      message = "No data to store",
      stored_count = 0
    ))
  }
  
  storage_start <- Sys.time()
  
  tryCatch({
    # Store in primary database
    primary_result <- store_documents_in_database(validated_data, pipeline_id)
    
    # Store in cache if successful
    if (primary_result$success) {
      cache_result <- cache_pipeline_documents(validated_data, pipeline_id)
    }
    
    # Create backup if enabled
    if (PIPELINE_CONFIG$archival$backup_enabled) {
      backup_result <- create_data_backup(validated_data, pipeline_id)
    }
    
    storage_duration <- as.numeric(Sys.time() - storage_start, units = "secs")
    
    result <- list(
      success = primary_result$success,
      duration_seconds = storage_duration,
      stored_count = primary_result$stored_count,
      cached = exists("cache_result") && cache_result$success,
      backed_up = exists("backup_result") && backup_result$success
    )
    
    log_event(paste("Storage stage completed:", result$stored_count, "documents stored"), "INFO")
    
    return(result)
    
  }, error = function(e) {
    log_event(paste("Storage stage error:", e$message), "ERROR")
    
    return(list(
      success = FALSE,
      error = e$message,
      stored_count = 0
    ))
  })
}

#' Collect data from specific source
#' @param source_name Source name
#' @param pipeline_id Pipeline identifier
#' @return Collection result for source
collect_from_source <- function(source_name, pipeline_id) {
  log_event(paste("Collecting data from source:", source_name), "INFO")
  
  collection_result <- switch(source_name,
    "government_apis" = collect_from_government_apis(),
    "regulatory_agencies" = collect_from_regulatory_agencies(),
    "lexml_feeds" = collect_from_lexml_feeds(),
    list(success = FALSE, error = paste("Unknown source:", source_name))
  )
  
  # Update collection status
  pipeline_state$collection_status[[source_name]] <<- list(
    last_collection = Sys.time(),
    success = collection_result$success,
    documents_collected = if (collection_result$success) nrow(collection_result$data) else 0
  )
  
  return(collection_result)
}

#' Collect from government APIs
#' @return Collection result
collect_from_government_apis <- function() {
  tryCatch({
    collected_docs <- list()
    
    # Collect from Câmara dos Deputados
    if (exists("integrate_camara_api")) {
      camara_result <- integrate_camara_api("/proposicoes", list(
        ordem = "DESC",
        ordenarPor = "id",
        itens = 100
      ))
      
      if (!("error" %in% names(camara_result))) {
        collected_docs$camara <- process_camara_response(camara_result)
      }
    }
    
    # Collect from Senado Federal
    if (exists("integrate_senado_api")) {
      senado_result <- integrate_senado_api("/materia/pesquisa/lista", list(v = 4))
      
      if (!("error" %in% names(senado_result))) {
        collected_docs$senado <- process_senado_response(senado_result)
      }
    }
    
    # Combine results
    combined_data <- do.call(rbind, collected_docs)
    
    return(list(
      success = !is.null(combined_data) && nrow(combined_data) > 0,
      data = combined_data,
      sources = names(collected_docs)
    ))
    
  }, error = function(e) {
    return(list(success = FALSE, error = e$message))
  })
}

#' Collect from regulatory agencies
#' @return Collection result
collect_from_regulatory_agencies <- function() {
  tryCatch({
    collected_docs <- list()
    
    # Collect from key agencies
    agencies <- c("antt", "antaq", "anac")
    
    for (agency in agencies) {
      if (exists("integrate_regulatory_agency")) {
        agency_result <- integrate_regulatory_agency(agency, "resolutions")
        
        if (!("error" %in% names(agency_result))) {
          collected_docs[[agency]] <- process_agency_response(agency_result, agency)
        }
      }
    }
    
    # Combine results
    if (length(collected_docs) > 0) {
      combined_data <- do.call(rbind, collected_docs)
    } else {
      combined_data <- NULL
    }
    
    return(list(
      success = !is.null(combined_data) && nrow(combined_data) > 0,
      data = combined_data,
      agencies = names(collected_docs)
    ))
    
  }, error = function(e) {
    return(list(success = FALSE, error = e$message))
  })
}

#' Collect from LexML feeds
#' @return Collection result
collect_from_lexml_feeds <- function() {
  tryCatch({
    # This would integrate with LexML RSS feeds or API
    # For now, return placeholder data
    
    sample_data <- data.frame(
      id = paste0("lexml_", 1:5),
      titulo = paste("Documento LexML", 1:5),
      tipo = "Lei",
      numero = 1:5,
      data = Sys.Date() - sample(1:30, 5),
      estado = sample(c("BR", "SP", "RJ"), 5, replace = TRUE),
      fonte = "LexML",
      urn = paste0("urn:lex:br:federal:lei:", format(Sys.Date(), "%Y"), "-", sprintf("%02d", 1:5)),
      stringsAsFactors = FALSE
    )
    
    return(list(
      success = TRUE,
      data = sample_data
    ))
    
  }, error = function(e) {
    return(list(success = FALSE, error = e$message))
  })
}

#' Start automated collection
start_automated_collection <- function() {
  future({
    while (TRUE) {
      Sys.sleep(PIPELINE_CONFIG$collection$collection_interval_hours * 3600)
      
      tryCatch({
        log_event("Starting automated data collection", "INFO")
        
        pipeline_result <- execute_data_pipeline()
        
        if (pipeline_result$status == "completed") {
          log_event(paste("Automated collection completed:", pipeline_result$total_documents, "documents"), "INFO")
        } else {
          log_event(paste("Automated collection failed:", pipeline_result$error), "ERROR")
        }
        
      }, error = function(e) {
        log_event(paste("Automated collection error:", e$message), "ERROR")
      })
    }
  })
  
  log_event("Automated data collection started", "INFO")
}

#' Start automated archival
start_automated_archival <- function() {
  future({
    while (TRUE) {
      Sys.sleep(PIPELINE_CONFIG$archival$archive_interval_days * 24 * 3600)
      
      tryCatch({
        log_event("Starting automated data archival", "INFO")
        
        archival_result <- execute_data_archival()
        
        log_event(paste("Automated archival completed:", archival_result$archived_count, "documents"), "INFO")
        
      }, error = function(e) {
        log_event(paste("Automated archival error:", e$message), "ERROR")
      })
    }
  })
  
  log_event("Automated data archival started", "INFO")
}

# Helper functions

#' Generate unique pipeline ID
#' @return Pipeline ID string
generate_pipeline_id <- function() {
  paste0("pipeline_", format(Sys.time(), "%Y%m%d_%H%M%S"), "_", sample(1000:9999, 1))
}

#' Combine data from multiple sources
#' @param source_data List of data from different sources
#' @return Combined data frame
combine_source_data <- function(source_data) {
  if (length(source_data) == 0) {
    return(NULL)
  }
  
  # Standardize column names across sources
  standardized_data <- lapply(source_data, function(data) {
    if (is.null(data) || nrow(data) == 0) {
      return(NULL)
    }
    
    # Ensure required columns exist
    required_cols <- c("id", "titulo", "tipo", "numero", "data", "estado", "fonte")
    
    for (col in required_cols) {
      if (!col %in% names(data)) {
        data[[col]] <- NA
      }
    }
    
    # Select and order columns
    data[, required_cols]
  })
  
  # Remove NULL entries
  standardized_data <- standardized_data[!sapply(standardized_data, is.null)]
  
  if (length(standardized_data) == 0) {
    return(NULL)
  }
  
  # Combine all data
  combined <- do.call(rbind, standardized_data)
  
  # Add collection timestamp
  combined$collected_at <- Sys.time()
  
  return(combined)
}

#' Normalize document data
#' @param data Raw document data
#' @return Normalized data
normalize_document_data <- function(data) {
  # Standardize dates
  data$data <- as.Date(data$data)
  
  # Standardize text fields
  if ("titulo" %in% names(data)) {
    data$titulo <- trimws(data$titulo)
  }
  
  # Standardize document types
  if ("tipo" %in% names(data)) {
    data$tipo <- standardize_document_types(data$tipo)
  }
  
  # Standardize states
  if ("estado" %in% names(data)) {
    data$estado <- standardize_state_codes(data$estado)
  }
  
  return(data)
}

#' Remove duplicate documents
#' @param data Document data
#' @param threshold Similarity threshold
#' @return Deduplicated data
remove_duplicate_documents <- function(data, threshold = 0.9) {
  if (nrow(data) <= 1) {
    return(data)
  }
  
  # Simple duplicate detection based on title and number
  duplicates <- c()
  
  for (i in 1:(nrow(data) - 1)) {
    for (j in (i + 1):nrow(data)) {
      similarity <- calculate_document_similarity(data[i, ], data[j, ])
      
      if (similarity >= threshold) {
        duplicates <- c(duplicates, j)
      }
    }
  }
  
  if (length(duplicates) > 0) {
    data <- data[-unique(duplicates), ]
  }
  
  return(data)
}

#' Score document quality
#' @param data Document data
#' @return Data with quality scores
score_document_quality <- function(data) {
  data$quality_score <- sapply(1:nrow(data), function(i) {
    doc <- data[i, ]
    
    score <- 0
    
    # Title quality (40 points)
    if (!is.na(doc$titulo) && nchar(doc$titulo) > 10) {
      score <- score + 40
    } else if (!is.na(doc$titulo) && nchar(doc$titulo) > 5) {
      score <- score + 20
    }
    
    # Date quality (20 points)
    if (!is.na(doc$data) && doc$data >= as.Date("1900-01-01")) {
      score <- score + 20
    }
    
    # Number quality (20 points)
    if (!is.na(doc$numero) && !is.na(as.numeric(doc$numero))) {
      score <- score + 20
    }
    
    # Type quality (10 points)
    if (!is.na(doc$tipo) && nchar(doc$tipo) > 2) {
      score <- score + 10
    }
    
    # State quality (10 points)
    if (!is.na(doc$estado) && nchar(doc$estado) >= 2) {
      score <- score + 10
    }
    
    return(score)
  })
  
  return(data)
}

#' Calculate document similarity
#' @param doc1 First document
#' @param doc2 Second document
#' @return Similarity score (0-1)
calculate_document_similarity <- function(doc1, doc2) {
  # Simple similarity based on title and number
  title_sim <- if (!is.na(doc1$titulo) && !is.na(doc2$titulo)) {
    # Basic string similarity (can be enhanced)
    common_words <- length(intersect(
      strsplit(tolower(doc1$titulo), "\\s+")[[1]],
      strsplit(tolower(doc2$titulo), "\\s+")[[1]]
    ))
    
    total_words <- length(unique(c(
      strsplit(tolower(doc1$titulo), "\\s+")[[1]],
      strsplit(tolower(doc2$titulo), "\\s+")[[1]]
    )))
    
    if (total_words > 0) common_words / total_words else 0
  } else {
    0
  }
  
  number_sim <- if (!is.na(doc1$numero) && !is.na(doc2$numero)) {
    if (doc1$numero == doc2$numero) 1 else 0
  } else {
    0
  }
  
  # Weighted average
  return(0.7 * title_sim + 0.3 * number_sim)
}

#' Standardize document types
#' @param types Vector of document types
#' @return Standardized types
standardize_document_types <- function(types) {
  type_mapping <- list(
    "lei" = "Lei",
    "decreto" = "Decreto",
    "resolucao" = "Resolução",
    "resolução" = "Resolução",
    "instrucao" = "Instrução Normativa",
    "instrução" = "Instrução Normativa",
    "portaria" = "Portaria"
  )
  
  standardized <- sapply(types, function(type) {
    if (is.na(type)) return(NA)
    
    clean_type <- tolower(trimws(type))
    return(type_mapping[[clean_type]] %||% type)
  })
  
  return(as.character(standardized))
}

#' Standardize state codes
#' @param states Vector of state codes
#' @return Standardized state codes
standardize_state_codes <- function(states) {
  # Map common variations to standard codes
  state_mapping <- list(
    "br" = "BR",
    "brasil" = "BR",
    "federal" = "BR",
    "sp" = "SP",
    "sao paulo" = "SP",
    "rj" = "RJ",
    "rio de janeiro" = "RJ"
  )
  
  standardized <- sapply(states, function(state) {
    if (is.na(state)) return(NA)
    
    clean_state <- tolower(trimws(state))
    return(state_mapping[[clean_state]] %||% toupper(state))
  })
  
  return(as.character(standardized))
}

#' Load validation rules
#' @return Validation rules list
load_validation_rules <- function() {
  rules_file <- PIPELINE_CONFIG$validation$validation_rules_file
  
  if (file.exists(rules_file)) {
    tryCatch({
      rules <- fromJSON(rules_file, simplifyVector = FALSE)
      log_event("Validation rules loaded successfully", "INFO")
      return(rules)
    }, error = function(e) {
      log_event(paste("Error loading validation rules:", e$message), "WARN")
      return(NULL)
    })
  }
  
  # Default validation rules
  default_rules <- list(
    required_fields = c("titulo", "tipo", "data"),
    date_range = list(min = "1900-01-01", max = Sys.Date() + 365),
    title_min_length = 5,
    valid_document_types = c("Lei", "Decreto", "Resolução", "Instrução Normativa", "Portaria")
  )
  
  return(default_rules)
}

#' Validate document schema
#' @param data Document data
#' @return Validation result
validate_document_schema <- function(data) {
  validation_rules <- load_validation_rules()
  errors <- c()
  
  # Check required fields
  for (field in validation_rules$required_fields) {
    if (!field %in% names(data)) {
      errors <- c(errors, paste("Missing required field:", field))
    } else if (all(is.na(data[[field]]))) {
      errors <- c(errors, paste("Required field is empty:", field))
    }
  }
  
  return(list(
    valid = length(errors) == 0,
    errors = if (length(errors) > 0) errors else NULL
  ))
}

#' Validate document content
#' @param data Document data
#' @return Validation result
validate_document_content <- function(data) {
  validation_rules <- load_validation_rules()
  errors <- c()
  
  # Validate dates
  if ("data" %in% names(data)) {
    invalid_dates <- which(
      !is.na(data$data) & (
        data$data < as.Date(validation_rules$date_range$min) |
        data$data > as.Date(validation_rules$date_range$max)
      )
    )
    
    if (length(invalid_dates) > 0) {
      errors <- c(errors, paste("Invalid dates found in", length(invalid_dates), "documents"))
    }
  }
  
  # Validate title length
  if ("titulo" %in% names(data)) {
    short_titles <- which(
      !is.na(data$titulo) & nchar(data$titulo) < validation_rules$title_min_length
    )
    
    if (length(short_titles) > 0) {
      errors <- c(errors, paste("Titles too short in", length(short_titles), "documents"))
    }
  }
  
  return(list(
    valid = length(errors) == 0,
    errors = if (length(errors) > 0) errors else NULL
  ))
}

#' Validate cross references
#' @param data Document data
#' @return Validation result
validate_cross_references <- function(data) {
  # Placeholder for cross-reference validation
  # Would check against existing documents, legal references, etc.
  
  return(list(valid = TRUE))
}

#' Store documents in database
#' @param data Document data
#' @param pipeline_id Pipeline identifier
#' @return Storage result
store_documents_in_database <- function(data, pipeline_id) {
  # Placeholder for database storage
  # Would use connection pool and batch inserts
  
  log_event(paste("Storing", nrow(data), "documents in database"), "INFO")
  
  # Simulate storage
  Sys.sleep(0.1)
  
  return(list(
    success = TRUE,
    stored_count = nrow(data)
  ))
}

#' Cache pipeline documents
#' @param data Document data
#' @param pipeline_id Pipeline identifier
#' @return Cache result
cache_pipeline_documents <- function(data, pipeline_id) {
  if (exists("cache_search_results")) {
    cache_key <- paste("pipeline", pipeline_id, sep = "_")
    cache_search_results(cache_key, list(), data)
    
    return(list(success = TRUE))
  }
  
  return(list(success = FALSE, message = "Cache system not available"))
}

#' Create data backup
#' @param data Document data
#' @param pipeline_id Pipeline identifier
#' @return Backup result
create_data_backup <- function(data, pipeline_id) {
  backup_dir <- "backups/pipeline"
  
  if (!dir.exists(backup_dir)) {
    dir.create(backup_dir, recursive = TRUE)
  }
  
  backup_file <- file.path(backup_dir, paste0(pipeline_id, "_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".rds"))
  
  tryCatch({
    saveRDS(data, backup_file)
    
    return(list(
      success = TRUE,
      backup_file = backup_file
    ))
    
  }, error = function(e) {
    return(list(
      success = FALSE,
      error = e$message
    ))
  })
}

#' Record pipeline metrics
#' @param pipeline_run Completed pipeline run
record_pipeline_metrics <- function(pipeline_run) {
  if (!PIPELINE_CONFIG$monitoring$track_pipeline_metrics) {
    return()
  }
  
  metric <- list(
    timestamp = pipeline_run$end_time,
    pipeline_id = pipeline_run$pipeline_id,
    duration_seconds = pipeline_run$duration_seconds,
    total_documents = pipeline_run$total_documents,
    success = pipeline_run$status == "completed"
  )
  
  pipeline_state$pipeline_metrics <<- append(pipeline_state$pipeline_metrics, list(metric), after = 0)
  
  # Limit metrics size
  if (length(pipeline_state$pipeline_metrics) > 500) {
    pipeline_state$pipeline_metrics <<- head(pipeline_state$pipeline_metrics, 500)
  }
}

#' Execute data archival
#' @return Archival result
execute_data_archival <- function() {
  # Placeholder for data archival process
  # Would archive old documents, compress data, etc.
  
  log_event("Executing data archival", "INFO")
  
  return(list(
    success = TRUE,
    archived_count = 0,
    message = "No documents require archival at this time"
  ))
}

#' Get data pipeline statistics
#' @return Pipeline statistics
get_pipeline_statistics <- function() {
  # Active pipelines
  active_count <- length(pipeline_state$active_pipelines)
  
  # Completed pipelines
  completed_count <- length(pipeline_state$completed_runs)
  
  # Recent metrics (last 24 hours)
  recent_cutoff <- Sys.time() - hours(24)
  recent_metrics <- Filter(function(x) x$timestamp > recent_cutoff, pipeline_state$pipeline_metrics)
  
  # Calculate averages
  avg_duration <- if (length(recent_metrics) > 0) {
    mean(sapply(recent_metrics, function(x) x$duration_seconds))
  } else {
    0
  }
  
  avg_documents <- if (length(recent_metrics) > 0) {
    mean(sapply(recent_metrics, function(x) x$total_documents))
  } else {
    0
  }
  
  success_rate <- if (length(recent_metrics) > 0) {
    sum(sapply(recent_metrics, function(x) x$success)) / length(recent_metrics)
  } else {
    0
  }
  
  return(list(
    active_pipelines = active_count,
    completed_pipelines = completed_count,
    recent_runs_24h = length(recent_metrics),
    avg_duration_seconds = round(avg_duration, 2),
    avg_documents_per_run = round(avg_documents, 0),
    success_rate = round(success_rate * 100, 1),
    last_collection = pipeline_state$last_collection,
    collection_status = pipeline_state$collection_status
  ))
}

# Response processing functions (placeholders)
process_camara_response <- function(response) {
  # Process Câmara API response into standard format
  return(data.frame(
    id = "camara_sample",
    titulo = "Sample Câmara Document",
    tipo = "Lei",
    numero = "123",
    data = Sys.Date(),
    estado = "BR",
    fonte = "Câmara",
    stringsAsFactors = FALSE
  ))
}

process_senado_response <- function(response) {
  # Process Senado API response into standard format
  return(data.frame(
    id = "senado_sample",
    titulo = "Sample Senado Document",
    tipo = "Decreto",
    numero = "456",
    data = Sys.Date(),
    estado = "BR",
    fonte = "Senado",
    stringsAsFactors = FALSE
  ))
}

process_agency_response <- function(response, agency) {
  # Process agency response into standard format
  return(data.frame(
    id = paste0(agency, "_sample"),
    titulo = paste("Sample", toupper(agency), "Document"),
    tipo = "Resolução",
    numero = "789",
    data = Sys.Date(),
    estado = "BR",
    fonte = toupper(agency),
    stringsAsFactors = FALSE
  ))
}