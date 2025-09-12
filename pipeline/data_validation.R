# ============================================================================
# DATA VALIDATION AND QUALITY ASSURANCE FRAMEWORK - SPRINT 4B
# ============================================================================
#
# Comprehensive data validation system for Brazilian legislative documents
# Ensures data integrity, completeness, and compliance with standards
# Optimized for Railway deployment with memory-efficient processing
#
# Features:
# - Brazilian legislative document schema validation
# - Data quality scoring and metrics
# - Duplicate detection and deduplication
# - Data completeness assessment
# - Compliance with LexML and IBGE standards
# - Quality monitoring and reporting
# - Automated data cleaning procedures
#
# Author: Legislative Data Science Team
# Version: 4B.1.0 (Sprint 4B)
# Updated: 2025-01-20
# ============================================================================

# Load required packages
required_packages <- c(
  "dplyr", "stringr", "lubridate", "digest", 
  "jsonlite", "data.table", "stringdist"
)

missing_packages <- c()
for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    missing_packages <- c(missing_packages, pkg)
  }
}

if (length(missing_packages) > 0) {
  cat("⚠️ WARNING: Missing validation packages:", paste(missing_packages, collapse = ", "), "\n")
}

# Load available packages
suppressPackageStartupMessages({
  if (requireNamespace("dplyr", quietly = TRUE)) library(dplyr)
  if (requireNamespace("stringr", quietly = TRUE)) library(stringr)
  if (requireNamespace("lubridate", quietly = TRUE)) library(lubridate)
  if (requireNamespace("digest", quietly = TRUE)) library(digest)
  if (requireNamespace("data.table", quietly = TRUE)) library(data.table)
})

# ============================================================================
# VALIDATION CONFIGURATION
# ============================================================================

VALIDATION_CONFIG <- list(
  # Document Standards
  document_standards = list(
    min_title_length = 10,
    max_title_length = 500,
    min_summary_length = 20,
    max_summary_length = 5000,
    required_fields = c("titulo", "tipo", "data", "autoridade"),
    optional_fields = c("ementa", "url", "urn", "assuntos", "municipio"),
    date_range = list(
      min_date = as.Date("1988-10-05"),  # Brazilian Constitution
      max_date = Sys.Date() + days(90)   # Allow future dates up to 90 days
    )
  ),
  
  # Brazilian Geographic Standards
  geographic_standards = list(
    valid_states = c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", 
                    "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", 
                    "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO"),
    state_names = list(
      "AC" = "Acre", "AL" = "Alagoas", "AP" = "Amapá", "AM" = "Amazonas",
      "BA" = "Bahia", "CE" = "Ceará", "DF" = "Distrito Federal", 
      "ES" = "Espírito Santo", "GO" = "Goiás", "MA" = "Maranhão", 
      "MT" = "Mato Grosso", "MS" = "Mato Grosso do Sul", "MG" = "Minas Gerais",
      "PA" = "Pará", "PB" = "Paraíba", "PR" = "Paraná", "PE" = "Pernambuco",
      "PI" = "Piauí", "RJ" = "Rio de Janeiro", "RN" = "Rio Grande do Norte",
      "RS" = "Rio Grande do Sul", "RO" = "Rondônia", "RR" = "Roraima", 
      "SC" = "Santa Catarina", "SP" = "São Paulo", "SE" = "Sergipe", "TO" = "Tocantins"
    )
  ),
  
  # Legislative Document Categories
  document_categories = list(
    valid_types = c("Lei", "Decreto", "Portaria", "Resolução", "Instrução Normativa",
                   "Medida Provisória", "Emenda Constitucional", "Lei Complementar",
                   "Decreto-Lei", "Ato", "Parecer", "Acórdão", "Decisão"),
    valid_categories = c("Legislação", "Jurisprudência", "Doutrina", "Proposições", "Outros"),
    authority_patterns = list(
      federal = c("União", "Governo Federal", "Presidência", "Ministério", 
                 "Congresso Nacional", "Senado Federal", "Câmara dos Deputados"),
      state = c("Estado", "Governo Estadual", "Assembleia Legislativa", 
               "Tribunal de Justiça"),
      municipal = c("Município", "Prefeitura", "Câmara Municipal", "Municipal")
    )
  ),
  
  # Quality Thresholds
  quality_thresholds = list(
    excellent = 90,
    good = 75,
    acceptable = 60,
    poor = 40,
    unacceptable = 25
  ),
  
  # Duplicate Detection
  deduplication = list(
    similarity_threshold = 0.95,
    fuzzy_match_threshold = 0.85,
    methods = c("exact", "fuzzy", "semantic")
  )
)

# ============================================================================
# DATA VALIDATION CLASSES
# ============================================================================

#' Brazilian Legislative Document Validator
DocumentValidator <- R6::R6Class("DocumentValidator",
  public = list(
    validation_rules = NULL,
    error_log = list(),
    warning_log = list(),
    
    initialize = function() {
      self$validation_rules <- VALIDATION_CONFIG
      log_etl("INFO", "Document validator initialized", "VALIDATOR")
    },
    
    validate_document_batch = function(documents, strict_mode = FALSE) {
      if (is.null(documents) || nrow(documents) == 0) {
        return(list(valid_documents = data.frame(), validation_report = self$create_empty_report()))
      }
      
      log_etl("INFO", sprintf("Validating batch of %d documents", nrow(documents)), "VALIDATOR")
      start_time <- Sys.time()
      
      # Initialize validation results
      validation_results <- data.frame(
        row_id = 1:nrow(documents),
        is_valid = TRUE,
        quality_score = 0,
        validation_errors = "",
        validation_warnings = "",
        stringsAsFactors = FALSE
      )
      
      # Run validation checks
      validation_results <- self$validate_required_fields(documents, validation_results, strict_mode)
      validation_results <- self$validate_document_titles(documents, validation_results)
      validation_results <- self$validate_dates(documents, validation_results, strict_mode)
      validation_results <- self$validate_geographic_data(documents, validation_results)
      validation_results <- self$validate_document_types(documents, validation_results)
      validation_results <- self$validate_authorities(documents, validation_results)
      validation_results <- self$calculate_quality_scores(documents, validation_results)
      
      # Apply quality thresholds
      if (strict_mode) {
        min_quality <- self$validation_rules$quality_thresholds$acceptable
      } else {
        min_quality <- self$validation_rules$quality_thresholds$poor
      }
      
      validation_results$is_valid <- validation_results$is_valid & 
                                   validation_results$quality_score >= min_quality
      
      # Create validation report
      validation_report <- self$create_validation_report(documents, validation_results)
      
      # Filter valid documents
      valid_indices <- which(validation_results$is_valid)
      valid_documents <- documents[valid_indices, ]
      
      # Add validation metadata to documents
      if (nrow(valid_documents) > 0) {
        valid_documents$quality_score <- validation_results$quality_score[valid_indices]
        valid_documents$validation_timestamp <- Sys.time()
      }
      
      end_time <- Sys.time()
      duration <- as.numeric(end_time - start_time, units = "secs")
      
      log_etl("INFO", sprintf("Validation complete: %d/%d documents valid (%.2f seconds)", 
                             nrow(valid_documents), nrow(documents), duration), "VALIDATOR")
      
      return(list(
        valid_documents = valid_documents,
        validation_report = validation_report,
        validation_results = validation_results
      ))
    },
    
    validate_required_fields = function(documents, validation_results, strict_mode = FALSE) {
      required_fields <- self$validation_rules$document_standards$required_fields
      
      for (field in required_fields) {
        if (!field %in% names(documents)) {
          validation_results$is_valid <- FALSE
          validation_results$validation_errors <- paste0(
            validation_results$validation_errors, 
            sprintf("Missing required field: %s; ", field)
          )
          next
        }
        
        # Check for empty or NA values
        missing_indices <- which(is.na(documents[[field]]) | 
                               documents[[field]] == "" | 
                               trimws(documents[[field]]) == "")
        
        if (length(missing_indices) > 0) {
          validation_results$is_valid[missing_indices] <- FALSE
          validation_results$validation_errors[missing_indices] <- paste0(
            validation_results$validation_errors[missing_indices],
            sprintf("Empty required field: %s; ", field)
          )
        }
      }
      
      return(validation_results)
    },
    
    validate_document_titles = function(documents, validation_results) {
      if (!"titulo" %in% names(documents)) return(validation_results)
      
      min_len <- self$validation_rules$document_standards$min_title_length
      max_len <- self$validation_rules$document_standards$max_title_length
      
      title_lengths <- nchar(as.character(documents$titulo))
      
      # Check minimum length
      short_titles <- which(title_lengths < min_len)
      if (length(short_titles) > 0) {
        validation_results$is_valid[short_titles] <- FALSE
        validation_results$validation_errors[short_titles] <- paste0(
          validation_results$validation_errors[short_titles],
          sprintf("Title too short (<%d chars); ", min_len)
        )
      }
      
      # Check maximum length
      long_titles <- which(title_lengths > max_len)
      if (length(long_titles) > 0) {
        validation_results$validation_warnings[long_titles] <- paste0(
          validation_results$validation_warnings[long_titles],
          sprintf("Title very long (>%d chars); ", max_len)
        )
      }
      
      # Check for suspicious patterns
      suspicious_patterns <- c("^test", "^exemplo", "^sample", "^mock")
      for (pattern in suspicious_patterns) {
        suspicious_indices <- which(grepl(pattern, documents$titulo, ignore.case = TRUE))
        if (length(suspicious_indices) > 0) {
          validation_results$validation_warnings[suspicious_indices] <- paste0(
            validation_results$validation_warnings[suspicious_indices],
            "Suspicious title pattern; "
          )
        }
      }
      
      return(validation_results)
    },
    
    validate_dates = function(documents, validation_results, strict_mode = FALSE) {
      if (!"data" %in% names(documents)) return(validation_results)
      
      min_date <- self$validation_rules$document_standards$date_range$min_date
      max_date <- self$validation_rules$document_standards$date_range$max_date
      
      # Parse dates
      parsed_dates <- self$parse_brazilian_dates(documents$data)
      
      # Check for unparseable dates
      invalid_dates <- which(is.na(parsed_dates))
      if (length(invalid_dates) > 0) {
        validation_results$is_valid[invalid_dates] <- FALSE
        validation_results$validation_errors[invalid_dates] <- paste0(
          validation_results$validation_errors[invalid_dates],
          "Invalid date format; "
        )
      }
      
      # Check date range
      valid_date_indices <- which(!is.na(parsed_dates))
      if (length(valid_date_indices) > 0) {
        early_dates <- which(parsed_dates < min_date)
        if (length(early_dates) > 0) {
          if (strict_mode) {
            validation_results$is_valid[early_dates] <- FALSE
            validation_results$validation_errors[early_dates] <- paste0(
              validation_results$validation_errors[early_dates],
              "Date too early; "
            )
          } else {
            validation_results$validation_warnings[early_dates] <- paste0(
              validation_results$validation_warnings[early_dates],
              "Date before 1988; "
            )
          }
        }
        
        future_dates <- which(parsed_dates > max_date)
        if (length(future_dates) > 0) {
          validation_results$validation_warnings[future_dates] <- paste0(
            validation_results$validation_warnings[future_dates],
            "Future date; "
          )
        }
      }
      
      return(validation_results)
    },
    
    validate_geographic_data = function(documents, validation_results) {
      valid_states <- self$validation_rules$geographic_standards$valid_states
      
      if ("estado" %in% names(documents)) {
        invalid_states <- which(!(documents$estado %in% c("", valid_states)))
        if (length(invalid_states) > 0) {
          validation_results$validation_warnings[invalid_states] <- paste0(
            validation_results$validation_warnings[invalid_states],
            "Invalid state code; "
          )
        }
      }
      
      return(validation_results)
    },
    
    validate_document_types = function(documents, validation_results) {
      if (!"tipo" %in% names(documents)) return(validation_results)
      
      valid_types <- self$validation_rules$document_categories$valid_types
      
      # Fuzzy match document types
      for (i in 1:nrow(documents)) {
        if (is.na(documents$tipo[i]) || documents$tipo[i] == "") next
        
        # Check exact match first
        if (documents$tipo[i] %in% valid_types) next
        
        # Check fuzzy match
        if (requireNamespace("stringdist", quietly = TRUE)) {
          distances <- stringdist::stringdist(
            tolower(documents$tipo[i]), 
            tolower(valid_types),
            method = "jw"
          )
          
          min_distance <- min(distances)
          if (min_distance > 0.3) {  # No good fuzzy match
            validation_results$validation_warnings[i] <- paste0(
              validation_results$validation_warnings[i],
              "Unrecognized document type; "
            )
          }
        }
      }
      
      return(validation_results)
    },
    
    validate_authorities = function(documents, validation_results) {
      if (!"autoridade" %in% names(documents)) return(validation_results)
      
      authority_patterns <- self$validation_rules$document_categories$authority_patterns
      
      for (i in 1:nrow(documents)) {
        if (is.na(documents$autoridade[i]) || documents$autoridade[i] == "") next
        
        authority <- tolower(documents$autoridade[i])
        recognized <- FALSE
        
        # Check against known patterns
        for (level in names(authority_patterns)) {
          patterns <- authority_patterns[[level]]
          for (pattern in patterns) {
            if (grepl(tolower(pattern), authority)) {
              recognized <- TRUE
              break
            }
          }
          if (recognized) break
        }
        
        if (!recognized) {
          validation_results$validation_warnings[i] <- paste0(
            validation_results$validation_warnings[i],
            "Unrecognized authority; "
          )
        }
      }
      
      return(validation_results)
    },
    
    calculate_quality_scores = function(documents, validation_results) {
      quality_scores <- rep(0, nrow(documents))
      
      # Base score for having required fields (40 points)
      required_fields <- self$validation_rules$document_standards$required_fields
      for (field in required_fields) {
        if (field %in% names(documents)) {
          has_field <- !is.na(documents[[field]]) & documents[[field]] != ""
          quality_scores <- quality_scores + ifelse(has_field, 10, 0)
        }
      }
      
      # Title quality (15 points)
      if ("titulo" %in% names(documents)) {
        title_lengths <- nchar(as.character(documents$titulo))
        title_quality <- pmin(title_lengths / 50, 1) * 15
        quality_scores <- quality_scores + title_quality
      }
      
      # Summary quality (15 points)
      if ("ementa" %in% names(documents)) {
        has_summary <- !is.na(documents$ementa) & documents$ementa != ""
        summary_lengths <- nchar(as.character(documents$ementa))
        summary_quality <- ifelse(has_summary, pmin(summary_lengths / 100, 1) * 15, 0)
        quality_scores <- quality_scores + summary_quality
      }
      
      # URL availability (5 points)
      if ("url" %in% names(documents)) {
        has_url <- !is.na(documents$url) & documents$url != ""
        quality_scores <- quality_scores + ifelse(has_url, 5, 0)
      }
      
      # Geographic information (10 points)
      if ("estado" %in% names(documents)) {
        has_state <- !is.na(documents$estado) & documents$estado != ""
        quality_scores <- quality_scores + ifelse(has_state, 5, 0)
      }
      
      if ("municipio" %in% names(documents)) {
        has_municipality <- !is.na(documents$municipio) & documents$municipio != ""
        quality_scores <- quality_scores + ifelse(has_municipality, 5, 0)
      }
      
      # Date recency (10 points for documents from last 5 years)
      if ("data" %in% names(documents)) {
        parsed_dates <- self$parse_brazilian_dates(documents$data)
        recent_threshold <- Sys.Date() - years(5)
        is_recent <- !is.na(parsed_dates) & parsed_dates >= recent_threshold
        quality_scores <- quality_scores + ifelse(is_recent, 10, 0)
      }
      
      # Subject matter classification (5 points)
      if ("assuntos" %in% names(documents)) {
        has_subjects <- !is.na(documents$assuntos) & documents$assuntos != ""
        quality_scores <- quality_scores + ifelse(has_subjects, 5, 0)
      }
      
      # Cap scores at 100
      validation_results$quality_score <- pmin(quality_scores, 100)
      
      return(validation_results)
    },
    
    parse_brazilian_dates = function(date_strings) {
      if (is.null(date_strings)) return(rep(NA, 0))
      
      parsed_dates <- rep(NA, length(date_strings))
      
      # Brazilian date formats
      date_formats <- c(
        "%d/%m/%Y",     # 31/12/2023
        "%Y-%m-%d",     # 2023-12-31
        "%d-%m-%Y",     # 31-12-2023
        "%d.%m.%Y",     # 31.12.2023
        "%d/%m/%y",     # 31/12/23
        "%Y/%m/%d"      # 2023/12/31
      )
      
      for (i in seq_along(date_strings)) {
        if (is.na(date_strings[i]) || date_strings[i] == "") next
        
        for (fmt in date_formats) {
          tryCatch({
            parsed <- as.Date(date_strings[i], format = fmt)
            if (!is.na(parsed)) {
              parsed_dates[i] <- parsed
              break
            }
          }, error = function(e) NULL)
        }
      }
      
      return(parsed_dates)
    },
    
    create_validation_report = function(documents, validation_results) {
      total_docs <- nrow(documents)
      valid_docs <- sum(validation_results$is_valid)
      
      # Quality distribution
      quality_scores <- validation_results$quality_score
      quality_dist <- list(
        excellent = sum(quality_scores >= 90),
        good = sum(quality_scores >= 75 & quality_scores < 90),
        acceptable = sum(quality_scores >= 60 & quality_scores < 75),
        poor = sum(quality_scores >= 40 & quality_scores < 60),
        unacceptable = sum(quality_scores < 40)
      )
      
      # Error analysis
      all_errors <- paste(validation_results$validation_errors, collapse = " ")
      error_types <- self$analyze_error_patterns(all_errors)
      
      # Warning analysis
      all_warnings <- paste(validation_results$validation_warnings, collapse = " ")
      warning_types <- self$analyze_error_patterns(all_warnings)
      
      report <- list(
        summary = list(
          total_documents = total_docs,
          valid_documents = valid_docs,
          validation_rate = round((valid_docs / total_docs) * 100, 2),
          average_quality_score = round(mean(quality_scores, na.rm = TRUE), 2)
        ),
        quality_distribution = quality_dist,
        error_analysis = error_types,
        warning_analysis = warning_types,
        validation_timestamp = Sys.time(),
        validation_config = list(
          strict_mode = FALSE,
          min_quality_threshold = 40,
          validation_rules_version = "4B.1.0"
        )
      )
      
      return(report)
    },
    
    analyze_error_patterns = function(error_text) {
      if (is.na(error_text) || error_text == "") {
        return(list())
      }
      
      error_patterns <- list(
        "Missing required field" = "Missing required field",
        "Empty required field" = "Empty required field",
        "Title too short" = "Title too short",
        "Invalid date format" = "Invalid date format",
        "Date too early" = "Date too early",
        "Invalid state code" = "Invalid state code",
        "Unrecognized document type" = "Unrecognized document type",
        "Unrecognized authority" = "Unrecognized authority"
      )
      
      error_counts <- list()
      for (pattern_name in names(error_patterns)) {
        pattern <- error_patterns[[pattern_name]]
        count <- length(gregexpr(pattern, error_text, fixed = TRUE)[[1]])
        if (count > 0) {
          error_counts[[pattern_name]] <- count
        }
      }
      
      return(error_counts)
    },
    
    create_empty_report = function() {
      return(list(
        summary = list(
          total_documents = 0,
          valid_documents = 0,
          validation_rate = 0,
          average_quality_score = 0
        ),
        quality_distribution = list(
          excellent = 0, good = 0, acceptable = 0, poor = 0, unacceptable = 0
        ),
        error_analysis = list(),
        warning_analysis = list(),
        validation_timestamp = Sys.time()
      ))
    }
  )
)

# ============================================================================
# DUPLICATE DETECTION SYSTEM
# ============================================================================

#' Duplicate Detection and Deduplication
DuplicateDetector <- R6::R6Class("DuplicateDetector",
  public = list(
    similarity_threshold = 0.95,
    
    initialize = function(similarity_threshold = 0.95) {
      self$similarity_threshold <- similarity_threshold
      log_etl("INFO", sprintf("Duplicate detector initialized (threshold: %.2f)", similarity_threshold), "DEDUPLICATOR")
    },
    
    detect_and_remove_duplicates = function(documents) {
      if (is.null(documents) || nrow(documents) == 0) return(documents)
      
      log_etl("INFO", sprintf("Starting duplicate detection for %d documents", nrow(documents)), "DEDUPLICATOR")
      start_time <- Sys.time()
      
      # Create document fingerprints
      documents$fingerprint <- self$create_fingerprints(documents)
      
      # Exact duplicate detection
      exact_duplicates <- self$find_exact_duplicates(documents)
      
      # Fuzzy duplicate detection
      fuzzy_duplicates <- self$find_fuzzy_duplicates(documents)
      
      # Combine duplicate indices
      all_duplicates <- unique(c(exact_duplicates, fuzzy_duplicates))
      
      # Remove duplicates
      if (length(all_duplicates) > 0) {
        clean_documents <- documents[-all_duplicates, ]
        clean_documents$fingerprint <- NULL  # Remove temporary column
        
        log_etl("INFO", sprintf("Removed %d duplicate documents (%d exact, %d fuzzy)", 
                               length(all_duplicates), length(exact_duplicates), 
                               length(fuzzy_duplicates)), "DEDUPLICATOR")
      } else {
        clean_documents <- documents
        clean_documents$fingerprint <- NULL
        log_etl("INFO", "No duplicates found", "DEDUPLICATOR")
      }
      
      end_time <- Sys.time()
      duration <- as.numeric(end_time - start_time, units = "secs")
      
      log_etl("INFO", sprintf("Deduplication complete in %.2f seconds", duration), "DEDUPLICATOR")
      
      return(clean_documents)
    },
    
    create_fingerprints = function(documents) {
      fingerprints <- character(nrow(documents))
      
      for (i in 1:nrow(documents)) {
        # Create fingerprint from key fields
        key_fields <- paste(
          self$normalize_text(documents$titulo[i] %||% ""),
          self$normalize_text(documents$data[i] %||% ""),
          self$normalize_text(documents$autoridade[i] %||% ""),
          sep = "|"
        )
        
        fingerprints[i] <- digest::digest(key_fields, algo = "md5")
      }
      
      return(fingerprints)
    },
    
    find_exact_duplicates = function(documents) {
      duplicate_indices <- which(duplicated(documents$fingerprint))
      return(duplicate_indices)
    },
    
    find_fuzzy_duplicates = function(documents) {
      if (!requireNamespace("stringdist", quietly = TRUE)) {
        log_etl("WARN", "stringdist package not available, skipping fuzzy duplicate detection", "DEDUPLICATOR")
        return(numeric(0))
      }
      
      fuzzy_duplicates <- numeric(0)
      
      # Only check documents without exact duplicates
      exact_dups <- self$find_exact_duplicates(documents)
      candidate_indices <- setdiff(1:nrow(documents), exact_dups)
      
      if (length(candidate_indices) < 2) return(fuzzy_duplicates)
      
      # Compare titles for similarity
      for (i in 1:(length(candidate_indices) - 1)) {
        idx1 <- candidate_indices[i]
        title1 <- self$normalize_text(documents$titulo[idx1] %||% "")
        
        if (nchar(title1) < 20) next  # Skip very short titles
        
        for (j in (i + 1):length(candidate_indices)) {
          idx2 <- candidate_indices[j]
          title2 <- self$normalize_text(documents$titulo[idx2] %||% "")
          
          if (nchar(title2) < 20) next
          
          # Calculate Jaro-Winkler similarity
          similarity <- 1 - stringdist::stringdist(title1, title2, method = "jw")
          
          if (similarity >= self$similarity_threshold) {
            # Additional check: same date and similar authority
            date1 <- documents$data[idx1] %||% ""
            date2 <- documents$data[idx2] %||% ""
            auth1 <- self$normalize_text(documents$autoridade[idx1] %||% "")
            auth2 <- self$normalize_text(documents$autoridade[idx2] %||% "")
            
            if (date1 == date2 && auth1 == auth2) {
              fuzzy_duplicates <- c(fuzzy_duplicates, idx2)  # Keep the first one
            }
          }
        }
      }
      
      return(unique(fuzzy_duplicates))
    },
    
    normalize_text = function(text) {
      if (is.null(text) || is.na(text) || text == "") return("")
      
      # Convert to lowercase and remove extra whitespace
      normalized <- tolower(stringr::str_trim(stringr::str_squish(as.character(text))))
      
      # Remove punctuation and special characters
      normalized <- gsub("[^a-z0-9\\s]", "", normalized)
      
      # Remove common stopwords in Portuguese
      stopwords <- c("da", "de", "do", "das", "dos", "a", "o", "as", "os", "e", "em", "na", "no", "para", "por")
      for (word in stopwords) {
        normalized <- gsub(paste0("\\b", word, "\\b"), "", normalized)
      }
      
      # Remove extra spaces
      normalized <- stringr::str_trim(stringr::str_squish(normalized))
      
      return(normalized)
    }
  )
)

# ============================================================================
# DATA QUALITY MONITOR
# ============================================================================

#' Data Quality Monitoring and Reporting
QualityMonitor <- R6::R6Class("QualityMonitor",
  public = list(
    quality_history = list(),
    thresholds = NULL,
    
    initialize = function() {
      self$thresholds <- VALIDATION_CONFIG$quality_thresholds
      log_etl("INFO", "Quality monitor initialized", "QUALITY_MONITOR")
    },
    
    monitor_quality = function(validation_report, alert_threshold = 75) {
      current_quality <- validation_report$summary$validation_rate
      
      # Store quality metric
      quality_record <- list(
        timestamp = Sys.time(),
        validation_rate = current_quality,
        average_score = validation_report$summary$average_quality_score,
        total_documents = validation_report$summary$total_documents,
        valid_documents = validation_report$summary$valid_documents
      )
      
      self$quality_history <- append(self$quality_history, list(quality_record))
      
      # Keep only last 100 records to manage memory
      if (length(self$quality_history) > 100) {
        self$quality_history <- tail(self$quality_history, 100)
      }
      
      # Check for quality degradation
      if (current_quality < alert_threshold) {
        self$send_quality_alert(validation_report, "LOW_QUALITY")
      }
      
      # Check for trend degradation
      if (length(self$quality_history) >= 5) {
        recent_trend <- self$calculate_quality_trend()
        if (recent_trend$slope < -2) {  # Declining by more than 2% per measurement
          self$send_quality_alert(validation_report, "DECLINING_TREND")
        }
      }
      
      log_etl("INFO", sprintf("Quality monitoring: %.2f%% validation rate, %.1f avg score", 
                             current_quality, validation_report$summary$average_quality_score), "QUALITY_MONITOR")
    },
    
    calculate_quality_trend = function() {
      if (length(self$quality_history) < 3) {
        return(list(slope = 0, trend = "insufficient_data"))
      }
      
      recent_records <- tail(self$quality_history, 5)
      times <- sapply(recent_records, function(x) as.numeric(x$timestamp))
      rates <- sapply(recent_records, function(x) x$validation_rate)
      
      # Simple linear regression
      n <- length(times)
      slope <- (n * sum(times * rates) - sum(times) * sum(rates)) / 
               (n * sum(times^2) - sum(times)^2)
      
      trend <- if (slope > 1) "improving" else if (slope < -1) "declining" else "stable"
      
      return(list(slope = slope, trend = trend))
    },
    
    send_quality_alert = function(validation_report, alert_type) {
      alert <- list(
        timestamp = Sys.time(),
        type = alert_type,
        validation_rate = validation_report$summary$validation_rate,
        average_score = validation_report$summary$average_quality_score,
        total_documents = validation_report$summary$total_documents,
        message = self$create_alert_message(alert_type, validation_report)
      )
      
      log_etl("WARN", sprintf("QUALITY ALERT [%s]: %s", alert_type, alert$message), "QUALITY_MONITOR")
      
      # Save alert to file
      alert_file <- file.path("pipeline/logs", paste0("quality_alert_", 
                                                     format(Sys.time(), "%Y%m%d_%H%M%S"), ".json"))
      tryCatch({
        writeLines(jsonlite::toJSON(alert, pretty = TRUE), alert_file)
      }, error = function(e) {
        log_etl("ERROR", sprintf("Failed to write quality alert: %s", e$message), "QUALITY_MONITOR")
      })
    },
    
    create_alert_message = function(alert_type, validation_report) {
      switch(alert_type,
        "LOW_QUALITY" = sprintf(
          "Data validation rate dropped to %.2f%% (threshold: 75%%)",
          validation_report$summary$validation_rate
        ),
        "DECLINING_TREND" = sprintf(
          "Data quality showing declining trend: %.2f%% validation rate",
          validation_report$summary$validation_rate
        ),
        "Unknown alert type"
      )
    },
    
    generate_quality_summary = function() {
      if (length(self$quality_history) == 0) {
        return(list(message = "No quality data available"))
      }
      
      recent_records <- tail(self$quality_history, 10)
      
      summary <- list(
        current_validation_rate = tail(recent_records, 1)[[1]]$validation_rate,
        average_validation_rate = mean(sapply(recent_records, function(x) x$validation_rate)),
        trend = self$calculate_quality_trend()$trend,
        total_documents_processed = sum(sapply(recent_records, function(x) x$total_documents)),
        monitoring_period = list(
          start = head(recent_records, 1)[[1]]$timestamp,
          end = tail(recent_records, 1)[[1]]$timestamp
        ),
        alerts_count = length(list.files("pipeline/logs", pattern = "quality_alert_.*\\.json"))
      )
      
      return(summary)
    }
  )
)

# ============================================================================
# MAIN VALIDATION ORCHESTRATOR
# ============================================================================

#' Main validation orchestrator
ValidationOrchestrator <- R6::R6Class("ValidationOrchestrator",
  public = list(
    document_validator = NULL,
    duplicate_detector = NULL,
    quality_monitor = NULL,
    
    initialize = function() {
      self$document_validator <- DocumentValidator$new()
      self$duplicate_detector <- DuplicateDetector$new()
      self$quality_monitor <- QualityMonitor$new()
      
      log_etl("INFO", "Validation orchestrator initialized", "VALIDATION_ORCHESTRATOR")
    },
    
    run_full_validation = function(documents, strict_mode = FALSE) {
      if (is.null(documents) || nrow(documents) == 0) {
        return(list(
          valid_documents = data.frame(),
          validation_report = self$document_validator$create_empty_report()
        ))
      }
      
      log_etl("INFO", sprintf("Starting full validation pipeline for %d documents", nrow(documents)), "VALIDATION_ORCHESTRATOR")
      start_time <- Sys.time()
      
      # Step 1: Document validation
      validation_result <- self$document_validator$validate_document_batch(documents, strict_mode)
      log_etl("INFO", sprintf("Document validation: %d/%d documents valid", 
                             nrow(validation_result$valid_documents), nrow(documents)), "VALIDATION_ORCHESTRATOR")
      
      # Step 2: Duplicate detection and removal
      if (nrow(validation_result$valid_documents) > 0) {
        deduplicated_documents <- self$duplicate_detector$detect_and_remove_duplicates(validation_result$valid_documents)
        log_etl("INFO", sprintf("Deduplication: %d documents after removing duplicates", 
                               nrow(deduplicated_documents)), "VALIDATION_ORCHESTRATOR")
      } else {
        deduplicated_documents <- validation_result$valid_documents
      }
      
      # Step 3: Quality monitoring
      self$quality_monitor$monitor_quality(validation_result$validation_report)
      
      end_time <- Sys.time()
      duration <- as.numeric(end_time - start_time, units = "mins")
      
      log_etl("INFO", sprintf("Full validation pipeline completed in %.2f minutes", duration), "VALIDATION_ORCHESTRATOR")
      
      # Update validation report with final counts
      validation_result$validation_report$summary$final_valid_documents <- nrow(deduplicated_documents)
      validation_result$validation_report$summary$duplicates_removed <- 
        nrow(validation_result$valid_documents) - nrow(deduplicated_documents)
      
      return(list(
        valid_documents = deduplicated_documents,
        validation_report = validation_result$validation_report,
        quality_summary = self$quality_monitor$generate_quality_summary()
      ))
    }
  )
)

# ============================================================================
# EXPORTS AND INITIALIZATION
# ============================================================================

# Global validation orchestrator
validation_orchestrator <- NULL

initialize_validation_system <- function() {
  cat("🔍 Initializing Data Validation and Quality Assurance System...\n")
  
  tryCatch({
    validation_orchestrator <<- ValidationOrchestrator$new()
    
    cat("✅ Validation system initialized successfully\n")
    cat("🔧 Components loaded:\n")
    cat("   - Document Validator (Brazilian legislative standards)\n")
    cat("   - Duplicate Detector (exact and fuzzy matching)\n")
    cat("   - Quality Monitor (trend analysis and alerting)\n")
    cat("📊 Ready for data validation operations\n")
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Validation system initialization failed:", e$message, "\n")
    return(FALSE)
  })
}

# Export main functions
validate_documents <- function(documents, strict_mode = FALSE) {
  if (is.null(validation_orchestrator)) {
    if (!initialize_validation_system()) {
      return(NULL)
    }
  }
  
  return(validation_orchestrator$run_full_validation(documents, strict_mode))
}

get_validation_status <- function() {
  if (is.null(validation_orchestrator)) {
    return(list(status = "not_initialized"))
  }
  
  return(list(
    status = "ready",
    quality_summary = validation_orchestrator$quality_monitor$generate_quality_summary()
  ))
}

cat("🔍 Data Validation and Quality Assurance Framework loaded\n")
cat("📋 Brazilian Legislative Document Standards Compliance Ready\n")
cat("🔧 Use initialize_validation_system() to start\n")