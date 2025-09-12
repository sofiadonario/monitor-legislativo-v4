# ============================================================================
# DATA VALIDATION SCHEMAS - SPRINT 6B (API-001)
# ============================================================================
# 
# Comprehensive data validation schemas for Brazilian legislative data
# Ensures data integrity, consistency, and LGPD compliance
# 
# Features:
# - Document structure validation
# - Brazilian-specific field validation (states, dates, legal terms)
# - Input sanitization and normalization
# - LGPD compliance validation
# - API request/response schema validation
# - Academic research data standards
# ============================================================================

cat("📋 Loading Data Validation Schemas\n")

# Brazilian states validation list
VALID_BRAZILIAN_STATES <- c(
  "AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
  "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
  "RS", "RO", "RR", "SC", "SP", "SE", "TO"
)

# Valid document categories
VALID_DOCUMENT_CATEGORIES <- c(
  "legislation", "jurisprudence", "doctrine", "other"
)

# Valid document types (Brazilian legal documents)
VALID_DOCUMENT_TYPES <- c(
  "Lei", "Decreto", "Portaria", "Resolução", "Medida Provisória", 
  "Lei Complementar", "Lei Orgânica", "Constituição", "Código",
  "Instrução Normativa", "Ordem de Serviço", "Circular",
  "Acórdão", "Decisão", "Sentença", "Súmula", "Agravo",
  "Apelação", "Recurso", "Embargos", "Mandado de Segurança",
  "Artigo", "Parecer", "Estudo", "Tese", "Dissertação",
  "Livro", "Capítulo", "Comentário", "Análise",
  "Notícia", "Informativo", "Comunicado", "Aviso", "Edital"
)

# Date validation patterns
DATE_PATTERNS <- c(
  "\\d{4}-\\d{2}-\\d{2}", # YYYY-MM-DD
  "\\d{2}/\\d{2}/\\d{4}", # DD/MM/YYYY
  "\\d{4}/\\d{2}/\\d{2}"  # YYYY/MM/DD
)

# Helper function to validate Brazilian state
validate_state <- function(state) {
  if (is.null(state) || is.na(state) || state == "") {
    return(list(valid = TRUE, normalized = ""))
  }
  
  # Normalize to uppercase
  state_upper <- toupper(trimws(state))
  
  if (state_upper %in% VALID_BRAZILIAN_STATES) {
    return(list(valid = TRUE, normalized = state_upper))
  } else {
    return(list(
      valid = FALSE,
      error = paste("Invalid Brazilian state code:", state),
      normalized = state_upper
    ))
  }
}

# Helper function to validate and normalize date
validate_date <- function(date_input) {
  if (is.null(date_input) || is.na(date_input) || date_input == "") {
    return(list(valid = TRUE, normalized = NULL))
  }
  
  # Try different date formats
  date_formats <- c("%Y-%m-%d", "%d/%m/%Y", "%Y/%m/%d", "%Y-%m-%dT%H:%M:%S")
  
  for (format in date_formats) {
    tryCatch({
      parsed_date <- as.Date(date_input, format = format)
      if (!is.na(parsed_date)) {
        # Validate date range (reasonable for Brazilian legislation)
        min_date <- as.Date("1824-01-01") # First Brazilian Constitution
        max_date <- Sys.Date() + 365 # Allow future dates up to 1 year
        
        if (parsed_date >= min_date && parsed_date <= max_date) {
          return(list(
            valid = TRUE,
            normalized = as.character(parsed_date),
            original_format = format
          ))
        } else {
          return(list(
            valid = FALSE,
            error = paste("Date out of valid range (1824-01-01 to", as.character(max_date), ")"),
            normalized = as.character(parsed_date)
          ))
        }
      }
    }, error = function(e) {
      # Continue trying other formats
    })
  }
  
  return(list(
    valid = FALSE,
    error = paste("Invalid date format:", date_input),
    normalized = date_input
  ))
}

# Helper function to validate document category
validate_category <- function(category) {
  if (is.null(category) || is.na(category) || category == "") {
    return(list(valid = TRUE, normalized = "other"))
  }
  
  category_lower <- tolower(trimws(category))
  
  if (category_lower %in% VALID_DOCUMENT_CATEGORIES) {
    return(list(valid = TRUE, normalized = category_lower))
  } else {
    return(list(
      valid = FALSE,
      error = paste("Invalid category. Valid options:", paste(VALID_DOCUMENT_CATEGORIES, collapse = ", ")),
      normalized = "other"
    ))
  }
}

# Helper function to validate document type
validate_document_type <- function(doc_type) {
  if (is.null(doc_type) || is.na(doc_type) || doc_type == "") {
    return(list(valid = TRUE, normalized = ""))
  }
  
  # Normalize case and spaces
  doc_type_normalized <- stringr::str_to_title(trimws(doc_type))
  
  # Check exact match
  if (doc_type_normalized %in% VALID_DOCUMENT_TYPES) {
    return(list(valid = TRUE, normalized = doc_type_normalized))
  }
  
  # Check partial match (fuzzy matching)
  fuzzy_matches <- VALID_DOCUMENT_TYPES[grepl(doc_type_normalized, VALID_DOCUMENT_TYPES, ignore.case = TRUE)]
  
  if (length(fuzzy_matches) == 1) {
    return(list(
      valid = TRUE,
      normalized = fuzzy_matches[1],
      fuzzy_match = TRUE
    ))
  } else if (length(fuzzy_matches) > 1) {
    return(list(
      valid = FALSE,
      error = paste("Ambiguous document type. Possible matches:", paste(fuzzy_matches, collapse = ", ")),
      normalized = doc_type_normalized,
      suggestions = fuzzy_matches
    ))
  } else {
    return(list(
      valid = TRUE, # Allow unknown types but flag them
      normalized = doc_type_normalized,
      warning = "Document type not in standard list",
      custom_type = TRUE
    ))
  }
}

# Helper function to validate and sanitize text fields
validate_text_field <- function(text, field_name, max_length = NULL, required = FALSE) {
  if (is.null(text) || is.na(text)) {
    if (required) {
      return(list(
        valid = FALSE,
        error = paste(field_name, "is required"),
        normalized = ""
      ))
    } else {
      return(list(valid = TRUE, normalized = ""))
    }
  }
  
  # Convert to character and trim
  text_str <- trimws(as.character(text))
  
  if (required && nchar(text_str) == 0) {
    return(list(
      valid = FALSE,
      error = paste(field_name, "cannot be empty"),
      normalized = ""
    ))
  }
  
  # Check length if specified
  if (!is.null(max_length) && nchar(text_str) > max_length) {
    return(list(
      valid = FALSE,
      error = paste(field_name, "exceeds maximum length of", max_length, "characters"),
      normalized = substr(text_str, 1, max_length)
    ))
  }
  
  # Basic sanitization (remove control characters, normalize spaces)
  sanitized_text <- gsub("[\\x00-\\x1F\\x7F]", "", text_str) # Remove control characters
  sanitized_text <- gsub("\\s+", " ", sanitized_text) # Normalize whitespace
  
  return(list(
    valid = TRUE,
    normalized = sanitized_text,
    original_length = nchar(text_str),
    sanitized = sanitized_text != text_str
  ))
}

# Helper function to validate URLs
validate_url <- function(url) {
  if (is.null(url) || is.na(url) || url == "") {
    return(list(valid = TRUE, normalized = ""))
  }
  
  url_trimmed <- trimws(url)
  
  # Basic URL pattern validation
  url_pattern <- "^https?://[^\\s/$.?#].[^\\s]*$"
  
  if (grepl(url_pattern, url_trimmed, ignore.case = TRUE)) {
    return(list(valid = TRUE, normalized = url_trimmed))
  } else {
    return(list(
      valid = FALSE,
      error = "Invalid URL format",
      normalized = url_trimmed
    ))
  }
}

# Helper function to validate pagination parameters
validate_pagination <- function(limit, offset) {
  result <- list(valid = TRUE, normalized = list())
  
  # Validate limit
  if (is.null(limit) || is.na(limit)) {
    result$normalized$limit <- 100 # Default
  } else {
    limit_num <- as.numeric(limit)
    if (is.na(limit_num) || limit_num < 1) {
      result$valid <- FALSE
      result$error <- "Limit must be a positive number"
      result$normalized$limit <- 100
    } else if (limit_num > 10000) {
      result$normalized$limit <- 10000 # Maximum
      result$warning <- "Limit capped at maximum value of 10000"
    } else {
      result$normalized$limit <- as.integer(limit_num)
    }
  }
  
  # Validate offset
  if (is.null(offset) || is.na(offset)) {
    result$normalized$offset <- 0 # Default
  } else {
    offset_num <- as.numeric(offset)
    if (is.na(offset_num) || offset_num < 0) {
      result$valid <- FALSE
      result$error <- paste(result$error %||% "", "Offset must be a non-negative number")
      result$normalized$offset <- 0
    } else {
      result$normalized$offset <- as.integer(offset_num)
    }
  }
  
  return(result)
}

# Main document validation schema
validate_document_schema <- function(document_data) {
  validation_results <- list(
    valid = TRUE,
    errors = c(),
    warnings = c(),
    normalized = list()
  )
  
  # Validate required fields
  title_validation <- validate_text_field(document_data$title, "title", max_length = 500, required = TRUE)
  if (!title_validation$valid) {
    validation_results$valid <- FALSE
    validation_results$errors <- c(validation_results$errors, title_validation$error)
  }
  validation_results$normalized$title <- title_validation$normalized
  
  # Validate optional fields
  category_validation <- validate_category(document_data$category)
  if (!category_validation$valid) {
    validation_results$warnings <- c(validation_results$warnings, category_validation$error)
  }
  validation_results$normalized$category <- category_validation$normalized
  
  state_validation <- validate_state(document_data$state)
  if (!state_validation$valid) {
    validation_results$warnings <- c(validation_results$warnings, state_validation$error)
  }
  validation_results$normalized$state <- state_validation$normalized
  
  date_validation <- validate_date(document_data$date)
  if (!date_validation$valid) {
    validation_results$warnings <- c(validation_results$warnings, date_validation$error)
  }
  validation_results$normalized$date <- date_validation$normalized
  
  summary_validation <- validate_text_field(document_data$summary, "summary", max_length = 2000)
  validation_results$normalized$summary <- summary_validation$normalized
  
  url_validation <- validate_url(document_data$url)
  if (!url_validation$valid) {
    validation_results$warnings <- c(validation_results$warnings, url_validation$error)
  }
  validation_results$normalized$url <- url_validation$normalized
  
  type_validation <- validate_document_type(document_data$document_type)
  if (!type_validation$valid) {
    validation_results$warnings <- c(validation_results$warnings, type_validation$error)
  } else if (!is.null(type_validation$warning)) {
    validation_results$warnings <- c(validation_results$warnings, type_validation$warning)
  }
  validation_results$normalized$document_type <- type_validation$normalized
  
  # Validate other text fields
  fields_to_validate <- c("urn", "municipality", "author", "subjects")
  for (field in fields_to_validate) {
    if (field %in% names(document_data)) {
      field_validation <- validate_text_field(document_data[[field]], field, max_length = 200)
      validation_results$normalized[[field]] <- field_validation$normalized
    } else {
      validation_results$normalized[[field]] <- ""
    }
  }
  
  return(validation_results)
}

# Search request validation schema
validate_search_request <- function(search_data) {
  validation_results <- list(
    valid = TRUE,
    errors = c(),
    warnings = c(),
    normalized = list()
  )
  
  # Validate query
  query_validation <- validate_text_field(search_data$query, "query", max_length = 200, required = TRUE)
  if (!query_validation$valid) {
    validation_results$valid <- FALSE
    validation_results$errors <- c(validation_results$errors, query_validation$error)
  }
  validation_results$normalized$query <- query_validation$normalized
  
  # Validate filters
  if (!is.null(search_data$filters)) {
    filters_normalized <- list()
    
    if (!is.null(search_data$filters$category)) {
      cat_validation <- validate_category(search_data$filters$category)
      filters_normalized$category <- cat_validation$normalized
    }
    
    if (!is.null(search_data$filters$state)) {
      state_validation <- validate_state(search_data$filters$state)
      filters_normalized$state <- state_validation$normalized
    }
    
    if (!is.null(search_data$filters$date_start)) {
      date_validation <- validate_date(search_data$filters$date_start)
      filters_normalized$date_start <- date_validation$normalized
    }
    
    if (!is.null(search_data$filters$date_end)) {
      date_validation <- validate_date(search_data$filters$date_end)
      filters_normalized$date_end <- date_validation$normalized
    }
    
    validation_results$normalized$filters <- filters_normalized
  }
  
  # Validate pagination
  pagination_validation <- validate_pagination(search_data$limit, search_data$offset)
  if (!pagination_validation$valid) {
    validation_results$errors <- c(validation_results$errors, pagination_validation$error)
  }
  if (!is.null(pagination_validation$warning)) {
    validation_results$warnings <- c(validation_results$warnings, pagination_validation$warning)
  }
  validation_results$normalized$limit <- pagination_validation$normalized$limit
  validation_results$normalized$offset <- pagination_validation$normalized$offset
  
  # Validate sort options
  valid_sort_options <- c("relevance", "date_desc", "date_asc", "title_asc", "title_desc")
  sort_by <- search_data$sort_by %||% "relevance"
  
  if (sort_by %in% valid_sort_options) {
    validation_results$normalized$sort_by <- sort_by
  } else {
    validation_results$warnings <- c(validation_results$warnings, 
                                   paste("Invalid sort option, using default. Valid options:", 
                                         paste(valid_sort_options, collapse = ", ")))
    validation_results$normalized$sort_by <- "relevance"
  }
  
  return(validation_results)
}

# API response validation schema
validate_api_response <- function(response_data) {
  validation_results <- list(
    valid = TRUE,
    errors = c(),
    warnings = c()
  )
  
  # Check required response structure
  required_fields <- c("error", "message", "timestamp")
  
  for (field in required_fields) {
    if (!field %in% names(response_data)) {
      validation_results$valid <- FALSE
      validation_results$errors <- c(validation_results$errors, 
                                   paste("Missing required response field:", field))
    }
  }
  
  # Validate error field
  if ("error" %in% names(response_data) && !is.logical(response_data$error)) {
    validation_results$warnings <- c(validation_results$warnings, 
                                   "Error field should be boolean")
  }
  
  # Validate data field structure for successful responses
  if ("data" %in% names(response_data) && !response_data$error) {
    if (is.null(response_data$data)) {
      validation_results$warnings <- c(validation_results$warnings, 
                                     "Data field is null in successful response")
    }
  }
  
  # Validate meta field
  if ("meta" %in% names(response_data)) {
    meta_data <- response_data$meta
    
    # Check for pagination metadata
    if ("total" %in% names(meta_data) && !is.numeric(meta_data$total)) {
      validation_results$warnings <- c(validation_results$warnings, 
                                     "Meta total field should be numeric")
    }
  }
  
  return(validation_results)
}

# LGPD compliance validation
validate_lgpd_compliance <- function(data) {
  compliance_results <- list(
    compliant = TRUE,
    issues = c(),
    recommendations = c()
  )
  
  # Check for potentially sensitive fields
  sensitive_fields <- c("cpf", "cnpj", "email", "phone", "address", "personal_data")
  
  for (field in sensitive_fields) {
    if (field %in% names(data)) {
      compliance_results$compliant <- FALSE
      compliance_results$issues <- c(compliance_results$issues, 
                                   paste("Potentially sensitive field detected:", field))
    }
  }
  
  # Check for IP address anonymization
  if ("client_ip" %in% names(data)) {
    ip <- data$client_ip
    if (!grepl("xxx|anonymized", ip)) {
      compliance_results$recommendations <- c(compliance_results$recommendations,
                                            "Consider anonymizing IP addresses for LGPD compliance")
    }
  }
  
  return(compliance_results)
}

# Function to get validation statistics
get_validation_stats <- function() {
  return(list(
    valid_states_count = length(VALID_BRAZILIAN_STATES),
    valid_categories_count = length(VALID_DOCUMENT_CATEGORIES),
    valid_document_types_count = length(VALID_DOCUMENT_TYPES),
    date_patterns_count = length(DATE_PATTERNS),
    lgpd_compliance_enabled = TRUE
  ))
}

cat("✅ Data Validation Schemas Loaded\n")