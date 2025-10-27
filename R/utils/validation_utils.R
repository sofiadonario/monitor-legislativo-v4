# Validation Utilities Module
# Monitor Legislativo v4 - Input Validation and Data Quality
# ==========================================================

#' Validation Utilities for Monitor Legislativo v4
#' 
#' This module provides comprehensive validation functions for user inputs,
#' data quality checks, and LGPD compliance validation for Brazilian
#' legislative document processing.

library(stringr)

# Validation configuration
VALIDATION_CONFIG <- list(
  max_search_length = 1000,
  max_file_size_mb = 100,
  allowed_file_types = c("csv", "xlsx", "json", "pdf"),
  min_password_length = 8,
  session_timeout_minutes = 120
)

# Brazilian legal document patterns
LEGAL_PATTERNS <- list(
  urn_pattern = "^urn:lex:br(:[a-z]{2})?(:[a-z.]+)?:(lei|decreto|resolucao|portaria|instrucao.normativa):([0-9]{4}(-[0-9]{2}){2})?:([0-9]+)$",
  lei_pattern = "^Lei\\s+(Federal\\s+)?n[ºo\\.°]?\\s*([0-9]{1,5})[,/\\s]*([0-9]{4})$",
  decreto_pattern = "^Decreto\\s+n[ºo\\.°]?\\s*([0-9]{1,5})[,/\\s]*([0-9]{4})$",
  resolucao_pattern = "^Resolução\\s+n[ºo\\.°]?\\s*([0-9]{1,5})[,/\\s]*([0-9]{4})$"
)

# Brazilian states and their codes
BRAZILIAN_STATES <- c(
  "AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
  "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
  "RS", "RO", "RR", "SC", "SP", "SE", "TO"
)

#' Validate Search Input Parameters
#' 
#' @param search_term Search query string
#' @param filters List of filter parameters
#' @return List with validation results
#' @export
validate_search_input <- function(search_term = "", filters = list()) {
  validation_result <- list(
    valid = TRUE,
    errors = c(),
    warnings = c(),
    sanitized_input = list()
  )
  
  # Validate search term
  if (!isTRUE(is.null(search_term)) && search_term != "") {
    # Length check
    if (nchar(search_term) > VALIDATION_CONFIG$max_search_length) {
      validation_result$errors <- c(validation_result$errors, 
        paste("Search term too long. Maximum", VALIDATION_CONFIG$max_search_length, "characters."))
    }
    
    # Sanitize search term (remove potentially dangerous characters)
    sanitized_search <- gsub("[<>\"'%;()&+]", "", search_term)
    sanitized_search <- str_trim(sanitized_search)
    
    if (sanitized_search != search_term) {
      validation_result$warnings <- c(validation_result$warnings, 
        "Search term was sanitized to remove potentially unsafe characters.")
    }
    
    validation_result$sanitized_input$search_term <- sanitized_search
  } else {
    validation_result$sanitized_input$search_term <- ""
  }
  
  # Validate state filter
  if (!isTRUE(is.null(filters$state)) && filters$state != "all") {
    if (!toupper(filters$state) %in% BRAZILIAN_STATES) {
      validation_result$errors <- c(validation_result$errors, 
        paste("Invalid state code:", filters$state))
    }
    validation_result$sanitized_input$state <- toupper(filters$state)
  } else {
    validation_result$sanitized_input$state <- "all"
  }
  
  # Validate category filter
  allowed_categories <- c("all", "legislation", "jurisprudence", "doctrine")
  if (!is.null(filters$category)) {
    if (!filters$category %in% allowed_categories) {
      validation_result$errors <- c(validation_result$errors, 
        paste("Invalid category:", filters$category))
    }
    validation_result$sanitized_input$category <- filters$category
  } else {
    validation_result$sanitized_input$category <- "all"
  }
  
  # Validate date range
  if (!isTRUE(is.null(filters$date_start)) || !is.null(filters$date_end)) {
    date_validation <- validate_date_range(filters$date_start, filters$date_end)
    if (!date_validation$valid) {
      validation_result$errors <- c(validation_result$errors, date_validation$errors)
    } else {
      validation_result$sanitized_input$date_start <- date_validation$date_start
      validation_result$sanitized_input$date_end <- date_validation$date_end
    }
  }
  
  # Validate pagination parameters
  if (!is.null(filters$limit)) {
    limit_validation <- validate_pagination_limit(filters$limit)
    if (!limit_validation$valid) {
      validation_result$errors <- c(validation_result$errors, limit_validation$errors)
    } else {
      validation_result$sanitized_input$limit <- limit_validation$limit
    }
  } else {
    validation_result$sanitized_input$limit <- 50  # Default limit
  }
  
  if (!is.null(filters$offset)) {
    offset_validation <- validate_pagination_offset(filters$offset)
    if (!offset_validation$valid) {
      validation_result$errors <- c(validation_result$errors, offset_validation$errors)
    } else {
      validation_result$sanitized_input$offset <- offset_validation$offset
    }
  } else {
    validation_result$sanitized_input$offset <- 0  # Default offset
  }
  
  # Set overall validation status
  validation_result$valid <- length(validation_result$errors) == 0
  
  return(validation_result)
}

#' Validate Date Range Parameters
#' 
#' @param date_start Start date (string or Date)
#' @param date_end End date (string or Date)
#' @return List with validation results
#' @export
validate_date_range <- function(date_start = NULL, date_end = NULL) {
  validation_result <- list(
    valid = TRUE,
    errors = c(),
    date_start = NULL,
    date_end = NULL
  )
  
  # Validate start date
  if (!isTRUE(is.null(date_start)) && date_start != "") {
    tryCatch({
      parsed_start <- as.Date(date_start)
      
      # Check if date is reasonable (not too far in the past or future)
      if (parsed_start < as.Date("1900-01-01")) {
        validation_result$errors <- c(validation_result$errors, 
          "Start date cannot be before 1900")
      } else if (parsed_start > Sys.Date()) {
        validation_result$errors <- c(validation_result$errors, 
          "Start date cannot be in the future")
      } else {
        validation_result$date_start <- parsed_start
      }
    }, error = function(e) {
      validation_result$errors <- c(validation_result$errors, 
        "Invalid start date format. Please use YYYY-MM-DD.")
    })
  }
  
  # Validate end date
  if (!isTRUE(is.null(date_end)) && date_end != "") {
    tryCatch({
      parsed_end <- as.Date(date_end)
      
      # Check if date is reasonable
      if (parsed_end < as.Date("1900-01-01")) {
        validation_result$errors <- c(validation_result$errors, 
          "End date cannot be before 1900")
      } else if (parsed_end > Sys.Date()) {
        validation_result$errors <- c(validation_result$errors, 
          "End date cannot be in the future")
      } else {
        validation_result$date_end <- parsed_end
      }
    }, error = function(e) {
      validation_result$errors <- c(validation_result$errors, 
        "Invalid end date format. Please use YYYY-MM-DD.")
    })
  }
  
  # Validate date range logic
  if (!isTRUE(is.null(validation_result$date_start)) && !is.null(validation_result$date_end)) {
    if (validation_result$date_start > validation_result$date_end) {
      validation_result$errors <- c(validation_result$errors, 
        "Start date must be before end date")
    }
    
    # Check for reasonable date range (not more than 50 years)
    date_diff <- as.numeric(validation_result$date_end - validation_result$date_start)
    if (date_diff > 365 * 50) {
      validation_result$errors <- c(validation_result$errors, 
        "Date range cannot exceed 50 years")
    }
  }
  
  validation_result$valid <- length(validation_result$errors) == 0
  return(validation_result)
}

#' Validate Pagination Limit
#' 
#' @param limit Number of results per page
#' @return List with validation results
#' @export
validate_pagination_limit <- function(limit) {
  validation_result <- list(
    valid = TRUE,
    errors = c(),
    limit = 50
  )
  
  if (isTRUE(is.null(limit)) || isTRUE(is.na(limit))) {
    validation_result$limit <- 50
    return(validation_result)
  }
  
  # Convert to numeric if it's a string
  if (is.character(limit)) {
    tryCatch({
      limit <- as.numeric(limit)
    }, error = function(e) {
      validation_result$errors <- c(validation_result$errors, 
        "Limit must be a number")
      validation_result$valid <- FALSE
      return(validation_result)
    })
  }
  
  # Validate range
  if (limit < 1) {
    validation_result$errors <- c(validation_result$errors, 
      "Limit must be at least 1")
  } else if (limit > 1000) {
    validation_result$errors <- c(validation_result$errors, 
      "Limit cannot exceed 1000")
  } else {
    validation_result$limit <- as.integer(limit)
  }
  
  validation_result$valid <- length(validation_result$errors) == 0
  return(validation_result)
}

#' Validate Pagination Offset
#' 
#' @param offset Starting position for results
#' @return List with validation results
#' @export
validate_pagination_offset <- function(offset) {
  validation_result <- list(
    valid = TRUE,
    errors = c(),
    offset = 0
  )
  
  if (isTRUE(is.null(offset)) || isTRUE(is.na(offset))) {
    validation_result$offset <- 0
    return(validation_result)
  }
  
  # Convert to numeric if it's a string
  if (is.character(offset)) {
    tryCatch({
      offset <- as.numeric(offset)
    }, error = function(e) {
      validation_result$errors <- c(validation_result$errors, 
        "Offset must be a number")
      validation_result$valid <- FALSE
      return(validation_result)
    })
  }
  
  # Validate range
  if (offset < 0) {
    validation_result$errors <- c(validation_result$errors, 
      "Offset cannot be negative")
  } else if (offset > 100000) {
    validation_result$errors <- c(validation_result$errors, 
      "Offset cannot exceed 100,000")
  } else {
    validation_result$offset <- as.integer(offset)
  }
  
  validation_result$valid <- length(validation_result$errors) == 0
  return(validation_result)
}

#' Validate Legal Document URN
#' 
#' @param urn Legal document URN string
#' @return List with validation results
#' @export
validate_legal_urn <- function(urn) {
  validation_result <- list(
    valid = FALSE,
    errors = c(),
    components = list()
  )
  
  if (isTRUE(is.null(urn)) || isTRUE(is.na(urn)) || urn == "") {
    validation_result$errors <- c(validation_result$errors, "URN cannot be empty")
    return(validation_result)
  }
  
  # Check URN pattern
  if (grepl(LEGAL_PATTERNS$urn_pattern, urn, ignore.case = TRUE)) {
    validation_result$valid <- TRUE
    
    # Extract components
    components <- unlist(strsplit(urn, ":"))
    if (length(components) >= 6) {
      validation_result$components <- list(
        scheme = components[1],
        namespace = components[2],
        country = components[3],
        state = if(length(components) > 3) components[4] else NULL,
        municipality = if(length(components) > 4) components[5] else NULL,
        document_type = if(length(components) > 5) components[6] else NULL,
        date = if(length(components) > 6) components[7] else NULL,
        number = if(length(components) > 7) components[8] else NULL
      )
    }
  } else {
    validation_result$errors <- c(validation_result$errors, 
      "Invalid URN format for Brazilian legal document")
  }
  
  return(validation_result)
}

#' Validate File Upload
#' 
#' @param file_info Shiny file input information
#' @return List with validation results
#' @export
validate_file_upload <- function(file_info) {
  validation_result <- list(
    valid = TRUE,
    errors = c(),
    warnings = c()
  )
  
  if (isTRUE(is.null(file_info)) || isTRUE(is.null(file_info$datapath))) {
    validation_result$errors <- c(validation_result$errors, "No file selected")
    validation_result$valid <- FALSE
    return(validation_result)
  }
  
  # Check file size
  file_size_mb <- file.size(file_info$datapath) / (1024 * 1024)
  if (file_size_mb > VALIDATION_CONFIG$max_file_size_mb) {
    validation_result$errors <- c(validation_result$errors, 
      paste("File size exceeds", VALIDATION_CONFIG$max_file_size_mb, "MB limit"))
  }
  
  # Check file extension
  file_ext <- tolower(tools::file_ext(file_info$name))
  if (!file_ext %in% VALIDATION_CONFIG$allowed_file_types) {
    validation_result$errors <- c(validation_result$errors, 
      paste("File type not allowed. Allowed types:", 
            paste(VALIDATION_CONFIG$allowed_file_types, collapse = ", ")))
  }
  
  # Security check for file content (basic)
  tryCatch({
    # Read first few bytes to check for malicious content
    con <- file(file_info$datapath, "rb")
    first_bytes <- readBin(con, "raw", 100)
    close(con)
    
    # Check for common malicious patterns (very basic)
    if (any(first_bytes == as.raw(0x4D) & first_bytes == as.raw(0x5A))) {  # MZ header
      validation_result$warnings <- c(validation_result$warnings, 
        "File appears to be an executable. Please verify content.")
    }
    
  }, error = function(e) {
    validation_result$warnings <- c(validation_result$warnings, 
      "Could not perform security scan on file")
  })
  
  validation_result$valid <- length(validation_result$errors) == 0
  return(validation_result)
}

#' Validate LGPD Compliance for Data Processing
#' 
#' @param data_type Type of data being processed
#' @param processing_purpose Purpose of data processing
#' @param user_consent User consent status
#' @return List with LGPD compliance validation
#' @export
validate_lgpd_compliance <- function(data_type, processing_purpose, user_consent = TRUE) {
  validation_result <- list(
    compliant = TRUE,
    violations = c(),
    recommendations = c()
  )
  
  # Check for sensitive personal data
  sensitive_patterns <- c("cpf", "cnpj", "rg", "passaporte", "email", "telefone", 
                         "endereco", "endereço", "salario", "salário", "renda")
  
  if (any(sapply(sensitive_patterns, function(pattern) {
    grepl(pattern, data_type, ignore.case = TRUE)
  }))) {
    if (!user_consent) {
      validation_result$violations <- c(validation_result$violations, 
        "Processing sensitive personal data requires explicit user consent")
      validation_result$compliant <- FALSE
    } else {
      validation_result$recommendations <- c(validation_result$recommendations, 
        "Sensitive personal data detected. Ensure anonymization when possible.")
    }
  }
  
  # Check processing purpose legitimacy
  legitimate_purposes <- c("academic_research", "legal_analysis", "public_interest", 
                          "government_transparency", "statistical_analysis")
  
  if (!processing_purpose %in% legitimate_purposes) {
    validation_result$violations <- c(validation_result$violations, 
      "Processing purpose must be legitimate and clearly defined")
    validation_result$compliant <- FALSE
  }
  
  # Add general LGPD recommendations
  validation_result$recommendations <- c(validation_result$recommendations, 
    "Implement data minimization principles",
    "Ensure data retention policies are followed",
    "Provide clear privacy notice to users",
    "Enable user data rights (access, correction, deletion)")
  
  return(validation_result)
}

#' Sanitize User Input for XSS Prevention
#' 
#' @param input Raw user input string
#' @return Sanitized input string
#' @export
sanitize_user_input <- function(input) {
  if (isTRUE(is.null(input)) || isTRUE(is.na(input))) {
    return("")
  }
  
  # Convert to character if not already
  input <- as.character(input)
  
  # Remove potentially dangerous HTML/JavaScript
  input <- gsub("<script[^>]*>.*?</script>", "", input, ignore.case = TRUE)
  input <- gsub("<[^>]+>", "", input)  # Remove all HTML tags
  input <- gsub("javascript:", "", input, ignore.case = TRUE)
  input <- gsub("vbscript:", "", input, ignore.case = TRUE)
  input <- gsub("onload=", "", input, ignore.case = TRUE)
  input <- gsub("onerror=", "", input, ignore.case = TRUE)
  
  # Remove potentially dangerous characters
  input <- gsub("[<>\"'%;()&+]", "", input)
  
  # Trim whitespace
  input <- str_trim(input)
  
  return(input)
}

#' Get Validation Configuration
#' 
#' @return Current validation configuration
#' @export
get_validation_config <- function() {
  return(VALIDATION_CONFIG)
}

cat("✅ Validation utilities module loaded successfully\n")