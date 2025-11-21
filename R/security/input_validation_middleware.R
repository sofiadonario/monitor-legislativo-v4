# =============================================================================
# Input Validation Middleware for Plumber APIs
# =============================================================================
# Implements comprehensive input validation for all API requests
# Prevents XSS, SQL injection, and other input-based vulnerabilities
# =============================================================================

# Source the input validation module
if (file.exists("R/security/input_validation.R")) {
  source("R/security/input_validation.R")
}

# Validation Configuration
INPUT_VALIDATION_CONFIG <- list(
  enabled = TRUE,
  # Max lengths for different input types
  max_search_length = 500,
  max_text_length = 1000,
  max_array_size = 100,
  # Validation modes
  strict_mode = TRUE,  # Reject invalid inputs
  sanitize_mode = TRUE,  # Sanitize valid inputs
  # Logging
  log_validation_failures = TRUE,
  log_all_validations = FALSE
)

#' Validate Query Parameters from Request
#'
#' Validates all query parameters in a Plumber request
#'
#' @param req Plumber request object
#' @return List with validation results
validate_query_params <- function(req) {
  if (is.null(req$args) || length(req$args) == 0) {
    return(list(
      valid = TRUE,
      sanitized_args = list(),
      errors = NULL
    ))
  }

  validation_results <- list()
  sanitized_args <- list()
  errors <- c()

  for (param_name in names(req$args)) {
    param_value <- req$args[[param_name]]

    # Skip NULL values
    if (is.null(param_value)) {
      sanitized_args[[param_name]] <- NULL
      next
    }

    # Determine validation type based on parameter name patterns
    validation_result <- NULL

    # Search term parameters
    if (grepl("search|query|term|keyword", param_name, ignore.case = TRUE)) {
      validation_result <- validate_text_input(
        input = param_value,
        max_length = INPUT_VALIDATION_CONFIG$max_search_length,
        field_name = param_name
      )
    }
    # Year parameters
    else if (grepl("year|ano", param_name, ignore.case = TRUE)) {
      validation_result <- validate_numeric_input(
        value = param_value,
        min_value = 1900,
        max_value = 2100,
        field_name = param_name
      )
    }
    # Limit parameters
    else if (grepl("limit|max|top", param_name, ignore.case = TRUE)) {
      validation_result <- validate_numeric_input(
        value = param_value,
        min_value = 1,
        max_value = 1000,
        field_name = param_name
      )
    }
    # Offset parameters
    else if (grepl("offset|skip|start", param_name, ignore.case = TRUE)) {
      validation_result <- validate_numeric_input(
        value = param_value,
        min_value = 0,
        max_value = NULL,
        field_name = param_name
      )
    }
    # State code parameters
    else if (grepl("estado|state|uf", param_name, ignore.case = TRUE)) {
      validation_result <- validate_state_code(param_value, field_name = param_name)
    }
    # Generic text parameters
    else {
      validation_result <- validate_text_input(
        input = param_value,
        max_length = INPUT_VALIDATION_CONFIG$max_text_length,
        field_name = param_name
      )
    }

    # Store validation result
    validation_results[[param_name]] <- validation_result

    if (validation_result$valid) {
      # Use sanitized value if available
      sanitized_args[[param_name]] <- validation_result$sanitized %||%
                                       validation_result$value %||%
                                       param_value
    } else {
      errors <- c(errors, validation_result$error)
    }
  }

  all_valid <- all(sapply(validation_results, function(x) x$valid))

  return(list(
    valid = all_valid,
    sanitized_args = sanitized_args,
    errors = if (length(errors) > 0) errors else NULL,
    validation_details = validation_results
  ))
}

#' Validate Brazilian State Code
#'
#' Validates two-letter Brazilian state codes (UF)
#'
#' @param state_code State code to validate
#' @param field_name Field name for error messages
#' @return List with validation result
validate_state_code <- function(state_code, field_name = "Estado") {
  valid_states <- c(
    "AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA",
    "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN",
    "RS", "RO", "RR", "SC", "SP", "SE", "TO"
  )

  if (is.null(state_code) || length(state_code) == 0) {
    return(list(
      valid = TRUE,
      value = NULL,
      error = NULL
    ))
  }

  # Convert to uppercase
  state_code <- toupper(trimws(as.character(state_code)))

  # Validate format (exactly 2 letters)
  if (!grepl("^[A-Z]{2}$", state_code)) {
    return(list(
      valid = FALSE,
      value = NULL,
      error = sprintf("%s deve ser um código de estado válido (2 letras)", field_name)
    ))
  }

  # Validate against whitelist
  if (!state_code %in% valid_states) {
    return(list(
      valid = FALSE,
      value = NULL,
      error = sprintf("%s '%s' não é um estado brasileiro válido", field_name, state_code)
    ))
  }

  return(list(
    valid = TRUE,
    value = state_code,
    error = NULL
  ))
}

#' Validate Request Body
#'
#' Validates JSON body in POST/PUT requests
#'
#' @param req Plumber request object
#' @return List with validation results
validate_request_body <- function(req) {
  if (is.null(req$body) || length(req$body) == 0) {
    return(list(
      valid = TRUE,
      sanitized_body = list(),
      errors = NULL
    ))
  }

  # If body is character (raw JSON), try to parse it
  if (is.character(req$body)) {
    tryCatch({
      req$body <- jsonlite::fromJSON(req$body, simplifyVector = FALSE)
    }, error = function(e) {
      return(list(
        valid = FALSE,
        sanitized_body = NULL,
        errors = "Invalid JSON in request body"
      ))
    })
  }

  validation_results <- list()
  sanitized_body <- list()
  errors <- c()

  # Validate each field in the body
  for (field_name in names(req$body)) {
    field_value <- req$body[[field_name]]

    # Skip NULL values
    if (is.null(field_value)) {
      sanitized_body[[field_name]] <- NULL
      next
    }

    # Validate based on field type
    if (is.character(field_value)) {
      validation_result <- validate_text_input(
        input = field_value,
        max_length = INPUT_VALIDATION_CONFIG$max_text_length,
        field_name = field_name
      )

      validation_results[[field_name]] <- validation_result

      if (validation_result$valid) {
        sanitized_body[[field_name]] <- validation_result$sanitized
      } else {
        errors <- c(errors, validation_result$error)
      }
    } else {
      # For non-string values, pass through (could add more validation)
      sanitized_body[[field_name]] <- field_value
    }
  }

  all_valid <- length(errors) == 0

  return(list(
    valid = all_valid,
    sanitized_body = sanitized_body,
    errors = if (length(errors) > 0) errors else NULL,
    validation_details = validation_results
  ))
}

#' Input Validation Middleware Filter for Plumber
#' @filter input_validation
input_validation_filter <- function(req, res) {
  # Skip if validation is disabled
  if (!INPUT_VALIDATION_CONFIG$enabled) {
    plumber::forward()
    return()
  }

  # Skip validation for safe methods (GET, HEAD, OPTIONS) query params only
  # We'll validate GET query params, but with less strict rules
  is_safe_method <- req$REQUEST_METHOD %in% c("GET", "HEAD", "OPTIONS")

  # Skip validation for health/info endpoints
  exempt_paths <- c("/health", "/info", "/", "/metrics", "/api/v1/info")
  if (req$PATH_INFO %in% exempt_paths) {
    plumber::forward()
    return()
  }

  # Validate query parameters (for all methods)
  query_validation <- validate_query_params(req)

  if (!query_validation$valid) {
    if (INPUT_VALIDATION_CONFIG$log_validation_failures) {
      cat(sprintf(
        "❌ Input validation failed for %s %s | Errors: %s\n",
        req$REQUEST_METHOD,
        req$PATH_INFO,
        paste(query_validation$errors, collapse = "; ")
      ))
    }

    res$status <- 400
    res$setHeader("Content-Type", "application/json")

    error_response <- list(
      error = TRUE,
      message = "Input validation failed",
      code = 400,
      details = query_validation$errors,
      timestamp = Sys.time()
    )

    return(jsonlite::toJSON(error_response, auto_unbox = TRUE))
  }

  # Replace request args with sanitized values
  req$args <- query_validation$sanitized_args

  # Validate request body for POST/PUT/PATCH requests
  if (req$REQUEST_METHOD %in% c("POST", "PUT", "PATCH")) {
    body_validation <- validate_request_body(req)

    if (!body_validation$valid) {
      if (INPUT_VALIDATION_CONFIG$log_validation_failures) {
        cat(sprintf(
          "❌ Body validation failed for %s %s | Errors: %s\n",
          req$REQUEST_METHOD,
          req$PATH_INFO,
          paste(body_validation$errors, collapse = "; ")
        ))
      }

      res$status <- 400
      res$setHeader("Content-Type", "application/json")

      error_response <- list(
        error = TRUE,
        message = "Request body validation failed",
        code = 400,
        details = body_validation$errors,
        timestamp = Sys.time()
      )

      return(jsonlite::toJSON(error_response, auto_unbox = TRUE))
    }

    # Replace request body with sanitized values
    req$body <- body_validation$sanitized_body
  }

  if (INPUT_VALIDATION_CONFIG$log_all_validations) {
    cat(sprintf(
      "✅ Input validation passed for %s %s\n",
      req$REQUEST_METHOD,
      req$PATH_INFO
    ))
  }

  # Validation passed, continue to endpoint
  plumber::forward()
}

#' Get Input Validation Statistics
#'
#' Returns statistics about input validation configuration
#'
#' @return List with validation stats
get_input_validation_stats <- function() {
  return(list(
    enabled = INPUT_VALIDATION_CONFIG$enabled,
    strict_mode = INPUT_VALIDATION_CONFIG$strict_mode,
    sanitize_mode = INPUT_VALIDATION_CONFIG$sanitize_mode,
    max_search_length = INPUT_VALIDATION_CONFIG$max_search_length,
    max_text_length = INPUT_VALIDATION_CONFIG$max_text_length,
    max_array_size = INPUT_VALIDATION_CONFIG$max_array_size,
    log_validation_failures = INPUT_VALIDATION_CONFIG$log_validation_failures
  ))
}

#' Helper: Null coalescing operator
`%||%` <- function(a, b) {
  if (is.null(a)) b else a
}

cat("✅ Input Validation Middleware Loaded\n")
cat("   Max search length:", INPUT_VALIDATION_CONFIG$max_search_length, "chars\n")
cat("   Max text length:", INPUT_VALIDATION_CONFIG$max_text_length, "chars\n")
cat("   Strict mode:", INPUT_VALIDATION_CONFIG$strict_mode, "\n")
