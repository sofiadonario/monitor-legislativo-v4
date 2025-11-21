# =============================================================================
# Input Validation Module for Shiny Applications
# =============================================================================
# Description: Comprehensive input validation and sanitization functions
# Author: Security Enhancement Team
# Date: 2025-11-19
# =============================================================================

library(htmltools)

# =============================================================================
# Text Input Validation
# =============================================================================

#' Validate Search Input with Comprehensive Security Checks
#'
#' Validates user search input with checks for:
#' - Length limits
#' - SQL injection patterns
#' - XSS (Cross-Site Scripting) patterns
#' - HTML injection attempts
#'
#' @param input Character string to validate
#' @param max_length Maximum allowed length (default: 500)
#' @param field_name Name of the field for error messages (default: "Input")
#' @return List with validation result, sanitized value, and error message
#' @export
#'
#' @examples
#' validate_text_input("transporte", max_length = 500)
#' validate_text_input("<script>alert('xss')</script>", max_length = 100)
validate_text_input <- function(input, max_length = 500, field_name = "Input") {

  if (is.null(input) || length(input) == 0) {
    return(list(
      valid = TRUE,
      sanitized = "",
      original = "",
      error = NULL
    ))
  }

  if (nchar(input) > max_length) {
    return(list(
      valid = FALSE,
      sanitized = substr(input, 1, max_length),
      original = input,
      error = sprintf("%s excede o limite de %d caracteres", field_name, max_length)
    ))
  }

  sql_patterns <- c(
    "DROP\\s+TABLE",
    "DELETE\\s+FROM",
    "INSERT\\s+INTO",
    "UPDATE\\s+SET",
    ";\\s*--",
    "UNION\\s+SELECT",
    "xp_cmdshell",
    "EXEC\\s*\\(",
    "EXECUTE\\s*\\("
  )

  for (pattern in sql_patterns) {
    if (grepl(pattern, input, ignore.case = TRUE)) {
      return(list(
        valid = FALSE,
        sanitized = "",
        original = input,
        error = sprintf("%s contém padrões SQL não permitidos", field_name)
      ))
    }
  }

  xss_patterns <- c(
    "<script",
    "javascript:",
    "onerror\\s*=",
    "onclick\\s*=",
    "onload\\s*=",
    "onmouseover\\s*=",
    "<iframe",
    "<object",
    "<embed"
  )

  for (pattern in xss_patterns) {
    if (grepl(pattern, input, ignore.case = TRUE)) {
      return(list(
        valid = FALSE,
        sanitized = "",
        original = input,
        error = sprintf("%s contém HTML/JavaScript não permitido", field_name)
      ))
    }
  }

  sanitized <- htmltools::htmlEscape(input)
  sanitized <- gsub("[\\r\\n]", " ", sanitized)
  sanitized <- trimws(sanitized)

  return(list(
    valid = TRUE,
    sanitized = as.character(sanitized),
    original = input,
    error = NULL
  ))
}

#' Validate Search Term Input
#'
#' Specialized validation for search terms in legislative documents
#'
#' @param search_term Character string search term
#' @return List with validation result
#' @export
validate_search_term <- function(search_term) {
  validate_text_input(
    input = search_term,
    max_length = 500,
    field_name = "Termo de pesquisa"
  )
}

# =============================================================================
# Select Input Validation
# =============================================================================

#' Validate Select Input (Dropdown) Choices
#'
#' Ensures selected value is within allowed choices
#'
#' @param selected Selected value from dropdown
#' @param allowed_values Vector of allowed values
#' @param field_name Name of the field for error messages
#' @return List with validation result
#' @export
validate_select_input <- function(selected, allowed_values, field_name = "Seleção") {

  if (is.null(selected) || length(selected) == 0) {
    return(list(
      valid = TRUE,
      value = NULL,
      error = NULL
    ))
  }

  if (!selected %in% allowed_values) {
    return(list(
      valid = FALSE,
      value = NULL,
      error = sprintf("%s contém valor não permitido: '%s'", field_name, selected)
    ))
  }

  return(list(
    valid = TRUE,
    value = selected,
    error = NULL
  ))
}

# =============================================================================
# Numeric Input Validation
# =============================================================================

#' Validate Numeric Input
#'
#' Validates numeric inputs with range checks
#'
#' @param value Numeric value to validate
#' @param min_value Minimum allowed value (default: NULL for no limit)
#' @param max_value Maximum allowed value (default: NULL for no limit)
#' @param field_name Name of the field for error messages
#' @return List with validation result
#' @export
validate_numeric_input <- function(value, min_value = NULL, max_value = NULL, field_name = "Valor") {

  if (is.null(value) || length(value) == 0) {
    return(list(
      valid = TRUE,
      value = NULL,
      error = NULL
    ))
  }

  if (!is.numeric(value) && !is.integer(value)) {
    numeric_value <- suppressWarnings(as.numeric(value))
    if (is.na(numeric_value)) {
      return(list(
        valid = FALSE,
        value = NULL,
        error = sprintf("%s deve ser um número válido", field_name)
      ))
    }
    value <- numeric_value
  }

  if (!is.null(min_value) && value < min_value) {
    return(list(
      valid = FALSE,
      value = value,
      error = sprintf("%s deve ser maior ou igual a %s", field_name, min_value)
    ))
  }

  if (!is.null(max_value) && value > max_value) {
    return(list(
      valid = FALSE,
      value = value,
      error = sprintf("%s deve ser menor ou igual a %s", field_name, max_value)
    ))
  }

  return(list(
    valid = TRUE,
    value = value,
    error = NULL
  ))
}

# =============================================================================
# Date Input Validation
# =============================================================================

#' Validate Date Input
#'
#' Validates date inputs with range checks
#'
#' @param date_value Date value to validate
#' @param min_date Minimum allowed date (default: NULL)
#' @param max_date Maximum allowed date (default: NULL)
#' @param field_name Name of the field for error messages
#' @return List with validation result
#' @export
validate_date_input <- function(date_value, min_date = NULL, max_date = NULL, field_name = "Data") {

  if (is.null(date_value) || length(date_value) == 0) {
    return(list(
      valid = TRUE,
      value = NULL,
      error = NULL
    ))
  }

  if (!inherits(date_value, "Date")) {
    date_parsed <- tryCatch(
      as.Date(date_value),
      error = function(e) NA
    )

    if (is.na(date_parsed)) {
      return(list(
        valid = FALSE,
        value = NULL,
        error = sprintf("%s não é uma data válida", field_name)
      ))
    }
    date_value <- date_parsed
  }

  if (!is.null(min_date) && date_value < min_date) {
    return(list(
      valid = FALSE,
      value = date_value,
      error = sprintf("%s deve ser posterior a %s", field_name, format(min_date, "%d/%m/%Y"))
    ))
  }

  if (!is.null(max_date) && date_value > max_date) {
    return(list(
      valid = FALSE,
      value = date_value,
      error = sprintf("%s deve ser anterior a %s", field_name, format(max_date, "%d/%m/%Y"))
    ))
  }

  return(list(
    valid = TRUE,
    value = date_value,
    error = NULL
  ))
}

# =============================================================================
# Batch Validation Helper
# =============================================================================

#' Validate Multiple Inputs at Once
#'
#' Helper function to validate multiple inputs and collect all errors
#'
#' @param validation_results List of validation results from other functions
#' @return List with overall validity and combined error messages
#' @export
validate_batch <- function(validation_results) {

  all_valid <- all(sapply(validation_results, function(x) x$valid))

  errors <- sapply(validation_results, function(x) {
    if (!is.null(x$error)) x$error else NA
  })

  errors <- errors[!is.na(errors)]

  return(list(
    valid = all_valid,
    errors = if (length(errors) > 0) errors else NULL,
    error_message = if (length(errors) > 0) paste(errors, collapse = "; ") else NULL
  ))
}
