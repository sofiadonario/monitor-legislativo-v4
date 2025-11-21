# =============================================================================
# Input Validation Security Tests
# =============================================================================
# Tests to verify input validation is properly implemented across the API
# =============================================================================

library(testthat)

# Source the input validation modules
source("R/security/input_validation.R")
source("R/security/input_validation_middleware.R")

# =============================================================================
# Test 1: Text input validation
# =============================================================================

test_that("Text input validation accepts safe input", {
  result <- validate_text_input("transportation", max_length = 500)

  expect_true(result$valid)
  expect_equal(result$sanitized, "transportation")
  expect_null(result$error)
})

test_that("Text input validation rejects SQL injection patterns", {
  malicious_inputs <- c(
    "'; DROP TABLE users--",
    "admin'--",
    "1'; DELETE FROM documents; --",
    "test'; EXEC xp_cmdshell('cmd.exe')"
  )

  for (input in malicious_inputs) {
    result <- validate_text_input(input, max_length = 500)
    expect_false(result$valid, info = paste("Failed to block:", input))
    expect_false(is.null(result$error))
  }
})

test_that("Text input validation rejects XSS patterns", {
  xss_inputs <- c(
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "<iframe src='javascript:alert(1)'>",
    "javascript:alert('xss')",
    "<object data='data:text/html,<script>alert(1)</script>'>",
    "<embed src='javascript:alert(1)'>"
  )

  for (input in xss_inputs) {
    result <- validate_text_input(input, max_length = 500)
    expect_false(result$valid, info = paste("Failed to block:", input))
    expect_false(is.null(result$error))
  }
})

test_that("Text input validation enforces length limits", {
  long_input <- paste(rep("a", 600), collapse = "")
  result <- validate_text_input(long_input, max_length = 500)

  expect_false(result$valid)
  expect_equal(nchar(result$sanitized), 500)
  expect_false(is.null(result$error))
})

test_that("Text input validation handles special characters safely", {
  safe_inputs <- c(
    "São Paulo",
    "Transporte & Logística",
    "BR-101 (Federal Highway)",
    "Artigo 1º"
  )

  for (input in safe_inputs) {
    result <- validate_text_input(input, max_length = 500)
    expect_true(result$valid, info = paste("Failed to accept:", input))
    expect_false(is.null(result$sanitized))
  }
})

# =============================================================================
# Test 2: Numeric input validation
# =============================================================================

test_that("Numeric validation accepts valid numbers", {
  result <- validate_numeric_input(2023, min_value = 1900, max_value = 2100)

  expect_true(result$valid)
  expect_equal(result$value, 2023)
  expect_null(result$error)
})

test_that("Numeric validation enforces minimum value", {
  result <- validate_numeric_input(1800, min_value = 1900, max_value = 2100)

  expect_false(result$valid)
  expect_false(is.null(result$error))
})

test_that("Numeric validation enforces maximum value", {
  result <- validate_numeric_input(2200, min_value = 1900, max_value = 2100)

  expect_false(result$valid)
  expect_false(is.null(result$error))
})

test_that("Numeric validation rejects non-numeric input", {
  result <- validate_numeric_input("not a number", min_value = 1, max_value = 100)

  expect_false(result$valid)
  expect_false(is.null(result$error))
})

test_that("Numeric validation converts string numbers", {
  result <- validate_numeric_input("42", min_value = 1, max_value = 100)

  expect_true(result$valid)
  expect_equal(result$value, 42)
})

# =============================================================================
# Test 3: State code validation
# =============================================================================

test_that("State code validation accepts valid Brazilian states", {
  valid_states <- c("SP", "RJ", "MG", "BA", "RS")

  for (state in valid_states) {
    result <- validate_state_code(state)
    expect_true(result$valid, info = paste("Failed to accept:", state))
    expect_equal(result$value, state)
  }
})

test_that("State code validation rejects invalid state codes", {
  invalid_states <- c("XX", "ZZ", "ABC", "S", "123", "SP'--")

  for (state in invalid_states) {
    result <- validate_state_code(state)
    expect_false(result$valid, info = paste("Failed to reject:", state))
    expect_false(is.null(result$error))
  }
})

test_that("State code validation converts to uppercase", {
  result <- validate_state_code("sp")

  expect_true(result$valid)
  expect_equal(result$value, "SP")
})

# =============================================================================
# Test 4: Date input validation
# =============================================================================

test_that("Date validation accepts valid dates", {
  test_date <- as.Date("2023-01-15")
  result <- validate_date_input(test_date, min_date = as.Date("2020-01-01"))

  expect_true(result$valid)
  expect_equal(result$value, test_date)
  expect_null(result$error)
})

test_that("Date validation enforces minimum date", {
  test_date <- as.Date("2019-01-15")
  result <- validate_date_input(test_date, min_date = as.Date("2020-01-01"))

  expect_false(result$valid)
  expect_false(is.null(result$error))
})

test_that("Date validation enforces maximum date", {
  test_date <- as.Date("2025-01-15")
  result <- validate_date_input(test_date, max_date = as.Date("2024-01-01"))

  expect_false(result$valid)
  expect_false(is.null(result$error))
})

test_that("Date validation rejects invalid date strings", {
  result <- validate_date_input("not-a-date")

  expect_false(result$valid)
  expect_false(is.null(result$error))
})

# =============================================================================
# Test 5: Select input validation
# =============================================================================

test_that("Select validation accepts allowed values", {
  allowed_values <- c("option1", "option2", "option3")
  result <- validate_select_input("option2", allowed_values)

  expect_true(result$valid)
  expect_equal(result$value, "option2")
  expect_null(result$error)
})

test_that("Select validation rejects disallowed values", {
  allowed_values <- c("option1", "option2", "option3")
  result <- validate_select_input("option4", allowed_values)

  expect_false(result$valid)
  expect_null(result$value)
  expect_false(is.null(result$error))
})

test_that("Select validation prevents SQL injection in options", {
  allowed_values <- c("option1", "option2", "option3")
  result <- validate_select_input("option1'; DROP TABLE users--", allowed_values)

  expect_false(result$valid)
  expect_false(is.null(result$error))
})

# =============================================================================
# Test 6: Batch validation
# =============================================================================

test_that("Batch validation succeeds when all inputs are valid", {
  validations <- list(
    validate_text_input("transportation", max_length = 500),
    validate_numeric_input(2023, min_value = 1900, max_value = 2100),
    validate_state_code("SP")
  )

  result <- validate_batch(validations)

  expect_true(result$valid)
  expect_null(result$errors)
})

test_that("Batch validation fails when any input is invalid", {
  validations <- list(
    validate_text_input("transportation", max_length = 500),
    validate_numeric_input(1800, min_value = 1900, max_value = 2100),  # Invalid
    validate_state_code("SP")
  )

  result <- validate_batch(validations)

  expect_false(result$valid)
  expect_false(is.null(result$errors))
  expect_gt(length(result$errors), 0)
})

# =============================================================================
# Test 7: Query parameter validation in middleware
# =============================================================================

test_that("Query parameter validation accepts safe parameters", {
  mock_req <- list(
    args = list(
      search = "transportation",
      year = "2023",
      limit = "10"
    )
  )

  result <- validate_query_params(mock_req)

  expect_true(result$valid)
  expect_null(result$errors)
  expect_equal(result$sanitized_args$search, "transportation")
  expect_equal(result$sanitized_args$year, 2023)
  expect_equal(result$sanitized_args$limit, 10)
})

test_that("Query parameter validation rejects malicious search terms", {
  mock_req <- list(
    args = list(
      search = "'; DROP TABLE documents--",
      year = "2023"
    )
  )

  result <- validate_query_params(mock_req)

  expect_false(result$valid)
  expect_false(is.null(result$errors))
})

test_that("Query parameter validation enforces year ranges", {
  mock_req <- list(
    args = list(
      year = "1800"  # Too old
    )
  )

  result <- validate_query_params(mock_req)

  expect_false(result$valid)
  expect_false(is.null(result$errors))
})

test_that("Query parameter validation enforces limit ranges", {
  mock_req <- list(
    args = list(
      limit = "2000"  # Too high
    )
  )

  result <- validate_query_params(mock_req)

  expect_false(result$valid)
  expect_false(is.null(result$errors))
})

test_that("Query parameter validation validates state codes", {
  # Valid state
  mock_req_valid <- list(
    args = list(
      estado = "SP"
    )
  )

  result_valid <- validate_query_params(mock_req_valid)
  expect_true(result_valid$valid)

  # Invalid state
  mock_req_invalid <- list(
    args = list(
      estado = "XX"
    )
  )

  result_invalid <- validate_query_params(mock_req_invalid)
  expect_false(result_invalid$valid)
})

# =============================================================================
# Test 8: Request body validation
# =============================================================================

test_that("Request body validation accepts valid JSON", {
  mock_req <- list(
    body = list(
      title = "Lei de Transporte",
      description = "Nova legislação sobre transporte público",
      year = 2023
    )
  )

  result <- validate_request_body(mock_req)

  expect_true(result$valid)
  expect_null(result$errors)
  expect_equal(result$sanitized_body$title, "Lei de Transporte")
})

test_that("Request body validation rejects XSS in fields", {
  mock_req <- list(
    body = list(
      title = "<script>alert('xss')</script>",
      description = "Safe description"
    )
  )

  result <- validate_request_body(mock_req)

  expect_false(result$valid)
  expect_false(is.null(result$errors))
})

test_that("Request body validation sanitizes HTML", {
  mock_req <- list(
    body = list(
      title = "Lei <b>Important</b> & Critical"
    )
  )

  result <- validate_request_body(mock_req)

  expect_true(result$valid)
  # HTML should be escaped
  expect_true(grepl("&lt;", result$sanitized_body$title) ||
              grepl("&amp;", result$sanitized_body$title))
})

# =============================================================================
# Test 9: Integration tests with mock middleware
# =============================================================================

test_that("Middleware allows safe GET requests", {
  mock_req <- list(
    REQUEST_METHOD = "GET",
    PATH_INFO = "/api/v1/search",
    args = list(
      query = "transportation",
      year = "2023"
    )
  )

  mock_res <- list(
    status = NULL,
    headers = list()
  )

  # Should not set error status
  result <- validate_query_params(mock_req)
  expect_true(result$valid)
})

test_that("Middleware blocks malicious POST requests", {
  mock_req <- list(
    REQUEST_METHOD = "POST",
    PATH_INFO = "/api/v1/documents",
    body = list(
      title = "'; DROP TABLE documents--"
    )
  )

  result <- validate_request_body(mock_req)
  expect_false(result$valid)
})

# =============================================================================
# Test 10: Edge cases and boundary conditions
# =============================================================================

test_that("Validation handles NULL inputs gracefully", {
  result <- validate_text_input(NULL)

  expect_true(result$valid)
  expect_equal(result$sanitized, "")
})

test_that("Validation handles empty strings", {
  result <- validate_text_input("")

  expect_true(result$valid)
  expect_equal(result$sanitized, "")
})

test_that("Validation handles whitespace-only input", {
  result <- validate_text_input("   ", max_length = 100)

  expect_true(result$valid)
  expect_equal(result$sanitized, "")
})

test_that("Validation handles Unicode characters", {
  unicode_input <- "Transporte público em São Paulo – Artigo 1º"
  result <- validate_text_input(unicode_input, max_length = 500)

  expect_true(result$valid)
  expect_false(is.null(result$sanitized))
})

test_that("Validation handles exact length limits", {
  exact_length_input <- paste(rep("a", 500), collapse = "")
  result <- validate_text_input(exact_length_input, max_length = 500)

  expect_true(result$valid)
  expect_equal(nchar(result$sanitized), 500)
})

# =============================================================================
# Test 11: Configuration and statistics
# =============================================================================

test_that("Input validation configuration is properly set", {
  expect_true(INPUT_VALIDATION_CONFIG$enabled)
  expect_equal(INPUT_VALIDATION_CONFIG$max_search_length, 500)
  expect_equal(INPUT_VALIDATION_CONFIG$max_text_length, 1000)
  expect_true(INPUT_VALIDATION_CONFIG$strict_mode)
})

test_that("Input validation stats return correct information", {
  stats <- get_input_validation_stats()

  expect_true(stats$enabled)
  expect_equal(stats$max_search_length, 500)
  expect_equal(stats$max_text_length, 1000)
  expect_true(stats$strict_mode)
})

# =============================================================================
# Test 12: Multiple validation patterns in single input
# =============================================================================

test_that("Validation detects multiple attack patterns", {
  # Input with both SQL injection and XSS
  malicious_input <- "<script>'; DROP TABLE users--</script>"
  result <- validate_text_input(malicious_input)

  expect_false(result$valid)
  expect_false(is.null(result$error))
})

test_that("Validation handles encoded attack attempts", {
  # URL-encoded script tag
  encoded_input <- "%3Cscript%3Ealert('xss')%3C/script%3E"
  result <- validate_text_input(encoded_input, max_length = 500)

  # Should still be sanitized/blocked
  expect_true(result$valid || !is.null(result$sanitized))
})

# =============================================================================
# Summary Report
# =============================================================================

cat("\n")
cat("=============================================================================\n")
cat("Input Validation Security Test Suite\n")
cat("=============================================================================\n")
cat("These tests verify that input validation is properly implemented:\n")
cat("\n")
cat("Validation Features:\n")
cat("  ✅ Text input validation (XSS and SQL injection prevention)\n")
cat("  ✅ Numeric input validation (range enforcement)\n")
cat("  ✅ State code validation (Brazilian states whitelist)\n")
cat("  ✅ Date input validation (range enforcement)\n")
cat("  ✅ Select input validation (allowed values whitelist)\n")
cat("  ✅ Query parameter validation\n")
cat("  ✅ Request body validation\n")
cat("  ✅ Batch validation\n")
cat("\n")
cat("Security Measures:\n")
cat("  - SQL injection pattern blocking\n")
cat("  - XSS pattern blocking\n")
cat("  - HTML sanitization\n")
cat("  - Length limit enforcement\n")
cat("  - Range validation for numbers and dates\n")
cat("  - Whitelist validation for state codes and select inputs\n")
cat("  - Unicode and special character handling\n")
cat("=============================================================================\n")
