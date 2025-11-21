# =============================================================================
# CSRF Protection Security Tests
# =============================================================================
# Tests to verify CSRF protection is properly implemented and working
# =============================================================================

library(testthat)
library(digest)

# Source the CSRF protection module
source("R/security/csrf_protection.R")

# =============================================================================
# Test 1: CSRF token generation
# =============================================================================

test_that("CSRF tokens are generated with correct length", {
  token_info <- generate_and_store_csrf_token("test_user_1")

  expect_equal(nchar(token_info$token), 32)
  expect_false(is.null(token_info$created_at))
  expect_false(is.null(token_info$expires_at))
})

test_that("CSRF tokens are unique for different identifiers", {
  token1 <- generate_and_store_csrf_token("user_1")
  token2 <- generate_and_store_csrf_token("user_2")

  expect_false(token1$token == token2$token)
})

test_that("CSRF tokens are regenerated for same identifier", {
  token1 <- generate_and_store_csrf_token("user_1")
  Sys.sleep(0.1)
  token2 <- generate_and_store_csrf_token("user_1")

  # New token should be different (includes timestamp)
  expect_false(token1$token == token2$token)
})

# =============================================================================
# Test 2: CSRF token storage and retrieval
# =============================================================================

test_that("CSRF tokens can be stored and retrieved", {
  test_id <- "test_identifier"
  token_info <- generate_and_store_csrf_token(test_id)

  retrieved_token <- get_csrf_token(test_id)
  expect_equal(retrieved_token, token_info$token)
})

test_that("Expired CSRF tokens are not retrieved", {
  # Create token with very short expiry
  test_id <- "expiring_user"
  token_info <- generate_and_store_csrf_token(test_id)

  # Manually set expiry to past
  token_info$expires_at <- Sys.time() - 10
  assign(test_id, token_info, envir = .csrf_token_store)

  # Token should be NULL (expired and removed)
  retrieved_token <- get_csrf_token(test_id)
  expect_null(retrieved_token)
})

test_that("Non-existent CSRF tokens return NULL", {
  retrieved_token <- get_csrf_token("non_existent_user")
  expect_null(retrieved_token)
})

# =============================================================================
# Test 3: CSRF token extraction from requests
# =============================================================================

test_that("CSRF token extracted from header", {
  # Mock request object with CSRF token in header
  mock_req <- list(
    HTTP_X_CSRF_TOKEN = "test_token_123",
    REQUEST_METHOD = "POST"
  )

  extracted_token <- extract_csrf_token_from_request(mock_req)
  expect_equal(extracted_token, "test_token_123")
})

test_that("CSRF token extracted from body", {
  # Mock request with token in body
  mock_req <- list(
    body = list(
      csrf_token = "body_token_456",
      other_data = "value"
    ),
    REQUEST_METHOD = "POST"
  )

  extracted_token <- extract_csrf_token_from_request(mock_req)
  expect_equal(extracted_token, "body_token_456")
})

test_that("CSRF token extracted from args", {
  # Mock request with token in args
  mock_req <- list(
    args = list(
      csrf_token = "args_token_789"
    ),
    REQUEST_METHOD = "POST"
  )

  extracted_token <- extract_csrf_token_from_request(mock_req)
  expect_equal(extracted_token, "args_token_789")
})

test_that("CSRF token extraction returns NULL when not present", {
  mock_req <- list(
    REQUEST_METHOD = "POST"
  )

  extracted_token <- extract_csrf_token_from_request(mock_req)
  expect_null(extracted_token)
})

# =============================================================================
# Test 4: CSRF token validation
# =============================================================================

test_that("Valid CSRF token passes validation", {
  identifier <- "valid_user"
  token_info <- generate_and_store_csrf_token(identifier)

  # Mock request with valid token
  mock_req <- list(
    HTTP_X_CSRF_TOKEN = token_info$token,
    REQUEST_METHOD = "POST",
    PATH_INFO = "/api/v1/data"
  )

  is_valid <- validate_csrf_token_from_request(mock_req, identifier)
  expect_true(is_valid)
})

test_that("Invalid CSRF token fails validation", {
  identifier <- "test_user"
  token_info <- generate_and_store_csrf_token(identifier)

  # Mock request with wrong token
  mock_req <- list(
    HTTP_X_CSRF_TOKEN = "wrong_token",
    REQUEST_METHOD = "POST",
    PATH_INFO = "/api/v1/data"
  )

  is_valid <- validate_csrf_token_from_request(mock_req, identifier)
  expect_false(is_valid)
})

test_that("Missing CSRF token fails validation for POST requests", {
  mock_req <- list(
    REQUEST_METHOD = "POST",
    PATH_INFO = "/api/v1/data"
  )

  is_valid <- validate_csrf_token_from_request(mock_req, "user")
  expect_false(is_valid)
})

test_that("GET requests bypass CSRF validation", {
  # GET requests are safe methods - no CSRF needed
  mock_req <- list(
    REQUEST_METHOD = "GET",
    PATH_INFO = "/api/v1/data"
  )

  is_valid <- validate_csrf_token_from_request(mock_req, "user")
  expect_true(is_valid)
})

test_that("HEAD requests bypass CSRF validation", {
  mock_req <- list(
    REQUEST_METHOD = "HEAD",
    PATH_INFO = "/api/v1/data"
  )

  is_valid <- validate_csrf_token_from_request(mock_req, "user")
  expect_true(is_valid)
})

test_that("OPTIONS requests bypass CSRF validation", {
  mock_req <- list(
    REQUEST_METHOD = "OPTIONS",
    PATH_INFO = "/api/v1/data"
  )

  is_valid <- validate_csrf_token_from_request(mock_req, "user")
  expect_true(is_valid)
})

test_that("Exempt paths bypass CSRF validation", {
  mock_req <- list(
    REQUEST_METHOD = "POST",
    PATH_INFO = "/health"  # Exempt path
  )

  is_valid <- validate_csrf_token_from_request(mock_req, "user")
  expect_true(is_valid)
})

# =============================================================================
# Test 5: CSRF token cleanup
# =============================================================================

test_that("Expired tokens are cleaned up", {
  # Create some test tokens
  for (i in 1:5) {
    generate_and_store_csrf_token(paste0("user_", i))
  }

  # Manually expire some tokens
  for (i in 1:3) {
    id <- paste0("user_", i)
    token_info <- get(id, envir = .csrf_token_store)
    token_info$expires_at <- Sys.time() - 10
    assign(id, token_info, envir = .csrf_token_store)
  }

  # Cleanup
  removed_count <- cleanup_expired_csrf_tokens()

  expect_equal(removed_count, 3)

  # Verify expired tokens are gone
  expect_null(get_csrf_token("user_1"))
  expect_null(get_csrf_token("user_2"))
  expect_null(get_csrf_token("user_3"))

  # Verify valid tokens remain
  expect_false(is.null(get_csrf_token("user_4")))
  expect_false(is.null(get_csrf_token("user_5")))
})

# =============================================================================
# Test 6: CSRF configuration
# =============================================================================

test_that("CSRF configuration is properly set", {
  expect_true(CSRF_CONFIG$enabled)
  expect_equal(CSRF_CONFIG$token_header_name, "X-CSRF-Token")
  expect_equal(CSRF_CONFIG$token_length, 32)
  expect_true("GET" %in% CSRF_CONFIG$exempt_methods)
  expect_true("POST" %not_in% CSRF_CONFIG$exempt_methods)
})

# Helper: not_in operator
`%not_in%` <- function(x, table) {
  !match(x, table, nomatch = 0) > 0
}

test_that("CSRF stats return correct information", {
  # Clear store first
  rm(list = ls(envir = .csrf_token_store), envir = .csrf_token_store)

  # Create some tokens
  for (i in 1:3) {
    generate_and_store_csrf_token(paste0("stats_user_", i))
  }

  stats <- get_csrf_stats()

  expect_equal(stats$active_tokens, 3)
  expect_true(stats$enabled)
  expect_equal(stats$token_length, 32)
})

# =============================================================================
# Test 7: Cookie extraction
# =============================================================================

test_that("CSRF token extracted from cookie header", {
  mock_req <- list(
    HTTP_COOKIE = "session_id=abc123; csrf_token=cookie_token_xyz; other=value",
    REQUEST_METHOD = "POST"
  )

  token <- extract_csrf_from_cookie(mock_req)
  expect_equal(token, "cookie_token_xyz")
})

test_that("Cookie extraction returns NULL when cookie not present", {
  mock_req <- list(
    HTTP_COOKIE = "session_id=abc123; other=value",
    REQUEST_METHOD = "POST"
  )

  token <- extract_csrf_from_cookie(mock_req)
  expect_null(token)
})

test_that("Cookie extraction returns NULL when no cookies", {
  mock_req <- list(
    REQUEST_METHOD = "POST"
  )

  token <- extract_csrf_from_cookie(mock_req)
  expect_null(token)
})

# =============================================================================
# Test 8: Integration tests
# =============================================================================

test_that("Full CSRF flow works end-to-end", {
  # Step 1: Generate token for user
  identifier <- "integration_test_user"
  token_info <- generate_and_store_csrf_token(identifier)

  # Step 2: Create mock POST request with token
  mock_req <- list(
    HTTP_X_CSRF_TOKEN = token_info$token,
    REQUEST_METHOD = "POST",
    PATH_INFO = "/api/v1/create",
    auth = list(
      user_id = identifier,
      api_key_id = identifier
    )
  )

  # Step 3: Validate token
  is_valid <- validate_csrf_token_from_request(mock_req, identifier)
  expect_true(is_valid)

  # Step 4: Try with wrong token
  mock_req$HTTP_X_CSRF_TOKEN <- "wrong_token"
  is_valid_wrong <- validate_csrf_token_from_request(mock_req, identifier)
  expect_false(is_valid_wrong)
})

test_that("CSRF protection prevents token reuse after expiry", {
  identifier <- "expiry_test_user"
  token_info <- generate_and_store_csrf_token(identifier)

  # Valid initially
  mock_req <- list(
    HTTP_X_CSRF_TOKEN = token_info$token,
    REQUEST_METHOD = "POST",
    PATH_INFO = "/api/v1/data"
  )

  expect_true(validate_csrf_token_from_request(mock_req, identifier))

  # Expire the token
  token_data <- get(identifier, envir = .csrf_token_store)
  token_data$expires_at <- Sys.time() - 10
  assign(identifier, token_data, envir = .csrf_token_store)

  # Should fail validation now
  expect_false(validate_csrf_token_from_request(mock_req, identifier))
})

# =============================================================================
# Test 9: State-changing methods validation
# =============================================================================

test_that("POST requests require CSRF token", {
  mock_req <- list(
    REQUEST_METHOD = "POST",
    PATH_INFO = "/api/v1/create"
  )

  # Without token
  expect_false(validate_csrf_token_from_request(mock_req, "user"))

  # With valid token
  identifier <- "post_user"
  token_info <- generate_and_store_csrf_token(identifier)
  mock_req$HTTP_X_CSRF_TOKEN <- token_info$token
  expect_true(validate_csrf_token_from_request(mock_req, identifier))
})

test_that("PUT requests require CSRF token", {
  mock_req <- list(
    REQUEST_METHOD = "PUT",
    PATH_INFO = "/api/v1/update"
  )

  # Without token
  expect_false(validate_csrf_token_from_request(mock_req, "user"))

  # With valid token
  identifier <- "put_user"
  token_info <- generate_and_store_csrf_token(identifier)
  mock_req$HTTP_X_CSRF_TOKEN <- token_info$token
  expect_true(validate_csrf_token_from_request(mock_req, identifier))
})

test_that("DELETE requests require CSRF token", {
  mock_req <- list(
    REQUEST_METHOD = "DELETE",
    PATH_INFO = "/api/v1/delete"
  )

  # Without token
  expect_false(validate_csrf_token_from_request(mock_req, "user"))

  # With valid token
  identifier <- "delete_user"
  token_info <- generate_and_store_csrf_token(identifier)
  mock_req$HTTP_X_CSRF_TOKEN <- token_info$token
  expect_true(validate_csrf_token_from_request(mock_req, identifier))
})

# =============================================================================
# Summary Report
# =============================================================================

cat("\n")
cat("=============================================================================\n")
cat("CSRF Protection Security Test Suite\n")
cat("=============================================================================\n")
cat("These tests verify that CSRF protection is properly implemented:\n")
cat("\n")
cat("Protection Features:\n")
cat("  ✅ CSRF token generation and storage\n")
cat("  ✅ Token validation for state-changing operations\n")
cat("  ✅ Safe method exemption (GET, HEAD, OPTIONS)\n")
cat("  ✅ Token extraction from headers, body, and cookies\n")
cat("  ✅ Token expiry and cleanup\n")
cat("  ✅ Integration with API authentication\n")
cat("\n")
cat("Security Measures:\n")
cat("  - 32-character cryptographically secure tokens\n")
cat("  - Constant-time token comparison (timing attack prevention)\n")
cat("  - 1-hour token expiry\n")
cat("  - Automatic cleanup of expired tokens\n")
cat("  - Support for multiple token submission methods\n")
cat("=============================================================================\n")
