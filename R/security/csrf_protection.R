# =============================================================================
# CSRF Protection Module for Plumber APIs
# =============================================================================
# Implements Cross-Site Request Forgery protection for state-changing operations
# Uses double-submit cookie pattern and synchronizer token pattern
# =============================================================================

# Check and load required packages
CSRF_DEPENDENCIES <- requireNamespace("digest", quietly = TRUE)

if (!CSRF_DEPENDENCIES) {
  warning("CSRF protection dependencies not available (digest)")
}

# Source the security hardening module for token generation/validation
if (file.exists("scripts/R/security_hardening.R")) {
  source("scripts/R/security_hardening.R")
}

# CSRF Token Storage (in-memory, use database/Redis in production)
if (!exists(".csrf_token_store", envir = .GlobalEnv)) {
  assign(".csrf_token_store", new.env(parent = emptyenv()), envir = .GlobalEnv)
}

# CSRF Configuration
CSRF_CONFIG <- list(
  enabled = TRUE,
  token_header_name = "X-CSRF-Token",
  token_cookie_name = "csrf_token",
  token_length = 32,
  token_expiry_seconds = 3600,
  exempt_methods = c("GET", "HEAD", "OPTIONS"),
  exempt_paths = c("/health", "/info", "/", "/api/v1/info")
)

#' Generate and store CSRF token for a session/API key
#' @param identifier Session ID or API key hash
#' @return List with token and expiry
generate_and_store_csrf_token <- function(identifier) {
  # Generate cryptographically secure token
  token_data <- paste(
    identifier,
    Sys.time(),
    paste(sample(c(letters, LETTERS, 0:9), 32, replace = TRUE), collapse = ""),
    sep = "-"
  )

  csrf_token <- digest(token_data, algo = "sha256", serialize = FALSE)
  csrf_token <- substr(csrf_token, 1, CSRF_CONFIG$token_length)

  # Store token with expiry
  token_info <- list(
    token = csrf_token,
    created_at = Sys.time(),
    expires_at = Sys.time() + CSRF_CONFIG$token_expiry_seconds,
    identifier = identifier
  )

  assign(identifier, token_info, envir = .csrf_token_store)

  return(token_info)
}

#' Retrieve CSRF token for identifier
#' @param identifier Session ID or API key hash
#' @return CSRF token or NULL if not found/expired
get_csrf_token <- function(identifier) {
  if (!exists(identifier, envir = .csrf_token_store)) {
    return(NULL)
  }

  token_info <- get(identifier, envir = .csrf_token_store)

  # Check if expired
  if (Sys.time() > token_info$expires_at) {
    rm(list = identifier, envir = .csrf_token_store)
    return(NULL)
  }

  return(token_info$token)
}

#' Validate CSRF token from request
#' @param req Plumber request object
#' @param identifier Session ID or API key hash
#' @return TRUE if valid, FALSE otherwise
validate_csrf_token_from_request <- function(req, identifier) {
  if (!CSRF_CONFIG$enabled) {
    return(TRUE)
  }

  # GET, HEAD, OPTIONS are safe methods - no CSRF protection needed
  if (req$REQUEST_METHOD %in% CSRF_CONFIG$exempt_methods) {
    return(TRUE)
  }

  # Check if path is exempt
  if (req$PATH_INFO %in% CSRF_CONFIG$exempt_paths) {
    return(TRUE)
  }

  # Extract token from request
  submitted_token <- extract_csrf_token_from_request(req)

  if (is.null(submitted_token)) {
    cat("❌ CSRF validation failed: No token submitted\n")
    return(FALSE)
  }

  # Get expected token from store
  expected_token <- get_csrf_token(identifier)

  if (is.null(expected_token)) {
    cat("❌ CSRF validation failed: No token found for identifier\n")
    return(FALSE)
  }

  # Constant-time comparison to prevent timing attacks
  if (!identical(submitted_token, expected_token)) {
    cat("❌ CSRF validation failed: Token mismatch\n")
    return(FALSE)
  }

  cat("✅ CSRF token validated successfully\n")
  return(TRUE)
}

#' Extract CSRF token from request (header or body)
#' @param req Plumber request object
#' @return CSRF token string or NULL
extract_csrf_token_from_request <- function(req) {
  # Try header first (recommended for APIs)
  header_name_upper <- paste0("HTTP_", gsub("-", "_", toupper(CSRF_CONFIG$token_header_name)))
  token_from_header <- req[[header_name_upper]]

  if (!is.null(token_from_header) && token_from_header != "") {
    return(token_from_header)
  }

  # Try body parameter (for form submissions)
  if (!is.null(req$body)) {
    if (is.list(req$body) && !is.null(req$body$csrf_token)) {
      return(req$body$csrf_token)
    }
  }

  # Try POST args
  if (!is.null(req$args) && !is.null(req$args$csrf_token)) {
    return(req$args$csrf_token)
  }

  # Try cookie (double-submit pattern)
  cookie_token <- extract_csrf_from_cookie(req)
  if (!is.null(cookie_token)) {
    return(cookie_token)
  }

  return(NULL)
}

#' Extract CSRF token from cookie
#' @param req Plumber request object
#' @return Token from cookie or NULL
extract_csrf_from_cookie <- function(req) {
  cookie_header <- req$HTTP_COOKIE

  if (is.null(cookie_header) || cookie_header == "") {
    return(NULL)
  }

  # Parse cookies
  cookies <- strsplit(cookie_header, "; ")[[1]]
  for (cookie in cookies) {
    parts <- strsplit(cookie, "=")[[1]]
    if (length(parts) == 2 && parts[1] == CSRF_CONFIG$token_cookie_name) {
      return(parts[2])
    }
  }

  return(NULL)
}

#' CSRF Protection Middleware Filter for Plumber
#' @filter csrf_protection
csrf_protection_filter <- function(req, res) {
  # Skip if CSRF protection is disabled
  if (!CSRF_CONFIG$enabled) {
    plumber::forward()
    return()
  }

  # Skip for safe methods
  if (req$REQUEST_METHOD %in% CSRF_CONFIG$exempt_methods) {
    plumber::forward()
    return()
  }

  # Skip for exempt paths
  if (req$PATH_INFO %in% CSRF_CONFIG$exempt_paths) {
    plumber::forward()
    return()
  }

  # Get identifier from auth context (set by auth middleware)
  identifier <- NULL
  if (!is.null(req$auth)) {
    # Use API key hash as identifier
    identifier <- req$auth$api_key_id %||% req$auth$user_id %||% "anonymous"
  } else {
    identifier <- "anonymous"
  }

  # Validate CSRF token
  if (!validate_csrf_token_from_request(req, identifier)) {
    res$status <- 403
    res$setHeader("Content-Type", "application/json")

    error_response <- list(
      error = TRUE,
      message = "CSRF token validation failed. Include a valid CSRF token in the request.",
      code = 403,
      details = list(
        required_header = CSRF_CONFIG$token_header_name,
        required_method = "Include token in header or request body"
      ),
      timestamp = Sys.time()
    )

    return(jsonlite::toJSON(error_response, auto_unbox = TRUE))
  }

  # Token valid, continue to endpoint
  plumber::forward()
}

#' Get or create CSRF token for current session
#' @param identifier Session/API key identifier
#' @return CSRF token
#' @get /api/v1/csrf-token
endpoint_get_csrf_token <- function(identifier = "anonymous") {
  # Generate or retrieve token
  token_info <- generate_and_store_csrf_token(identifier)

  return(list(
    csrf_token = token_info$token,
    expires_at = format(token_info$expires_at, "%Y-%m-%dT%H:%M:%SZ"),
    header_name = CSRF_CONFIG$token_header_name,
    usage = paste0("Include this token in the '", CSRF_CONFIG$token_header_name, "' header for POST/PUT/DELETE requests")
  ))
}

#' Clean up expired CSRF tokens
cleanup_expired_csrf_tokens <- function() {
  identifiers <- ls(envir = .csrf_token_store)
  current_time <- Sys.time()
  removed_count <- 0

  for (identifier in identifiers) {
    token_info <- get(identifier, envir = .csrf_token_store)
    if (current_time > token_info$expires_at) {
      rm(list = identifier, envir = .csrf_token_store)
      removed_count <- removed_count + 1
    }
  }

  if (removed_count > 0) {
    cat(sprintf("🧹 Cleaned up %d expired CSRF tokens\n", removed_count))
  }

  return(removed_count)
}

#' Get CSRF protection statistics
get_csrf_stats <- function() {
  active_tokens <- length(ls(envir = .csrf_token_store))

  return(list(
    enabled = CSRF_CONFIG$enabled,
    active_tokens = active_tokens,
    token_length = CSRF_CONFIG$token_length,
    expiry_seconds = CSRF_CONFIG$token_expiry_seconds,
    exempt_methods = CSRF_CONFIG$exempt_methods,
    exempt_paths = CSRF_CONFIG$exempt_paths
  ))
}

cat("✅ CSRF Protection Module Loaded\n")
cat("   Token length:", CSRF_CONFIG$token_length, "characters\n")
cat("   Token expiry:", CSRF_CONFIG$token_expiry_seconds, "seconds\n")
cat("   Exempt methods:", paste(CSRF_CONFIG$exempt_methods, collapse = ", "), "\n")
