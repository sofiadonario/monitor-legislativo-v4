# =============================================================================
# Security Hardening Module for Shiny Applications
# ============================================================================
# Description: CSRF protection and security utilities for Shiny apps
# Author: Security Enhancement Team
# Date: 2025-11-19
# =============================================================================

library(digest)
library(uuid)

# =============================================================================
# CSRF Token Management
# =============================================================================

#' Initialize Security Hardening
#'
#' Creates a security object with CSRF protection capabilities
#'
#' @return List with security functions
#' @export
init_security_hardening <- function() {

  list(
    generate_csrf_token = function(session) {
      token <- UUIDgenerate(use.time = TRUE)
      token_hash <- digest(token, algo = "sha256")

      session$userData$csrf_token <- token_hash
      session$userData$csrf_generated_at <- Sys.time()

      return(token_hash)
    },

    validate_csrf_token = function(token, session) {
      if (is.null(token) || is.null(session$userData$csrf_token)) {
        return(FALSE)
      }

      if (token != session$userData$csrf_token) {
        return(FALSE)
      }

      generated_at <- session$userData$csrf_generated_at
      if (is.null(generated_at)) {
        return(FALSE)
      }

      token_age <- difftime(Sys.time(), generated_at, units = "hours")
      if (token_age > 24) {
        return(FALSE)
      }

      return(TRUE)
    },

    regenerate_token_if_needed = function(session) {
      generated_at <- session$userData$csrf_generated_at
      if (is.null(generated_at)) {
        return(NULL)
      }

      token_age <- difftime(Sys.time(), generated_at, units = "hours")
      if (token_age > 12) {
        return(init_security_hardening()$generate_csrf_token(session))
      }

      return(session$userData$csrf_token)
    }
  )
}

# =============================================================================
# Input Sanitization Helpers
# =============================================================================

#' Sanitize User Input
#'
#' Remove potentially dangerous characters from user input
#'
#' @param input Character string to sanitize
#' @return Sanitized string
#' @export
sanitize_input <- function(input) {
  if (is.null(input) || length(input) == 0) {
    return("")
  }

  input <- gsub("[<>]", "", input)
  input <- gsub("[\r\n]", " ", input)
  input <- trimws(input)

  return(input)
}

#' Validate SQL Search Input
#'
#' Ensure search input is safe for database queries
#' Note: This is a helper - parameterized queries are still MANDATORY
#'
#' @param input Search string
#' @return Logical indicating if input is safe
#' @export
validate_search_input <- function(input) {
  if (is.null(input) || nchar(input) == 0) {
    return(TRUE)
  }

  if (nchar(input) > 500) {
    return(FALSE)
  }

  dangerous_patterns <- c(
    "DROP\\s+TABLE",
    "DELETE\\s+FROM",
    "INSERT\\s+INTO",
    "UPDATE\\s+SET",
    ";\\s*--",
    "UNION\\s+SELECT",
    "xp_cmdshell"
  )

  for (pattern in dangerous_patterns) {
    if (grepl(pattern, input, ignore.case = TRUE)) {
      return(FALSE)
    }
  }

  return(TRUE)
}

# =============================================================================
# Security Headers
# =============================================================================

#' Get Security Headers for HTTP Responses
#'
#' Returns recommended security headers
#'
#' @return Named list of security headers
#' @export
get_security_headers <- function() {
  list(
    "X-Frame-Options" = "SAMEORIGIN",
    "X-Content-Type-Options" = "nosniff",
    "X-XSS-Protection" = "1; mode=block",
    "Referrer-Policy" = "strict-origin-when-cross-origin",
    "Content-Security-Policy" = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'"
  )
}
