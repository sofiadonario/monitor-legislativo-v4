# =============================================================================
# Security Headers Middleware for Plumber APIs
# =============================================================================
# Implements comprehensive HTTP security headers
# Protects against common web vulnerabilities
# =============================================================================

# Security Headers Configuration
SECURITY_HEADERS_CONFIG <- list(
  enabled = TRUE,

  # Content Security Policy
  csp_enabled = TRUE,
  csp_policy = paste(
    "default-src 'self';",
    "script-src 'self' 'unsafe-inline' 'unsafe-eval';",
    "style-src 'self' 'unsafe-inline';",
    "img-src 'self' data: https:;",
    "font-src 'self' data:;",
    "connect-src 'self';",
    "frame-ancestors 'none';",
    "base-uri 'self';",
    "form-action 'self';"
  ),

  # Strict Transport Security (HSTS)
  hsts_enabled = TRUE,
  hsts_max_age = 31536000,  # 1 year in seconds
  hsts_include_subdomains = TRUE,
  hsts_preload = FALSE,

  # X-Frame-Options
  x_frame_options = "DENY",  # or "SAMEORIGIN"

  # X-Content-Type-Options
  x_content_type_options = "nosniff",

  # X-XSS-Protection
  x_xss_protection = "1; mode=block",

  # Referrer-Policy
  referrer_policy = "strict-origin-when-cross-origin",

  # Permissions-Policy (formerly Feature-Policy)
  permissions_policy = paste(
    "geolocation=()",
    "microphone=()",
    "camera=()",
    "payment=()",
    "usb=()",
    "magnetometer=()"
  ),

  # CORS settings
  cors_enabled = FALSE,  # Disable by default, enable if needed
  cors_origin = "*",
  cors_methods = "GET, POST, PUT, DELETE, OPTIONS",
  cors_headers = "Content-Type, Authorization, X-CSRF-Token, X-API-Key",
  cors_credentials = "true",
  cors_max_age = 86400,  # 24 hours

  # Custom headers
  custom_headers = list(
    "X-Powered-By" = "Monitor Legislativo v4",
    "X-Content-Type-Options" = "nosniff"
  )
)

#' Build HSTS Header Value
#'
#' Constructs the Strict-Transport-Security header value
#'
#' @return HSTS header string
build_hsts_header <- function() {
  if (!SECURITY_HEADERS_CONFIG$hsts_enabled) {
    return(NULL)
  }

  hsts_value <- sprintf("max-age=%d", SECURITY_HEADERS_CONFIG$hsts_max_age)

  if (SECURITY_HEADERS_CONFIG$hsts_include_subdomains) {
    hsts_value <- paste0(hsts_value, "; includeSubDomains")
  }

  if (SECURITY_HEADERS_CONFIG$hsts_preload) {
    hsts_value <- paste0(hsts_value, "; preload")
  }

  return(hsts_value)
}

#' Apply Security Headers to Response
#'
#' Adds all configured security headers to a Plumber response
#'
#' @param res Plumber response object
#' @return Modified response object
apply_security_headers <- function(res) {
  if (!SECURITY_HEADERS_CONFIG$enabled) {
    return(res)
  }

  # Content Security Policy
  if (SECURITY_HEADERS_CONFIG$csp_enabled) {
    res$setHeader("Content-Security-Policy", SECURITY_HEADERS_CONFIG$csp_policy)
  }

  # Strict Transport Security (HSTS)
  hsts_header <- build_hsts_header()
  if (!is.null(hsts_header)) {
    res$setHeader("Strict-Transport-Security", hsts_header)
  }

  # X-Frame-Options
  if (!is.null(SECURITY_HEADERS_CONFIG$x_frame_options)) {
    res$setHeader("X-Frame-Options", SECURITY_HEADERS_CONFIG$x_frame_options)
  }

  # X-Content-Type-Options
  if (!is.null(SECURITY_HEADERS_CONFIG$x_content_type_options)) {
    res$setHeader("X-Content-Type-Options", SECURITY_HEADERS_CONFIG$x_content_type_options)
  }

  # X-XSS-Protection
  if (!is.null(SECURITY_HEADERS_CONFIG$x_xss_protection)) {
    res$setHeader("X-XSS-Protection", SECURITY_HEADERS_CONFIG$x_xss_protection)
  }

  # Referrer-Policy
  if (!is.null(SECURITY_HEADERS_CONFIG$referrer_policy)) {
    res$setHeader("Referrer-Policy", SECURITY_HEADERS_CONFIG$referrer_policy)
  }

  # Permissions-Policy
  if (!is.null(SECURITY_HEADERS_CONFIG$permissions_policy)) {
    res$setHeader("Permissions-Policy", SECURITY_HEADERS_CONFIG$permissions_policy)
  }

  # CORS headers (if enabled)
  if (SECURITY_HEADERS_CONFIG$cors_enabled) {
    res$setHeader("Access-Control-Allow-Origin", SECURITY_HEADERS_CONFIG$cors_origin)
    res$setHeader("Access-Control-Allow-Methods", SECURITY_HEADERS_CONFIG$cors_methods)
    res$setHeader("Access-Control-Allow-Headers", SECURITY_HEADERS_CONFIG$cors_headers)
    res$setHeader("Access-Control-Allow-Credentials", SECURITY_HEADERS_CONFIG$cors_credentials)
    res$setHeader("Access-Control-Max-Age", as.character(SECURITY_HEADERS_CONFIG$cors_max_age))
  }

  # Custom headers
  for (header_name in names(SECURITY_HEADERS_CONFIG$custom_headers)) {
    header_value <- SECURITY_HEADERS_CONFIG$custom_headers[[header_name]]
    res$setHeader(header_name, header_value)
  }

  # Remove potentially dangerous headers
  res$setHeader("X-Powered-By", NULL)  # Remove default X-Powered-By
  res$setHeader("Server", NULL)  # Hide server information

  return(res)
}

#' Security Headers Middleware Filter for Plumber
#' @filter security_headers
security_headers_filter <- function(req, res) {
  # Apply security headers to all responses
  apply_security_headers(res)

  # Handle OPTIONS requests for CORS preflight
  if (req$REQUEST_METHOD == "OPTIONS" && SECURITY_HEADERS_CONFIG$cors_enabled) {
    res$status <- 204
    res$body <- ""
    return(res)
  }

  # Continue to next handler
  plumber::forward()
}

#' Get Security Headers Configuration
#'
#' Returns current security headers configuration
#'
#' @return List with security headers settings
get_security_headers_config <- function() {
  return(list(
    enabled = SECURITY_HEADERS_CONFIG$enabled,
    csp_enabled = SECURITY_HEADERS_CONFIG$csp_enabled,
    hsts_enabled = SECURITY_HEADERS_CONFIG$hsts_enabled,
    hsts_max_age = SECURITY_HEADERS_CONFIG$hsts_max_age,
    cors_enabled = SECURITY_HEADERS_CONFIG$cors_enabled,
    x_frame_options = SECURITY_HEADERS_CONFIG$x_frame_options,
    referrer_policy = SECURITY_HEADERS_CONFIG$referrer_policy
  ))
}

#' Update Content Security Policy
#'
#' Allows dynamic updating of CSP policy
#'
#' @param policy New CSP policy string
update_csp_policy <- function(policy) {
  if (!is.character(policy) || length(policy) != 1) {
    stop("CSP policy must be a single character string")
  }

  SECURITY_HEADERS_CONFIG$csp_policy <<- policy
  cat(sprintf("✅ CSP policy updated: %s\n", substr(policy, 1, 100)))

  return(invisible(TRUE))
}

#' Enable/Disable CORS
#'
#' Dynamically enable or disable CORS
#'
#' @param enabled Boolean to enable/disable CORS
#' @param origin Allowed origin (default: "*")
enable_cors <- function(enabled = TRUE, origin = "*") {
  SECURITY_HEADERS_CONFIG$cors_enabled <<- enabled
  SECURITY_HEADERS_CONFIG$cors_origin <<- origin

  if (enabled) {
    cat(sprintf("✅ CORS enabled for origin: %s\n", origin))
  } else {
    cat("❌ CORS disabled\n")
  }

  return(invisible(TRUE))
}

#' Validate Security Headers Configuration
#'
#' Checks if security headers are properly configured
#'
#' @return List with validation results
validate_security_headers_config <- function() {
  issues <- c()

  # Check if HSTS is enabled
  if (!SECURITY_HEADERS_CONFIG$hsts_enabled) {
    issues <- c(issues, "HSTS is disabled - enable for production")
  } else if (SECURITY_HEADERS_CONFIG$hsts_max_age < 31536000) {
    issues <- c(issues, "HSTS max-age is less than 1 year - recommended: 31536000 seconds")
  }

  # Check if CSP is enabled
  if (!SECURITY_HEADERS_CONFIG$csp_enabled) {
    issues <- c(issues, "CSP is disabled - enable for production")
  }

  # Check X-Frame-Options
  if (is.null(SECURITY_HEADERS_CONFIG$x_frame_options)) {
    issues <- c(issues, "X-Frame-Options not set - risk of clickjacking")
  }

  # Check if CSP policy contains unsafe directives in production
  if (SECURITY_HEADERS_CONFIG$csp_enabled) {
    if (grepl("'unsafe-inline'|'unsafe-eval'", SECURITY_HEADERS_CONFIG$csp_policy)) {
      issues <- c(issues, "CSP contains 'unsafe-inline' or 'unsafe-eval' - remove for production")
    }
  }

  # Check CORS configuration
  if (SECURITY_HEADERS_CONFIG$cors_enabled && SECURITY_HEADERS_CONFIG$cors_origin == "*") {
    issues <- c(issues, "CORS is enabled with wildcard origin - specify exact origins for production")
  }

  return(list(
    valid = length(issues) == 0,
    issues = if (length(issues) > 0) issues else NULL,
    warnings_count = length(issues)
  ))
}

#' Get Security Headers Report
#'
#' Generates a report of all active security headers
#'
#' @return List with header information
get_security_headers_report <- function() {
  # Create a mock response object to extract headers
  mock_res <- list(
    headers = list(),
    setHeader = function(name, value) {
      if (!is.null(value)) {
        self$headers[[name]] <- value
      }
    }
  )

  # Make setHeader function work with self reference
  environment(mock_res$setHeader)$self <- mock_res

  # Apply headers
  apply_security_headers(mock_res)

  return(list(
    active_headers = names(mock_res$headers),
    header_values = mock_res$headers,
    config = get_security_headers_config(),
    validation = validate_security_headers_config()
  ))
}

cat("✅ Security Headers Module Loaded\n")
cat("   CSP enabled:", SECURITY_HEADERS_CONFIG$csp_enabled, "\n")
cat("   HSTS enabled:", SECURITY_HEADERS_CONFIG$hsts_enabled, "\n")
cat("   HSTS max-age:", SECURITY_HEADERS_CONFIG$hsts_max_age, "seconds\n")
cat("   CORS enabled:", SECURITY_HEADERS_CONFIG$cors_enabled, "\n")
cat("   X-Frame-Options:", SECURITY_HEADERS_CONFIG$x_frame_options, "\n")
