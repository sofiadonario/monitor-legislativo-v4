# ============================================================================
# SECURITY MIDDLEWARE - SPRINT 6B (API-001)
# ============================================================================
# 
# Comprehensive security middleware for Brazilian Legislative API
# Implements security headers, CORS, input validation, and threat protection
# LGPD compliant security measures
# 
# Features:
# - Security headers (HSTS, CSP, X-Frame-Options, etc.)
# - CORS configuration for cross-origin requests
# - Input validation and sanitization
# - SQL injection prevention
# - XSS protection
# - Rate limiting by IP address
# - Request size limits
# - LGPD compliance headers
# ============================================================================

cat("🛡️ Loading Security Middleware\n")

# Security configuration
SECURITY_CONFIG <- list(
  # CORS settings
  cors_enabled = TRUE,
  cors_origins = c("*"), # In production, specify allowed origins
  cors_methods = c("GET", "POST", "PUT", "DELETE", "OPTIONS"),
  cors_headers = c("Content-Type", "Authorization", "X-API-Key", "X-Requested-With"),
  cors_max_age = 86400,
  
  # Security headers
  security_headers_enabled = TRUE,
  hsts_enabled = TRUE,
  hsts_max_age = 31536000, # 1 year
  csp_enabled = TRUE,
  frame_options = "DENY",
  content_type_options = "nosniff",
  referrer_policy = "strict-origin-when-cross-origin",
  
  # Request validation
  max_request_size_mb = 10,
  max_query_params = 50,
  max_header_size = 8192,
  
  # Rate limiting by IP
  ip_rate_limit_enabled = TRUE,
  ip_requests_per_minute = 300,
  
  # Input validation
  validate_inputs = TRUE,
  block_suspicious_patterns = TRUE,
  
  # LGPD compliance
  lgpd_headers_enabled = TRUE
)

# IP-based rate limiting storage
IP_RATE_LIMITS <- list()

# Suspicious patterns for input validation
SUSPICIOUS_PATTERNS <- c(
  # SQL injection patterns
  "(?i)(union|select|insert|update|delete|drop|create|alter)\\s+",
  "(?i)(script|javascript|vbscript|onload|onerror|onclick)",
  "(?i)(<script|</script>|<iframe|</iframe>)",
  "(?i)(eval\\s*\\(|exec\\s*\\(|system\\s*\\()",
  "(?i)(\\||&&|;|`)",
  # Path traversal
  "(\\.\\./|\\.\\\\\\.\\.)",
  # Command injection
  "(?i)(cmd|powershell|bash|sh)\\s+",
  # XSS patterns
  "(?i)(alert\\s*\\(|confirm\\s*\\(|prompt\\s*\\()"
)

# Helper function to validate request size
validate_request_size <- function(req) {
  # Check content length
  content_length <- as.numeric(req$HTTP_CONTENT_LENGTH %||% 0)
  max_size_bytes <- SECURITY_CONFIG$max_request_size_mb * 1024 * 1024
  
  if (content_length > max_size_bytes) {
    return(list(
      valid = FALSE,
      error = paste("Request too large. Maximum size:", SECURITY_CONFIG$max_request_size_mb, "MB")
    ))
  }
  
  # Check query string length
  query_string <- req$QUERY_STRING %||% ""
  if (nchar(query_string) > 2048) {
    return(list(
      valid = FALSE,
      error = "Query string too long"
    ))
  }
  
  # Check number of query parameters
  if (!isTRUE(is.null(req$args)) && length(req$args) > SECURITY_CONFIG$max_query_params) {
    return(list(
      valid = FALSE,
      error = paste("Too many query parameters. Maximum:", SECURITY_CONFIG$max_query_params)
    ))
  }
  
  return(list(valid = TRUE))
}

# Helper function to validate input for suspicious patterns
validate_input_security <- function(input_text) {
  if (!SECURITY_CONFIG$validate_inputs || isTRUE(is.null(input_text)) || nchar(input_text) == 0) {
    return(list(valid = TRUE))
  }
  
  if (!SECURITY_CONFIG$block_suspicious_patterns) {
    return(list(valid = TRUE))
  }
  
  # Check against suspicious patterns
  for (pattern in SUSPICIOUS_PATTERNS) {
    if (grepl(pattern, input_text, perl = TRUE)) {
      return(list(
        valid = FALSE,
        error = "Suspicious input pattern detected",
        pattern = pattern
      ))
    }
  }
  
  return(list(valid = TRUE))
}

# Helper function to check IP-based rate limiting
check_ip_rate_limit <- function(client_ip) {
  if (!SECURITY_CONFIG$ip_rate_limit_enabled) {
    return(list(allowed = TRUE))
  }
  
  current_time <- Sys.time()
  minute_key <- paste0(client_ip, "_", format(current_time, "%Y%m%d%H%M"))
  
  # Initialize rate limit counter if not exists
  if (!minute_key %in% names(IP_RATE_LIMITS)) {
    IP_RATE_LIMITS[[minute_key]] <<- 0
  }
  
  # Check current usage
  current_usage <- IP_RATE_LIMITS[[minute_key]]
  
  if (current_usage >= SECURITY_CONFIG$ip_requests_per_minute) {
    return(list(
      allowed = FALSE,
      error = paste("IP rate limit exceeded. Maximum", SECURITY_CONFIG$ip_requests_per_minute, "requests per minute"),
      reset_time = ceiling(60 - as.numeric(format(current_time, "%S")))
    ))
  }
  
  # Increment counter
  IP_RATE_LIMITS[[minute_key]] <<- current_usage + 1
  
  return(list(
    allowed = TRUE,
    remaining = SECURITY_CONFIG$ip_requests_per_minute - (current_usage + 1)
  ))
}

# Helper function to set security headers
set_security_headers <- function(res) {
  if (!SECURITY_CONFIG$security_headers_enabled) {
    return()
  }
  
  # HSTS (HTTP Strict Transport Security)
  if (SECURITY_CONFIG$hsts_enabled) {
    res$setHeader("Strict-Transport-Security", 
                  paste0("max-age=", SECURITY_CONFIG$hsts_max_age, "; includeSubDomains; preload"))
  }
  
  # Content Security Policy
  if (SECURITY_CONFIG$csp_enabled) {
    csp_policy <- "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'none';"
    res$setHeader("Content-Security-Policy", csp_policy)
  }
  
  # X-Frame-Options
  res$setHeader("X-Frame-Options", SECURITY_CONFIG$frame_options)
  
  # X-Content-Type-Options
  res$setHeader("X-Content-Type-Options", SECURITY_CONFIG$content_type_options)
  
  # X-XSS-Protection
  res$setHeader("X-XSS-Protection", "1; mode=block")
  
  # Referrer Policy
  res$setHeader("Referrer-Policy", SECURITY_CONFIG$referrer_policy)
  
  # X-Permitted-Cross-Domain-Policies
  res$setHeader("X-Permitted-Cross-Domain-Policies", "none")
  
  # X-Download-Options
  res$setHeader("X-Download-Options", "noopen")
  
  # Server header (hide server information)
  res$setHeader("Server", "Monitor-Legislativo-API")
  
  # LGPD compliance headers
  if (SECURITY_CONFIG$lgpd_headers_enabled) {
    res$setHeader("X-Data-Protection", "LGPD-Compliant")
    res$setHeader("X-Privacy-Policy", "https://monitorlegislativo.gov.br/privacy")
  }
}

# Helper function to set CORS headers
set_cors_headers <- function(req, res) {
  if (!SECURITY_CONFIG$cors_enabled) {
    return()
  }
  
  origin <- req$HTTP_ORIGIN %||% ""
  
  # Check if origin is allowed
  if ("*" %in% SECURITY_CONFIG$cors_origins || origin %in% SECURITY_CONFIG$cors_origins) {
    allowed_origin <- if ("*" %in% SECURITY_CONFIG$cors_origins) "*" else origin
    res$setHeader("Access-Control-Allow-Origin", allowed_origin)
  }
  
  # Set other CORS headers
  res$setHeader("Access-Control-Allow-Methods", paste(SECURITY_CONFIG$cors_methods, collapse = ", "))
  res$setHeader("Access-Control-Allow-Headers", paste(SECURITY_CONFIG$cors_headers, collapse = ", "))
  res$setHeader("Access-Control-Max-Age", as.character(SECURITY_CONFIG$cors_max_age))
  res$setHeader("Access-Control-Allow-Credentials", "false")
  
  # Expose custom headers
  custom_headers <- c("X-RateLimit-Remaining", "X-RateLimit-Reset", "X-Daily-Quota-Remaining", "X-API-Tier")
  res$setHeader("Access-Control-Expose-Headers", paste(custom_headers, collapse = ", "))
}

# Main security filter
#* @filter security
function(req, res) {
  start_time <- Sys.time()
  
  # Extract client information
  client_ip <- req$HTTP_X_FORWARDED_FOR %||% req$HTTP_X_REAL_IP %||% req$REMOTE_ADDR %||% "unknown"
  user_agent <- req$HTTP_USER_AGENT %||% "unknown"
  
  # Set security headers
  set_security_headers(res)
  
  # Set CORS headers
  set_cors_headers(req, res)
  
  # Handle preflight OPTIONS requests
  if (req$REQUEST_METHOD == "OPTIONS") {
    res$status <- 200
    res$setHeader("Content-Length", "0")
    return("")
  }
  
  # Validate request size
  size_validation <- validate_request_size(req)
  if (!size_validation$valid) {
    res$status <- 413
    res$setHeader("Content-Type", "application/json")
    
    error_response <- list(
      error = TRUE,
      message = size_validation$error,
      code = 413,
      timestamp = Sys.time()
    )
    
    # Log security event
    if (exists("log_security_event")) {
      log_security_event("REQUEST_TOO_LARGE", list(
        size_mb = as.numeric(req$HTTP_CONTENT_LENGTH %||% 0) / 1024 / 1024,
        max_size_mb = SECURITY_CONFIG$max_request_size_mb
      ), req)
    }
    
    return(jsonlite::toJSON(error_response, auto_unbox = TRUE))
  }
  
  # Check IP-based rate limiting
  ip_rate_check <- check_ip_rate_limit(client_ip)
  if (!ip_rate_check$allowed) {
    res$status <- 429
    res$setHeader("X-IP-RateLimit-Remaining", "0")
    res$setHeader("Retry-After", as.character(ip_rate_check$reset_time))
    res$setHeader("Content-Type", "application/json")
    
    error_response <- list(
      error = TRUE,
      message = ip_rate_check$error,
      code = 429,
      details = list(
        type = "ip_rate_limit",
        reset_in_seconds = ip_rate_check$reset_time
      ),
      timestamp = Sys.time()
    )
    
    # Log security event
    if (exists("log_security_event")) {
      log_security_event("IP_RATE_LIMIT_EXCEEDED", list(
        requests_per_minute = SECURITY_CONFIG$ip_requests_per_minute
      ), req)
    }
    
    return(jsonlite::toJSON(error_response, auto_unbox = TRUE))
  }
  
  # Validate query parameters for suspicious content
  if (!isTRUE(is.null(req$args)) && length(req$args) > 0) {
    for (param_name in names(req$args)) {
      param_value <- req$args[[param_name]]
      
      # Validate parameter name
      name_validation <- validate_input_security(param_name)
      if (!name_validation$valid) {
        res$status <- 400
        res$setHeader("Content-Type", "application/json")
        
        error_response <- list(
          error = TRUE,
          message = "Invalid parameter name detected",
          code = 400,
          timestamp = Sys.time()
        )
        
        # Log security event
        if (exists("log_security_event")) {
          log_security_event("SUSPICIOUS_PARAMETER_NAME", list(
            parameter = param_name,
            pattern = name_validation$pattern
          ), req)
        }
        
        return(jsonlite::toJSON(error_response, auto_unbox = TRUE))
      }
      
      # Validate parameter value
      value_validation <- validate_input_security(param_value)
      if (!value_validation$valid) {
        res$status <- 400
        res$setHeader("Content-Type", "application/json")
        
        error_response <- list(
          error = TRUE,
          message = "Suspicious input detected in parameter",
          code = 400,
          timestamp = Sys.time()
        )
        
        # Log security event
        if (exists("log_security_event")) {
          log_security_event("SUSPICIOUS_PARAMETER_VALUE", list(
            parameter = param_name,
            pattern = value_validation$pattern
          ), req)
        }
        
        return(jsonlite::toJSON(error_response, auto_unbox = TRUE))
      }
    }
  }
  
  # Validate request body for POST requests
  if (req$REQUEST_METHOD %in% c("POST", "PUT", "PATCH") && !is.null(req$postBody)) {
    body_validation <- validate_input_security(req$postBody)
    if (!body_validation$valid) {
      res$status <- 400
      res$setHeader("Content-Type", "application/json")
      
      error_response <- list(
        error = TRUE,
        message = "Suspicious content detected in request body",
        code = 400,
        timestamp = Sys.time()
      )
      
      # Log security event
      if (exists("log_security_event")) {
        log_security_event("SUSPICIOUS_REQUEST_BODY", list(
          pattern = body_validation$pattern
        ), req)
      }
      
      return(jsonlite::toJSON(error_response, auto_unbox = TRUE))
    }
  }
  
  # Check for suspicious User-Agent strings
  if (grepl("(?i)(bot|crawler|spider|scraper)", user_agent) && 
      !grepl("(?i)(googlebot|bingbot|slurp)", user_agent)) {
    
    # Log suspicious bot activity
    if (exists("log_security_event")) {
      log_security_event("SUSPICIOUS_USER_AGENT", list(
        user_agent = user_agent
      ), req)
    }
  }
  
  # Set IP rate limit remaining header
  if (SECURITY_CONFIG$ip_rate_limit_enabled) {
    res$setHeader("X-IP-RateLimit-Remaining", as.character(ip_rate_check$remaining))
  }
  
  # Store security context in request
  req$security <- list(
    client_ip = client_ip,
    user_agent = user_agent,
    security_check_time = as.numeric(difftime(Sys.time(), start_time, units = "secs")),
    headers_set = TRUE,
    input_validated = TRUE
  )
  
  plumber::forward()
}

# Function to validate JSON input
validate_json_input <- function(json_string) {
  if (isTRUE(is.null(json_string)) || nchar(json_string) == 0) {
    return(list(valid = TRUE, data = list()))
  }
  
  tryCatch({
    # Validate JSON structure
    parsed_json <- jsonlite::fromJSON(json_string, simplifyVector = FALSE)
    
    # Check for suspicious content in JSON values
    json_text <- jsonlite::toJSON(parsed_json, auto_unbox = TRUE)
    input_validation <- validate_input_security(json_text)
    
    if (!input_validation$valid) {
      return(list(
        valid = FALSE,
        error = "Suspicious content detected in JSON",
        pattern = input_validation$pattern
      ))
    }
    
    return(list(valid = TRUE, data = parsed_json))
    
  }, error = function(e) {
    return(list(
      valid = FALSE,
      error = paste("Invalid JSON:", e$message)
    ))
  })
}

# Function to get security statistics
get_security_stats <- function() {
  # Count blocked requests by type
  current_minute <- format(Sys.time(), "%Y%m%d%H%M")
  
  ip_blocks <- 0
  for (key in names(IP_RATE_LIMITS)) {
    if (grepl(current_minute, key) && IP_RATE_LIMITS[[key]] >= SECURITY_CONFIG$ip_requests_per_minute) {
      ip_blocks <- ip_blocks + 1
    }
  }
  
  return(list(
    security_headers_enabled = SECURITY_CONFIG$security_headers_enabled,
    cors_enabled = SECURITY_CONFIG$cors_enabled,
    input_validation_enabled = SECURITY_CONFIG$validate_inputs,
    ip_rate_limiting_enabled = SECURITY_CONFIG$ip_rate_limit_enabled,
    ip_blocks_current_minute = ip_blocks,
    lgpd_compliance_enabled = SECURITY_CONFIG$lgpd_headers_enabled,
    suspicious_patterns_count = length(SUSPICIOUS_PATTERNS)
  ))
}

# Function to update security configuration (for admin use)
update_security_config <- function(new_config) {
  # Validate new configuration
  valid_keys <- names(SECURITY_CONFIG)
  
  for (key in names(new_config)) {
    if (key %in% valid_keys) {
      SECURITY_CONFIG[[key]] <<- new_config[[key]]
    }
  }
  
  # Log configuration change
  if (exists("log_security_event")) {
    log_security_event("SECURITY_CONFIG_UPDATED", list(
      updated_keys = names(new_config)
    ))
  }
  
  return(SECURITY_CONFIG)
}

cat("✅ Security Middleware Loaded\n")