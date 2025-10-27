# Security Hardening Module for Monitor Legislativo v4
# Week 7: Security Hardening - Phase 3 Implementation
# ===================================================
# 
# This module provides comprehensive security hardening including:
# - Input validation and sanitization
# - CSRF protection
# - XSS prevention
# - SQL injection protection
# - Security headers implementation
# - Content Security Policy (CSP)
# - Brazilian compliance standards

library(shiny)
library(digest)
library(jsonlite)
library(stringr)
library(htmltools)
library(DBI)

# Security Configuration
# =====================

.security_config <- list(
  # Input Validation Rules
  input_validation = list(
    max_string_length = 10000,
    max_search_terms = 20,
    allowed_file_types = c("csv", "xlsx", "pdf", "json"),
    max_file_size_mb = 10,
    
    # SQL injection patterns to detect
    sql_injection_patterns = c(
      "\\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\\b",
      "'\\s*(or|and)\\s*'",
      "--",
      "/\\*.*\\*/",
      "\\bxp_cmdshell\\b",
      "\\bsp_executesql\\b"
    ),
    
    # XSS patterns to detect
    xss_patterns = c(
      "<script[^>]*>.*?</script>",
      "javascript:",
      "vbscript:",
      "onload\\s*=",
      "onerror\\s*=",
      "onclick\\s*=",
      "<iframe[^>]*>",
      "<object[^>]*>",
      "<embed[^>]*>"
    ),
    
    # Path traversal patterns
    path_traversal_patterns = c(
      "\\.\\./",
      "\\.\\.\\\\",
      "%2e%2e%2f",
      "%2e%2e%5c"
    )
  ),
  
  # CSRF Protection
  csrf_protection = list(
    enabled = TRUE,
    token_length = 32,
    token_lifetime_minutes = 60,
    require_referrer = TRUE,
    require_origin = TRUE,
    trusted_origins = c(
      "http://localhost:3838",
      "https://monitorlegislativo.railway.app",
      "https://monitor-legislativo.mackenzie.br"
    )
  ),
  
  # Security Headers
  security_headers = list(
    # Strict Transport Security
    strict_transport_security = "max-age=31536000; includeSubDomains; preload",
    
    # Content Security Policy
    content_security_policy = paste(
      "default-src 'self';",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com;",
      "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com;",
      "img-src 'self' data: https:;",
      "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com;",
      "connect-src 'self' https://api.ibge.gov.br https://accounts.google.com https://login.microsoftonline.com;",
      "frame-ancestors 'none';",
      "base-uri 'self';",
      "form-action 'self';"
    ),
    
    # XSS Protection
    x_xss_protection = "1; mode=block",
    
    # Content Type Options
    x_content_type_options = "nosniff",
    
    # Frame Options
    x_frame_options = "DENY",
    
    # Referrer Policy
    referrer_policy = "strict-origin-when-cross-origin",
    
    # Permissions Policy
    permissions_policy = paste(
      "geolocation=(),",
      "microphone=(),",
      "camera=(),",
      "magnetometer=(),",
      "gyroscope=(),",
      "speaker=()",
      sep = " "
    )
  ),
  
  # Rate Limiting
  rate_limiting = list(
    global_requests_per_minute = 100,
    per_ip_requests_per_minute = 30,
    burst_allowance = 10,
    lockout_duration_minutes = 15
  ),
  
  # Audit Logging
  audit_logging = list(
    log_all_requests = TRUE,
    log_failed_validations = TRUE,
    log_security_events = TRUE,
    log_file_path = "logs/security_audit.log",
    max_log_size_mb = 100,
    log_rotation_days = 30
  )
)

# Security Hardening Class
# ========================

SecurityHardening <- R6::R6Class(
  "SecurityHardening",
  
  public = list(
    config = NULL,
    csrf_tokens = NULL,
    rate_limit_store = NULL,
    
    # Initialize security hardening
    initialize = function(config = .security_config) {
      self$config <- config
      self$csrf_tokens <- new.env(hash = TRUE)
      self$rate_limit_store <- new.env(hash = TRUE)
      
      # Initialize security components
      private$init_security_logging()
      
      message("🛡️ Security Hardening initialized successfully")
    },
    
    # Input Validation Methods
    # =======================
    
    # Validate and sanitize text input
    validate_text_input = function(input_text, field_name = "input", max_length = NULL) {
      if (isTRUE(is.null(input_text)) || isTRUE(is.na(input_text))) {
        return(list(valid = TRUE, sanitized = "", warnings = character()))
      }
      
      # Convert to character and trim
      input_text <- as.character(input_text)
      input_text <- str_trim(input_text)
      
      warnings <- character()
      
      # Check length
      max_len <- max_length %||% self$config$input_validation$max_string_length
      if (nchar(input_text) > max_len) {
        input_text <- substr(input_text, 1, max_len)
        warnings <- c(warnings, paste("Input truncated to", max_len, "characters"))
      }
      
      # Check for SQL injection patterns
      sql_violations <- private$check_sql_injection(input_text)
      if (length(sql_violations) > 0) {
        private$log_security_violation("sql_injection_attempt", field_name, input_text, sql_violations)
        return(list(valid = FALSE, error = "Invalid input detected", violations = sql_violations))
      }
      
      # Check for XSS patterns
      xss_violations <- private$check_xss_patterns(input_text)
      if (length(xss_violations) > 0) {
        private$log_security_violation("xss_attempt", field_name, input_text, xss_violations)
        return(list(valid = FALSE, error = "Invalid input detected", violations = xss_violations))
      }
      
      # Check for path traversal
      path_violations <- private$check_path_traversal(input_text)
      if (length(path_violations) > 0) {
        private$log_security_violation("path_traversal_attempt", field_name, input_text, path_violations)
        return(list(valid = FALSE, error = "Invalid input detected", violations = path_violations))
      }
      
      # Sanitize HTML
      sanitized_text <- private$sanitize_html(input_text)
      
      return(list(
        valid = TRUE,
        sanitized = sanitized_text,
        original = input_text,
        warnings = warnings
      ))
    },
    
    # Validate search parameters
    validate_search_params = function(search_params) {
      if (isTRUE(is.null(search_params)) || length(search_params) == 0) {
        return(list(valid = TRUE, sanitized = list()))
      }
      
      sanitized_params <- list()
      warnings <- character()
      
      for (param_name in names(search_params)) {
        param_value <- search_params[[param_name]]
        
        # Validate individual parameter
        validation_result <- self$validate_text_input(param_value, param_name)
        
        if (!validation_result$valid) {
          return(validation_result)
        }
        
        sanitized_params[[param_name]] <- validation_result$sanitized
        warnings <- c(warnings, validation_result$warnings)
      }
      
      # Check total number of search terms
      if (length(sanitized_params) > self$config$input_validation$max_search_terms) {
        private$log_security_violation("excessive_search_terms", "search_params", 
                                     length(sanitized_params), "Too many search terms")
        return(list(valid = FALSE, error = "Too many search parameters"))
      }
      
      return(list(
        valid = TRUE,
        sanitized = sanitized_params,
        warnings = unique(warnings)
      ))
    },
    
    # Validate file upload
    validate_file_upload = function(file_info) {
      if (isTRUE(is.null(file_info)) || !is.list(file_info)) {
        return(list(valid = FALSE, error = "Invalid file information"))
      }
      
      # Check file extension
      if (!is.null(file_info$name)) {
        file_ext <- tolower(tools::file_ext(file_info$name))
        if (!file_ext %in% self$config$input_validation$allowed_file_types) {
          private$log_security_violation("invalid_file_type", "file_upload", file_info$name, file_ext)
          return(list(valid = FALSE, error = "File type not allowed"))
        }
      }
      
      # Check file size
      if (!is.null(file_info$size)) {
        max_size_bytes <- self$config$input_validation$max_file_size_mb * 1024 * 1024
        if (file_info$size > max_size_bytes) {
          private$log_security_violation("file_too_large", "file_upload", file_info$name, file_info$size)
          return(list(valid = FALSE, error = "File too large"))
        }
      }
      
      # Validate filename for path traversal
      if (!is.null(file_info$name)) {
        path_violations <- private$check_path_traversal(file_info$name)
        if (length(path_violations) > 0) {
          private$log_security_violation("path_traversal_filename", "file_upload", file_info$name, path_violations)
          return(list(valid = FALSE, error = "Invalid filename"))
        }
      }
      
      return(list(valid = TRUE, sanitized = file_info))
    },
    
    # CSRF Protection Methods
    # ======================
    
    # Generate CSRF token
    generate_csrf_token = function(session) {
      token_data <- paste(
        session$token,
        Sys.time(),
        runif(1),
        sep = "_"
      )
      
      csrf_token <- digest(token_data, algo = "sha256")
      
      # Store token with expiration
      expiration <- Sys.time() + (self$config$csrf_protection$token_lifetime_minutes * 60)
      self$csrf_tokens[[csrf_token]] <- list(
        created = Sys.time(),
        expires = expiration,
        session_id = session$token
      )
      
      # Clean up expired tokens
      private$cleanup_expired_csrf_tokens()
      
      return(csrf_token)
    },
    
    # Validate CSRF token
    validate_csrf_token = function(token, session) {
      if (!self$config$csrf_protection$enabled) {
        return(TRUE)
      }
      
      if (isTRUE(is.null(token)) || token == "") {
        private$log_security_violation("missing_csrf_token", "csrf_validation", session$token, "No token provided")
        return(FALSE)
      }
      
      token_info <- self$csrf_tokens[[token]]
      if (is.null(token_info)) {
        private$log_security_violation("invalid_csrf_token", "csrf_validation", session$token, token)
        return(FALSE)
      }
      
      # Check expiration
      if (Sys.time() > token_info$expires) {
        rm(list = token, envir = self$csrf_tokens)
        private$log_security_violation("expired_csrf_token", "csrf_validation", session$token, token)
        return(FALSE)
      }
      
      # Check session match
      if (token_info$session_id != session$token) {
        private$log_security_violation("csrf_session_mismatch", "csrf_validation", session$token, token)
        return(FALSE)
      }
      
      # Remove used token (single use)
      rm(list = token, envir = self$csrf_tokens)
      
      return(TRUE)
    },
    
    # Security Headers Methods
    # =======================
    
    # Add security headers to response
    add_security_headers = function(response = NULL) {
      headers <- self$config$security_headers
      
      security_headers_list <- list(
        "Strict-Transport-Security" = headers$strict_transport_security,
        "Content-Security-Policy" = headers$content_security_policy,
        "X-XSS-Protection" = headers$x_xss_protection,
        "X-Content-Type-Options" = headers$x_content_type_options,
        "X-Frame-Options" = headers$x_frame_options,
        "Referrer-Policy" = headers$referrer_policy,
        "Permissions-Policy" = headers$permissions_policy,
        "X-Powered-By" = ""  # Remove server identification
      )
      
      return(security_headers_list)
    },
    
    # Rate Limiting Methods
    # ====================
    
    # Check rate limit for IP address
    check_rate_limit = function(ip_address, endpoint = "general") {
      if (is.null(ip_address)) {
        ip_address <- "unknown"
      }
      
      current_time <- Sys.time()
      rate_key <- paste(ip_address, endpoint, sep = "_")
      
      # Get current rate limit data
      rate_data <- self$rate_limit_store[[rate_key]]
      
      if (is.null(rate_data)) {
        # Initialize rate limit data
        rate_data <- list(
          requests = 0,
          window_start = current_time,
          last_request = current_time,
          lockout_until = NULL
        )
      }
      
      # Check if in lockout period
      if (!isTRUE(is.null(rate_data$lockout_until)) && current_time < rate_data$lockout_until) {
        private$log_security_violation("rate_limit_lockout", "rate_limiting", ip_address, 
                                     paste("Locked until", rate_data$lockout_until))
        return(list(
          allowed = FALSE,
          reason = "Rate limit exceeded - temporary lockout",
          retry_after = as.numeric(rate_data$lockout_until - current_time)
        ))
      }
      
      # Reset window if expired
      window_duration <- 60  # 1 minute window
      if (current_time - rate_data$window_start > window_duration) {
        rate_data$requests <- 0
        rate_data$window_start <- current_time
        rate_data$lockout_until <- NULL
      }
      
      # Check rate limit
      limit <- self$config$rate_limiting$per_ip_requests_per_minute
      if (rate_data$requests >= limit) {
        # Apply lockout
        lockout_duration <- self$config$rate_limiting$lockout_duration_minutes * 60
        rate_data$lockout_until <- current_time + lockout_duration
        
        private$log_security_violation("rate_limit_exceeded", "rate_limiting", ip_address, 
                                     paste("Requests:", rate_data$requests, "Limit:", limit))
        
        self$rate_limit_store[[rate_key]] <- rate_data
        
        return(list(
          allowed = FALSE,
          reason = "Rate limit exceeded",
          retry_after = lockout_duration
        ))
      }
      
      # Allow request and increment counter
      rate_data$requests <- rate_data$requests + 1
      rate_data$last_request <- current_time
      self$rate_limit_store[[rate_key]] <- rate_data
      
      return(list(
        allowed = TRUE,
        remaining = limit - rate_data$requests,
        reset_time = rate_data$window_start + window_duration
      ))
    },
    
    # Database Security Methods
    # ========================
    
    # Create parameterized query wrapper
    safe_db_query = function(connection, query, params = list()) {
      tryCatch({
        # Log database queries for audit
        if (self$config$audit_logging$log_all_requests) {
          private$log_security_event("database_query", list(
            query = query,
            param_count = length(params)
          ))
        }
        
        # Execute parameterized query
        if (length(params) > 0) {
          result <- DBI::dbGetQuery(connection, query, params = params)
        } else {
          result <- DBI::dbGetQuery(connection, query)
        }
        
        return(result)
        
      }, error = function(e) {
        private$log_security_violation("database_query_error", "database", query, e$message)
        stop("Database query failed: ", e$message)
      })
    },
    
    # Validate SQL query for safety
    validate_sql_query = function(query) {
      # Check for dangerous SQL operations
      dangerous_patterns <- c(
        "\\bDROP\\s+TABLE\\b",
        "\\bDELETE\\s+FROM\\b.*WHERE\\s+1\\s*=\\s*1",
        "\\bUPDATE\\s+.*SET\\s+.*WHERE\\s+1\\s*=\\s*1",
        "\\bINSERT\\s+INTO\\s+.*VALUES\\s*\\(.*\\)\\s*;\\s*DROP",
        "\\bEXEC\\s*\\(",
        "\\bEXECUTE\\s*\\(",
        "xp_cmdshell",
        "sp_executesql"
      )
      
      for (pattern in dangerous_patterns) {
        if (grepl(pattern, query, ignore.case = TRUE)) {
          private$log_security_violation("dangerous_sql_pattern", "query_validation", query, pattern)
          return(list(valid = FALSE, error = "Dangerous SQL pattern detected"))
        }
      }
      
      return(list(valid = TRUE))
    }
  ),
  
  # Private Methods
  # ==============
  
  private = list(
    
    # Initialize security logging
    init_security_logging = function() {
      log_dir <- dirname(self$config$audit_logging$log_file_path)
      if (!dir.exists(log_dir)) {
        dir.create(log_dir, recursive = TRUE, mode = "0755")
      }
      
      # Initialize log file with headers
      if (!file.exists(self$config$audit_logging$log_file_path)) {
        log_header <- paste(
          "timestamp",
          "event_type",
          "source",
          "details",
          "ip_address",
          sep = "\t"
        )
        write(log_header, file = self$config$audit_logging$log_file_path)
      }
    },
    
    # Check for SQL injection patterns
    check_sql_injection = function(input_text) {
      violations <- character()
      
      for (pattern in self$config$input_validation$sql_injection_patterns) {
        if (grepl(pattern, input_text, ignore.case = TRUE, perl = TRUE)) {
          violations <- c(violations, pattern)
        }
      }
      
      return(violations)
    },
    
    # Check for XSS patterns
    check_xss_patterns = function(input_text) {
      violations <- character()
      
      for (pattern in self$config$input_validation$xss_patterns) {
        if (grepl(pattern, input_text, ignore.case = TRUE, perl = TRUE)) {
          violations <- c(violations, pattern)
        }
      }
      
      return(violations)
    },
    
    # Check for path traversal patterns
    check_path_traversal = function(input_text) {
      violations <- character()
      
      for (pattern in self$config$input_validation$path_traversal_patterns) {
        if (grepl(pattern, input_text, ignore.case = TRUE, perl = TRUE)) {
          violations <- c(violations, pattern)
        }
      }
      
      return(violations)
    },
    
    # Sanitize HTML content
    sanitize_html = function(input_text) {
      # Remove dangerous HTML tags and attributes
      sanitized <- input_text
      
      # Remove script tags
      sanitized <- gsub("<script[^>]*>.*?</script>", "", sanitized, ignore.case = TRUE)
      
      # Remove dangerous attributes
      dangerous_attrs <- c("onload", "onerror", "onclick", "onmouseover", "onmouseout", 
                          "onfocus", "onblur", "onchange", "onsubmit")
      
      for (attr in dangerous_attrs) {
        pattern <- paste0("\\s+", attr, "\\s*=\\s*[\"'][^\"']*[\"']")
        sanitized <- gsub(pattern, "", sanitized, ignore.case = TRUE)
      }
      
      # Remove javascript: and vbscript: URLs
      sanitized <- gsub("javascript:", "", sanitized, ignore.case = TRUE)
      sanitized <- gsub("vbscript:", "", sanitized, ignore.case = TRUE)
      
      return(sanitized)
    },
    
    # Clean up expired CSRF tokens
    cleanup_expired_csrf_tokens = function() {
      current_time <- Sys.time()
      expired_tokens <- character()
      
      for (token in ls(self$csrf_tokens)) {
        token_info <- self$csrf_tokens[[token]]
        if (!isTRUE(is.null(token_info)) && current_time > token_info$expires) {
          expired_tokens <- c(expired_tokens, token)
        }
      }
      
      if (length(expired_tokens) > 0) {
        rm(list = expired_tokens, envir = self$csrf_tokens)
      }
    },
    
    # Log security violations
    log_security_violation = function(violation_type, source, input_data, details) {
      log_entry <- list(
        timestamp = format(Sys.time(), "%Y-%m-%d %H:%M:%S"),
        event_type = paste("VIOLATION", violation_type, sep = "_"),
        source = source,
        details = paste(details, collapse = "; "),
        input_data = substr(as.character(input_data), 1, 500),  # Limit log size
        ip_address = "unknown"  # Will be filled by caller if available
      )
      
      # Write to security log
      private$write_security_log(log_entry)
      
      # Also log to console in development
      message(sprintf("[SECURITY VIOLATION] %s: %s", violation_type, log_entry$details))
    },
    
    # Log general security events
    log_security_event = function(event_type, details) {
      log_entry <- list(
        timestamp = format(Sys.time(), "%Y-%m-%d %H:%M:%S"),
        event_type = event_type,
        source = "security_system",
        details = if (is.list(details)) jsonlite::toJSON(details, auto_unbox = TRUE) else details,
        input_data = "",
        ip_address = "system"
      )
      
      private$write_security_log(log_entry)
    },
    
    # Write to security log file
    write_security_log = function(log_entry) {
      tryCatch({
        log_line <- paste(
          log_entry$timestamp,
          log_entry$event_type,
          log_entry$source,
          log_entry$details,
          log_entry$ip_address,
          sep = "\t"
        )
        
        write(log_line, file = self$config$audit_logging$log_file_path, append = TRUE)
        
        # Rotate log if too large
        private$rotate_log_if_needed()
        
      }, error = function(e) {
        warning("Failed to write security log: ", e$message)
      })
    },
    
    # Rotate log file if it gets too large
    rotate_log_if_needed = function() {
      log_file <- self$config$audit_logging$log_file_path
      max_size_bytes <- self$config$audit_logging$max_log_size_mb * 1024 * 1024
      
      if (file.exists(log_file) && file.size(log_file) > max_size_bytes) {
        backup_file <- paste0(log_file, ".", format(Sys.time(), "%Y%m%d_%H%M%S"))
        file.rename(log_file, backup_file)
        
        # Initialize new log file
        log_header <- paste(
          "timestamp",
          "event_type", 
          "source",
          "details",
          "ip_address",
          sep = "\t"
        )
        write(log_header, file = log_file)
      }
    }
  )
)

# Utility Functions
# ================

#' Initialize Security Hardening
#' @return SecurityHardening instance
init_security_hardening <- function() {
  security_hardening <- SecurityHardening$new(config = .security_config)
  return(security_hardening)
}

#' Secure Shiny Input Wrapper
#' @param input_id Input ID
#' @param input_value Input value
#' @param security_hardening SecurityHardening instance
#' @return Validated and sanitized input
secure_input <- function(input_id, input_value, security_hardening) {
  validation_result <- security_hardening$validate_text_input(input_value, input_id)
  
  if (!validation_result$valid) {
    stop("Invalid input: ", validation_result$error)
  }
  
  return(validation_result$sanitized)
}

# Export security hardening for global use
.GlobalEnv$security_hardening <- NULL

# Initialize on module load
.onLoad <- function(libname, pkgname) {
  message("🛡️ Security Hardening module loaded")
}