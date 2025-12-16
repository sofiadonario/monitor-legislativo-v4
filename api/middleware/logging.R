# ============================================================================
# LOGGING MIDDLEWARE - SPRINT 6B (API-001)
# ============================================================================
# 
# Comprehensive logging middleware for Brazilian Legislative API
# Provides structured logging for requests, responses, errors, and performance
# LGPD compliant logging with data anonymization
# 
# Features:
# - Structured JSON logging for Cloud Run log aggregation
# - Request/response logging with performance metrics
# - Error logging with stack traces
# - Security event logging
# - LGPD compliant data anonymization
# - Log rotation and retention policies
# ============================================================================

cat("📝 Loading Logging Middleware\n")

# Logging configuration
LOG_CONFIG <- list(
  enabled = TRUE,
  log_level = "INFO", # DEBUG, INFO, WARN, ERROR
  log_requests = TRUE,
  log_responses = TRUE,
  log_performance = TRUE,
  anonymize_ip = TRUE, # LGPD compliance
  max_body_size = 1000, # Maximum request/response body size to log
  sensitive_headers = c("authorization", "x-api-key", "cookie"),
  log_file_path = "logs/api.log",
  max_log_size_mb = 100,
  retention_days = 30
)

# Global logging state
LOG_STATE <- list(
  requests_logged = 0,
  errors_logged = 0,
  last_rotation = Sys.time(),
  log_file_handle = NULL
)

# Helper function to anonymize IP address (LGPD compliance)
anonymize_ip <- function(ip_address) {
  if (isTRUE(is.null(ip_address)) || ip_address == "unknown") {
    return("unknown")
  }
  
  # IPv4 anonymization: mask last octet
  if (grepl("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$", ip_address)) {
    parts <- strsplit(ip_address, "\\.")[[1]]
    return(paste0(paste(parts[1:3], collapse = "."), ".xxx"))
  }
  
  # IPv6 anonymization: mask last 64 bits
  if (grepl(":", ip_address)) {
    parts <- strsplit(ip_address, ":")[[1]]
    if (length(parts) > 4) {
      return(paste0(paste(parts[1:4], collapse = ":"), "::xxxx"))
    }
  }
  
  return("anonymized")
}

# Helper function to sanitize headers (remove sensitive information)
sanitize_headers <- function(headers) {
  if (isTRUE(is.null(headers)) || length(headers) == 0) {
    return(list())
  }
  
  sanitized <- headers
  
  for (sensitive_header in LOG_CONFIG$sensitive_headers) {
    header_names <- names(sanitized)
    if (!is.null(header_names)) {
      # Case-insensitive matching
      matches <- grepl(paste0("^", sensitive_header, "$"), header_names, ignore.case = TRUE)
      if (any(matches)) {
        sanitized[header_names[matches]] <- "***REDACTED***"
      }
    }
  }
  
  return(sanitized)
}

# Helper function to truncate large bodies
truncate_body <- function(body, max_size = LOG_CONFIG$max_body_size) {
  if (is.null(body)) {
    return(NULL)
  }
  
  body_str <- if (is.character(body)) body else as.character(body)
  
  if (nchar(body_str) > max_size) {
    return(paste0(substr(body_str, 1, max_size), "... [TRUNCATED]"))
  }
  
  return(body_str)
}

# Helper function to create structured log entry
create_log_entry <- function(level, message, context = list()) {
  log_entry <- list(
    timestamp = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC"),
    level = level,
    message = message,
    service = "monitor-legislativo-api",
    version = API_CONFIG$version,
    environment = Sys.getenv("K_SERVICE", Sys.getenv("GOOGLE_CLOUD_PROJECT", "development"))
  )
  
  # Add context information
  if (length(context) > 0) {
    log_entry <- c(log_entry, context)
  }
  
  return(log_entry)
}

# Helper function to write log entry
write_log_entry <- function(log_entry) {
  if (!LOG_CONFIG$enabled) {
    return()
  }
  
  # Convert to JSON
  json_log <- jsonlite::toJSON(log_entry, auto_unbox = TRUE, pretty = FALSE)
  
  # Write to console (Cloud Run will capture this)
  cat(json_log, "\n")
  
  # Also write to file if configured
  if (!is.null(LOG_CONFIG$log_file_path)) {
    tryCatch({
      # Ensure log directory exists
      log_dir <- dirname(LOG_CONFIG$log_file_path)
      if (!dir.exists(log_dir)) {
        dir.create(log_dir, recursive = TRUE)
      }
      
      # Append to log file
      write(json_log, file = LOG_CONFIG$log_file_path, append = TRUE)
      
    }, error = function(e) {
      cat("Error writing to log file:", e$message, "\n")
    })
  }
}

# Main request logging filter
#* @filter logger
function(req, res) {
  start_time <- Sys.time()
  request_id <- digest::digest(paste(Sys.time(), req$PATH_INFO, runif(1)), algo = "md5", serialize = FALSE)
  
  # Extract request information
  client_ip <- req$HTTP_X_FORWARDED_FOR %||% req$HTTP_X_REAL_IP %||% req$REMOTE_ADDR %||% "unknown"
  user_agent <- req$HTTP_USER_AGENT %||% "unknown"
  referer <- req$HTTP_REFERER %||% ""
  
  # Anonymize IP for LGPD compliance
  anonymized_ip <- if (LOG_CONFIG$anonymize_ip) anonymize_ip(client_ip) else client_ip
  
  # Log request start
  if (LOG_CONFIG$log_requests) {
    request_context <- list(
      request_id = request_id,
      method = req$REQUEST_METHOD,
      path = req$PATH_INFO,
      query_string = req$QUERY_STRING %||% "",
      client_ip = anonymized_ip,
      user_agent = user_agent,
      referer = referer,
      content_type = req$HTTP_CONTENT_TYPE %||% "",
      content_length = req$HTTP_CONTENT_LENGTH %||% 0,
      api_key_tier = if (!is.null(req$auth)) req$auth$key_info$tier else "unauthenticated",
      headers = sanitize_headers(req$headers)
    )
    
    # Add request body if available and not too large
    if (!isTRUE(is.null(req$postBody)) && LOG_CONFIG$log_level == "DEBUG") {
      request_context$body = truncate_body(req$postBody)
    }
    
    log_entry <- create_log_entry("INFO", "API request started", request_context)
    write_log_entry(log_entry)
    
    LOG_STATE$requests_logged <<- LOG_STATE$requests_logged + 1
  }
  
  # Store request metadata for response logging
  req$log_metadata <- list(
    request_id = request_id,
    start_time = start_time,
    client_ip = anonymized_ip,
    user_agent = user_agent
  )
  
  # Continue with request processing
  plumber::forward()
}

# Response logging hook (called after request processing)
log_response <- function(req, res, value) {
  if (!LOG_CONFIG$log_responses || isTRUE(is.null(req$log_metadata))) {
    return(value)
  }
  
  end_time <- Sys.time()
  duration_ms <- round(as.numeric(difftime(end_time, req$log_metadata$start_time, units = "secs")) * 1000, 2)
  
  # Extract response information
  response_context <- list(
    request_id = req$log_metadata$request_id,
    method = req$REQUEST_METHOD,
    path = req$PATH_INFO,
    status_code = res$status %||% 200,
    duration_ms = duration_ms,
    client_ip = req$log_metadata$client_ip,
    user_agent = req$log_metadata$user_agent,
    response_size_bytes = if (is.character(value)) nchar(value) else 0,
    api_key_tier = if (!is.null(req$auth)) req$auth$key_info$tier else "unauthenticated"
  )
  
  # Add response body if debug level and not too large
  if (LOG_CONFIG$log_level == "DEBUG" && is.character(value)) {
    response_context$response_body <- truncate_body(value)
  }
  
  # Determine log level based on status code
  log_level <- if (res$status >= 500) "ERROR" else
              if (res$status >= 400) "WARN" else "INFO"
  
  log_entry <- create_log_entry(log_level, "API request completed", response_context)
  write_log_entry(log_entry)
  
  # Log performance metrics if enabled
  if (LOG_CONFIG$log_performance && duration_ms > 1000) {
    perf_context <- list(
      request_id = req$log_metadata$request_id,
      path = req$PATH_INFO,
      duration_ms = duration_ms,
      performance_category = if (duration_ms > 5000) "slow" else "warning"
    )
    
    perf_entry <- create_log_entry("WARN", "Slow API request detected", perf_context)
    write_log_entry(perf_entry)
  }
  
  return(value)
}

# Error logging function
log_error <- function(error, req = NULL, additional_context = list()) {
  error_context <- list(
    error_message = as.character(error$message),
    error_class = class(error)[1]
  )
  
  # Add request context if available
  if (!is.null(req)) {
    error_context$request_id <- req$log_metadata$request_id %||% "unknown"
    error_context$method <- req$REQUEST_METHOD
    error_context$path <- req$PATH_INFO
    error_context$client_ip <- req$log_metadata$client_ip %||% "unknown"
  }
  
  # Add stack trace if available
  if (!is.null(error$call)) {
    error_context$call <- as.character(error$call)
  }
  
  # Add additional context
  if (length(additional_context) > 0) {
    error_context <- c(error_context, additional_context)
  }
  
  log_entry <- create_log_entry("ERROR", "API error occurred", error_context)
  write_log_entry(log_entry)
  
  LOG_STATE$errors_logged <<- LOG_STATE$errors_logged + 1
}

# Security event logging function
log_security_event <- function(event_type, details, req = NULL) {
  security_context <- list(
    event_type = event_type,
    details = details,
    severity = "HIGH"
  )
  
  # Add request context if available
  if (!is.null(req)) {
    security_context$client_ip <- req$log_metadata$client_ip %||% "unknown"
    security_context$user_agent <- req$log_metadata$user_agent %||% "unknown"
    security_context$path <- req$PATH_INFO
    security_context$method <- req$REQUEST_METHOD
  }
  
  log_entry <- create_log_entry("WARN", paste("Security event:", event_type), security_context)
  write_log_entry(log_entry)
}

# API usage logging function
log_api_usage <- function(api_key, endpoint, success = TRUE, response_time_ms = 0) {
  usage_context <- list(
    api_key_hash = digest::digest(api_key, algo = "sha256", serialize = FALSE),
    endpoint = endpoint,
    success = success,
    response_time_ms = response_time_ms,
    timestamp = Sys.time()
  )
  
  log_entry <- create_log_entry("INFO", "API usage recorded", usage_context)
  write_log_entry(log_entry)
}

# Function to get logging statistics
get_logging_stats <- function() {
  return(list(
    requests_logged = LOG_STATE$requests_logged,
    errors_logged = LOG_STATE$errors_logged,
    log_level = LOG_CONFIG$log_level,
    anonymization_enabled = LOG_CONFIG$anonymize_ip,
    last_rotation = LOG_STATE$last_rotation,
    uptime_hours = round(as.numeric(difftime(Sys.time(), API_STATE$start_time, units = "hours")), 2)
  ))
}

# Function to rotate logs (called periodically)
rotate_logs <- function() {
  if (is.null(LOG_CONFIG$log_file_path)) {
    return()
  }
  
  tryCatch({
    # Check if log file exists and is large enough to rotate
    if (file.exists(LOG_CONFIG$log_file_path)) {
      file_size_mb <- file.info(LOG_CONFIG$log_file_path)$size / 1024 / 1024
      
      if (file_size_mb > LOG_CONFIG$max_log_size_mb) {
        # Create rotated filename with timestamp
        timestamp <- format(Sys.time(), "%Y%m%d_%H%M%S")
        rotated_name <- paste0(LOG_CONFIG$log_file_path, ".", timestamp)
        
        # Move current log to rotated name
        file.rename(LOG_CONFIG$log_file_path, rotated_name)
        
        # Log rotation event
        rotation_context <- list(
          old_file = LOG_CONFIG$log_file_path,
          new_file = rotated_name,
          file_size_mb = round(file_size_mb, 2)
        )
        
        log_entry <- create_log_entry("INFO", "Log file rotated", rotation_context)
        write_log_entry(log_entry)
        
        LOG_STATE$last_rotation <<- Sys.time()
        
        # Clean up old log files beyond retention period
        cleanup_old_logs()
      }
    }
    
  }, error = function(e) {
    cat("Error rotating logs:", e$message, "\n")
  })
}

# Function to clean up old log files
cleanup_old_logs <- function() {
  if (isTRUE(is.null(LOG_CONFIG$log_file_path)) || LOG_CONFIG$retention_days <= 0) {
    return()
  }
  
  tryCatch({
    log_dir <- dirname(LOG_CONFIG$log_file_path)
    log_base_name <- basename(LOG_CONFIG$log_file_path)
    
    # Find rotated log files
    log_files <- list.files(log_dir, pattern = paste0("^", log_base_name, "\\.\\d{8}_\\d{6}$"), full.names = TRUE)
    
    # Check age of each file
    cutoff_date <- Sys.time() - (LOG_CONFIG$retention_days * 24 * 3600)
    
    for (log_file in log_files) {
      file_info <- file.info(log_file)
      if (file_info$mtime < cutoff_date) {
        file.remove(log_file)
        cat("Cleaned up old log file:", log_file, "\n")
      }
    }
    
  }, error = function(e) {
    cat("Error cleaning up old logs:", e$message, "\n")
  })
}

# Initialize logging
tryCatch({
  # Log startup event
  startup_context <- list(
    version = API_CONFIG$version,
    environment = Sys.getenv("K_SERVICE", Sys.getenv("GOOGLE_CLOUD_PROJECT", "development")),
    log_level = LOG_CONFIG$log_level,
    anonymization_enabled = LOG_CONFIG$anonymize_ip
  )
  
  startup_entry <- create_log_entry("INFO", "API logging system initialized", startup_context)
  write_log_entry(startup_entry)
  
}, error = function(e) {
  cat("Error initializing logging:", e$message, "\n")
})

cat("✅ Logging Middleware Loaded\n")