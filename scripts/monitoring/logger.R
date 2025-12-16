# STRUCTURED LOGGING SYSTEM FOR R SHINY CLOUD RUN DEPLOYMENT
# ===========================================================
# Production-ready structured logging with JSON format
# LGPD-compliant with data sanitization
# Cloud Run platform optimized

library(jsonlite)
library(digest)

# Logger Configuration
LOGGER_CONFIG <- list(
  enabled = TRUE,
  default_level = Sys.getenv("LOG_LEVEL", "INFO"),
  format = "JSON",
  include_session = TRUE,
  include_user = TRUE,
  include_ip = FALSE,  # LGPD compliance - IP logging disabled by default
  sanitize_sensitive = TRUE,
  max_message_length = 1000,
  cloud_run_compatible = TRUE
)

# Log Levels (numeric for filtering)
LOG_LEVELS <- list(
  DEBUG = list(numeric = 10, name = "DEBUG", emoji = "🔍"),
  INFO = list(numeric = 20, name = "INFO", emoji = "ℹ️"),
  WARN = list(numeric = 30, name = "WARN", emoji = "⚠️"),
  ERROR = list(numeric = 40, name = "ERROR", emoji = "❌"),
  CRITICAL = list(numeric = 50, name = "CRITICAL", emoji = "🚨")
)

# Get current log level threshold
get_log_level_threshold <- function() {
  level_name <- toupper(LOGGER_CONFIG$default_level)
  if (level_name %in% names(LOG_LEVELS)) {
    return(LOG_LEVELS[[level_name]]$numeric)
  }
  return(LOG_LEVELS$INFO$numeric)
}

# Sensitive data patterns for sanitization (LGPD compliance)
SENSITIVE_PATTERNS <- c(
  "password", "senha", "pass", "pwd", "secret", "key", "token",
  "cpf", "cnpj", "rg", "email", "telefone", "phone", "address",
  "endereco", "credit", "card", "cartao", "account", "conta"
)

# Sanitize sensitive data from log messages
sanitize_log_data <- function(data) {
  if (!LOGGER_CONFIG$sanitize_sensitive) {
    return(data)
  }
  
  if (is.character(data)) {
    # Replace sensitive patterns
    for (pattern in SENSITIVE_PATTERNS) {
      data <- gsub(paste0("(?i)", pattern, "\\s*[:=]\\s*[^\\s,}]+"), 
                   paste0(pattern, ": [REDACTED]"), data, perl = TRUE)
    }
  } else if (is.list(data)) {
    # Recursively sanitize list/object
    for (key in names(data)) {
      if (tolower(key) %in% SENSITIVE_PATTERNS) {
        data[[key]] <- "[REDACTED]"
      } else if (is.list(data[[key]])) {
        data[[key]] <- sanitize_log_data(data[[key]])
      }
    }
  }
  
  return(data)
}

# Generate correlation ID for request tracing
generate_correlation_id <- function() {
  paste0("req_", format(Sys.time(), "%Y%m%d_%H%M%S"), "_", 
         substr(digest::digest(runif(1)), 1, 8))
}

# Get session context (LGPD compliant)
get_session_context <- function(session = NULL) {
  context <- list()
  
  if (!isTRUE(is.null(session)) && LOGGER_CONFIG$include_session) {
    context$session_id <- session$token
    context$user_agent <- "session_logged"
    
    # Only include IP if explicitly enabled (LGPD compliance)
    if (LOGGER_CONFIG$include_ip) {
      context$client_ip <- "session_ip_logged"
    }
  }
  
  # Add server context
  context$hostname <- Sys.getenv("HOSTNAME", "unknown")
  context$cloud_run_service <- Sys.getenv("K_SERVICE", "shiny-app")
  context$cloud_run_revision <- Sys.getenv("K_REVISION", "unknown")
  
  return(context)
}

# Core logging function
write_log <- function(level, message, context = list(), session = NULL, 
                      correlation_id = NULL, error_object = NULL) {
  
  if (!LOGGER_CONFIG$enabled) return(invisible(NULL))
  
  # Check log level threshold
  level_info <- LOG_LEVELS[[toupper(level)]]
  if (isTRUE(is.null(level_info)) || level_info$numeric < get_log_level_threshold()) {
    return(invisible(NULL))
  }
  
  # Create log entry
  timestamp <- format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC")
  
  log_entry <- list(
    timestamp = timestamp,
    level = level_info$name,
    level_numeric = level_info$numeric,
    message = substr(as.character(message), 1, LOGGER_CONFIG$max_message_length),
    service = "monitor_legislativo_v4",
    version = Sys.getenv("APP_VERSION", "1.0.0")
  )
  
  # Add correlation ID
  if (is.null(correlation_id)) {
    correlation_id <- generate_correlation_id()
  }
  log_entry$correlation_id <- correlation_id
  
  # Add session context
  if (LOGGER_CONFIG$include_session || LOGGER_CONFIG$include_user) {
    session_context <- get_session_context(session)
    if (length(session_context) > 0) {
      log_entry$session <- session_context
    }
  }
  
  # Add additional context
  if (length(context) > 0) {
    log_entry$context <- sanitize_log_data(context)
  }
  
  # Add error details if present
  if (!is.null(error_object)) {
    log_entry$error <- list(
      message = as.character(error_object),
      call = if(exists("sys.calls")) deparse(sys.calls()[[1]]) else "unknown"
    )
  }
  
  # Format for Cloud Run logs
  if (LOGGER_CONFIG$cloud_run_compatible) {
    # Cloud Run (Cloud Logging) prefers structured JSON on stdout
    json_log <- jsonlite::toJSON(log_entry, auto_unbox = TRUE, pretty = FALSE)
    cat(json_log, "\n", file = stdout())
  } else {
    # Fallback to console output
    cat(sprintf("[%s] %s %s: %s\n", 
                timestamp, level_info$emoji, level_info$name, message))
  }
  
  # Return log entry for testing/debugging
  invisible(log_entry)
}

# Convenience logging functions
log_debug <- function(message, context = list(), session = NULL, correlation_id = NULL) {
  write_log("DEBUG", message, context, session, correlation_id)
}

log_info <- function(message, context = list(), session = NULL, correlation_id = NULL) {
  write_log("INFO", message, context, session, correlation_id)
}

log_warn <- function(message, context = list(), session = NULL, correlation_id = NULL) {
  write_log("WARN", message, context, session, correlation_id)
}

log_error <- function(message, context = list(), session = NULL, correlation_id = NULL, error = NULL) {
  write_log("ERROR", message, context, session, correlation_id, error)
}

log_critical <- function(message, context = list(), session = NULL, correlation_id = NULL, error = NULL) {
  write_log("CRITICAL", message, context, session, correlation_id, error)
}

# Performance logging wrapper
log_performance <- function(operation_name, func, context = list(), session = NULL) {
  correlation_id <- generate_correlation_id()
  start_time <- Sys.time()
  
  log_info(paste("Starting operation:", operation_name), 
           c(context, list(operation = operation_name)), 
           session, correlation_id)
  
  result <- NULL
  error_occurred <- FALSE
  
  tryCatch({
    result <- func()
  }, error = function(e) {
    error_occurred <- TRUE
    log_error(paste("Operation failed:", operation_name),
              c(context, list(operation = operation_name, error = as.character(e))),
              session, correlation_id, e)
    stop(e)
  })
  
  end_time <- Sys.time()
  duration_ms <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
  
  if (!error_occurred) {
    log_info(paste("Operation completed:", operation_name),
             c(context, list(
               operation = operation_name,
               duration_ms = round(duration_ms, 2),
               success = TRUE
             )), session, correlation_id)
  }
  
  return(result)
}

# Database operation logging wrapper
log_db_operation <- function(query_type, table = NULL, session = NULL) {
  context <- list(
    query_type = query_type,
    database = "cloud_sql_postgres"
  )
  
  if (!is.null(table)) {
    context$table <- table
  }
  
  log_info(paste("Database operation:", query_type), context, session)
}

# User action logging (LGPD compliant)
log_user_action <- function(action, details = list(), session = NULL) {
  if (!LOGGER_CONFIG$include_user) return(invisible(NULL))
  
  # Sanitize user details for LGPD compliance
  sanitized_details <- sanitize_log_data(details)
  
  context <- c(list(
    action_type = "user_interaction",
    action = action
  ), sanitized_details)
  
  log_info(paste("User action:", action), context, session)
}

# Security event logging
log_security_event <- function(event_type, details = list(), session = NULL, severity = "WARN") {
  context <- c(list(
    security_event = TRUE,
    event_type = event_type,
    timestamp_utc = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC")
  ), sanitize_log_data(details))
  
  if (severity == "CRITICAL") {
    log_critical(paste("Security event:", event_type), context, session)
  } else if (severity == "ERROR") {
    log_error(paste("Security event:", event_type), context, session)
  } else {
    log_warn(paste("Security event:", event_type), context, session)
  }
}

# Application lifecycle logging
log_app_start <- function() {
  context <- list(
    event = "application_start",
    r_version = R.version.string,
    platform = Sys.info()["sysname"],
    hostname = Sys.getenv("HOSTNAME", "unknown"),
    cloud_run_service = Sys.getenv("K_SERVICE", "unknown"),
    cloud_run_revision = Sys.getenv("K_REVISION", "unknown")
  )
  
  log_info("Application starting", context)
}

log_app_ready <- function() {
  context <- list(
    event = "application_ready",
    startup_time = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC")
  )
  
  log_info("Application ready to serve requests", context)
}

log_app_shutdown <- function() {
  context <- list(
    event = "application_shutdown",
    shutdown_time = format(Sys.time(), "%Y-%m-%dT%H:%M:%S.%OSZ", tz = "UTC")
  )
  
  log_info("Application shutting down", context)
}

# Replace existing cat/print functions
replace_legacy_logging <- function() {
  if (exists("cat", envir = .GlobalEnv)) {
    original_cat <<- get("cat", envir = .GlobalEnv)
  }
  
  # Override cat function to use structured logging
  cat <- function(..., sep = " ", fill = FALSE, labels = NULL, append = FALSE) {
    message <- paste(..., sep = sep, collapse = "")
    
    # Detect log level from message
    if (grepl("ERROR|❌", message, ignore.case = TRUE)) {
      log_error(message)
    } else if (grepl("WARN|WARNING|⚠️", message, ignore.case = TRUE)) {
      log_warn(message)
    } else if (grepl("DEBUG|🔍", message, ignore.case = TRUE)) {
      log_debug(message)
    } else {
      log_info(message)
    }
  }
  
  # Assign to global environment
  assign("cat", cat, envir = .GlobalEnv)
}

# Initialize logger
init_logger <- function(config_overrides = list()) {
  # Apply configuration overrides
  for (key in names(config_overrides)) {
    LOGGER_CONFIG[[key]] <<- config_overrides[[key]]
  }
  
  # Log system initialization
  log_info("Structured logging system initialized", list(
    config = LOGGER_CONFIG,
    log_level_threshold = get_log_level_threshold()
  ))
  
  # Replace legacy logging if requested
  if (Sys.getenv("REPLACE_LEGACY_LOGGING", "false") == "true") {
    replace_legacy_logging()
    log_info("Legacy logging functions replaced with structured logging")
  }
  
  invisible(TRUE)
}

# Export functions for external use
#' @export
list(
  # Core functions
  log_debug = log_debug,
  log_info = log_info,
  log_warn = log_warn,
  log_error = log_error,
  log_critical = log_critical,
  
  # Specialized functions
  log_performance = log_performance,
  log_db_operation = log_db_operation,
  log_user_action = log_user_action,
  log_security_event = log_security_event,
  
  # Application lifecycle
  log_app_start = log_app_start,
  log_app_ready = log_app_ready,
  log_app_shutdown = log_app_shutdown,
  
  # Utilities
  generate_correlation_id = generate_correlation_id,
  init_logger = init_logger,
  sanitize_log_data = sanitize_log_data
)

# Initialize on load
init_logger()