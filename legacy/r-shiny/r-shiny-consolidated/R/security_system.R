# Security System for Monitor Legislativo v4
# Input validation, CSRF protection, audit logging, and security hardening

library(shiny)
library(digest)
library(jose)
library(stringr)
library(DBI)
library(htmltools)
library(jsonlite)
library(lubridate)

# Security configuration
SECURITY_CONFIG <- list(
  input_validation = list(
    max_text_length = 10000,
    max_email_length = 254,
    max_name_length = 100,
    allowed_file_types = c(".jpg", ".jpeg", ".png", ".pdf", ".doc", ".docx", ".csv", ".xlsx"),
    max_file_size_mb = 10,
    sql_injection_patterns = c(
      "('|(\\-\\-)|;|\\||\\*|\\%|=|'|\"",
      "union.*select", "insert.*into", "delete.*from", "update.*set",
      "drop.*table", "create.*table", "alter.*table", "exec(ute)?",
      "sp_.*", "xp_.*", "script", "javascript", "vbscript"
    ),
    xss_patterns = c(
      "<script", "</script>", "javascript:", "onload=", "onerror=",
      "onclick=", "onmouseover=", "eval\\(", "expression\\(",
      "vbscript:", "livescript:", "mocha:", "charset=", "meta.*refresh"
    )
  ),
  
  csrf_protection = list(
    token_length = 32,
    token_expiry_minutes = 60,
    require_token = TRUE,
    header_name = "X-CSRF-Token"
  ),
  
  rate_limiting = list(
    max_requests_per_minute = 60,
    max_login_attempts_per_hour = 5,
    max_export_requests_per_hour = 10,
    ban_duration_minutes = 15
  ),
  
  session_security = list(
    require_https = TRUE,
    secure_cookies = TRUE,
    http_only_cookies = TRUE,
    same_site = "Strict",
    session_regeneration_interval = 30  # minutes
  ),
  
  audit_config = list(
    log_all_actions = TRUE,
    sensitive_actions = c(
      "login_attempt", "login_success", "login_failure", "logout",
      "profile_update", "role_change", "user_create", "user_delete",
      "export_data", "admin_access", "system_config_change"
    ),
    retention_days = 365,
    log_ip_addresses = TRUE,
    log_user_agents = TRUE
  ),
  
  content_security = list(
    allowed_domains = c(
      "self", "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
      "fonts.googleapis.com", "fonts.gstatic.com",
      "api.github.com", "accounts.google.com", "login.microsoftonline.com"
    ),
    disable_inline_scripts = TRUE,
    enable_xframe_protection = TRUE,
    enable_content_type_sniffing_protection = TRUE
  )
)

#' Validate input against common security threats
#' @param input_value Input value to validate
#' @param input_type Type of input (text, email, number, etc.)
#' @param max_length Maximum allowed length
#' @return List with valid (boolean) and message
validate_input <- function(input_value, input_type = "text", max_length = NULL) {
  if (is.null(input_value) || is.na(input_value)) {
    return(list(valid = TRUE, message = NULL))
  }
  
  # Convert to character for validation
  input_str <- as.character(input_value)
  
  # Check length
  if (is.null(max_length)) {
    max_length <- switch(input_type,
      "email" = SECURITY_CONFIG$input_validation$max_email_length,
      "name" = SECURITY_CONFIG$input_validation$max_name_length,
      SECURITY_CONFIG$input_validation$max_text_length
    )
  }
  
  if (nchar(input_str) > max_length) {
    return(list(
      valid = FALSE, 
      message = paste("Input too long. Maximum", max_length, "characters allowed.")
    ))
  }
  
  # SQL injection detection
  for (pattern in SECURITY_CONFIG$input_validation$sql_injection_patterns) {
    if (grepl(pattern, input_str, ignore.case = TRUE)) {
      log_security_event("sql_injection_attempt", input_value = substr(input_str, 1, 100))
      return(list(
        valid = FALSE,
        message = "Invalid characters detected in input."
      ))
    }
  }
  
  # XSS detection
  for (pattern in SECURITY_CONFIG$input_validation$xss_patterns) {
    if (grepl(pattern, input_str, ignore.case = TRUE)) {
      log_security_event("xss_attempt", input_value = substr(input_str, 1, 100))
      return(list(
        valid = FALSE,
        message = "Invalid content detected in input."
      ))
    }
  }
  
  # Type-specific validation
  if (input_type == "email") {
    email_pattern <- "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    if (!grepl(email_pattern, input_str)) {
      return(list(
        valid = FALSE,
        message = "Invalid email format."
      ))
    }
  }
  
  if (input_type == "url") {
    url_pattern <- "^https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}(/.*)?$"
    if (!grepl(url_pattern, input_str)) {
      return(list(
        valid = FALSE,
        message = "Invalid URL format."
      ))
    }
  }
  
  if (input_type == "phone") {
    # Brazilian phone pattern
    phone_pattern <- "^\\+?55\\s?\\(?[1-9]{2}\\)?\\s?[0-9]{4,5}-?[0-9]{4}$"
    if (!grepl(phone_pattern, gsub("[^0-9+()]", "", input_str))) {
      return(list(
        valid = FALSE,
        message = "Invalid phone number format. Use Brazilian format."
      ))
    }
  }
  
  return(list(valid = TRUE, message = NULL))
}

#' Sanitize input to remove potentially harmful content
#' @param input_value Input value to sanitize
#' @param input_type Type of input
#' @return Sanitized input
sanitize_input <- function(input_value, input_type = "text") {
  if (is.null(input_value) || is.na(input_value)) return(input_value)
  
  input_str <- as.character(input_value)
  
  # Remove null bytes
  input_str <- gsub("\\0", "", input_str)
  
  # Remove/escape HTML tags for text inputs
  if (input_type %in% c("text", "textarea")) {
    input_str <- gsub("<", "&lt;", input_str)
    input_str <- gsub(">", "&gt;", input_str)
    input_str <- gsub("\"", "&quot;", input_str)
    input_str <- gsub("'", "&#x27;", input_str)
  }
  
  # Trim whitespace
  input_str <- trimws(input_str)
  
  return(input_str)
}

#' Generate CSRF token
#' @param session Shiny session object
#' @return CSRF token
generate_csrf_token <- function(session) {
  if (!SECURITY_CONFIG$csrf_protection$require_token) return(NULL)
  
  # Generate random token
  token <- paste0(
    sample(c(letters, LETTERS, 0:9), SECURITY_CONFIG$csrf_protection$token_length, replace = TRUE),
    collapse = ""
  )
  
  # Store token in session with timestamp
  session$userData$csrf_token <- token
  session$userData$csrf_token_created <- Sys.time()
  
  log_security_event("csrf_token_generated", session_id = session$token)
  
  return(token)
}

#' Validate CSRF token
#' @param session Shiny session object
#' @param provided_token Token provided by client
#' @return Boolean indicating if token is valid
validate_csrf_token <- function(session, provided_token) {
  if (!SECURITY_CONFIG$csrf_protection$require_token) return(TRUE)
  
  stored_token <- session$userData$csrf_token
  token_created <- session$userData$csrf_token_created
  
  # Check if token exists
  if (is.null(stored_token) || is.null(token_created)) {
    log_security_event("csrf_token_missing", session_id = session$token)
    return(FALSE)
  }
  
  # Check if token has expired
  if (Sys.time() - token_created > minutes(SECURITY_CONFIG$csrf_protection$token_expiry_minutes)) {
    log_security_event("csrf_token_expired", session_id = session$token)
    return(FALSE)
  }
  
  # Check if tokens match
  if (stored_token != provided_token) {
    log_security_event("csrf_token_mismatch", session_id = session$token)
    return(FALSE)
  }
  
  return(TRUE)
}

#' Check rate limiting for specific action
#' @param con Database connection
#' @param ip_address Client IP address
#' @param action Action being performed
#' @return List with allowed (boolean) and message
check_rate_limit <- function(con, ip_address, action) {
  if (is.null(con) || is.null(ip_address)) return(list(allowed = TRUE, message = NULL))
  
  current_time <- Sys.time()
  
  # Define rate limits based on action
  rate_limit <- switch(action,
    "login" = list(max_attempts = SECURITY_CONFIG$rate_limiting$max_login_attempts_per_hour, window_minutes = 60),
    "export" = list(max_attempts = SECURITY_CONFIG$rate_limiting$max_export_requests_per_hour, window_minutes = 60),
    list(max_attempts = SECURITY_CONFIG$rate_limiting$max_requests_per_minute, window_minutes = 1)
  )
  
  tryCatch({
    # Check rate limit table (create if not exists)
    dbExecute(con, "
      CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT NOT NULL,
        action TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        INDEX(ip_address, action, timestamp)
      )
    ")
    
    # Count recent attempts
    window_start <- current_time - minutes(rate_limit$window_minutes)
    
    recent_attempts <- dbGetQuery(con, "
      SELECT COUNT(*) as count 
      FROM rate_limits 
      WHERE ip_address = ? AND action = ? AND timestamp > ?
    ", params = list(ip_address, action, format(window_start, "%Y-%m-%d %H:%M:%S")))
    
    if (recent_attempts$count[1] >= rate_limit$max_attempts) {
      log_security_event("rate_limit_exceeded", ip_address = ip_address, action = action)
      return(list(
        allowed = FALSE,
        message = paste("Rate limit exceeded. Try again in", rate_limit$window_minutes, "minutes.")
      ))
    }
    
    # Record this attempt
    dbExecute(con, "
      INSERT INTO rate_limits (ip_address, action) VALUES (?, ?)
    ", params = list(ip_address, action))
    
    # Clean old records (keep only last 24 hours)
    cleanup_time <- current_time - hours(24)
    dbExecute(con, "DELETE FROM rate_limits WHERE timestamp < ?", 
              params = list(format(cleanup_time, "%Y-%m-%d %H:%M:%S")))
    
    return(list(allowed = TRUE, message = NULL))
    
  }, error = function(e) {
    log_event(paste("Error checking rate limit:", e$message), "ERROR")
    return(list(allowed = TRUE, message = NULL))  # Allow on error to prevent lockout
  })
}

#' Log security event
#' @param event_type Type of security event
#' @param ... Additional parameters to log
log_security_event <- function(event_type, ...) {
  additional_info <- list(...)
  
  security_log <- list(
    timestamp = format(Sys.time(), "%Y-%m-%d %H:%M:%S"),
    event_type = event_type,
    additional_info = additional_info
  )
  
  # Log to file (in production, this might go to a SIEM system)
  tryCatch({
    # Create logs directory if it doesn't exist
    logs_dir <- "logs"
    if (!dir.exists(logs_dir)) {
      dir.create(logs_dir, recursive = TRUE)
    }
    
    log_file <- file.path(logs_dir, paste0("security_", Sys.Date(), ".log"))
    log_entry <- paste(toJSON(security_log), "\n")
    
    # Append to log file
    cat(log_entry, file = log_file, append = TRUE)
    
  }, error = function(e) {
    # If file logging fails, at least log to console
    cat("SECURITY EVENT:", toJSON(security_log), "\n")
  })
}

#' Validate file upload security
#' @param file_info File information from fileInput
#' @return List with valid (boolean) and message
validate_file_upload <- function(file_info) {
  if (is.null(file_info) || nrow(file_info) == 0) {
    return(list(valid = TRUE, message = NULL))
  }
  
  for (i in 1:nrow(file_info)) {
    file_path <- file_info$datapath[i]
    file_name <- file_info$name[i]
    file_size <- file_info$size[i]
    
    # Check file extension
    file_ext <- tolower(tools::file_ext(file_name))
    if (!paste0(".", file_ext) %in% SECURITY_CONFIG$input_validation$allowed_file_types) {
      log_security_event("invalid_file_type", filename = file_name, extension = file_ext)
      return(list(
        valid = FALSE,
        message = paste("File type not allowed:", file_ext)
      ))
    }
    
    # Check file size
    max_size_bytes <- SECURITY_CONFIG$input_validation$max_file_size_mb * 1024 * 1024
    if (file_size > max_size_bytes) {
      log_security_event("file_too_large", filename = file_name, size = file_size)
      return(list(
        valid = FALSE,
        message = paste("File too large. Maximum size:", SECURITY_CONFIG$input_validation$max_file_size_mb, "MB")
      ))
    }
    
    # Check file content (basic magic number validation)
    if (!validate_file_content(file_path, file_ext)) {
      log_security_event("file_content_mismatch", filename = file_name)
      return(list(
        valid = FALSE,
        message = "File content does not match extension."
      ))
    }
  }
  
  return(list(valid = TRUE, message = NULL))
}

#' Validate file content matches extension
#' @param file_path Path to uploaded file
#' @param expected_ext Expected file extension
#' @return Boolean indicating if content matches
validate_file_content <- function(file_path, expected_ext) {
  if (!file.exists(file_path)) return(FALSE)
  
  tryCatch({
    # Read first few bytes to check magic numbers
    con <- file(file_path, "rb")
    magic_bytes <- readBin(con, "raw", n = 16)
    close(con)
    
    # Convert to hex string
    magic_hex <- paste(sprintf("%02x", as.integer(magic_bytes)), collapse = "")
    
    # Check common file signatures
    valid_signatures <- switch(expected_ext,
      "jpg" = c("ffd8ff"),
      "jpeg" = c("ffd8ff"),
      "png" = c("89504e47"),
      "pdf" = c("25504446"),
      "xlsx" = c("504b0304"),
      "docx" = c("504b0304"),
      "csv" = TRUE,  # CSV files don't have a specific magic number
      TRUE  # Allow other types for now
    )
    
    if (is.logical(valid_signatures)) return(valid_signatures)
    
    # Check if any valid signature matches
    for (signature in valid_signatures) {
      if (startsWith(magic_hex, signature)) return(TRUE)
    }
    
    return(FALSE)
    
  }, error = function(e) {
    log_event(paste("Error validating file content:", e$message), "ERROR")
    return(TRUE)  # Allow on error to prevent false positives
  })
}

#' Create security headers for HTTP responses
#' @return List of security headers
get_security_headers <- function() {
  headers <- list(
    "X-Frame-Options" = "DENY",
    "X-Content-Type-Options" = "nosniff",
    "X-XSS-Protection" = "1; mode=block",
    "Referrer-Policy" = "strict-origin-when-cross-origin",
    "Permissions-Policy" = "camera=(), microphone=(), geolocation=()"
  )
  
  # Content Security Policy
  if (SECURITY_CONFIG$content_security$disable_inline_scripts) {
    csp_directives <- c(
      "default-src 'self'",
      paste("script-src", paste(SECURITY_CONFIG$content_security$allowed_domains, collapse = " ")),
      paste("style-src 'self' 'unsafe-inline'", paste(SECURITY_CONFIG$content_security$allowed_domains, collapse = " ")),
      paste("img-src 'self' data:", paste(SECURITY_CONFIG$content_security$allowed_domains, collapse = " ")),
      "object-src 'none'",
      "base-uri 'self'"
    )
    
    headers[["Content-Security-Policy"]] <- paste(csp_directives, collapse = "; ")
  }
  
  return(headers)
}

#' Security middleware wrapper for protecting content
#' @param content UI content to protect
#' @param required_permission Required permission (optional)
#' @param validate_csrf Whether to validate CSRF token
#' @return Protected content with security checks
security_wrapper <- function(content, required_permission = NULL, validate_csrf = TRUE) {
  function(input, output, session) {
    # Apply security headers
    security_headers <- get_security_headers()
    for (header_name in names(security_headers)) {
      session$sendCustomMessage(
        type = "setHeader",
        message = list(name = header_name, value = security_headers[[header_name]])
      )
    }
    
    # Generate CSRF token
    if (validate_csrf) {
      csrf_token <- generate_csrf_token(session)
      session$sendCustomMessage(
        type = "setCsrfToken",
        message = list(token = csrf_token)
      )
    }
    
    # Log access attempt
    log_security_event(
      "content_access",
      url = session$clientData$url_pathname,
      user_agent = session$clientData$user_agent %||% "unknown",
      ip_address = session$clientData$url_hostname
    )
    
    # Return protected content
    return(content)
  }
}

#' Create secure input with validation
#' @param inputId Input ID
#' @param label Input label
#' @param value Default value
#' @param input_type Input type for validation
#' @param max_length Maximum length
#' @param required Whether input is required
#' @return Secure input element
secure_text_input <- function(inputId, label, value = "", input_type = "text", max_length = NULL, required = FALSE) {
  # Set default max length if not provided
  if (is.null(max_length)) {
    max_length <- switch(input_type,
      "email" = SECURITY_CONFIG$input_validation$max_email_length,
      "name" = SECURITY_CONFIG$input_validation$max_name_length,
      SECURITY_CONFIG$input_validation$max_text_length
    )
  }
  
  # Create input with validation attributes
  input_attrs <- list(
    id = inputId,
    type = if (input_type == "textarea") "text" else input_type,
    class = "form-control secure-input",
    value = sanitize_input(value, input_type),
    maxlength = max_length,
    `data-input-type` = input_type
  )
  
  if (required) {
    input_attrs$required <- "required"
  }
  
  # Add pattern for specific input types
  if (input_type == "email") {
    input_attrs$pattern <- "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
  }
  
  # Create input element
  input_element <- if (input_type == "textarea") {
    do.call(tags$textarea, c(input_attrs, list(value)))
  } else {
    do.call(tags$input, input_attrs)
  }
  
  # Wrap in form group with label and validation feedback
  div(
    class = "form-group secure-input-group",
    
    if (!is.null(label)) {
      tags$label(
        `for` = inputId,
        class = if (required) "form-label required" else "form-label",
        label
      )
    },
    
    input_element,
    
    div(
      class = "invalid-feedback",
      id = paste0(inputId, "_validation"),
      style = "display: none;"
    ),
    
    if (!is.null(max_length)) {
      div(
        class = "form-text",
        paste("Máximo", max_length, "caracteres")
      )
    }
  )
}

#' Secure file input with validation
#' @param inputId Input ID
#' @param label Input label
#' @param accept Accepted file types
#' @param multiple Allow multiple files
#' @return Secure file input element
secure_file_input <- function(inputId, label, accept = NULL, multiple = FALSE) {
  # Use allowed file types if accept not specified
  if (is.null(accept)) {
    accept <- SECURITY_CONFIG$input_validation$allowed_file_types
  }
  
  div(
    class = "form-group secure-file-group",
    
    if (!is.null(label)) {
      tags$label(
        `for` = inputId,
        class = "form-label",
        label
      )
    },
    
    tags$input(
      id = inputId,
      type = "file",
      class = "form-control secure-file-input",
      accept = paste(accept, collapse = ","),
      multiple = if (multiple) "multiple" else NULL,
      `data-max-size` = SECURITY_CONFIG$input_validation$max_file_size_mb
    ),
    
    div(
      class = "invalid-feedback",
      id = paste0(inputId, "_validation"),
      style = "display: none;"
    ),
    
    div(
      class = "form-text",
      paste(
        "Tipos permitidos:", paste(accept, collapse = ", "),
        "| Tamanho máximo:", SECURITY_CONFIG$input_validation$max_file_size_mb, "MB"
      )
    )
  )
}

#' Initialize security system
#' @param session Shiny session object
initialize_security <- function(session) {
  # Add client-side validation scripts
  session$sendCustomMessage(
    type = "initializeSecurity",
    message = list(
      validation_config = SECURITY_CONFIG$input_validation,
      csrf_config = SECURITY_CONFIG$csrf_protection
    )
  )
  
  # Set up session security
  if (SECURITY_CONFIG$session_security$require_https && 
      !grepl("^https:", session$clientData$url_protocol)) {
    log_security_event("insecure_connection", url = session$clientData$url_protocol)
  }
  
  # Log session start
  log_security_event(
    "session_start",
    session_id = session$token,
    user_agent = session$clientData$user_agent,
    ip_address = session$clientData$url_hostname
  )
}

# JavaScript for client-side security
security_js <- "
// Client-side input validation
$(document).on('input', '.secure-input', function() {
  var input = $(this);
  var inputType = input.data('input-type');
  var value = input.val();
  var maxLength = input.attr('maxlength');
  var feedback = $('#' + input.attr('id') + '_validation');
  
  // Length validation
  if (maxLength && value.length > maxLength) {
    input.addClass('is-invalid');
    feedback.text('Input too long. Maximum ' + maxLength + ' characters allowed.').show();
    return;
  }
  
  // XSS pattern detection (basic)
  var xssPatterns = ['<script', '</script>', 'javascript:', 'onload=', 'onerror='];
  for (var i = 0; i < xssPatterns.length; i++) {
    if (value.toLowerCase().indexOf(xssPatterns[i]) !== -1) {
      input.addClass('is-invalid');
      feedback.text('Invalid content detected in input.').show();
      return;
    }
  }
  
  // Remove validation classes if valid
  input.removeClass('is-invalid').addClass('is-valid');
  feedback.hide();
});

// File upload validation
$(document).on('change', '.secure-file-input', function() {
  var input = $(this);
  var files = input[0].files;
  var maxSize = parseInt(input.data('max-size')) * 1024 * 1024; // Convert MB to bytes
  var allowedTypes = input.attr('accept').split(',');
  var feedback = $('#' + input.attr('id') + '_validation');
  
  for (var i = 0; i < files.length; i++) {
    var file = files[i];
    
    // Size validation
    if (file.size > maxSize) {
      input.addClass('is-invalid');
      feedback.text('File too large. Maximum size: ' + input.data('max-size') + 'MB').show();
      return;
    }
    
    // Type validation
    var fileExt = '.' + file.name.split('.').pop().toLowerCase();
    if (allowedTypes.indexOf(fileExt) === -1) {
      input.addClass('is-invalid');
      feedback.text('File type not allowed: ' + fileExt).show();
      return;
    }
  }
  
  // Remove validation classes if valid
  input.removeClass('is-invalid').addClass('is-valid');
  feedback.hide();
});

// CSRF token handling
var csrfToken = null;

Shiny.addCustomMessageHandler('setCsrfToken', function(message) {
  csrfToken = message.token;
  // Add token to all AJAX requests
  $.ajaxSetup({
    beforeSend: function(xhr, settings) {
      if (csrfToken && settings.type !== 'GET') {
        xhr.setRequestHeader('X-CSRF-Token', csrfToken);
      }
    }
  });
});

// Security headers handling
Shiny.addCustomMessageHandler('setHeader', function(message) {
  // This would typically be handled by server-side middleware
  console.log('Security header set:', message.name, message.value);
});

// Initialize security on document ready
$(document).ready(function() {
  // Additional client-side security measures can be added here
  console.log('Security system initialized');
});
"

#' Get JavaScript code for security features
#' @return Security JavaScript code
get_security_js <- function() {
  return(security_js)
}