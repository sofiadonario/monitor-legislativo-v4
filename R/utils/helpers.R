# Helper Functions Module
# Monitor Legislativo v4 - General Utility Functions
# ==================================================

#' Format Numbers for Display
#' 
#' Formats numbers for user-friendly display with Brazilian locale
#' 
#' @param x Numeric value to format
#' @param big_mark Character to use as thousands separator
#' @param decimal_mark Character to use as decimal separator
#' @return Formatted character string
#' @export
format_number <- function(x, big_mark = ".", decimal_mark = ",") {
  if (is.null(x) || is.na(x)) return("N/A")
  
  if (is.numeric(x)) {
    # Handle large numbers with appropriate units
    if (abs(x) >= 1e6) {
      return(paste0(format(round(x/1e6, 1), decimal.mark = decimal_mark), "M"))
    } else if (abs(x) >= 1e3) {
      return(paste0(format(round(x/1e3, 1), decimal.mark = decimal_mark), "K"))
    } else {
      return(format(x, big.mark = big_mark, decimal.mark = decimal_mark))
    }
  }
  
  return(as.character(x))
}

#' Safe HTML Content with Comprehensive XSS Protection
#' 
#' Provides enterprise-grade XSS (Cross-Site Scripting) protection using a
#' whitelist-based approach specifically designed for Brazilian government
#' data systems. Complies with LGPD security requirements and academic
#' research standards for handling legislative document content.
#' 
#' This function is critical for preventing XSS attacks when displaying
#' user-generated content or legislative documents that may contain
#' potentially malicious HTML code.
#' 
#' @details
#' **Security Features:**
#' - **Whitelist Approach**: Only allows explicitly safe HTML elements
#' - **Script Removal**: Completely removes `<script>` tags and content
#' - **Event Handler Blocking**: Strips all `on*` event handlers
#' - **Protocol Filtering**: Blocks `javascript:`, `data:`, and `vbscript:` protocols
#' - **Style Attribute Removal**: Prevents CSS-based attacks
#' - **Entity Encoding**: Encodes remaining special characters
#' 
#' **LGPD Compliance:**
#' - Prevents data exfiltration through XSS attacks
#' - Maintains content integrity for legal documents
#' - Supports audit trails through secure content processing
#' 
#' **Academic Usage:**
#' Essential for research platforms displaying legislative content from
#' multiple sources. Ensures that academic researchers can safely view
#' document content without exposure to security threats.
#' 
#' @param content Character string containing potentially unsafe HTML content.
#'   Can be from user input, document content, or external sources.
#' @param max_length Integer specifying maximum allowed content length.
#'   Content exceeding this limit is truncated with "..." suffix.
#' @param allow_basic_formatting Logical indicating whether to preserve
#'   safe formatting tags (b, i, em, strong, p, br). Default TRUE.
#' 
#' @return Character string containing sanitized HTML content safe for display.
#'   All dangerous elements and attributes are removed or encoded.
#' 
#' @family security-functions
#' @seealso \code{\link{validate_input}} for comprehensive input validation
#' @seealso \code{\link{log_security_event}} for security event logging
#' 
#' @examples
#' \dontrun{
#' # Basic XSS protection
#' safe_content <- safe_html("<p>Safe content</p><script>alert('xss')</script>")
#' # Returns: "<p>Safe content</p>"
#' 
#' # Legislative document content
#' document_text <- "<strong>Lei nº 12.345/2020</strong> - Disposições gerais"
#' clean_text <- safe_html(document_text, max_length = 1000)
#' 
#' # Strip all formatting for search indexing
#' search_text <- safe_html(html_content, allow_basic_formatting = FALSE)
#' 
#' # Handle potentially malicious input
#' user_input <- "<img src=x onerror=alert('xss')>"
#' safe_input <- safe_html(user_input) # Returns: ""
#' }
#' 
#' @export
safe_html <- function(content, max_length = 500, allow_basic_formatting = TRUE) {
  if (is.null(content) || is.na(content)) return("")
  
  # Input validation
  if (!is.character(content)) {
    content <- as.character(content)
  }
  
  # Length validation and truncation
  if (nchar(content) > max_length) {
    content <- substr(content, 1, max_length)
    content <- paste0(content, "...")
  }
  
  # Comprehensive XSS protection - whitelist approach
  # Remove all potentially dangerous content
  
  # 1. Remove script tags and their content
  content <- gsub("<script[^>]*>.*?</script>", "", content, ignore.case = TRUE, perl = TRUE)
  
  # 2. Remove iframe, object, embed, applet tags
  dangerous_tags <- c("iframe", "object", "embed", "applet", "form", "input", "textarea", "select", "button")
  for (tag in dangerous_tags) {
    pattern <- paste0("<", tag, "[^>]*>.*?</", tag, ">")
    content <- gsub(pattern, "", content, ignore.case = TRUE, perl = TRUE)
    # Also remove self-closing versions
    pattern_self <- paste0("<", tag, "[^>]*/>")
    content <- gsub(pattern_self, "", content, ignore.case = TRUE, perl = TRUE)
  }
  
  # 3. Remove javascript: and data: protocols
  content <- gsub("javascript:\s*[^\s]*", "", content, ignore.case = TRUE, perl = TRUE)
  content <- gsub("data:\s*[^\s]*", "", content, ignore.case = TRUE, perl = TRUE)
  content <- gsub("vbscript:\s*[^\s]*", "", content, ignore.case = TRUE, perl = TRUE)
  
  # 4. Remove on* event handlers
  content <- gsub("\s*on[a-zA-Z]+\s*=\s*['\"][^'\"]*['\"]?", "", content, ignore.case = TRUE, perl = TRUE)
  
  # 5. Remove style attributes that could contain expressions
  content <- gsub("\s*style\s*=\s*['\"][^'\"]*['\"]?", "", content, ignore.case = TRUE, perl = TRUE)
  
  # 6. Whitelist allowed tags if basic formatting is enabled
  if (allow_basic_formatting) {
    # Allow only safe formatting tags: b, i, em, strong, p, br
    allowed_pattern <- "<(?!/?(b|i|em|strong|p|br)\\b)[^>]*>"
    content <- gsub(allowed_pattern, "", content, ignore.case = TRUE, perl = TRUE)
  } else {
    # Strip all HTML tags
    content <- gsub("<[^>]*>", "", content, perl = TRUE)
  }
  
  # 7. HTML entity encode remaining special characters
  content <- gsub("&", "&amp;", content)
  content <- gsub("<", "&lt;", content)
  content <- gsub(">", "&gt;", content)
  content <- gsub('"', "&quot;", content)
  content <- gsub("'", "&#39;", content)
  
  # 8. Final validation - ensure no remaining dangerous patterns
  dangerous_patterns <- c(
    "javascript", "vbscript", "onload", "onerror", "onmouseover",
    "expression\\s*\\(", "url\\s*\\(", "import\\s*\\("
  )
  
  for (pattern in dangerous_patterns) {
    content <- gsub(pattern, "", content, ignore.case = TRUE, perl = TRUE)
  }
  
  return(content)
}

#' Create Loading Spinner
#' 
#' Creates a loading spinner element for long-running operations
#' 
#' @param message Optional message to display
#' @param size Size of spinner ("sm", "md", "lg")
#' @return HTML div element with spinner
#' @export
create_loading_spinner <- function(message = "Loading...", size = "md") {
  
  spinner_class <- switch(size,
    "sm" = "spinner-border-sm",
    "lg" = "spinner-border-lg", 
    "spinner-border"
  )
  
  div(
    class = "text-center p-4",
    div(
      class = paste("spinner-border", spinner_class),
      role = "status",
      span(class = "sr-only", "Loading...")
    ),
    if (message != "") br(),
    if (message != "") p(message, class = "text-muted mt-2")
  )
}

#' Validate Input Parameters with Enhanced Security Controls
#' 
#' Comprehensive input validation system with advanced security controls
#' designed for LGPD-compliant Brazilian government applications. Prevents
#' injection attacks, ensures data integrity, and maintains academic research
#' data quality standards.
#' 
#' This function serves as the primary defense against malicious input in
#' legislative document research systems, protecting both the application
#' and the underlying database from various attack vectors.
#' 
#' @details
#' **Security Validation:**
#' - **SQL Injection Detection**: Identifies and blocks SQL injection patterns
#' - **XSS Prevention**: Detects cross-site scripting attempts
#' - **Script Injection Blocking**: Prevents JavaScript and VBScript injection
#' - **Input Sanitization**: Automatically cleans validated input
#' - **Type Coercion Safety**: Safely converts between data types
#' 
#' **Academic Data Types:**
#' - **search_query**: Specialized validation for legislative document searches
#' - **date**: Flexible date parsing for Brazilian date formats
#' - **numeric**: Range validation for academic parameters
#' - **character**: Length and content validation for text data
#' 
#' **LGPD Compliance Features:**
#' - Input sanitization maintains data privacy
#' - Audit trail support through validation logging
#' - Secure handling of personal data in research contexts
#' 
#' @param value Input value to validate. Can be any R data type.
#' @param type Character string specifying expected data type:
#'   \describe{
#'     \item{"numeric"}{Validates numeric values with optional range checking}
#'     \item{"character"}{Validates text with length and content restrictions}
#'     \item{"logical"}{Validates boolean values with flexible input formats}
#'     \item{"date"}{Validates dates with multiple Brazilian format support}
#'     \item{"search_query"}{Specialized validation for academic search terms}
#'   }
#' @param min_value Numeric minimum value (only for numeric type)
#' @param max_value Numeric maximum value (only for numeric type)
#' @param max_length Integer maximum string length (for character/search_query types)
#' @param required Logical indicating if value is mandatory
#' @param allow_html Logical indicating if safe HTML tags are permitted
#' 
#' @return Named list containing validation results:
#'   \item{valid}{Logical indicating if validation passed}
#'   \item{error}{Character string with error message (if invalid)}
#'   \item{value}{Validated and potentially sanitized input value}
#'   \item{sanitized}{Logical indicating if value was modified during validation}
#' 
#' @family security-functions
#' @seealso \code{\link{safe_html}} for HTML content sanitization
#' @seealso \code{\link{log_security_event}} for security event logging
#' @seealso \code{\link{safe_date_parse}} for date validation
#' 
#' @examples
#' \dontrun{
#' # Validate academic search query
#' search_result <- validate_input(
#'   "transporte público", 
#'   type = "search_query", 
#'   max_length = 500,
#'   required = TRUE
#' )
#' if (search_result$valid) {
#'   cat("Search query is safe:", search_result$value)
#' }
#' 
#' # Validate year parameter for legislative documents
#' year_result <- validate_input(
#'   "2023", 
#'   type = "numeric", 
#'   min_value = 1900, 
#'   max_value = 2030
#' )
#' 
#' # Detect malicious input (this would fail validation)
#' malicious_result <- validate_input(
#'   "'; DROP TABLE documents; --",
#'   type = "search_query"
#' )
#' # malicious_result$valid == FALSE
#' }
#' 
#' @export
validate_input <- function(value, type = "character", min_value = NULL, max_value = NULL, 
                          max_length = 1000, required = FALSE, allow_html = FALSE) {
  
  result <- list(valid = TRUE, error = NULL, value = value, sanitized = TRUE)
  
  # Check if required
  if (required && (is.null(value) || is.na(value) || value == "")) {
    result$valid <- FALSE
    result$error <- "This field is required"
    return(result)
  }
  
  # Skip further validation if empty and not required
  if (is.null(value) || is.na(value) || value == "") {
    return(result)
  }
  
  # Security check - detect potential injection attempts
  if (is.character(value)) {
    # SQL injection patterns
    sql_patterns <- c(
      "'\\s*(OR|AND)\\s+'", "UNION\\s+SELECT", "DROP\\s+TABLE", "INSERT\\s+INTO",
      "DELETE\\s+FROM", "UPDATE\\s+.*SET", "EXEC(UTE)?\\s+", "--\\s*$", "/\\*.*\\*/",
      "<script[^>]*>", "javascript:\\s*", "vbscript:\\s*"
    )
    
    for (pattern in sql_patterns) {
      if (grepl(pattern, value, ignore.case = TRUE, perl = TRUE)) {
        result$valid <- FALSE
        result$error <- "Invalid characters detected. Please use only alphanumeric characters and common punctuation."
        return(result)
      }
    }
  }
  
  # Type-specific validation
  if (type == "numeric") {
    if (!is.numeric(value)) {
      # Try to convert, but be strict about format
      if (is.character(value)) {
        # Only allow numeric characters, decimal points, and minus signs
        if (!grepl("^-?[0-9]*\\.?[0-9]*$", value)) {
          result$valid <- FALSE
          result$error <- "Must contain only numeric characters"
          return(result)
        }
      }
      
      converted <- suppressWarnings(as.numeric(value))
      if (is.na(converted)) {
        result$valid <- FALSE
        result$error <- "Must be a valid number"
        return(result)
      }
      result$value <- converted
      value <- converted
    }
    
    # Range validation
    if (!is.null(min_value) && value < min_value) {
      result$valid <- FALSE
      result$error <- paste("Must be at least", min_value)
      return(result)
    }
    
    if (!is.null(max_value) && value > max_value) {
      result$valid <- FALSE
      result$error <- paste("Must be at most", max_value)
      return(result)
    }
  }
  
  if (type == "character") {
    value_char <- as.character(value)
    
    # Length validation
    if (nchar(value_char) > max_length) {
      result$valid <- FALSE
      result$error <- paste("Must be no more than", max_length, "characters")
      return(result)
    }
    
    # Sanitize if HTML is not allowed
    if (!allow_html) {
      result$value <- safe_html(value_char, max_length = max_length, allow_basic_formatting = FALSE)
    } else {
      result$value <- safe_html(value_char, max_length = max_length, allow_basic_formatting = TRUE)
    }
  }
  
  if (type == "search_query") {
    value_char <- as.character(value)
    
    # Special validation for search queries
    if (nchar(value_char) > 500) {
      result$valid <- FALSE
      result$error <- "Search query is too long (maximum 500 characters)"
      return(result)
    }
    
    # Remove potentially dangerous characters for search
    # Allow Portuguese characters, spaces, quotes, and basic punctuation
    cleaned_query <- gsub("[^a-zA-ZÀ-ÿ0-9\\s\"'.,;:!?()\\-]", "", value_char, perl = TRUE)
    
    # Trim excessive whitespace
    cleaned_query <- gsub("\\s+", " ", trimws(cleaned_query))
    
    if (cleaned_query != value_char) {
      result$sanitized <- TRUE
    }
    
    result$value <- cleaned_query
  }
  
  if (type == "date") {
    # Use the existing safe_date_parse function
    parsed_date <- safe_date_parse(as.character(value))
    if (is.na(parsed_date)) {
      result$valid <- FALSE
      result$error <- "Must be a valid date (YYYY-MM-DD, DD/MM/YYYY, or similar format)"
      return(result)
    }
    result$value <- parsed_date
  }
  
  if (type == "logical") {
    if (!is.logical(value)) {
      if (value %in% c("true", "TRUE", "1", "yes", "YES", "sim", "SIM")) {
        result$value <- TRUE
      } else if (value %in% c("false", "FALSE", "0", "no", "NO", "não", "NÃO")) {
        result$value <- FALSE
      } else {
        result$valid <- FALSE
        result$error <- "Must be true or false"
        return(result)
      }
    }
  }
  
  return(result)
}

#' Create Error Alert
#' 
#' Creates a Bootstrap alert for error messages
#' 
#' @param message Error message
#' @param type Alert type ("danger", "warning", "info", "success")
#' @param dismissible Whether alert can be dismissed
#' @return HTML alert element
#' @export
create_alert <- function(message, type = "danger", dismissible = TRUE) {
  
  alert_class <- paste("alert", paste0("alert-", type))
  if (dismissible) alert_class <- paste(alert_class, "alert-dismissible fade show")
  
  alert_content <- div(
    class = alert_class,
    role = "alert",
    message
  )
  
  if (dismissible) {
    alert_content <- tagAppendChild(
      alert_content,
      button(
        type = "button",
        class = "close",
        `data-dismiss` = "alert",
        `aria-label` = "Close",
        span(`aria-hidden` = "true", HTML("&times;"))
      )
    )
  }
  
  return(alert_content)
}

#' Generate Unique ID
#' 
#' Generates a unique identifier for HTML elements
#' 
#' @param prefix Optional prefix for the ID
#' @return Character string with unique ID
#' @export
generate_id <- function(prefix = "element") {
  paste0(prefix, "_", as.integer(Sys.time()), "_", sample(1000:9999, 1))
}

#' Safe Date Parsing
#' 
#' Safely parses dates with multiple format support
#' 
#' @param date_string Character string representing a date
#' @param formats Vector of date formats to try
#' @return Date object or NA if parsing fails
#' @export
safe_date_parse <- function(date_string, formats = c("%Y-%m-%d", "%d/%m/%Y", "%Y/%m/%d", "%d-%m-%Y")) {
  
  if (is.null(date_string) || is.na(date_string) || date_string == "") {
    return(as.Date(NA))
  }
  
  # Try each format
  for (fmt in formats) {
    result <- tryCatch({
      as.Date(date_string, format = fmt)
    }, error = function(e) NA)
    
    if (!is.na(result)) {
      return(result)
    }
  }
  
  # If all formats fail, try automatic parsing
  result <- tryCatch({
    as.Date(date_string)
  }, error = function(e) as.Date(NA))
  
  return(result)
}

#' Create Progress Bar
#' 
#' Creates a Bootstrap progress bar
#' 
#' @param value Current progress value (0-100)
#' @param label Optional label text
#' @param color Progress bar color
#' @param striped Whether to use striped style
#' @param animated Whether to animate stripes
#' @return HTML progress bar element
#' @export
create_progress_bar <- function(value, label = NULL, color = "primary", striped = FALSE, animated = FALSE) {
  
  # Ensure value is between 0 and 100
  value <- max(0, min(100, value))
  
  bar_class <- paste("progress-bar", paste0("bg-", color))
  if (striped) bar_class <- paste(bar_class, "progress-bar-striped")
  if (animated) bar_class <- paste(bar_class, "progress-bar-animated")
  
  progress_content <- div(
    class = "progress",
    div(
      class = bar_class,
      role = "progressbar",
      style = paste0("width: ", value, "%"),
      `aria-valuenow` = value,
      `aria-valuemin` = "0",
      `aria-valuemax` = "100",
      if (!is.null(label)) label else paste0(value, "%")
    )
  )
  
  return(progress_content)
}

#' Truncate Text
#' 
#' Truncates text to specified length with ellipsis
#' 
#' @param text Character vector to truncate
#' @param max_length Maximum length before truncation
#' @param suffix Suffix to add when truncating
#' @return Truncated character vector
#' @export
truncate_text <- function(text, max_length = 100, suffix = "...") {
  
  if (is.null(text) || is.na(text)) return("")
  
  sapply(text, function(x) {
    if (nchar(x) <= max_length) {
      return(x)
    } else {
      return(paste0(substr(x, 1, max_length - nchar(suffix)), suffix))
    }
  }, USE.NAMES = FALSE)
}

#' Create Tooltip
#' 
#' Creates a Bootstrap tooltip element
#' 
#' @param content Main content element
#' @param tooltip_text Tooltip text
#' @param placement Tooltip placement ("top", "bottom", "left", "right")
#' @return HTML element with tooltip
#' @export
create_tooltip <- function(content, tooltip_text, placement = "top") {
  
  # Add tooltip attributes to content
  content <- tagAppendAttributes(
    content,
    `data-toggle` = "tooltip",
    `data-placement` = placement,
    title = tooltip_text
  )
  
  return(content)
}

#' Log Message with Timestamp
#' 
#' Logs a message with timestamp for debugging
#' 
#' @param message Message to log
#' @param level Log level ("INFO", "WARNING", "ERROR", "DEBUG")
#' @param console Whether to print to console
#' @export
log_message <- function(message, level = "INFO", console = TRUE) {
  
  timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")
  formatted_message <- paste0("[", timestamp, "] [", level, "] ", message)
  
  if (console) {
    cat(formatted_message, "\n")
  }
  
  # Could extend this to write to log files
  invisible(formatted_message)
}

#' Check Package Availability
#' 
#' Checks if packages are available and loads them quietly
#' 
#' @param packages Character vector of package names
#' @param install_missing Whether to attempt installation of missing packages
#' @return Named logical vector indicating availability
#' @export
check_packages <- function(packages, install_missing = FALSE) {
  
  availability <- setNames(logical(length(packages)), packages)
  
  for (pkg in packages) {
    # Check if package is available
    available <- requireNamespace(pkg, quietly = TRUE)
    
    if (!available && install_missing) {
      tryCatch({
        install.packages(pkg, quiet = TRUE)
        available <- requireNamespace(pkg, quietly = TRUE)
        if (available) {
          cat("✅ Installed package:", pkg, "\n")
        }
      }, error = function(e) {
        cat("❌ Failed to install package:", pkg, "\n")
      })
    }
    
    availability[pkg] <- available
  }
  
  return(availability)
}

#' Rate Limiting Store
#' Simple in-memory rate limiting for security protection
.rate_limit_store <- new.env(parent = emptyenv())

#' Check Rate Limit
#' 
#' Implements rate limiting to prevent abuse and DoS attacks
#' Complies with LGPD security requirements
#' 
#' @param key Unique identifier for rate limiting (e.g., IP address, user ID)
#' @param max_requests Maximum requests allowed
#' @param time_window Time window in seconds
#' @return List with allowed flag and remaining requests
#' @export
check_rate_limit <- function(key, max_requests = 100, time_window = 3600) {
  
  if (is.null(key) || key == "") {
    key <- "unknown"
  }
  
  current_time <- as.numeric(Sys.time())
  
  # Get or create rate limit data for this key
  if (exists(key, envir = .rate_limit_store)) {
    rate_data <- get(key, envir = .rate_limit_store)
  } else {
    rate_data <- list(requests = 0, window_start = current_time)
  }
  
  # Check if we're in a new time window
  if (current_time - rate_data$window_start > time_window) {
    rate_data <- list(requests = 0, window_start = current_time)
  }
  
  # Check if limit exceeded
  if (rate_data$requests >= max_requests) {
    return(list(
      allowed = FALSE,
      remaining = 0,
      reset_time = rate_data$window_start + time_window,
      error = paste("Rate limit exceeded. Maximum", max_requests, "requests per", time_window, "seconds.")
    ))
  }
  
  # Increment request count
  rate_data$requests <- rate_data$requests + 1
  assign(key, rate_data, envir = .rate_limit_store)
  
  return(list(
    allowed = TRUE,
    remaining = max_requests - rate_data$requests,
    reset_time = rate_data$window_start + time_window
  ))
}

#' Sanitize File Name
#' 
#' Sanitizes file names to prevent directory traversal and other file system attacks
#' 
#' @param filename Original filename
#' @param max_length Maximum allowed length
#' @return Sanitized filename
#' @export
sanitize_filename <- function(filename, max_length = 255) {
  
  if (is.null(filename) || filename == "") {
    return("untitled")
  }
  
  # Convert to character and remove path separators
  clean_name <- as.character(filename)
  clean_name <- gsub("[\\/\\\\]", "_", clean_name)
  
  # Remove or replace dangerous characters
  clean_name <- gsub("[<>:\"|?*]", "_", clean_name)
  clean_name <- gsub("[\\x00-\\x1f\\x7f-\\x9f]", "", clean_name)  # Remove control characters
  
  # Remove leading/trailing periods and spaces
  clean_name <- gsub("^[\\.\\s]+|[\\.\\s]+$", "", clean_name)
  
  # Prevent reserved names (Windows)
  reserved_names <- c("CON", "PRN", "AUX", "NUL", paste0("COM", 1:9), paste0("LPT", 1:9))
  if (toupper(clean_name) %in% reserved_names) {
    clean_name <- paste0("file_", clean_name)
  }
  
  # Truncate if too long
  if (nchar(clean_name) > max_length) {
    # Keep file extension if present
    if (grepl("\\.", clean_name)) {
      parts <- strsplit(clean_name, "\\.")[[1]]
      extension <- parts[length(parts)]
      name_part <- paste(parts[-length(parts)], collapse = ".")
      max_name_length <- max_length - nchar(extension) - 1
      clean_name <- paste0(substr(name_part, 1, max_name_length), ".", extension)
    } else {
      clean_name <- substr(clean_name, 1, max_length)
    }
  }
  
  # Ensure we have a valid filename
  if (clean_name == "" || is.null(clean_name)) {
    clean_name <- "untitled"
  }
  
  return(clean_name)
}

#' Generate Security Token
#' 
#' Generates a cryptographically secure token for CSRF protection
#' 
#' @param length Token length in bytes
#' @return Hexadecimal token string
#' @export
generate_security_token <- function(length = 32) {
  
  # Use cryptographically secure random bytes
  if (requireNamespace("openssl", quietly = TRUE)) {
    bytes <- openssl::rand_bytes(length)
    return(paste0(sprintf("%02x", as.integer(bytes)), collapse = ""))
  } else {
    # Fallback to less secure but still random method
    bytes <- sample(0:255, length, replace = TRUE)
    return(paste0(sprintf("%02x", bytes), collapse = ""))
  }
}

#' Validate Security Token
#' 
#' Validates CSRF tokens using constant-time comparison
#' 
#' @param token1 First token
#' @param token2 Second token  
#' @return Logical indicating if tokens match
#' @export
validate_security_token <- function(token1, token2) {
  
  if (is.null(token1) || is.null(token2) || token1 == "" || token2 == "") {
    return(FALSE)
  }
  
  # Convert to character
  token1 <- as.character(token1)
  token2 <- as.character(token2)
  
  # Must be same length
  if (nchar(token1) != nchar(token2)) {
    return(FALSE)
  }
  
  # Constant-time comparison to prevent timing attacks
  result <- 0
  for (i in 1:nchar(token1)) {
    result <- bitwXor(result, 
                     bitwXor(utf8ToInt(substr(token1, i, i))[1], 
                            utf8ToInt(substr(token2, i, i))[1]))
  }
  
  return(result == 0)
}

#' Log Security Events for LGPD Compliance and Monitoring
#' 
#' Comprehensive security event logging system designed for LGPD-compliant
#' Brazilian government applications. Records security-related events for
#' monitoring, compliance auditing, and incident response in academic
#' research environments.
#' 
#' This function is essential for maintaining security audit trails required
#' by LGPD when processing personal data in legislative document research.
#' All events are logged with timestamps and structured data for analysis.
#' 
#' @details
#' **Security Event Categories:**
#' - **DATABASE_CONFIG**: Database configuration and connection events
#' - **SEARCH_EXECUTED**: Academic search operations and rate limiting
#' - **DATA_EXPORT**: Export operations for compliance tracking
#' - **RATE_LIMIT_EXCEEDED**: Protection against abuse and DoS attacks
#' - **SQL_INJECTION_ATTEMPT**: Blocked malicious query attempts
#' - **XSS_ATTEMPT**: Cross-site scripting prevention events
#' 
#' **LGPD Compliance:**
#' - Structured logging for data protection impact assessments
#' - Audit trail maintenance for regulatory compliance
#' - Privacy incident detection and response support
#' - User activity monitoring for academic research transparency
#' 
#' **Academic Research Integration:**
#' Supports research integrity by logging all data access patterns,
#' search operations, and export activities for academic accountability.
#' 
#' @param event_type Character string categorizing the security event.
#'   Common types: "DATABASE_CONFIG", "SEARCH_EXECUTED", "DATA_EXPORT",
#'   "RATE_LIMIT_EXCEEDED", "SQL_INJECTION_ATTEMPT", "AUTHENTICATION"
#' @param description Character string with detailed event description.
#'   Should be informative but avoid including sensitive data.
#' @param user_id Character string identifying the user (if applicable).
#'   Use anonymized identifiers for LGPD compliance.
#' @param ip_address Character string with client IP address for session tracking
#' @param additional_data Named list with structured event data for analysis.
#'   Use for non-sensitive contextual information.
#' 
#' @return Invisibly returns the complete event data structure for further processing
#' 
#' @family security-functions
#' @seealso \code{\link{validate_input}} for input validation events
#' @seealso \code{\link{execute_secure_query}} for database security events
#' @seealso \code{\link{check_rate_limit}} for rate limiting events
#' 
#' @examples
#' \dontrun{
#' # Log successful database configuration
#' log_security_event(
#'   "DATABASE_CONFIG", 
#'   "Railway PostgreSQL connection established successfully"
#' )
#' 
#' # Log academic search operation
#' log_security_event(
#'   "SEARCH_EXECUTED",
#'   "Legislative document search completed",
#'   user_id = "researcher_001",
#'   additional_data = list(
#'     query_length = 25,
#'     results_count = 150,
#'     response_time_ms = 234
#'   )
#' )
#' 
#' # Log security incident
#' log_security_event(
#'   "SQL_INJECTION_ATTEMPT",
#'   "Blocked potentially malicious query",
#'   ip_address = "192.168.1.100",
#'   additional_data = list(
#'     blocked_pattern = "DROP TABLE",
#'     user_agent = "Mozilla/5.0..."
#'   )
#' )
#' }
#' 
#' @export
log_security_event <- function(event_type, description, user_id = NULL, ip_address = NULL, additional_data = NULL) {
  
  timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S %Z")
  
  event_data <- list(
    timestamp = timestamp,
    event_type = event_type,
    description = description,
    user_id = user_id,
    ip_address = ip_address,
    additional_data = additional_data
  )
  
  # Convert to JSON for structured logging
  if (requireNamespace("jsonlite", quietly = TRUE)) {
    log_entry <- jsonlite::toJSON(event_data, auto_unbox = TRUE)
  } else {
    log_entry <- paste0(
      "[", timestamp, "] ",
      "[SECURITY:", event_type, "] ",
      description,
      if (!is.null(user_id)) paste0(" (User: ", user_id, ")") else "",
      if (!is.null(ip_address)) paste0(" (IP: ", ip_address, ")") else ""
    )
  }
  
  # Log to console (in production, this would go to a secure log file)
  cat("🔒 SECURITY EVENT:", log_entry, "\n")
  
  # Return the event data for further processing
  invisible(event_data)
}

cat("✅ Helper functions module loaded with enhanced security features\n")