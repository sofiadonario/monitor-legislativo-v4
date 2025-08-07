# Security Hardening Module for Monitor Legislativo v4
# Implements CSRF protection, input validation, rate limiting, and security headers
# Ensures secure communication and prevents common web application attacks

library(digest)
library(stringr)
library(httr)

# Global security configuration
.security_config <- list(
  csrf_token_length = 32,
  rate_limit_window = 60,  # seconds
  max_requests_per_window = 100,
  max_search_length = 1000,
  max_export_records = 10000,
  session_cookie_secure = TRUE,
  session_cookie_httponly = TRUE,
  xss_protection = TRUE
)

# Rate limiting storage (in production, use Redis)
.rate_limit_store <- new.env(parent = emptyenv())

#' Generate secure CSRF token
#' @param session_id User session identifier
#' @return CSRF token string
generate_csrf_token <- function(session_id = NULL) {
  # Create unique token based on session and timestamp
  token_data <- paste(
    session_id %||% "anonymous",
    Sys.time(),
    sample(letters, 10, replace = TRUE),
    collapse = ""
  )
  
  csrf_token <- digest(token_data, algo = "sha256", serialize = FALSE)
  substr(csrf_token, 1, .security_config$csrf_token_length)
}

#' Validate CSRF token
#' @param submitted_token Token submitted by client
#' @param expected_token Expected token from session
#' @return TRUE if valid, FALSE otherwise
validate_csrf_token <- function(submitted_token, expected_token) {
  if (is.null(submitted_token) || is.null(expected_token)) {
    return(FALSE)
  }
  
  if (nchar(submitted_token) != .security_config$csrf_token_length ||
      nchar(expected_token) != .security_config$csrf_token_length) {
    return(FALSE)
  }
  
  # Constant-time comparison to prevent timing attacks
  identical(submitted_token, expected_token)
}

#' Add CSRF protection to forms
#' @param csrf_token Current CSRF token
#' @return Hidden input field with CSRF token
csrf_token_input <- function(csrf_token) {
  if (is.null(csrf_token)) {
    csrf_token <- generate_csrf_token()
  }
  
  tags$input(
    type = "hidden",
    name = "csrf_token",
    id = "csrf_token",
    value = csrf_token
  )
}

#' Sanitize user input to prevent XSS
#' @param input User input string
#' @param allow_html Whether to allow safe HTML tags
#' @return Sanitized string
sanitize_input <- function(input, allow_html = FALSE) {
  if (is.null(input) || !is.character(input)) {
    return("")
  }
  
  # Remove null bytes and control characters
  input <- gsub("[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", input)
  
  if (!allow_html) {
    # Escape HTML special characters
    input <- gsub("&", "&amp;", input)
    input <- gsub("<", "&lt;", input)
    input <- gsub(">", "&gt;", input)
    input <- gsub("\"", "&quot;", input)
    input <- gsub("'", "&#x27;", input)
    input <- gsub("/", "&#x2F;", input)
  } else {
    # Allow only safe HTML tags (basic formatting)
    allowed_tags <- c("b", "i", "em", "strong", "u", "br", "p")
    
    # Remove potentially dangerous tags and attributes
    input <- gsub("<script[^>]*>.*?</script>", "", input, ignore.case = TRUE)
    input <- gsub("<iframe[^>]*>.*?</iframe>", "", input, ignore.case = TRUE)
    input <- gsub("javascript:", "", input, ignore.case = TRUE)
    input <- gsub("on\\w+\\s*=", "", input, ignore.case = TRUE)
  }
  
  # Limit input length
  if (nchar(input) > .security_config$max_search_length) {
    input <- substr(input, 1, .security_config$max_search_length)
  }
  
  return(input)
}

#' Validate email format
#' @param email Email address to validate
#' @return TRUE if valid format
validate_email <- function(email) {
  if (is.null(email) || !is.character(email) || length(email) != 1) {
    return(FALSE)
  }
  
  email_pattern <- "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
  grepl(email_pattern, email) && nchar(email) <= 254
}

#' Validate institutional email domain
#' @param email Email address to check
#' @return List with validation result and institution info
validate_institutional_domain <- function(email) {
  if (!validate_email(email)) {
    return(list(valid = FALSE, reason = "invalid_format"))
  }
  
  domain <- sub(".*@", "", email)
  
  # Check against trusted domains in database
  if (!is.null(.db_pool)) {
    tryCatch({
      domain_info <- dbGetQuery(.db_pool,
        "SELECT institution_name, institution_type, verification_status 
         FROM trusted_domains 
         WHERE domain = $1",
        params = list(domain)
      )
      
      if (nrow(domain_info) == 0) {
        return(list(
          valid = FALSE, 
          reason = "domain_not_trusted",
          domain = domain
        ))
      }
      
      if (domain_info$verification_status[1] != "verified") {
        return(list(
          valid = FALSE,
          reason = "domain_not_verified", 
          domain = domain,
          status = domain_info$verification_status[1]
        ))
      }
      
      return(list(
        valid = TRUE,
        domain = domain,
        institution = domain_info$institution_name[1],
        type = domain_info$institution_type[1]
      ))
      
    }, error = function(e) {
      log_event(paste("Domain validation error:", e$message), "ERROR")
      return(list(valid = FALSE, reason = "validation_error"))
    })
  }
  
  # Fallback validation for common Brazilian academic domains
  academic_domains <- c(
    "usp.br", "unicamp.br", "ufrj.br", "ufmg.br", "ufrs.br",
    "mackenzie.br", "puc-rio.br", "fgv.br", "cnpq.br", "capes.gov.br"
  )
  
  if (domain %in% academic_domains) {
    return(list(valid = TRUE, domain = domain, fallback = TRUE))
  }
  
  return(list(valid = FALSE, reason = "domain_not_academic", domain = domain))
}

#' Rate limiting check
#' @param identifier User identifier (IP, user ID, etc.)
#' @param action_type Type of action being rate limited
#' @return List with allowed status and remaining requests
check_rate_limit <- function(identifier, action_type = "general") {
  if (is.null(identifier)) {
    return(list(allowed = FALSE, reason = "no_identifier"))
  }
  
  current_time <- as.numeric(Sys.time())
  window_start <- current_time - .security_config$rate_limit_window
  rate_key <- paste(identifier, action_type, sep = ":")
  
  # Get current request history
  if (exists(rate_key, envir = .rate_limit_store)) {
    request_times <- get(rate_key, envir = .rate_limit_store)
    
    # Remove old requests outside the window
    request_times <- request_times[request_times > window_start]
  } else {
    request_times <- c()
  }
  
  # Check if limit exceeded
  if (length(request_times) >= .security_config$max_requests_per_window) {
    log_event(paste("Rate limit exceeded for", identifier, "action:", action_type), "WARN")
    
    return(list(
      allowed = FALSE,
      reason = "rate_limit_exceeded",
      requests_made = length(request_times),
      window_reset = window_start + .security_config$rate_limit_window
    ))
  }
  
  # Add current request
  request_times <- c(request_times, current_time)
  assign(rate_key, request_times, envir = .rate_limit_store)
  
  return(list(
    allowed = TRUE,
    requests_made = length(request_times),
    requests_remaining = .security_config$max_requests_per_window - length(request_times)
  ))
}

#' Validate search parameters
#' @param search_params List of search parameters
#' @return List with validation result and sanitized parameters
validate_search_parameters <- function(search_params) {
  errors <- c()
  sanitized_params <- list()
  
  # Search text validation
  if (!is.null(search_params$search_text)) {
    if (nchar(search_params$search_text) > .security_config$max_search_length) {
      errors <- c(errors, paste("Texto de busca muito longo (máximo", 
                               .security_config$max_search_length, "caracteres)"))
    }
    
    sanitized_params$search_text <- sanitize_input(
      search_params$search_text, allow_html = FALSE
    )
  }
  
  # Date validation
  if (!is.null(search_params$date_from)) {
    date_from <- tryCatch(
      as.Date(search_params$date_from),
      error = function(e) NULL
    )
    
    if (is.null(date_from)) {
      errors <- c(errors, "Data inicial inválida")
    } else if (date_from < as.Date("1900-01-01")) {
      errors <- c(errors, "Data inicial muito antiga")
    } else if (date_from > Sys.Date()) {
      errors <- c(errors, "Data inicial não pode ser futura")
    } else {
      sanitized_params$date_from <- date_from
    }
  }
  
  if (!is.null(search_params$date_to)) {
    date_to <- tryCatch(
      as.Date(search_params$date_to),
      error = function(e) NULL
    )
    
    if (is.null(date_to)) {
      errors <- c(errors, "Data final inválida")
    } else if (date_to > Sys.Date()) {
      errors <- c(errors, "Data final não pode ser futura")
    } else {
      sanitized_params$date_to <- date_to
    }
  }
  
  # Validate date range
  if (!is.null(sanitized_params$date_from) && !is.null(sanitized_params$date_to)) {
    if (sanitized_params$date_from > sanitized_params$date_to) {
      errors <- c(errors, "Data inicial deve ser anterior à data final")
    }
    
    # Limit search range to prevent performance issues
    if (difftime(sanitized_params$date_to, sanitized_params$date_from, units = "days") > 3650) {
      errors <- c(errors, "Período de busca muito amplo (máximo 10 anos)")
    }
  }
  
  # Document type validation
  if (!is.null(search_params$document_types)) {
    valid_types <- c("jurisprudencia", "legislacao", "doutrina", "outros")
    invalid_types <- setdiff(search_params$document_types, valid_types)
    
    if (length(invalid_types) > 0) {
      errors <- c(errors, paste("Tipos de documento inválidos:", 
                               paste(invalid_types, collapse = ", ")))
    } else {
      sanitized_params$document_types <- search_params$document_types
    }
  }
  
  # State validation
  if (!is.null(search_params$states)) {
    valid_states <- c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO",
                     "MA", "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI",
                     "RJ", "RN", "RS", "RO", "RR", "SC", "SP", "SE", "TO")
    
    invalid_states <- setdiff(search_params$states, valid_states)
    
    if (length(invalid_states) > 0) {
      errors <- c(errors, paste("Estados inválidos:", 
                               paste(invalid_states, collapse = ", ")))
    } else {
      sanitized_params$states <- search_params$states
    }
  }
  
  # Limit validation
  if (!is.null(search_params$limit)) {
    limit <- as.numeric(search_params$limit)
    
    if (is.na(limit) || limit < 1) {
      errors <- c(errors, "Limite deve ser um número positivo")
    } else if (limit > .security_config$max_export_records) {
      errors <- c(errors, paste("Limite muito alto (máximo", 
                               .security_config$max_export_records, ")"))
    } else {
      sanitized_params$limit <- as.integer(limit)
    }
  }
  
  return(list(
    valid = length(errors) == 0,
    errors = errors,
    parameters = sanitized_params
  ))
}

#' Generate security headers for HTTP responses
#' @return List of security headers
generate_security_headers <- function() {
  headers <- list(
    "X-Content-Type-Options" = "nosniff",
    "X-Frame-Options" = "DENY",
    "X-XSS-Protection" = "1; mode=block",
    "Strict-Transport-Security" = "max-age=31536000; includeSubDomains",
    "Content-Security-Policy" = paste(
      "default-src 'self';",
      "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com;",
      "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com;",
      "font-src 'self' https://fonts.gstatic.com;",
      "img-src 'self' data: https:;",
      "connect-src 'self' https://api.github.com;",
      "frame-ancestors 'none';"
    ),
    "Referrer-Policy" = "strict-origin-when-cross-origin",
    "Permissions-Policy" = "camera=(), microphone=(), location=(), payment=()"
  )
  
  return(headers)
}

#' Log security events for monitoring
#' @param event_type Type of security event
#' @param user_id User identifier (if applicable)
#' @param ip_address IP address
#' @param details Additional details
#' @param severity Severity level
log_security_event <- function(event_type, user_id = NULL, ip_address = NULL, 
                              details = NULL, severity = "WARN") {
  
  security_log_entry <- list(
    timestamp = Sys.time(),
    event_type = event_type,
    user_id = user_id,
    ip_address = ip_address,
    details = details,
    severity = severity
  )
  
  # Log to application log
  log_message <- paste(
    "SECURITY_EVENT:",
    "type=" %||% event_type,
    "user=" %||% user_id,
    "ip=" %||% ip_address,
    "details=" %||% details
  )
  
  log_event(log_message, severity)
  
  # In production, also send to SIEM system
  # send_to_siem(security_log_entry)
  
  return(TRUE)
}

#' Detect suspicious activity patterns
#' @param user_id User identifier
#' @param ip_address IP address
#' @param action_type Action being performed
#' @return List with suspicion level and reasons
detect_suspicious_activity <- function(user_id = NULL, ip_address = NULL, action_type = NULL) {
  suspicion_level <- 0
  reasons <- c()
  
  if (!is.null(ip_address)) {
    # Check for multiple failed login attempts
    if (!is.null(.db_pool)) {
      tryCatch({
        failed_attempts <- dbGetQuery(.db_pool,
          "SELECT COUNT(*) as count 
           FROM data_access_log 
           WHERE ip_address = $1::inet 
           AND action_type = 'login_failed' 
           AND timestamp > (CURRENT_TIMESTAMP - INTERVAL '1 hour')",
          params = list(ip_address)
        )
        
        if (failed_attempts$count[1] > 5) {
          suspicion_level <- suspicion_level + 3
          reasons <- c(reasons, "multiple_failed_logins")
        }
        
        # Check for rapid requests from same IP
        rapid_requests <- dbGetQuery(.db_pool,
          "SELECT COUNT(*) as count 
           FROM data_access_log 
           WHERE ip_address = $1::inet 
           AND timestamp > (CURRENT_TIMESTAMP - INTERVAL '5 minutes')",
          params = list(ip_address)
        )
        
        if (rapid_requests$count[1] > 50) {
          suspicion_level <- suspicion_level + 2
          reasons <- c(reasons, "rapid_requests")
        }
        
      }, error = function(e) {
        log_event(paste("Suspicious activity detection error:", e$message), "ERROR")
      })
    }
  }
  
  if (!is.null(user_id)) {
    # Check for unusual access patterns
    if (!is.null(.db_pool)) {
      tryCatch({
        # Check for access outside normal hours (very basic heuristic)
        current_hour <- as.numeric(format(Sys.time(), "%H"))
        if (current_hour < 6 || current_hour > 23) {
          suspicion_level <- suspicion_level + 1
          reasons <- c(reasons, "unusual_hours")
        }
        
        # Check for mass export attempts
        if (action_type == "export") {
          recent_exports <- dbGetQuery(.db_pool,
            "SELECT COUNT(*) as count 
             FROM data_access_log 
             WHERE user_id = $1 
             AND action_type = 'export' 
             AND timestamp > (CURRENT_TIMESTAMP - INTERVAL '1 hour')",
            params = list(user_id)
          )
          
          if (recent_exports$count[1] > 5) {
            suspicion_level <- suspicion_level + 2
            reasons <- c(reasons, "mass_export_attempts")
          }
        }
        
      }, error = function(e) {
        log_event(paste("User activity analysis error:", e$message), "ERROR")
      })
    }
  }
  
  return(list(
    suspicion_level = suspicion_level,
    is_suspicious = suspicion_level >= 3,
    reasons = reasons
  ))
}

#' Input validation for file uploads
#' @param file_info File information from Shiny fileInput
#' @return List with validation result
validate_file_upload <- function(file_info) {
  if (is.null(file_info) || nrow(file_info) == 0) {
    return(list(valid = FALSE, error = "Nenhum arquivo selecionado"))
  }
  
  # Check file size (max 10MB)
  max_size <- 10 * 1024 * 1024  # 10MB in bytes
  if (file_info$size > max_size) {
    return(list(valid = FALSE, error = "Arquivo muito grande (máximo 10MB)"))
  }
  
  # Check file extension
  allowed_extensions <- c(".csv", ".txt", ".json", ".pdf")
  file_ext <- tolower(tools::file_ext(file_info$name))
  
  if (!paste0(".", file_ext) %in% allowed_extensions) {
    return(list(
      valid = FALSE, 
      error = paste("Tipo de arquivo não permitido. Permitidos:", 
                   paste(allowed_extensions, collapse = ", "))
    ))
  }
  
  # Basic file content validation
  tryCatch({
    # Read first few bytes to check for suspicious content
    file_content <- readBin(file_info$datapath, "raw", n = 1024)
    
    # Check for executable signatures
    if (length(file_content) >= 2) {
      # MZ header (Windows executable)
      if (file_content[1] == 0x4D && file_content[2] == 0x5A) {
        return(list(valid = FALSE, error = "Arquivo executável não permitido"))
      }
      
      # ELF header (Linux executable) 
      if (length(file_content) >= 4 && 
          file_content[1] == 0x7F && file_content[2] == 0x45 && 
          file_content[3] == 0x4C && file_content[4] == 0x46) {
        return(list(valid = FALSE, error = "Arquivo executável não permitido"))
      }
    }
    
    return(list(valid = TRUE))
    
  }, error = function(e) {
    return(list(valid = FALSE, error = "Erro ao validar arquivo"))
  })
}

#' Initialize security hardening
init_security_hardening <- function() {
  tryCatch({
    # Set secure session options
    options(shiny.port = Sys.getenv("PORT", 3838))
    
    # Enable security features
    if (.security_config$xss_protection) {
      options(shiny.sanitize.errors = TRUE)
    }
    
    # Initialize rate limiting cleanup
    # (In production, use Redis with TTL)
    
    log_event("Security hardening initialized")
    return(TRUE)
    
  }, error = function(e) {
    log_event(paste("Security hardening initialization error:", e$message), "ERROR")
    return(FALSE)
  })
}

#' Clean up rate limiting data periodically
cleanup_rate_limiting <- function() {
  current_time <- as.numeric(Sys.time())
  window_start <- current_time - .security_config$rate_limit_window
  
  # Remove expired entries
  all_keys <- ls(envir = .rate_limit_store)
  
  for (key in all_keys) {
    request_times <- get(key, envir = .rate_limit_store)
    
    # Filter out old requests
    valid_requests <- request_times[request_times > window_start]
    
    if (length(valid_requests) == 0) {
      rm(list = key, envir = .rate_limit_store)
    } else {
      assign(key, valid_requests, envir = .rate_limit_store)
    }
  }
}

# Utility function for null coalescing
`%||%` <- function(a, b) {
  if (is.null(a)) b else a
}

log_event("Security Hardening Module loaded - CSRF, Rate limiting, Input validation")