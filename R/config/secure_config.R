# secure_config.R - Secure Configuration Management
# ============================================================================
# Purpose: Load secrets from environment variables with validation and fallback
# Created: 2025
# ============================================================================

library(digest)

#' Get configuration value from environment or use default
#'
#' @param key Environment variable name
#' @param default Default value if env var not found
#' @param required Whether the value is required (will error if missing)
#' @param mask Whether to mask the value in logs
#' @return Configuration value
get_config <- function(key, default = NULL, required = FALSE, mask = FALSE) {
  value <- Sys.getenv(key, unset = NA)

  if (is.na(value) || value == "") {
    if (required && is.null(default)) {
      stop(sprintf("Required configuration '%s' not found in environment", key))
    }
    value <- default
  }

  # Log configuration loading (with masking for sensitive values)
  if (mask && !is.null(value)) {
    cat(sprintf("✓ Loaded %s: ***MASKED***\n", key))
  } else if (!is.null(value)) {
    cat(sprintf("✓ Loaded %s\n", key))
  }

  return(value)
}

#' Load database configuration from environment
#'
#' @return List with database connection parameters
get_db_config <- function() {
  list(
    host = get_config("DB_HOST", "localhost"),
    port = as.numeric(get_config("DB_PORT", "5432")),
    dbname = get_config("DB_NAME", "railway"),
    user = get_config("DB_USER", "postgres"),
    password = get_config("DB_PASSWORD", required = TRUE, mask = TRUE)
  )
}

#' Load authentication credentials from environment
#'
#' @return List of user credentials with hashed passwords
get_auth_credentials <- function() {
  # Check for custom auth configuration file
  auth_config_file <- get_config("AUTH_CONFIG_FILE")

  if (!is.null(auth_config_file) && file.exists(auth_config_file)) {
    # Load from external file (JSON or R source)
    if (endsWith(auth_config_file, ".json")) {
      return(jsonlite::fromJSON(auth_config_file))
    } else if (endsWith(auth_config_file, ".R")) {
      source(auth_config_file, local = TRUE)
      if (exists("auth_credentials")) {
        return(auth_credentials)
      }
    }
  }

  # Load from environment variables
  credentials <- list()

  # Admin user
  admin_pass <- get_config("AUTH_ADMIN_PASSWORD", required = TRUE, mask = TRUE)
  credentials[["admin"]] <- list(
    password_hash = digest(admin_pass, algo = "sha256"),
    role = "admin",
    name = get_config("AUTH_ADMIN_NAME", "Administrator")
  )

  # Researcher user (optional)
  researcher_pass <- get_config("AUTH_RESEARCHER_PASSWORD", mask = TRUE)
  if (!is.null(researcher_pass)) {
    credentials[["researcher"]] <- list(
      password_hash = digest(researcher_pass, algo = "sha256"),
      role = "user",
      name = get_config("AUTH_RESEARCHER_NAME", "Researcher")
    )
  }

  # Student user (optional)
  student_pass <- get_config("AUTH_STUDENT_PASSWORD", mask = TRUE)
  if (!is.null(student_pass)) {
    credentials[["student"]] <- list(
      password_hash = digest(student_pass, algo = "sha256"),
      role = "user",
      name = get_config("AUTH_STUDENT_NAME", "Student")
    )
  }

  return(credentials)
}

#' Load API keys from environment or external source
#'
#' @return List of API key configurations
get_api_keys <- function() {
  # Check for external API key configuration
  api_keys_file <- get_config("API_KEYS_FILE")

  if (!is.null(api_keys_file) && file.exists(api_keys_file)) {
    # Load from external file
    if (endsWith(api_keys_file, ".json")) {
      return(jsonlite::fromJSON(api_keys_file))
    } else if (endsWith(api_keys_file, ".R")) {
      source(api_keys_file, local = TRUE)
      if (exists("api_keys")) {
        return(api_keys)
      }
    }
  }

  # Load from environment variables
  keys <- list()

  # Parse comma-separated API keys from environment
  api_keys_str <- get_config("API_KEYS")
  if (!is.null(api_keys_str)) {
    key_list <- strsplit(api_keys_str, ",")[[1]]
    for (key_def in key_list) {
      # Format: key:name:tier:rate_limit:quota:permissions
      parts <- strsplit(trimws(key_def), ":")[[1]]
      if (length(parts) >= 3) {
        key_id <- parts[1]
        keys[[key_id]] <- list(
          name = parts[2],
          tier = parts[3],
          rate_limit_per_minute = if(length(parts) >= 4) as.numeric(parts[4]) else 100,
          quota_per_day = if(length(parts) >= 5) as.numeric(parts[5]) else 10000,
          permissions = if(length(parts) >= 6) strsplit(parts[6], ";")[[1]] else c("read"),
          created_at = Sys.time(),
          last_used = NULL,
          usage_count = 0
        )
      }
    }
  }

  # If no keys configured, return default demo key with warning
  if (length(keys) == 0) {
    warning("No API keys configured in environment. Using demo key for development only!")
    keys[["demo_development_only"]] <- list(
      name = "Development Demo Key",
      tier = "demo",
      rate_limit_per_minute = 10,
      quota_per_day = 100,
      permissions = c("read"),
      created_at = Sys.time(),
      last_used = NULL,
      usage_count = 0
    )
  }

  return(keys)
}

#' Mask sensitive values in logs
#'
#' @param text Text that may contain sensitive values
#' @param patterns Regex patterns to match sensitive data
#' @return Text with sensitive values masked
mask_sensitive <- function(text, patterns = NULL) {
  if (is.null(patterns)) {
    patterns <- c(
      # PostgreSQL connection strings
      "password=([^\\s;]+)" = "password=***MASKED***",
      # API keys
      "api[_-]?key['\"]?\\s*[:=]\\s*['\"]?([^'\"\\s]+)" = "api_key=***MASKED***",
      # Bearer tokens
      "Bearer\\s+([A-Za-z0-9+/=]+)" = "Bearer ***MASKED***"
    )
  }

  result <- text
  for (pattern in names(patterns)) {
    result <- gsub(pattern, patterns[[pattern]], result, ignore.case = TRUE, perl = TRUE)
  }

  return(result)
}

#' Validate environment configuration
#'
#' @return TRUE if all required configurations are present
validate_config <- function() {
  errors <- character()

  # Check database configuration
  db_config <- tryCatch(get_db_config(), error = function(e) NULL)
  if (is.null(db_config)) {
    errors <- c(errors, "Database configuration incomplete")
  }

  # Check authentication configuration
  auth_config <- tryCatch(get_auth_credentials(), error = function(e) NULL)
  if (is.null(auth_config) || length(auth_config) == 0) {
    errors <- c(errors, "Authentication configuration incomplete")
  }

  # Report results
  if (length(errors) > 0) {
    cat("❌ Configuration validation failed:\n")
    for (error in errors) {
      cat(sprintf("  - %s\n", error))
    }
    return(FALSE)
  }

  cat("✅ Configuration validation successful\n")
  return(TRUE)
}