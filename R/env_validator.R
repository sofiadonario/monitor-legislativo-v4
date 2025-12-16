# Environment Variable Validation and Configuration Module
# =========================================================
# This module handles environment variable validation, defaults, and error reporting
# for the Monitor Legislativo v4 application

# Define required and optional environment variables
ENV_CONFIG <- list(
  # Critical database variables (required for database mode)
  database = list(
    DATABASE_URL = list(
      required = FALSE,  # Not required if using CSV fallback
      description = "Primary PostgreSQL connection string",
      example = "postgresql://user:pass@host:port/dbname"
    ),
    DATABASE_PUBLIC_URL = list(
      required = FALSE,
      description = "Cloud SQL public connection string (TCP)",
      example = "postgresql://user:pass@public-ip:5432/dbname"
    ),
    DATABASE_PRIVATE_URL = list(
      required = FALSE,
      description = "Cloud SQL private connection string (internal)",
      example = "postgresql://user:pass@/cloudsql/project:region:instance/dbname"
    ),
    PGHOST = list(
      required = FALSE,
      description = "PostgreSQL host",
      default = function() {
        # Try to extract from DATABASE_URL if available
        url <- Sys.getenv("DATABASE_URL")
        if (url != "") {
          parsed <- regmatches(url, regexpr("@([^:]+):", url))
          if (length(parsed) > 0) {
            return(gsub("[@:]", "", parsed))
          }
        }
        return("")
      }
    ),
    PGPORT = list(
      required = FALSE,
      description = "PostgreSQL port",
      default = function() {
        url <- Sys.getenv("DATABASE_URL")
        if (url != "") {
          parsed <- regmatches(url, regexpr(":([0-9]+)/", url))
          if (length(parsed) > 0) {
            return(gsub("[:/]", "", parsed))
          }
        }
        return("5432")
      }
    ),
    PGDATABASE = list(
      required = FALSE,
      description = "PostgreSQL database name",
      default = function() {
        url <- Sys.getenv("DATABASE_URL")
        if (url != "") {
          parsed <- regmatches(url, regexpr("/([^?]+)", url))
          if (length(parsed) > 0) {
            return(gsub("/", "", parsed[length(parsed)]))
          }
        }
        return("railway")
      }
    ),
    PGUSER = list(
      required = FALSE,
      description = "PostgreSQL username",
      default = function() {
        url <- Sys.getenv("DATABASE_URL")
        if (url != "") {
          parsed <- regmatches(url, regexpr("//([^:]+):", url))
          if (length(parsed) > 0) {
            return(gsub("[/:]", "", parsed))
          }
        }
        return("postgres")
      }
    ),
    PGPASSWORD = list(
      required = FALSE,
      description = "PostgreSQL password",
      default = function() {
        url <- Sys.getenv("DATABASE_URL")
        if (url != "") {
          parsed <- regmatches(url, regexpr(":([^@]+)@", url))
          if (length(parsed) > 0) {
            user_pass <- gsub("[:@]", "", parsed)
            # Extract password part after username
            parts <- strsplit(user_pass, ":")[[1]]
            if (length(parts) > 1) {
              return(parts[2])
            }
          }
        }
        return("")
      }
    )
  ),

  # Cloud Run-specific variables
  cloud_run = list(
    PORT = list(
      required = TRUE,
      description = "Port for the Shiny application",
      default = function() "8080"
    ),
    K_SERVICE = list(
      required = FALSE,
      description = "Cloud Run service name",
      default = function() ""
    ),
    GOOGLE_CLOUD_PROJECT = list(
      required = FALSE,
      description = "Google Cloud project ID",
      default = function() ""
    )
  ),

  # Application configuration
  app = list(
    R_CONFIG_ACTIVE = list(
      required = FALSE,
      description = "R configuration profile",
      default = function() "production"
    ),
    R_MAX_MEM_SIZE = list(
      required = FALSE,
      description = "Maximum memory allocation for R",
      default = function() "2000M"
    ),
    CACHE_TTL = list(
      required = FALSE,
      description = "Cache time-to-live in seconds",
      default = function() "3600"
    )
  ),

  # Redis configuration (optional)
  redis = list(
    REDIS_URL = list(
      required = FALSE,
      description = "Redis connection URL for caching",
      default = function() ""
    )
  )
)

# Function to validate environment variables
validate_environment <- function(mode = "production") {
  cat("\n=== Environment Variable Validation ===\n")
  cat("Mode:", mode, "\n\n")

  validation_results <- list(
    valid = TRUE,
    errors = character(),
    warnings = character(),
    database_available = FALSE,
    redis_available = FALSE,
    csv_fallback_needed = FALSE
  )

  # Check each category of variables
  for (category_name in names(ENV_CONFIG)) {
    cat(sprintf("Checking %s variables:\n", category_name))
    category <- ENV_CONFIG[[category_name]]

    for (var_name in names(category)) {
      var_config <- category[[var_name]]
      current_value <- Sys.getenv(var_name)

      # Check if variable is set
      if (current_value == "") {
        # Try to set default value if available
        if (!is.null(var_config$default)) {
          default_value <- var_config$default()
          if (default_value != "") {
            Sys.setenv(.env = setNames(list(default_value), var_name))
            cat(sprintf("  %s %s: Set to default value\n", "✓", var_name))
          } else if (var_config$required) {
            validation_results$errors <- c(
              validation_results$errors,
              sprintf("%s is required but not set. %s", var_name, var_config$description)
            )
            validation_results$valid <- FALSE
            cat(sprintf("  %s %s: MISSING (required)\n", "✗", var_name))
          } else {
            validation_results$warnings <- c(
              validation_results$warnings,
              sprintf("%s not set (optional). %s", var_name, var_config$description)
            )
            cat(sprintf("  %s %s: Not set (optional)\n", "⚠", var_name))
          }
        } else if (var_config$required) {
          validation_results$errors <- c(
            validation_results$errors,
            sprintf("%s is required but not set. %s", var_name, var_config$description)
          )
          validation_results$valid <- FALSE
          cat(sprintf("  %s %s: MISSING (required)\n", "✗", var_name))
        } else {
          cat(sprintf("  %s %s: Not set (optional)\n", "⚠", var_name))
        }
      } else {
        # Variable is set - mask sensitive values in output
        if (grepl("PASSWORD|SECRET|KEY", var_name, ignore.case = TRUE)) {
          display_value <- "***MASKED***"
        } else {
          display_value <- substr(current_value, 1, 50)
          if (nchar(current_value) > 50) {
            display_value <- paste0(display_value, "...")
          }
        }
        cat(sprintf("  %s %s: %s\n", "✓", var_name, display_value))
      }
    }
    cat("\n")
  }

  # Special checks for Cloud SQL database availability
  database_urls <- c(
    Sys.getenv("DATABASE_PUBLIC_URL"),
    Sys.getenv("DATABASE_PRIVATE_URL"),
    Sys.getenv("DATABASE_URL")
  )

  available_urls <- database_urls[database_urls != ""]

  if (length(available_urls) > 0) {
    validation_results$database_available <- TRUE
    cat("✅ Database configuration detected (", length(available_urls), "connection options)\n")

    # Validate Cloud SQL-specific database URLs
    cloud_sql_validation <- validate_cloud_sql_database_urls(available_urls)
    if (!cloud_sql_validation$valid) {
      validation_results$warnings <- c(
        validation_results$warnings,
        cloud_sql_validation$warnings
      )
    }
  } else {
    validation_results$csv_fallback_needed <- TRUE
    cat("⚠️ No database URLs configured - will use CSV fallback\n")
  }

  # Check for Redis
  if (Sys.getenv("REDIS_URL") != "") {
    validation_results$redis_available <- TRUE
    cat("✅ Redis caching available\n")
  } else {
    cat("ℹ️ Redis not configured - using in-memory caching\n")
  }

  # Summary
  cat("\n=== Validation Summary ===\n")
  if (validation_results$valid) {
    cat("✅ All required environment variables are configured\n")
  } else {
    cat("❌ Missing required environment variables:\n")
    for (error in validation_results$errors) {
      cat("  -", error, "\n")
    }
  }

  if (length(validation_results$warnings) > 0) {
    cat("\n⚠️ Optional configurations:\n")
    for (warning in validation_results$warnings) {
      cat("  -", warning, "\n")
    }
  }

  cat("\n")
  return(validation_results)
}

# Function to get safe environment variable with fallback
get_env_var <- function(name, default = "", required = FALSE) {
  value <- Sys.getenv(name)

  if (value == "") {
    if (required) {
      stop(sprintf("Required environment variable %s is not set", name))
    }
    return(default)
  }

  return(value)
}

# Function to display environment help
show_env_help <- function() {
  cat("\n=== Environment Variable Configuration Help ===\n\n")

  cat("To configure your Railway deployment, set these environment variables:\n\n")

  for (category_name in names(ENV_CONFIG)) {
    cat(sprintf("## %s Configuration\n", tools::toTitleCase(category_name)))
    category <- ENV_CONFIG[[category_name]]

    for (var_name in names(category)) {
      var_config <- category[[var_name]]
      required_text <- if (var_config$required) "[REQUIRED]" else "[OPTIONAL]"
      cat(sprintf("\n%s %s\n", var_name, required_text))
      cat(sprintf("  Description: %s\n", var_config$description))
      if (!is.null(var_config$example)) {
        cat(sprintf("  Example: %s\n", var_config$example))
      }
    }
    cat("\n")
  }

  cat("## Setting Variables in Cloud Run\n")
  cat("1. Go to Google Cloud Console\n")
  cat("2. Navigate to Cloud Run > Services\n")
  cat("3. Select your service and click 'Edit & Deploy New Revision'\n")
  cat("4. Navigate to the 'Variables & Secrets' tab\n")
  cat("5. Add each variable with its value\n")
  cat("6. Deploy the new revision\n\n")

  cat("## Local Development\n")
  cat("Create a .env file in your project root with:\n")
  cat("DATABASE_URL=your_connection_string\n")
  cat("PORT=3838\n")
  cat("... other variables\n\n")
}

# Validate Cloud SQL-specific database URLs
validate_cloud_sql_database_urls <- function(urls) {
  cat("🔍 Validating Cloud SQL database URLs...\n")

  validation_result <- list(
    valid = TRUE,
    warnings = character(),
    url_info = list()
  )

  for (i in seq_along(urls)) {
    url <- urls[i]
    cat("🔗 Checking URL", i, "...\n")

    # Parse the URL
    parsed <- tryCatch({
      # Basic PostgreSQL URL pattern
      pattern <- "postgresql://([^:]+):([^@]+)@([^:]+):(\\d+)/(.+)"
      matches <- regmatches(url, regexec(pattern, url))[[1]]

      if (length(matches) == 6) {
        list(
          user = matches[2],
          password = matches[3],
          host = matches[4],
          port = as.numeric(matches[5]),
          database = matches[6],
          valid = TRUE
        )
      } else {
        list(valid = FALSE, error = "Invalid PostgreSQL URL format")
      }
    }, error = function(e) {
      list(valid = FALSE, error = e$message)
    })

    if (parsed$valid) {
      cat("  ✅ Host:", parsed$host, "Port:", parsed$port, "\n")
      cat("  🗄️ Database:", parsed$database, "User:", parsed$user, "\n")

      # Check for Cloud SQL-specific patterns
      if (grepl("cloudsql", parsed$host, ignore.case = TRUE)) {
        cat("  ☁️ Cloud SQL Unix socket connection detected\n")
      } else if (grepl("\\d+\\.\\d+\\.\\d+\\.\\d+", parsed$host)) {
        cat("  📡 Cloud SQL public IP connection detected\n")
      }

      # Validate port range
      if (parsed$port < 1024 || parsed$port > 65535) {
        validation_result$warnings <- c(
          validation_result$warnings,
          paste("Unusual port number:", parsed$port, "for URL", i)
        )
      }

      validation_result$url_info[[paste0("url_", i)]] <- parsed
    } else {
      validation_result$valid <- FALSE
      validation_result$warnings <- c(
        validation_result$warnings,
        paste("Invalid database URL", i, ":", parsed$error)
      )
      cat("  ❌ Invalid URL:", parsed$error, "\n")
    }
  }

  if (validation_result$valid) {
    cat("✅ All database URLs are valid\n")
  } else {
    cat("⚠️ Some database URLs have issues\n")
  }

  return(validation_result)
}

# Test Cloud SQL database connectivity
test_cloud_sql_database_connection <- function(urls) {
  cat("🧪 Testing Cloud SQL database connectivity...\n")

  if (!requireNamespace("RPostgres", quietly = TRUE)) {
    return(list(
      success = FALSE,
      error = "RPostgres package not available"
    ))
  }

  for (i in seq_along(urls)) {
    url <- urls[i]
    cat("🔌 Testing connection", i, "...\n")

    result <- tryCatch({
      # Parse URL
      pattern <- "postgresql://([^:]+):([^@]+)@([^:]+):(\\d+)/(.+)"
      matches <- regmatches(url, regexec(pattern, url))[[1]]

      if (length(matches) == 6) {
        # Attempt connection
        conn <- DBI::dbConnect(
          RPostgres::Postgres(),
          host = matches[4],
          port = as.numeric(matches[5]),
          dbname = matches[6],
          user = matches[2],
          password = matches[3],
          sslmode = "require",
          connect_timeout = 15
        )

        # Test query
        test_result <- DBI::dbGetQuery(conn, "SELECT current_database(), version()")
        DBI::dbDisconnect(conn)

        cat("  ✅ Connection successful\n")
        cat("  🗄️ Database:", test_result$current_database, "\n")

        return(list(
          success = TRUE,
          database = test_result$current_database,
          url_index = i
        ))
      } else {
        return(list(
          success = FALSE,
          error = "Invalid URL format",
          url_index = i
        ))
      }
    }, error = function(e) {
      cat("  ❌ Connection failed:", e$message, "\n")
      return(list(
        success = FALSE,
        error = e$message,
        url_index = i
      ))
    })

    if (result$success) {
      return(result)
    }
  }

  return(list(
    success = FALSE,
    error = "All connection attempts failed"
  ))
}

# Export functions
list(
  validate_environment = validate_environment,
  get_env_var = get_env_var,
  show_env_help = show_env_help,
  validate_cloud_sql_database_urls = validate_cloud_sql_database_urls,
  test_cloud_sql_database_connection = test_cloud_sql_database_connection,
  ENV_CONFIG = ENV_CONFIG
)