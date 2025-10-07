# Global Configuration and Initialization - Monitor Legislativo v4
# ==================================================================
# Clean Architecture - No Emergency Patches
# LGPD Compliant | Brazilian Legal Context | Railway Optimized

# Ensure utils are sourced early
safely_source <- function(path) if (file.exists(path)) source(path, chdir = TRUE, local = TRUE)
safely_source("R/utils/scalar_utils.R")
safely_source("R/utils/ui_utils.R")

# AGGRESSIVE DEBUGGING: Force full stacktrace + module name on error
options(
  shiny.sanitize.errors = FALSE,
  shiny.fullstacktrace = TRUE,
  shiny.error = function(e) {
    # Capture enhanced stack information
    calls <- sys.calls()
    frames <- sys.frames()

    # Multiple strategies to identify the problematic reactive/output
    outname <- "unknown"
    for (i in length(frames):1) {
      frame <- frames[[i]]
      # Check for Shiny output name patterns
      if (exists("..name", envir = frame, inherits = FALSE)) {
        outname <- get("..name", envir = frame)
        break
      }
      if (exists("name", envir = frame, inherits = FALSE)) {
        name_val <- get("name", envir = frame)
        if (is.character(name_val) && length(name_val) == 1) {
          outname <- name_val
          break
        }
      }
      # Check for renderXX function calls
      if (length(calls) >= i && length(calls[[i]]) > 0) {
        call_text <- deparse(calls[[i]])
        if (grepl("render(Plot|Table|Text|UI|ValueBox)", call_text)) {
          outname <- paste0("render_call_", i)
          break
        }
      }
    }

    # Clean, readable error output
    cat("\n=====================================\n", file = stderr())
    cat("[SCALAR ERROR]\n", file = stderr())
    cat(paste0("  output = ", outname, "\n"), file = stderr())
    cat(paste0("  message = ", conditionMessage(e), "\n"), file = stderr())

    # Try to get the failing call
    failing_call <- tryCatch({
      call_str <- deparse(conditionCall(e), width.cutoff = 100L)
      if (length(call_str) > 0 && nzchar(call_str[1])) {
        paste(call_str, collapse = " ")
      } else {
        "N/A"
      }
    }, error = function(err) "N/A")
    cat(paste0("  call = ", failing_call, "\n"), file = stderr())

    cat("\nCall stack (recent first):\n", file = stderr())
    for (i in min(length(calls), 10):max(1, length(calls) - 20)) {
      call_str <- tryCatch(
        paste0(deparse(calls[[i]], width.cutoff = 80L), collapse = " "),
        error = function(err) "<unprintable>"
      )
      cat(paste0("  ", i, ": ", call_str, "\n"), file = stderr())
    }
    cat("=====================================\n\n", file = stderr())
    stop(e)
  }
)

# Show full errors in production while we diagnose (toggle with env var)
if (identical(Sys.getenv("DEBUG_ERRORS", "0"), "1")) {
  options(
    shiny.sanitize.errors = FALSE,           # show real error text in UI
    shiny.fullstacktrace  = TRUE,
    shiny.error = function(e) {
      ts  <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")
      msg <- sprintf("[%s] FATAL UI ERROR: %s\n", ts, conditionMessage(e))
      cat(msg, file = stderr())
      utils::writeLines(c(msg, utils::capture.output(sys.calls())), stderr())
      # Optionally show a user-friendly banner:
      shiny::showNotification("Erro interno — logs atualizados.", type = "error", duration = 10)
    }
  )
}

# Also keep the original APP_DEBUG flag for compatibility
if (identical(Sys.getenv("APP_DEBUG"), "1")) {
  options(
    shiny.fullstacktrace = TRUE,
    shiny.sanitize.errors = FALSE,
    shiny.traceback.lines = 60L,
    shiny.error = function() { traceback(2) }
  )
}

# ---- Load unified scalar utilities (SINGLE SOURCE OF TRUTH) ----
source("R/utils/scalar_utils.R", local = TRUE)

# Additional comparison helper (uses scalar utilities internally)
safe_compare <- function(x, y, op = ">", default = FALSE) {
  x_val <- scalar(x, default = NULL)
  if (is.null(x_val)) return(default)
  switch(op,
    ">" = isTRUE(x_val > y),
    ">=" = isTRUE(x_val >= y),
    "<" = isTRUE(x_val < y),
    "<=" = isTRUE(x_val <= y),
    "==" = isTRUE(x_val == y),
    "!=" = isTRUE(x_val != y),
    default
  )
}

safe_subset <- function(x, condition, default = NULL) {
  if (is.null(x) || !is.data.frame(x) || nrow(x) == 0) return(default)
  tryCatch(x[condition, , drop = FALSE], error = function(e) default)
}

# Environment flags
ENABLE_QUERY_MONITORING <- tolower(Sys.getenv("ENABLE_QUERY_MONITORING", "false")) %in% c("1","true","yes")

# Ensure our UI helpers are available everywhere
source("R/utils/ui_utils.R", local = TRUE)

# ESSENTIAL PACKAGES
# ==================
library(shiny)
library(shinydashboard)
library(DT)
library(plotly)
library(dplyr)
library(RColorBrewer)
library(DBI)
library(RPostgres)  # Use RPostgres instead of RPostgreSQL
library(pool)
library(readr)
library(stringr)

# CRITICAL FEATURE PACKAGES
# =========================
# These packages power core application features and must be available
library(jsonlite)   # JSON parsing for APIs and data export
library(lubridate)  # Date/time manipulation for temporal analytics
library(httr)       # HTTP client for external API integrations
library(leaflet)    # Interactive maps (Geographic Analysis + Interactive Maps tabs)
library(sf)         # Spatial data operations (geospatial analysis)
library(geobr)      # Brazilian geographic boundaries from IBGE
library(htmltools)  # HTML generation for custom UI components

cat("Core packages loaded\n")

# OPTIONAL PACKAGES WITH GRACEFUL DEGRADATION
# ============================================
# These packages improve performance/UX but app functions without them
optional_packages <- c("data.table", "scales", "shinyjs")

for (pkg in optional_packages) {
  tryCatch({
    suppressPackageStartupMessages(library(pkg, character.only = TRUE))
    cat("✓ Optional package loaded:", pkg, "\n")
  }, error = function(e) {
    cat("⚠ Optional package", pkg, "not available (non-critical)\n")
  })
}

cat("Optional packages processed\n")

# Ensure DB helpers are loaded and pool initialized
source("R/utils/database_utils.R", local = TRUE)
init_db_pool()

# LOAD DATA SERVICE MODULE
# ========================
source("modules/data_service.R")
data_service <- local(source("modules/data_service.R")$value)
cat("Data service module loaded\n")

# Export database pool for other modules
tryCatch({
  if (exists("db_connection_pool") && !is.null(db_connection_pool)) {
    options(app_db_pool = db_connection_pool)
  } else if (exists("get_db_connection") && is.function(get_db_connection)) {
    pool_obj <- get_db_connection()
    if (!is.null(pool_obj)) {
      options(app_db_pool = pool_obj)
    } else {
      options(app_db_pool = NULL)
    }
  } else {
    options(app_db_pool = NULL)
  }
}, error = function(e) {
  options(app_db_pool = NULL)
  cat("Warning: Could not export database pool:", e$message, "\n")
})

# LOAD UTILITY MODULES
# ====================
module_files <- c(
  "R/utils/database_utils.R",
  "R/utils/api_utils.R",
  "R/utils/validation_utils.R",
  "R/utils/cache_utils.R",
  "R/utils/ui_utils.R"
)

for (module_file in module_files) {
  if (file.exists(module_file)) {
    tryCatch({
      source(module_file, local = FALSE)
      cat("Loaded:", module_file, "\n")
    }, error = function(e) {
      cat("Failed to load", module_file, ":", e$message, "\n")
    })
  }
}

# Global hammer: mask valueBox to prevent length-0 crashes
if (exists("safe_valueBox") && is.function(safe_valueBox)) {
  valueBox <- safe_valueBox
  cat("✅ Global valueBox masking applied for crash prevention\n")
}

# LOAD SYSTEM MODULES
# ===================

# Monitoring and Logging System
monitoring_enabled <- FALSE
tryCatch({
  if (file.exists("monitoring/logger.R")) {
    source("monitoring/logger.R")
    source("monitoring/app_monitor.R")
    source("monitoring/telemetry.R")
    source("monitoring/monitoring_ui.R")

    # Initialize monitoring systems
    init_logger(list(
      enabled = TRUE,
      railway_compatible = TRUE,
      sanitize_sensitive = TRUE
    ))

    init_telemetry()
    # start_monitoring()  # Temporarily disabled - causing 10min hangs
    log_app_start()

    monitoring_enabled <- TRUE
    log_info("Monitoring and logging system initialized")
  }
}, error = function(e) {
  cat("Monitoring system initialization failed:", e$message, "\n")
})

# Health Check System
if (file.exists("health_check.R")) {
  tryCatch({
    source("health_check.R")
    cat("Health check system loaded\n")
  }, error = function(e) {
    cat("Health check system loading failed:", e$message, "\n")
  })
}

# Authentication System
auth_enabled <- as.logical(Sys.getenv("AUTH_ENABLED", "FALSE"))
if (auth_enabled && file.exists("modules/authentication.R")) {
  tryCatch({
    source("modules/authentication.R")
    cat("Authentication system loaded\n")
  }, error = function(e) {
    cat("Authentication system loading failed:", e$message, "\n")
  })
}

# CONFIGURATION
# =============
app_config <- list(
  app_title = "Monitor Legislativo v4",
  app_version = "4.0.0",
  environment = Sys.getenv("RAILWAY_ENVIRONMENT", "development"),
  max_file_size = 50 * 1024^2,  # 50MB
  session_timeout = 30 * 60,     # 30 minutes
  cache_ttl = 300,               # 5 minutes
  enable_debug = Sys.getenv("ENABLE_DEBUG", "FALSE") == "TRUE",
  auth_enabled = auth_enabled,
  monitoring_enabled = monitoring_enabled,
  use_demo_data = FALSE  # Production always uses real data
)

# SECURITY CONFIGURATION
# ======================
security_config <- list(
  session_cookie_secure = TRUE,
  session_cookie_httponly = TRUE,
  session_cookie_samesite = "Strict",
  content_security_policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
  x_frame_options = "DENY",
  x_content_type_options = "nosniff",
  strict_transport_security = "max-age=31536000; includeSubDomains"
)

# DATABASE CONNECTION CONFIGURATION
# ==================================
db_config <- list(
  host = Sys.getenv("PGHOST", "localhost"),
  port = as.integer(Sys.getenv("PGPORT", "5432")),
  dbname = Sys.getenv("PGDATABASE", "railway"),
  user = Sys.getenv("PGUSER", "postgres"),
  password = Sys.getenv("PGPASSWORD", ""),
  ssl_mode = Sys.getenv("PGSSLMODE", "require"),
  connection_timeout = 10,
  query_timeout = 30
)

# GLOBAL FUNCTIONS
# ================

# Main data retrieval function - delegates to data service
get_documents <- function(...) {
  data_service$get_documents(...)
}

# Analytics data function - delegates to data service
get_analytics_data <- function() {
  data_service$get_analytics_data()
}

# Chart preparation function - delegates to data service
prepare_chart_data <- function(...) {
  data_service$prepare_chart_data(...)
}

# Dashboard metrics function
get_lexml_dashboard_metrics <- function() {
  tryCatch({
    # Get actual metrics from data service
    data <- get_documents(limit = 1000)

    # Handle NULL or empty data safely
    if (!is.null(data) && is.data.frame(data) && nrow(data) > 0) {
      # Calculate real metrics
      # Get total count safely
      total_count <- tryCatch({
        full_data <- get_documents()
        if (!is.null(full_data) && is.data.frame(full_data)) {
          scalar_int(nrow(full_data), default = 0)
        } else {
          0
        }
      }, error = function(e) 0)

      # Safe column access with fallbacks and NA handling
      states <- if ("state" %in% names(data) && !is.null(data$state)) {
        unique(data$state[!is.na(data$state)])
      } else {
        character(0)
      }
      municipalities <- if ("municipality" %in% names(data) && !is.null(data$municipality)) {
        unique(data$municipality[!is.na(data$municipality)])
      } else {
        character(0)
      }

      # Safe date range calculation
      date_range_years <- tryCatch({
        if ("date" %in% names(data)) {
          dates <- as.Date(data$date)
          dates <- dates[!is.na(dates)]
          if (length(dates) > 1) {
            scalar_num(as.numeric(difftime(max(dates), min(dates), units = "days")) / 365.25, default = 0)
          } else {
            0
          }
        } else {
          0
        }
      }, error = function(e) 0)

      metrics <- list(
        total_documents = scalar_int(total_count, default = 0),
        states_with_docs = scalar_int(length(states), default = 0),
        municipalities_with_docs = scalar_int(length(municipalities), default = 0),
        states_percentage = scalar_num((length(states) / 27) * 100, default = 0),
        municipalities_percentage = scalar_num((length(municipalities) / 5570) * 100, default = 0),
        date_range_years = scalar_num(date_range_years, default = 0),
        last_updated = Sys.time(),
        data_source = if (isTRUE(app_config$use_demo_data)) "demo" else "production",
        connection_status = "operational"
      )
    } else {
      # Return minimal metrics if no data
      metrics <- list(
        total_documents = 0,
        states_with_docs = 0,
        municipalities_with_docs = 0,
        states_percentage = 0,
        municipalities_percentage = 0,
        date_range_years = 0,
        last_updated = Sys.time(),
        data_source = "none",
        connection_status = "no_data"
      )
    }

    return(metrics)

  }, error = function(e) {
    if (monitoring_enabled) {
      log_error(paste("Error calculating dashboard metrics:", e$message))
    }

    # Return error state metrics
    return(list(
      total_documents = 0,
      states_with_docs = 0,
      municipalities_with_docs = 0,
      states_percentage = 0,
      municipalities_percentage = 0,
      date_range_years = 0,
      last_updated = Sys.time(),
      data_source = "error",
      connection_status = "error"
    ))
  })
}

# Utility function for safe numeric conversion
safe_numeric <- function(x, default = 0) {
  result <- suppressWarnings(as.numeric(x))
  if (is.null(result) || length(result) == 0 || is.na(result)) return(default)
  result
}

# Utility function for safe date conversion
safe_date <- function(x, format = "%Y-%m-%d") {
  tryCatch(
    as.Date(x, format = format),
    error = function(e) NA
  )
}

# Export configuration for use in app
assign("app_config", app_config, envir = .GlobalEnv)
assign("security_config", security_config, envir = .GlobalEnv)
assign("db_config", db_config, envir = .GlobalEnv)

cat("\n========================================\n")
cat("Monitor Legislativo v4 - Global Configuration Loaded\n")
cat("Environment:", app_config$environment, "\n")
cat("Version:", app_config$app_version, "\n")
cat("Demo Mode:", app_config$use_demo_data, "\n")
cat("Auth Enabled:", app_config$auth_enabled, "\n")
cat("Monitoring:", ifelse(monitoring_enabled, "Enabled", "Disabled"), "\n")
cat("========================================\n\n")