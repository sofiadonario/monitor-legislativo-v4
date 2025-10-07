# Railway Chart Logging System
# ============================
# Comprehensive logging system for chart debugging in production

cat("Loading Railway chart logging system...\n")

# Initialize logging system
CHART_LOG_STATE <- list(
  enabled = TRUE,
  start_time = Sys.time(),
  log_entries = list(),
  max_entries = 1000
)

# Enhanced logging function with timestamps
chart_log <- function(message, level = "INFO", component = "GENERAL") {
  if (!CHART_LOG_STATE$enabled) return()

  timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")
  formatted_message <- paste0("[", timestamp, "] [", level, "] [", component, "] ", message)

  # Print to console (visible in Railway logs)
  cat(formatted_message, "\n")

  # Store in memory (for diagnostic endpoint)
  if (length(CHART_LOG_STATE$log_entries) >= CHART_LOG_STATE$max_entries) {
    CHART_LOG_STATE$log_entries <<- CHART_LOG_STATE$log_entries[-1]
  }

  CHART_LOG_STATE$log_entries <<- append(CHART_LOG_STATE$log_entries, list(list(
    timestamp = Sys.time(),
    level = level,
    component = component,
    message = message
  )))
}

# Database operation logging
log_database_operation <- function(operation, success, details = "", execution_time = NULL) {
  level <- ifelse(success, "INFO", "ERROR")
  status <- ifelse(success, "SUCCESS", "FAILED")

  message <- paste0("DB_", operation, " ", status)
  if (details != "") {
    message <- paste0(message, " - ", details)
  }
  if (!is.null(execution_time)) {
    message <- paste0(message, " (", round(execution_time, 3), "s)")
  }

  chart_log(message, level, "DATABASE")
}

# Chart rendering logging
log_chart_operation <- function(chart_id, operation, success, details = "", data_rows = NULL) {
  level <- ifelse(success, "INFO", "ERROR")
  status <- ifelse(success, "SUCCESS", "FAILED")

  message <- paste0("CHART_", chart_id, "_", operation, " ", status)
  if (!is.null(data_rows)) {
    message <- paste0(message, " (", data_rows, " rows)")
  }
  if (details != "") {
    message <- paste0(message, " - ", details)
  }

  chart_log(message, level, "CHART")
}

# Data loading operation logging
log_data_operation <- function(source, operation, success, rows = NULL, details = "") {
  level <- ifelse(success, "INFO", "ERROR")
  status <- ifelse(success, "SUCCESS", "FAILED")

  message <- paste0("DATA_", source, "_", operation, " ", status)
  if (!is.null(rows)) {
    message <- paste0(message, " (", rows, " rows)")
  }
  if (details != "") {
    message <- paste0(message, " - ", details)
  }

  chart_log(message, level, "DATA")
}

# Performance monitoring
log_performance <- function(operation, start_time, end_time = NULL, details = "") {
  if (is.null(end_time)) end_time <- Sys.time()

  execution_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
  performance_level <- if (execution_time > 10) "WARN" else if (execution_time > 5) "INFO" else "DEBUG"

  message <- paste0("PERF_", operation, " completed in ", round(execution_time, 3), "s")
  if (details != "") {
    message <- paste0(message, " - ", details)
  }

  chart_log(message, performance_level, "PERFORMANCE")
}

# Memory usage logging
log_memory_usage <- function(component = "GENERAL") {
  tryCatch({
    memory_info <- gc()
    memory_mb <- sum(memory_info[, 2]) / 1024

    message <- paste0("Memory usage: ", round(memory_mb, 1), "MB")

    # Add warning for high memory usage
    level <- if (memory_mb > 1500) "WARN" else "INFO"

    chart_log(message, level, paste0("MEMORY_", component))
  }, error = function(e) {
    chart_log(paste("Failed to get memory info:", e$message), "ERROR", "MEMORY")
  })
}

# System health logging
log_system_health <- function() {
  chart_log("=== SYSTEM HEALTH CHECK ===", "INFO", "HEALTH")

  # Memory usage
  log_memory_usage("SYSTEM")

  # Database status
  if (exists("CONNECTION_STATE")) {
    db_status <- CONNECTION_STATE$status
    chart_log(paste("Database status:", db_status), "INFO", "HEALTH")
    if (!is.null(CONNECTION_STATE$document_count)) {
      chart_log(paste("Document count:", CONNECTION_STATE$document_count), "INFO", "HEALTH")
    }
  } else {
    chart_log("CONNECTION_STATE not found", "WARN", "HEALTH")
  }

  # Function availability
  critical_functions <- c("get_library_documents", "analytics_data_fixed_csv", "load_emergency_data")
  for (func in critical_functions) {
    exists_status <- exists(func)
    chart_log(paste("Function", func, ":", ifelse(exists_status, "AVAILABLE", "MISSING")),
             ifelse(exists_status, "INFO", "WARN"), "HEALTH")
  }

  # Package availability
  critical_packages <- c("plotly", "ggplot2", "dplyr", "leaflet", "DT")
  for (pkg in critical_packages) {
    available <- requireNamespace(pkg, quietly = TRUE)
    chart_log(paste("Package", pkg, ":", ifelse(available, "AVAILABLE", "MISSING")),
             ifelse(available, "INFO", "ERROR"), "HEALTH")
  }

  chart_log("=== END HEALTH CHECK ===", "INFO", "HEALTH")
}

# Create enhanced analytics data with comprehensive logging
create_logged_analytics_data <- function() {
  chart_log("Creating logged analytics data function", "INFO", "INIT")

  # Create non-reactive version first
  logged_analytics_data_function <<- function() {
    start_time <- Sys.time()
    chart_log("Analytics data function called", "INFO", "ANALYTICS")

    # Log memory usage at start
    log_memory_usage("ANALYTICS_START")

    docs <- NULL
    data_source <- "unknown"

    # Try database first
    if (exists("CONNECTION_STATE") && !is.null(CONNECTION_STATE$connection_pool) &&
        CONNECTION_STATE$status == "connected") {

      chart_log("Attempting database query", "INFO", "ANALYTICS")
      db_start <- Sys.time()

      docs <- tryCatch({
        result <- pool::dbGetQuery(CONNECTION_STATE$connection_pool, "
          SELECT
            titulo as title,
            ementa as summary,
            tipo as document_type,
            categoria as category,
            estado as state,
            municipio as municipality,
            data as date,
            EXTRACT(YEAR FROM data) as year,
            autoridade as authority
          FROM documents
          WHERE titulo IS NOT NULL AND titulo != ''
          ORDER BY data DESC
          LIMIT 10000
        ")

        log_database_operation("QUERY", TRUE, paste("Retrieved", nrow(result), "documents"),
                              as.numeric(difftime(Sys.time(), db_start, units = "secs")))

        if (nrow(result) > 0) {
          result$date <- as.Date(result$date)
          result$year <- as.numeric(result$year)
          data_source <- "database"
          result
        } else {
          log_database_operation("QUERY", FALSE, "No documents returned")
          NULL
        }
      }, error = function(e) {
        log_database_operation("QUERY", FALSE, e$message)
        NULL
      })
    } else {
      chart_log("Database not available, skipping", "WARN", "ANALYTICS")
    }

    # Try get_library_documents if database failed
    if (is.null(docs) || nrow(docs) == 0) {
      chart_log("Trying get_library_documents", "INFO", "ANALYTICS")

      if (exists("get_library_documents")) {
        docs <- tryCatch({
          lib_start <- Sys.time()
          result <- get_library_documents(limit = 10000)

          log_data_operation("LIBRARY", "QUERY", TRUE, nrow(result),
                           paste("Execution time:", round(as.numeric(difftime(Sys.time(), lib_start, units = "secs")), 3), "s"))

          if (!is.null(result) && nrow(result) > 0) {
            # Standardize columns
            if ("titulo" %in% names(result)) names(result)[names(result) == "titulo"] <- "title"
            if ("categoria" %in% names(result)) names(result)[names(result) == "categoria"] <- "category"

            data_source <- "library_function"
            result
          } else {
            log_data_operation("LIBRARY", "QUERY", FALSE, 0, "No data returned")
            NULL
          }
        }, error = function(e) {
          log_data_operation("LIBRARY", "QUERY", FALSE, NULL, e$message)
          NULL
        })
      } else {
        chart_log("get_library_documents not available", "WARN", "ANALYTICS")
      }
    }

    # Try CSV data if still no results
    if (is.null(docs) || nrow(docs) == 0) {
      chart_log("Trying CSV data fallback", "INFO", "ANALYTICS")

      if (exists("analytics_data_fixed_csv")) {
        docs <- tryCatch({
          csv_start <- Sys.time()
          result <- analytics_data_fixed_csv(limit = 10000)

          log_data_operation("CSV", "LOAD", TRUE, nrow(result),
                           paste("Execution time:", round(as.numeric(difftime(Sys.time(), csv_start, units = "secs")), 3), "s"))

          if (!is.null(result) && nrow(result) > 0) {
            data_source <- "csv_file"
            result
          } else {
            log_data_operation("CSV", "LOAD", FALSE, 0, "No data returned")
            NULL
          }
        }, error = function(e) {
          log_data_operation("CSV", "LOAD", FALSE, NULL, e$message)
          NULL
        })
      } else {
        chart_log("analytics_data_fixed_csv not available", "WARN", "ANALYTICS")
      }
    }

    # Emergency data as final fallback
    if (is.null(docs) || nrow(docs) == 0) {
      chart_log("Using emergency data fallback", "WARN", "ANALYTICS")

      docs <- tryCatch({
        if (exists("load_emergency_data")) {
          result <- load_emergency_data(limit = 1000)
          log_data_operation("EMERGENCY", "CREATE", TRUE, nrow(result))
          data_source <- "emergency"
          result
        } else {
          # Minimal fallback
          minimal_data <- data.frame(
            title = "Sistema Indisponível",
            category = "Sistema",
            state = "DF",
            date = as.Date(Sys.Date()),
            year = as.numeric(format(Sys.Date(), "%Y")),
            stringsAsFactors = FALSE
          )
          log_data_operation("MINIMAL", "CREATE", TRUE, nrow(minimal_data))
          data_source <- "minimal"
          minimal_data
        }
      }, error = function(e) {
        log_data_operation("EMERGENCY", "CREATE", FALSE, NULL, e$message)
        data.frame(title = "Error", category = "Error", state = "XX",
                  date = as.Date(Sys.Date()), year = 2024, stringsAsFactors = FALSE)
      })
    }

    # Log final results
    execution_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    chart_log(paste("Analytics data completed -", nrow(docs), "documents from", data_source,
                   "in", round(execution_time, 3), "seconds"), "INFO", "ANALYTICS")

    # Log memory usage at end
    log_memory_usage("ANALYTICS_END")

    return(docs)
  }

  # Create reactive version if shiny is available
  if (requireNamespace("shiny", quietly = TRUE)) {
    logged_analytics_data <<- shiny::reactive({
      logged_analytics_data_function()
    })
    chart_log("Reactive logged analytics data function created", "INFO", "INIT")
  } else {
    logged_analytics_data <<- logged_analytics_data_function
    chart_log("Non-reactive logged analytics data function created", "INFO", "INIT")
  }
}

# Create health monitoring endpoint
create_health_endpoint <- function() {
  chart_log("Creating health monitoring endpoint", "INFO", "INIT")

  chart_health_status <<- function() {
    chart_log("Health status requested", "INFO", "HEALTH")
    log_system_health()

    # Return recent log entries
    recent_logs <- tail(CHART_LOG_STATE$log_entries, 50)

    health_data <- list(
      status = "operational",
      timestamp = Sys.time(),
      uptime = difftime(Sys.time(), CHART_LOG_STATE$start_time, units = "hours"),
      recent_logs = recent_logs,
      system_info = list(
        r_version = R.version.string,
        working_directory = getwd(),
        memory_usage = paste(round(sum(gc()[, 2]) / 1024, 1), "MB")
      )
    )

    return(health_data)
  }

  chart_log("Health monitoring endpoint created", "INFO", "INIT")
}

# Initialize logging system
chart_log("Initializing Railway chart logging system", "INFO", "SYSTEM")
create_logged_analytics_data()
create_health_endpoint()

# Initial system health check
log_system_health()

chart_log("Railway chart logging system loaded successfully", "INFO", "SYSTEM")