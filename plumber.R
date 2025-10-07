# ============================================================================
# PLUMBER HEALTH CHECK API FOR RAILWAY DEPLOYMENT
# ============================================================================
#
# Provides health check endpoints for container orchestration and monitoring
# Railway-optimized for Brazilian Legislative Monitoring System
# Follows Railway best practices for health checks and readiness probes
#
# Endpoints:
# - GET /health - Basic health check (always returns 200 if process is running)
# - GET /ready - Readiness check (verifies database connectivity and essential services)
# - GET /metrics - Performance metrics for monitoring
#
# ============================================================================

suppressPackageStartupMessages({
  library(plumber)
  library(jsonlite)
  library(DBI)
})

# Initialize monitoring flag from environment
ENABLE_DETAILED_HEALTH <- tolower(Sys.getenv("HEALTH_CHECK_DETAILED", "true")) %in% c("1", "true", "yes")

#* Health Check Endpoint - Always returns 200 if process is running
#* @get /health
function() {
  list(
    status = "OK",
    timestamp = Sys.time(),
    service = "Monitor Legislativo v4",
    environment = Sys.getenv("RAILWAY_ENVIRONMENT", "development"),
    uptime_seconds = as.numeric(Sys.time() - .GlobalEnv$.start_time %||% Sys.time())
  )
}

#* Readiness Probe - Verifies essential services are operational
#* @get /ready
function() {
  ready <- TRUE
  checks <- list()

  # Basic process check
  checks$process <- list(
    status = "OK",
    details = "Application process running"
  )

  # Database connectivity check (if enabled)
  if (ENABLE_DETAILED_HEALTH) {
    tryCatch({
      # Try to get database pool from options
      db_pool <- getOption("app_db_pool", NULL)

      if (!is.null(db_pool)) {
        # Test database connection
        test_query <- "SELECT 1 as test"
        result <- DBI::dbGetQuery(db_pool, test_query)

        if (nrow(result) == 1 && result$test[1] == 1) {
          checks$database <- list(
            status = "OK",
            details = "Database connection successful"
          )
        } else {
          checks$database <- list(
            status = "ERROR",
            details = "Database query returned unexpected result"
          )
          ready <- FALSE
        }
      } else {
        checks$database <- list(
          status = "WARNING",
          details = "No database pool available - running in limited mode"
        )
        # Don't mark as not ready - app can run with fallback data
      }
    }, error = function(e) {
      checks$database <- list(
        status = "ERROR",
        details = paste("Database connection failed:", e$message)
      )
      ready <- FALSE
    })
  } else {
    checks$database <- list(
      status = "SKIPPED",
      details = "Detailed health checks disabled"
    )
  }

  # Memory check
  tryCatch({
    memory_info <- gc()
    used_mb <- sum(memory_info[, "used"]) * 8 / 1024 / 1024  # Convert to MB
    max_mb <- as.numeric(Sys.getenv("MEMORY_LIMIT", "3072"))
    memory_usage_percent <- (used_mb / max_mb) * 100

    if (memory_usage_percent < 90) {
      checks$memory <- list(
        status = "OK",
        details = paste("Memory usage:", round(memory_usage_percent, 1), "%"),
        used_mb = round(used_mb, 1),
        limit_mb = max_mb
      )
    } else {
      checks$memory <- list(
        status = "WARNING",
        details = paste("High memory usage:", round(memory_usage_percent, 1), "%"),
        used_mb = round(used_mb, 1),
        limit_mb = max_mb
      )
    }
  }, error = function(e) {
    checks$memory <- list(
      status = "ERROR",
      details = paste("Memory check failed:", e$message)
    )
  })

  # Overall status
  overall_status <- if (ready) "READY" else "NOT_READY"
  response_code <- if (ready) 200 else 503

  response <- list(
    status = overall_status,
    ready = ready,
    timestamp = Sys.time(),
    checks = checks
  )

  # Set HTTP status code
  if (!ready) {
    res$status <- 503
  }

  return(response)
}

#* Performance Metrics Endpoint
#* @get /metrics
function() {
  metrics <- list(
    timestamp = Sys.time(),
    service = "Monitor Legislativo v4"
  )

  # Memory metrics
  tryCatch({
    memory_info <- gc()
    used_mb <- sum(memory_info[, "used"]) * 8 / 1024 / 1024
    max_mb <- as.numeric(Sys.getenv("MEMORY_LIMIT", "3072"))

    metrics$memory <- list(
      used_mb = round(used_mb, 2),
      limit_mb = max_mb,
      usage_percent = round((used_mb / max_mb) * 100, 2)
    )
  }, error = function(e) {
    metrics$memory <- list(error = e$message)
  })

  # Performance stats (if available)
  if (exists("get_performance_stats") && is.function(get_performance_stats)) {
    tryCatch({
      perf_stats <- get_performance_stats()
      metrics$performance <- perf_stats
    }, error = function(e) {
      metrics$performance <- list(error = e$message)
    })
  }

  # Environment info
  metrics$environment <- list(
    railway_env = Sys.getenv("RAILWAY_ENVIRONMENT", "unknown"),
    r_version = R.version.string,
    platform = Sys.info()["sysname"],
    detailed_health = ENABLE_DETAILED_HEALTH
  )

  return(metrics)
}

#* Root endpoint - Basic info
#* @get /
function() {
  list(
    service = "Monitor Legislativo v4 Health API",
    version = "4.0.0",
    endpoints = list(
      "/health" = "Basic health check",
      "/ready" = "Readiness probe with service validation",
      "/metrics" = "Performance and operational metrics"
    ),
    timestamp = Sys.time(),
    documentation = "Railway-optimized health check API for Brazilian Legislative Monitoring"
  )
}

# Define null-coalescing operator if not available
if (!exists("%||%", mode = "function")) {
  `%||%` <- function(a, b) if (is.null(a)) b else a
}

# Store start time for uptime calculation
if (!exists(".start_time", envir = .GlobalEnv)) {
  assign(".start_time", Sys.time(), envir = .GlobalEnv)
}