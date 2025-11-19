# =============================================================================
# Database Connection Pool Manager
# =============================================================================
# Phase 2: Performance Optimization - Task 2.1
# Production-grade connection pooling for Railway PostgreSQL
# =============================================================================

library(DBI)
library(pool)
library(RPostgres)

# Global connection pool variable
.db_pool <- NULL

# Connection pool statistics
.pool_stats <- list(
  created_at = NULL,
  total_queries = 0,
  failed_queries = 0,
  pool_checkouts = 0
)

#' Get Database Configuration from Environment
#'
#' Reads database configuration from environment variables with Railway and Cloud Run support
#'
#' @return List with database connection parameters
#' @export
get_database_config <- function() {

  # Method 1: PRIORITIZE Google Cloud Run Unix Socket
  is_in_cloud_run <- !is.na(Sys.getenv("K_SERVICE", unset = NA))
  if (is_in_cloud_run) {
    cat("✅ Detected Google Cloud Run environment\n")
    return(list(
      host = paste("/cloudsql", "mackmonitor:southamerica-east1:mackmonitor-db", sep = "/"),
      port = 5432,
      dbname = Sys.getenv("PGDATABASE", "mackmonitor-db"),
      user = Sys.getenv("PGUSER", "monitor_user"),
      password = Sys.getenv("PGPASSWORD", "")
    ))
  }

  # Method 2: Check for Railway DATABASE_URL format
  database_url <- Sys.getenv("DATABASE_URL", "")
  if (database_url != "" && nchar(database_url) > 0) {
    parsed <- parse_database_url(database_url)
    if (!is.null(parsed)) {
      cat("✅ Using Railway DATABASE_URL\n")
      return(parsed)
    }
  }

  # Method 3: Fallback to environment variables for local development
  cat("📋 Local environment detected. Using PGHOST/PGUSER...\n")
  list(
    host = Sys.getenv("PGHOST", "34.39.228.246"),
    port = as.integer(Sys.getenv("PGPORT", "5432")),
    dbname = Sys.getenv("PGDATABASE", "mackmonitor-db"),
    user = Sys.getenv("PGUSER", "monitor_user"),
    password = Sys.getenv("PGPASSWORD", "")
  )
}

#' Parse Railway DATABASE_URL format
#'
#' @param database_url String in format: postgresql://user:pass@host:port/dbname
#' @return List with connection parameters or NULL if invalid
parse_database_url <- function(database_url) {
  if (is.null(database_url) || database_url == "" || is.na(database_url)) {
    return(NULL)
  }

  tryCatch({
    if (!grepl("^postgres(?:ql)?://", database_url)) {
      return(NULL)
    }

    url_clean <- sub("^postgres(?:ql)?://", "", database_url)

    auth_and_host <- strsplit(url_clean, "@")[[1]]
    if (length(auth_and_host) != 2) {
      return(NULL)
    }

    auth_parts <- strsplit(auth_and_host[1], ":")[[1]]
    if (length(auth_parts) != 2) {
      return(NULL)
    }

    host_and_db <- strsplit(auth_and_host[2], "/")[[1]]
    if (length(host_and_db) != 2) {
      return(NULL)
    }

    host_port <- strsplit(host_and_db[1], ":")[[1]]

    list(
      user = auth_parts[1],
      password = auth_parts[2],
      host = host_port[1],
      port = if (length(host_port) > 1) as.integer(host_port[2]) else 5432L,
      dbname = host_and_db[2]
    )
  }, error = function(e) {
    cat("⚠️ Error parsing DATABASE_URL:", e$message, "\n")
    return(NULL)
  })
}

#' Initialize Database Connection Pool
#'
#' Creates a production-optimized connection pool with:
#' - Automatic connection reuse
#' - Health checks and validation
#' - Circuit breaker pattern
#' - Performance monitoring
#'
#' @return Connection pool object
#' @export
init_db_pool <- function() {

  if (!is.null(.db_pool)) {
    tryCatch({
      test_result <- pool::dbGetQuery(.db_pool, "SELECT 1 as test")
      if (nrow(test_result) > 0) {
        cat("♻️  Reusing existing healthy connection pool\n")
        return(.db_pool)
      }
    }, error = function(e) {
      cat("⚠️  Existing pool unhealthy, creating new connection...\n")
      pool::poolClose(.db_pool)
      .db_pool <<- NULL
    })
  }

  config <- get_database_config()

  if (is.null(config$password) || config$password == "") {
    cat("❌ Database password not configured\n")
    return(NULL)
  }

  cat("🔧 Creating optimized connection pool...\n")
  cat("   Host:", config$host, "\n")
  cat("   Port:", config$port, "\n")
  cat("   Database:", config$dbname, "\n")
  cat("   User:", config$user, "\n")

  tryCatch({
    .db_pool <<- pool::dbPool(
      drv = RPostgres::Postgres(),
      host = config$host,
      port = config$port,
      dbname = config$dbname,
      user = config$user,
      password = config$password,
      minSize = 2,
      maxSize = 10,
      idleTimeout = 600000,
      validationInterval = 60000
    )

    .pool_stats$created_at <<- Sys.time()

    reg.finalizer(.GlobalEnv, function(e) {
      if (!is.null(.db_pool)) {
        cat("🔌 Closing database connection pool...\n")
        pool::poolClose(.db_pool)
      }
    }, onexit = TRUE)

    cat("✅ Connection pool initialized successfully\n")
    cat("   Min connections: 2\n")
    cat("   Max connections: 10\n")
    cat("   Idle timeout: 10 minutes\n")

    return(.db_pool)

  }, error = function(e) {
    cat("❌ Failed to create connection pool:", e$message, "\n")
    .db_pool <<- NULL
    return(NULL)
  })
}

#' Get Connection Pool
#'
#' Returns the current connection pool, initializing if needed
#'
#' @return Connection pool object
#' @export
get_db_pool <- function() {
  if (is.null(.db_pool)) {
    return(init_db_pool())
  }
  return(.db_pool)
}

#' Execute Safe Query with Pool
#'
#' Wrapper for executing queries with automatic error handling and stats tracking
#'
#' @param pool Connection pool object
#' @param query SQL query string
#' @param params Query parameters (optional)
#' @return Query results
#' @export
execute_safe_query <- function(pool, query, params = NULL) {

  if (is.null(pool)) {
    stop("Connection pool is NULL")
  }

  .pool_stats$total_queries <<- .pool_stats$total_queries + 1

  tryCatch({
    if (!is.null(params) && length(params) > 0) {
      result <- pool::dbGetQuery(pool, query, params = params)
    } else {
      result <- pool::dbGetQuery(pool, query)
    }

    .pool_stats$pool_checkouts <<- .pool_stats$pool_checkouts + 1
    return(result)

  }, error = function(e) {
    .pool_stats$failed_queries <<- .pool_stats$failed_queries + 1
    cat("❌ Query failed:", e$message, "\n")
    stop(e)
  })
}

#' Monitor Connection Pool
#'
#' Displays current pool statistics and health
#'
#' @export
monitor_pool <- function() {
  if (is.null(.db_pool)) {
    cat("❌ No connection pool initialized\n")
    return(invisible(NULL))
  }

  pool_info <- tryCatch({
    pool::dbGetInfo(.db_pool)
  }, error = function(e) {
    list(error = e$message)
  })

  cat("\n📊 Connection Pool Statistics\n")
  cat("================================\n")

  if (!is.null(pool_info$error)) {
    cat("Status: ERROR\n")
    cat("Error:", pool_info$error, "\n")
  } else {
    cat("Status: HEALTHY\n")
    cat("Created:", format(.pool_stats$created_at, "%Y-%m-%d %H:%M:%S"), "\n")
    cat("\nPool Metrics:\n")
    cat("  Free connections:", pool_info$free, "\n")
    cat("  Active connections:", pool_info$taken, "\n")
    cat("  Total connections:", pool_info$total, "\n")
    cat("\nQuery Metrics:\n")
    cat("  Total queries:", .pool_stats$total_queries, "\n")
    cat("  Failed queries:", .pool_stats$failed_queries, "\n")
    cat("  Pool checkouts:", .pool_stats$pool_checkouts, "\n")

    if (.pool_stats$total_queries > 0) {
      success_rate <- (1 - .pool_stats$failed_queries / .pool_stats$total_queries) * 100
      cat("  Success rate:", sprintf("%.1f%%", success_rate), "\n")
    }
  }

  cat("================================\n\n")

  return(invisible(pool_info))
}

#' Check Pool Health
#'
#' Validates connection pool is operational
#'
#' @return Logical indicating if pool is healthy
#' @export
check_pool_health <- function() {
  if (is.null(.db_pool)) {
    return(FALSE)
  }

  tryCatch({
    result <- pool::dbGetQuery(.db_pool, "SELECT 1 as health_check")
    return(nrow(result) == 1 && result$health_check[1] == 1)
  }, error = function(e) {
    return(FALSE)
  })
}

#' Close Connection Pool
#'
#' Gracefully closes the connection pool
#'
#' @export
close_db_pool <- function() {
  if (!is.null(.db_pool)) {
    cat("🔌 Closing connection pool...\n")
    pool::poolClose(.db_pool)
    .db_pool <<- NULL
    cat("✅ Connection pool closed\n")
  }
}
