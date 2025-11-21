# =============================================================================
# Database Transaction Support
# =============================================================================
# Monitor Legislativo v4 - Phase 4: Optimization & Polish
#
# Provides ACID transaction support for multi-step database operations
# Ensures data consistency and rollback capability on errors
#
# Author: Monitor Legislativo v4 Team
# Version: 4.0.0
# Last Updated: 2025-11-21
# =============================================================================

library(DBI)
library(pool)

# =============================================================================
# TRANSACTION WRAPPER FUNCTIONS
# =============================================================================

#' Execute Operations in Database Transaction
#'
#' Wraps database operations in a transaction with automatic rollback on error.
#' Ensures ACID properties for multi-step operations.
#'
#' @param pool Database connection pool
#' @param operations Function that takes a connection and performs operations
#' @param isolation_level Transaction isolation level (default: "READ COMMITTED")
#' @param log_transactions Logical, whether to log transaction details
#'
#' @return Result from operations function
#'
#' @examples
#' \dontrun{
#' # Execute multiple inserts atomically
#' result <- execute_in_transaction(db_pool, function(conn) {
#'   DBI::dbExecute(conn, "INSERT INTO table1 VALUES ($1)", list(value1))
#'   DBI::dbExecute(conn, "INSERT INTO table2 VALUES ($1)", list(value2))
#'   return(TRUE)
#' })
#' }
#'
#' @export
execute_in_transaction <- function(pool,
                                   operations,
                                   isolation_level = "READ COMMITTED",
                                   log_transactions = TRUE) {

  # Validate inputs
  if (!inherits(pool, "Pool")) {
    stop("Parameter 'pool' must be a Pool object")
  }

  if (!is.function(operations)) {
    stop("Parameter 'operations' must be a function")
  }

  # Checkout connection from pool
  conn <- pool::poolCheckout(pool)

  # Ensure connection is returned even on error
  on.exit({
    pool::poolReturn(conn)
  }, add = TRUE)

  # Transaction tracking
  transaction_id <- sprintf("TXN-%s-%d",
                           format(Sys.time(), "%Y%m%d%H%M%S"),
                           sample(1000:9999, 1))

  if (log_transactions) {
    message(sprintf("[TRANSACTION START] ID: %s | Isolation: %s",
                   transaction_id, isolation_level))
  }

  # Execute transaction
  tryCatch({
    # Set transaction isolation level
    if (isolation_level != "READ COMMITTED") {
      DBI::dbExecute(conn, paste("SET TRANSACTION ISOLATION LEVEL", isolation_level))
    }

    # Begin transaction
    DBI::dbBegin(conn)

    if (log_transactions) {
      message(sprintf("[TRANSACTION EXECUTING] ID: %s", transaction_id))
    }

    # Execute operations
    start_time <- Sys.time()
    result <- operations(conn)
    execution_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))

    # Commit transaction
    DBI::dbCommit(conn)

    if (log_transactions) {
      message(sprintf("[TRANSACTION COMMIT] ID: %s | Time: %.3fs",
                     transaction_id, execution_time))
    }

    return(result)

  }, error = function(e) {
    # Rollback on error
    DBI::dbRollback(conn)

    if (log_transactions) {
      message(sprintf("[TRANSACTION ROLLBACK] ID: %s | Error: %s",
                     transaction_id, e$message))
    }

    # Log rollback for monitoring
    log_transaction_rollback(transaction_id, e$message)

    # Re-throw error
    stop(sprintf("Transaction %s failed: %s", transaction_id, e$message))
  })
}

#' Execute Read-Only Transaction
#'
#' Optimized for read-only operations with READ ONLY transaction mode
#'
#' @param pool Database connection pool
#' @param operations Function that performs read operations
#'
#' @return Result from operations function
#' @export
execute_readonly_transaction <- function(pool, operations) {
  execute_in_transaction(
    pool = pool,
    operations = function(conn) {
      DBI::dbExecute(conn, "SET TRANSACTION READ ONLY")
      operations(conn)
    },
    isolation_level = "READ COMMITTED",
    log_transactions = FALSE
  )
}

#' Log Transaction Rollback
#'
#' Records transaction rollback for monitoring and debugging
#'
#' @param transaction_id Unique transaction identifier
#' @param error_message Error that caused rollback
#' @param details Additional details (optional)
#'
#' @return NULL (logs to file/console)
#' @keywords internal
log_transaction_rollback <- function(transaction_id, error_message, details = NULL) {
  log_entry <- list(
    timestamp = Sys.time(),
    transaction_id = transaction_id,
    error_message = error_message,
    details = details
  )

  # Log to console
  cat(sprintf("\n⚠️ TRANSACTION ROLLBACK: %s\n", transaction_id), file = stderr())
  cat(sprintf("   Error: %s\n", error_message), file = stderr())

  # TODO: Integrate with audit logging system if available
  if (exists("log_user_action")) {
    tryCatch({
      log_user_action(
        action = "transaction_rollback",
        details = log_entry
      )
    }, error = function(e) {
      # Silently fail if logging not available
    })
  }

  invisible(NULL)
}

# =============================================================================
# TRANSACTION HELPERS
# =============================================================================

#' Batch Insert with Transaction
#'
#' Inserts multiple rows in a single transaction for data consistency
#'
#' @param pool Database connection pool
#' @param table Table name
#' @param data Data frame to insert
#' @param batch_size Number of rows per batch (default: 1000)
#'
#' @return Number of rows inserted
#' @export
batch_insert_transaction <- function(pool, table, data, batch_size = 1000) {

  if (nrow(data) == 0) {
    message("No data to insert")
    return(0)
  }

  execute_in_transaction(pool, function(conn) {
    total_rows <- 0

    # Split into batches
    n_batches <- ceiling(nrow(data) / batch_size)

    for (i in seq_len(n_batches)) {
      start_idx <- (i - 1) * batch_size + 1
      end_idx <- min(i * batch_size, nrow(data))
      batch_data <- data[start_idx:end_idx, , drop = FALSE]

      # Insert batch
      DBI::dbWriteTable(conn, table, batch_data, append = TRUE, row.names = FALSE)
      total_rows <- total_rows + nrow(batch_data)

      message(sprintf("Batch %d/%d: Inserted %d rows", i, n_batches, nrow(batch_data)))
    }

    return(total_rows)
  })
}

#' Update with Transaction Rollback
#'
#' Updates records with automatic rollback on error
#'
#' @param pool Database connection pool
#' @param query SQL UPDATE query
#' @param params Query parameters
#'
#' @return Number of rows affected
#' @export
update_with_transaction <- function(pool, query, params = list()) {
  execute_in_transaction(pool, function(conn) {
    result <- DBI::dbExecute(conn, query, params = params)
    return(result)
  })
}

#' Delete with Transaction Rollback
#'
#' Deletes records with automatic rollback on error
#'
#' @param pool Database connection pool
#' @param query SQL DELETE query
#' @param params Query parameters
#'
#' @return Number of rows deleted
#' @export
delete_with_transaction <- function(pool, query, params = list()) {
  execute_in_transaction(pool, function(conn) {
    result <- DBI::dbExecute(conn, query, params = params)
    return(result)
  })
}

# =============================================================================
# TRANSACTION STATUS MONITORING
# =============================================================================

#' Get Transaction Statistics
#'
#' Returns statistics about database transactions
#'
#' @param pool Database connection pool
#'
#' @return List with transaction statistics
#' @export
get_transaction_stats <- function(pool) {
  tryCatch({
    stats <- pool::dbGetQuery(pool, "
      SELECT
        datname as database,
        xact_commit as commits,
        xact_rollback as rollbacks,
        ROUND(100.0 * xact_rollback / NULLIF(xact_commit + xact_rollback, 0), 2) as rollback_rate
      FROM pg_stat_database
      WHERE datname = current_database()
    ")

    return(as.list(stats[1, ]))

  }, error = function(e) {
    warning("Could not retrieve transaction statistics: ", e$message)
    return(list(
      database = NA,
      commits = NA,
      rollbacks = NA,
      rollback_rate = NA
    ))
  })
}

#' Check for Long-Running Transactions
#'
#' Identifies transactions that have been running for too long
#'
#' @param pool Database connection pool
#' @param threshold_seconds Threshold in seconds (default: 300 = 5 minutes)
#'
#' @return Data frame of long-running transactions
#' @export
check_long_transactions <- function(pool, threshold_seconds = 300) {
  tryCatch({
    long_txns <- pool::dbGetQuery(pool, sprintf("
      SELECT
        pid,
        usename as username,
        datname as database,
        state,
        EXTRACT(EPOCH FROM (now() - xact_start)) as duration_seconds,
        query
      FROM pg_stat_activity
      WHERE xact_start IS NOT NULL
        AND EXTRACT(EPOCH FROM (now() - xact_start)) > %d
        AND pid != pg_backend_pid()
      ORDER BY duration_seconds DESC
    ", threshold_seconds))

    if (nrow(long_txns) > 0) {
      warning(sprintf("Found %d long-running transaction(s)", nrow(long_txns)))
    }

    return(long_txns)

  }, error = function(e) {
    warning("Could not check for long transactions: ", e$message)
    return(data.frame())
  })
}

# =============================================================================
# EXAMPLE USAGE
# =============================================================================

# Example 1: Multi-step insert with rollback on error
# result <- execute_in_transaction(db_pool, function(conn) {
#   # Insert user
#   user_id <- DBI::dbGetQuery(conn,
#     "INSERT INTO users (name, email) VALUES ($1, $2) RETURNING id",
#     list("John Doe", "john@example.com"))$id
#
#   # Insert user preferences (will rollback if fails)
#   DBI::dbExecute(conn,
#     "INSERT INTO preferences (user_id, theme) VALUES ($1, $2)",
#     list(user_id, "dark"))
#
#   return(user_id)
# })

# Example 2: Batch insert with transaction
# data <- data.frame(
#   title = c("Doc1", "Doc2", "Doc3"),
#   content = c("Content1", "Content2", "Content3")
# )
# rows_inserted <- batch_insert_transaction(db_pool, "documents", data)

# Example 3: Monitor transactions
# stats <- get_transaction_stats(db_pool)
# cat("Commits:", stats$commits, "| Rollbacks:", stats$rollbacks, "\n")
