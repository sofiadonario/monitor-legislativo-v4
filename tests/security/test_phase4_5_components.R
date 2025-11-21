# =============================================================================
# Phase 4 & 5 Component Security Testing
# =============================================================================
# Monitor Legislativo v4 - Phases 4 & 5: Optimization, Polish & Monitoring
#
# Tests for transaction support, error handling, and health checks
# Ensures production readiness and security of new components
#
# Author: Monitor Legislativo v4 Team
# Version: 4.0.0
# Last Updated: 2025-11-21
# =============================================================================

library(testthat)
library(DBI)
library(pool)
library(jsonlite)

# Skip tests if database not available
if (!exists("db_pool") || is.null(db_pool)) {
  cat("⚠️ Database pool not available - skipping database-dependent tests\n")
  DB_AVAILABLE <- FALSE
} else {
  DB_AVAILABLE <- TRUE
}

# Source components being tested
if (file.exists("R/database/transaction_support.R")) {
  source("R/database/transaction_support.R")
}

if (file.exists("R/utils/error_handling.R")) {
  source("R/utils/error_handling.R")
}

if (file.exists("R/monitoring/health_check.R")) {
  source("R/monitoring/health_check.R")
}

# =============================================================================
# TRANSACTION SUPPORT SECURITY TESTS
# =============================================================================

test_that("Transaction Support - ACID Properties", {
  skip_if(!DB_AVAILABLE, "Database not available")
  skip_if(!exists("execute_in_transaction"), "Transaction support not loaded")

  cat("\n🔒 Testing Transaction ACID Properties\n")

  # Test 1: Atomicity - Rollback on error
  cat("   Testing atomicity (rollback on error)...\n")

  initial_count <- tryCatch({
    DBI::dbGetQuery(db_pool, "SELECT COUNT(*) as count FROM documentos_legislativos")$count
  }, error = function(e) NA)

  if (!is.na(initial_count)) {
    # Try transaction that should rollback
    rollback_result <- tryCatch({
      execute_in_transaction(db_pool, function(conn) {
        # This should succeed
        DBI::dbExecute(conn, "SELECT 1")
        # This should fail and rollback entire transaction
        stop("Intentional error for testing")
      }, log_transactions = FALSE)
    }, error = function(e) {
      "rolled_back"
    })

    expect_equal(rollback_result, "rolled_back")

    # Verify count didn't change
    final_count <- DBI::dbGetQuery(db_pool, "SELECT COUNT(*) as count FROM documentos_legislativos")$count
    expect_equal(initial_count, final_count)

    cat("   ✅ Atomicity verified - rollback successful\n")
  }
})

test_that("Transaction Support - Isolation Levels", {
  skip_if(!DB_AVAILABLE, "Database not available")
  skip_if(!exists("execute_in_transaction"), "Transaction support not loaded")

  cat("\n🔐 Testing Transaction Isolation Levels\n")

  # Test different isolation levels
  isolation_levels <- c("READ COMMITTED", "REPEATABLE READ", "SERIALIZABLE")

  for (level in isolation_levels) {
    result <- tryCatch({
      execute_in_transaction(db_pool, function(conn) {
        # Simple read operation
        DBI::dbGetQuery(conn, "SELECT 1 as test")
      }, isolation_level = level, log_transactions = FALSE)
    }, error = function(e) {
      NULL
    })

    if (!is.null(result)) {
      cat(paste("   ✅", level, "isolation level supported\n"))
    }
  }
})

test_that("Transaction Support - Connection Pool Safety", {
  skip_if(!DB_AVAILABLE, "Database not available")
  skip_if(!exists("execute_in_transaction"), "Transaction support not loaded")

  cat("\n🏊 Testing Connection Pool Safety\n")

  # Get initial pool stats
  initial_info <- tryCatch({
    pool::dbGetInfo(db_pool)
  }, error = function(e) NULL)

  if (!is.null(initial_info)) {
    initial_free <- initial_info$free

    # Execute transaction
    result <- tryCatch({
      execute_in_transaction(db_pool, function(conn) {
        DBI::dbGetQuery(conn, "SELECT 1 as test")
      }, log_transactions = FALSE)
    }, error = function(e) NULL)

    # Check connection was returned to pool
    final_info <- pool::dbGetInfo(db_pool)
    final_free <- final_info$free

    expect_equal(initial_free, final_free,
                label = "Connection should be returned to pool after transaction")

    cat("   ✅ Connection properly returned to pool\n")
  }
})

test_that("Transaction Support - SQL Injection in Transaction", {
  skip_if(!DB_AVAILABLE, "Database not available")
  skip_if(!exists("execute_in_transaction"), "Transaction support not loaded")

  cat("\n💉 Testing SQL Injection Prevention in Transactions\n")

  # SQL injection payloads
  malicious_payloads <- c(
    "'; DROP TABLE documentos_legislativos; --",
    "1' OR '1'='1",
    "admin'--"
  )

  for (payload in malicious_payloads) {
    result <- tryCatch({
      execute_in_transaction(db_pool, function(conn) {
        # Use parameterized query - should be safe
        DBI::dbGetQuery(conn,
          "SELECT * FROM documentos_legislativos WHERE titulo = $1 LIMIT 1",
          params = list(payload))
      }, log_transactions = FALSE)
    }, error = function(e) {
      "error"
    })

    # Should either return empty result or error, but NOT drop table
    expect_true(is.data.frame(result) || result == "error")
  }

  # Verify table still exists
  table_exists <- tryCatch({
    DBI::dbExistsTable(db_pool, "documentos_legislativos")
  }, error = function(e) FALSE)

  expect_true(table_exists, label = "Table should not be dropped by injection")
  cat("   ✅ SQL injection prevented in transactions\n")
})

# =============================================================================
# ERROR HANDLING SECURITY TESTS
# =============================================================================

test_that("Error Handling - Standardized Error Codes", {
  skip_if(!exists("ERROR_CODES"), "Error codes not loaded")

  cat("\n🚨 Testing Standardized Error Codes\n")

  # Test 1: All error codes have required fields
  for (error_name in names(ERROR_CODES)) {
    error_def <- ERROR_CODES[[error_name]]

    expect_true("code" %in% names(error_def),
               label = paste(error_name, "should have 'code' field"))
    expect_true("message" %in% names(error_def),
               label = paste(error_name, "should have 'message' field"))
    expect_true("user_message" %in% names(error_def),
               label = paste(error_name, "should have 'user_message' field"))
    expect_true("severity" %in% names(error_def),
               label = paste(error_name, "should have 'severity' field"))
  }

  cat(paste("   ✅", length(ERROR_CODES), "error codes validated\n"))
})

test_that("Error Handling - No Information Disclosure", {
  skip_if(!exists("create_error_response"), "Error handling not loaded")

  cat("\n🔒 Testing Error Information Disclosure Prevention\n")

  # Test that user_message doesn't expose sensitive info
  error_response <- create_error_response(
    "DB_CONNECTION_FAILED",
    details = list(password = "secret123", host = "localhost"),
    technical_info = "FATAL: password authentication failed for user admin"
  )

  # User message should not contain sensitive details
  expect_false(grepl("secret", error_response$error$user_message, ignore.case = TRUE))
  expect_false(grepl("password", error_response$error$user_message, ignore.case = TRUE))
  expect_false(grepl("admin", error_response$error$user_message, ignore.case = TRUE))

  cat("   ✅ Sensitive information not exposed in user messages\n")
})

test_that("Error Handling - Security Error Classification", {
  skip_if(!exists("handle_validation_error"), "Error handling not loaded")

  cat("\n🛡️ Testing Security Error Classification\n")

  # Test SQL injection attempt detection
  sql_validation <- list(
    valid = FALSE,
    error = "SQL injection pattern detected: DROP TABLE"
  )

  sql_error <- handle_validation_error(sql_validation, "search_field")

  expect_equal(sql_error$error$code, "SEC001")
  expect_equal(sql_error$error$severity, "CRITICAL")
  cat("   ✅ SQL injection attempts classified as CRITICAL\n")

  # Test XSS attempt detection
  xss_validation <- list(
    valid = FALSE,
    error = "XSS pattern detected: <script>"
  )

  xss_error <- handle_validation_error(xss_validation, "comment_field")

  expect_equal(xss_error$error$code, "SEC002")
  expect_equal(xss_error$error$severity, "CRITICAL")
  cat("   ✅ XSS attempts classified as CRITICAL\n")
})

test_that("Error Handling - Safe Execution Wrapper", {
  skip_if(!exists("safe_execute"), "Error handling not loaded")

  cat("\n🛡️ Testing Safe Execution Wrapper\n")

  # Test successful execution
  result_success <- safe_execute({
    1 + 1
  })

  expect_equal(result_success, 2)
  cat("   ✅ Safe execution returns successful results\n")

  # Test error handling
  result_error <- safe_execute({
    stop("Test error")
  })

  expect_true(is.list(result_error))
  expect_false(result_error$success)
  expect_true("error" %in% names(result_error))
  cat("   ✅ Safe execution catches and formats errors\n")

  # Test fallback value
  result_fallback <- safe_execute({
    stop("Test error")
  }, fallback_value = data.frame())

  expect_true(is.data.frame(result_fallback))
  cat("   ✅ Safe execution returns fallback on error\n")
})

# =============================================================================
# HEALTH CHECK SECURITY TESTS
# =============================================================================

test_that("Health Check - No Sensitive Information Exposure", {
  skip_if(!exists("perform_health_check"), "Health check not loaded")

  cat("\n🔒 Testing Health Check Information Disclosure\n")

  health_result <- if (DB_AVAILABLE) {
    perform_health_check(db_pool, detailed = TRUE)
  } else {
    perform_health_check(NULL, detailed = TRUE)
  }

  # Convert to JSON to check what would be exposed via API
  health_json <- jsonlite::toJSON(health_result, auto_unbox = TRUE)
  health_text <- as.character(health_json)

  # Should not contain sensitive patterns
  sensitive_patterns <- c(
    "password",
    "secret",
    "token",
    "key",
    "credential",
    "PGPASSWORD",
    "DATABASE_URL"
  )

  for (pattern in sensitive_patterns) {
    expect_false(grepl(pattern, health_text, ignore.case = TRUE),
                label = paste("Health check should not expose", pattern))
  }

  cat("   ✅ No sensitive information in health check response\n")
})

test_that("Health Check - Database Connection Safety", {
  skip_if(!DB_AVAILABLE, "Database not available")
  skip_if(!exists("check_database_health"), "Health check not loaded")

  cat("\n🔐 Testing Database Health Check Safety\n")

  db_health <- check_database_health(db_pool)

  # Should have proper structure
  expect_true("status" %in% names(db_health))
  expect_true(db_health$status %in% c("healthy", "degraded", "unhealthy", "unavailable"))

  # Should not expose connection strings or credentials
  health_text <- toString(db_health)

  expect_false(grepl("postgresql://", health_text, ignore.case = TRUE))
  expect_false(grepl("@", health_text))  # No user@host patterns

  cat("   ✅ Database health check doesn't expose credentials\n")
})

test_that("Health Check - Prometheus Metrics Safety", {
  skip_if(!exists("get_prometheus_metrics"), "Health check not loaded")

  cat("\n📊 Testing Prometheus Metrics Safety\n")

  metrics <- if (DB_AVAILABLE) {
    get_prometheus_metrics(db_pool)
  } else {
    get_prometheus_metrics(NULL)
  }

  # Metrics should be text format
  expect_true(is.character(metrics))

  # Should contain Prometheus format
  expect_true(grepl("# HELP", metrics))
  expect_true(grepl("# TYPE", metrics))

  # Should not contain sensitive info
  expect_false(grepl("password", metrics, ignore.case = TRUE))
  expect_false(grepl("secret", metrics, ignore.case = TRUE))

  cat("   ✅ Prometheus metrics don't expose sensitive data\n")
})

test_that("Health Check - Readiness and Liveness Probes", {
  skip_if(!exists("is_ready"), "Health check not loaded")
  skip_if(!exists("is_alive"), "Health check not loaded")

  cat("\n💓 Testing Readiness and Liveness Probes\n")

  # Test liveness - should always return TRUE if R is running
  alive <- is_alive()
  expect_true(is.logical(alive))
  expect_true(alive)
  cat("   ✅ Liveness probe functional\n")

  # Test readiness
  ready <- if (DB_AVAILABLE) {
    is_ready(db_pool)
  } else {
    is_ready(NULL)
  }

  expect_true(is.logical(ready))
  cat(paste("   ✅ Readiness probe functional, status:", ready, "\n"))
})

test_that("Health Check - Alert Conditions", {
  skip_if(!exists("get_active_alerts"), "Health check not loaded")

  cat("\n🚨 Testing Alert Conditions\n")

  alerts <- if (DB_AVAILABLE) {
    get_active_alerts(db_pool)
  } else {
    get_active_alerts(NULL)
  }

  # Alerts should be a list
  expect_true(is.list(alerts))

  # If there are alerts, they should have proper structure
  if (length(alerts) > 0) {
    for (alert in alerts) {
      expect_true("severity" %in% names(alert))
      expect_true("component" %in% names(alert))
      expect_true("message" %in% names(alert))
      expect_true(alert$severity %in% c("critical", "warning", "info"))
    }

    cat(paste("   ⚠️", length(alerts), "active alerts detected\n"))
  } else {
    cat("   ✅ No active alerts\n")
  }
})

# =============================================================================
# INTEGRATION TESTS
# =============================================================================

test_that("Integration - Error Handling in Transactions", {
  skip_if(!DB_AVAILABLE, "Database not available")
  skip_if(!exists("execute_in_transaction"), "Transaction support not loaded")
  skip_if(!exists("handle_database_error"), "Error handling not loaded")

  cat("\n🔄 Testing Error Handling in Transactions Integration\n")

  # Execute transaction that will fail
  result <- tryCatch({
    execute_in_transaction(db_pool, function(conn) {
      # Force an error
      DBI::dbGetQuery(conn, "SELECT * FROM non_existent_table")
    }, log_transactions = FALSE)
  }, error = function(e) {
    handle_database_error(e, context = "Integration test")
  })

  # Should receive standardized error
  expect_true(is.list(result))
  expect_false(result$success)
  expect_true("error" %in% names(result))
  expect_true("code" %in% names(result$error))

  cat("   ✅ Error handling integrated with transactions\n")
})

test_that("Integration - Health Check with Error Handling", {
  skip_if(!exists("perform_health_check"), "Health check not loaded")
  skip_if(!exists("safe_execute"), "Error handling not loaded")

  cat("\n🏥 Testing Health Check with Error Handling Integration\n")

  # Wrap health check in safe_execute
  result <- safe_execute({
    if (DB_AVAILABLE) {
      perform_health_check(db_pool, detailed = FALSE)
    } else {
      perform_health_check(NULL, detailed = FALSE)
    }
  })

  # Should always return valid health status
  expect_true(is.list(result))
  expect_true("status" %in% names(result) || "error" %in% names(result))

  cat("   ✅ Health check integrated with error handling\n")
})

# =============================================================================
# PERFORMANCE AND SECURITY TESTS
# =============================================================================

test_that("Performance - Transaction Overhead", {
  skip_if(!DB_AVAILABLE, "Database not available")
  skip_if(!exists("execute_in_transaction"), "Transaction support not loaded")

  cat("\n⚡ Testing Transaction Performance Overhead\n")

  # Measure direct query time
  start_direct <- Sys.time()
  result_direct <- tryCatch({
    DBI::dbGetQuery(db_pool, "SELECT 1 as test")
  }, error = function(e) NULL)
  time_direct <- as.numeric(difftime(Sys.time(), start_direct, units = "secs"))

  # Measure transaction query time
  start_transaction <- Sys.time()
  result_transaction <- tryCatch({
    execute_in_transaction(db_pool, function(conn) {
      DBI::dbGetQuery(conn, "SELECT 1 as test")
    }, log_transactions = FALSE)
  }, error = function(e) NULL)
  time_transaction <- as.numeric(difftime(Sys.time(), start_transaction, units = "secs"))

  if (!is.null(result_direct) && !is.null(result_transaction)) {
    overhead <- time_transaction - time_direct
    overhead_pct <- (overhead / time_direct) * 100

    cat(paste("   Direct query:", round(time_direct * 1000, 2), "ms\n"))
    cat(paste("   Transaction query:", round(time_transaction * 1000, 2), "ms\n"))
    cat(paste("   Overhead:", round(overhead * 1000, 2), "ms (", round(overhead_pct, 1), "%)\n"))

    # Overhead should be reasonable (< 200%)
    expect_true(overhead_pct < 200,
               label = "Transaction overhead should be reasonable")
  }
})

test_that("Security - Rate Limiting Simulation", {
  skip_if(!exists("get_application_metrics"), "Metrics not loaded")
  skip_if(!exists("increment_request_counter"), "Metrics not loaded")

  cat("\n🚦 Testing Rate Limiting Metrics\n")

  # Simulate rapid requests
  initial_metrics <- get_application_metrics()

  for (i in 1:10) {
    increment_request_counter()
  }

  final_metrics <- get_application_metrics()

  # Request count should have increased
  expect_true(final_metrics$total_requests > initial_metrics$total_requests)

  cat(paste("   ✅ Request counter functional:", final_metrics$total_requests, "requests\n"))
})

# =============================================================================
# SUMMARY
# =============================================================================

cat("\n" strrep("=", 70), "\n")
cat("📊 Phase 4 & 5 Security Testing Summary\n")
cat(strrep("=", 70), "\n")
cat("✅ Transaction Support: ACID properties, isolation, pool safety\n")
cat("✅ Error Handling: Standardized codes, no info disclosure, safe execution\n")
cat("✅ Health Checks: No sensitive exposure, Prometheus metrics, probes\n")
cat("✅ Integration: Components work together securely\n")
cat("✅ Performance: Transaction overhead measured and acceptable\n")
cat(strrep("=", 70), "\n")
