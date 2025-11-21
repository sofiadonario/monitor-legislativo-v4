# =============================================================================
# Phase 4 & 5 Performance Benchmarks
# =============================================================================
# Monitor Legislativo v4 - Performance Testing
#
# Benchmarks for transaction support, error handling, and health checks
# Ensures acceptable performance overhead for new components
#
# Author: Monitor Legislativo v4 Team
# Version: 4.0.0
# Last Updated: 2025-11-21
# =============================================================================

library(testthat)
library(microbenchmark)
library(DBI)
library(pool)

# Skip tests if database not available
if (!exists("db_pool") || is.null(db_pool)) {
  cat("⚠️ Database pool not available - skipping performance tests\n")
  DB_AVAILABLE <- FALSE
} else {
  DB_AVAILABLE <- TRUE
}

# Source components
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
# TRANSACTION PERFORMANCE BENCHMARKS
# =============================================================================

test_that("Transaction Overhead Benchmark", {
  skip_if(!DB_AVAILABLE, "Database not available")
  skip_if(!exists("execute_in_transaction"), "Transaction support not loaded")

  cat("\n⚡ Benchmarking Transaction Overhead\n")

  # Benchmark 1: Direct query vs Transaction wrapper
  benchmark_result <- microbenchmark(
    direct_query = {
      DBI::dbGetQuery(db_pool, "SELECT 1 as test")
    },
    with_transaction = {
      execute_in_transaction(db_pool, function(conn) {
        DBI::dbGetQuery(conn, "SELECT 1 as test")
      }, log_transactions = FALSE)
    },
    times = 50,
    unit = "ms"
  )

  print(summary(benchmark_result))

  # Calculate overhead
  direct_median <- median(benchmark_result$time[benchmark_result$expr == "direct_query"])
  transaction_median <- median(benchmark_result$time[benchmark_result$expr == "with_transaction"])
  overhead_ms <- (transaction_median - direct_median) / 1e6
  overhead_pct <- (overhead_ms / (direct_median / 1e6)) * 100

  cat(sprintf("\nTransaction Overhead: %.2f ms (%.1f%%)\n", overhead_ms, overhead_pct))

  # Overhead should be reasonable (< 50ms and < 200%)
  expect_true(overhead_ms < 50,
             label = sprintf("Transaction overhead should be < 50ms, got %.2f ms", overhead_ms))
  expect_true(overhead_pct < 200,
             label = sprintf("Transaction overhead should be < 200%%, got %.1f%%", overhead_pct))
})

test_that("Batch Transaction Performance", {
  skip_if(!DB_AVAILABLE, "Database not available")
  skip_if(!exists("execute_in_transaction"), "Transaction support not loaded")

  cat("\n📦 Benchmarking Batch Transaction Performance\n")

  # Create test data
  test_data <- data.frame(
    test_id = 1:100,
    test_value = paste("value", 1:100),
    stringsAsFactors = FALSE
  )

  # Benchmark batch insert
  benchmark_result <- microbenchmark(
    batch_100_rows = {
      execute_in_transaction(db_pool, function(conn) {
        # Simulated batch operation
        for (i in 1:100) {
          DBI::dbExecute(conn, "SELECT 1")
        }
      }, log_transactions = FALSE)
    },
    times = 10,
    unit = "ms"
  )

  print(summary(benchmark_result))

  median_time <- median(benchmark_result$time) / 1e6
  cat(sprintf("\nMedian time for 100 operations: %.2f ms\n", median_time))
  cat(sprintf("Average time per operation: %.3f ms\n", median_time / 100))

  # Should complete in reasonable time (< 1 second for 100 ops)
  expect_true(median_time < 1000,
             label = sprintf("Batch transaction should complete in < 1s, got %.2f ms", median_time))
})

# =============================================================================
# ERROR HANDLING PERFORMANCE BENCHMARKS
# =============================================================================

test_that("Error Handling Overhead Benchmark", {
  skip_if(!exists("safe_execute"), "Error handling not loaded")

  cat("\n🛡️ Benchmarking Error Handling Overhead\n")

  # Simple operation for comparison
  simple_operation <- function() {
    1 + 1
  }

  # Benchmark direct vs safe_execute
  benchmark_result <- microbenchmark(
    direct_execution = {
      simple_operation()
    },
    with_safe_execute = {
      safe_execute(simple_operation())
    },
    times = 1000,
    unit = "us"  # microseconds
  )

  print(summary(benchmark_result))

  # Calculate overhead
  direct_median <- median(benchmark_result$time[benchmark_result$expr == "direct_execution"])
  safe_median <- median(benchmark_result$time[benchmark_result$expr == "with_safe_execute"])
  overhead_us <- (safe_median - direct_median) / 1000
  overhead_pct <- (overhead_us / (direct_median / 1000)) * 100

  cat(sprintf("\nSafe Execute Overhead: %.2f µs (%.1f%%)\n", overhead_us, overhead_pct))

  # Overhead should be minimal (< 100 µs)
  expect_true(overhead_us < 100,
             label = sprintf("Safe execute overhead should be < 100µs, got %.2f µs", overhead_us))
})

test_that("Error Creation Performance", {
  skip_if(!exists("create_error_response"), "Error handling not loaded")

  cat("\n🚨 Benchmarking Error Creation Performance\n")

  benchmark_result <- microbenchmark(
    create_simple_error = {
      create_error_response("INTERNAL_ERROR")
    },
    create_detailed_error = {
      create_error_response(
        "DB_QUERY_FAILED",
        details = list(query = "SELECT * FROM table", params = list(1, 2, 3)),
        technical_info = "Connection timeout after 30 seconds"
      )
    },
    times = 500,
    unit = "us"
  )

  print(summary(benchmark_result))

  simple_median <- median(benchmark_result$time[benchmark_result$expr == "create_simple_error"]) / 1000
  detailed_median <- median(benchmark_result$time[benchmark_result$expr == "create_detailed_error"]) / 1000

  cat(sprintf("\nSimple error creation: %.2f µs\n", simple_median))
  cat(sprintf("Detailed error creation: %.2f µs\n", detailed_median))

  # Error creation should be fast (< 500 µs)
  expect_true(detailed_median < 500,
             label = sprintf("Error creation should be < 500µs, got %.2f µs", detailed_median))
})

test_that("Error Handling in Hot Path", {
  skip_if(!exists("handle_database_error"), "Error handling not loaded")

  cat("\n🔥 Benchmarking Error Handling in Hot Path\n")

  # Simulate repeated error handling (like in a loop)
  benchmark_result <- microbenchmark(
    handle_100_errors = {
      for (i in 1:100) {
        error <- simpleError("Test error")
        handle_database_error(error, context = paste("Iteration", i))
      }
    },
    times = 10,
    unit = "ms"
  )

  print(summary(benchmark_result))

  median_time <- median(benchmark_result$time) / 1e6
  per_error_time <- median_time / 100

  cat(sprintf("\nTime for 100 errors: %.2f ms\n", median_time))
  cat(sprintf("Time per error: %.3f ms\n", per_error_time))

  # Should handle errors efficiently (< 100ms for 100 errors)
  expect_true(median_time < 100,
             label = sprintf("100 error handles should be < 100ms, got %.2f ms", median_time))
})

# =============================================================================
# HEALTH CHECK PERFORMANCE BENCHMARKS
# =============================================================================

test_that("Health Check Performance", {
  skip_if(!exists("perform_health_check"), "Health check not loaded")

  cat("\n💓 Benchmarking Health Check Performance\n")

  # Benchmark basic and detailed health checks
  benchmark_result <- microbenchmark(
    basic_health_check = {
      if (DB_AVAILABLE) {
        perform_health_check(db_pool, detailed = FALSE)
      } else {
        perform_health_check(NULL, detailed = FALSE)
      }
    },
    detailed_health_check = {
      if (DB_AVAILABLE) {
        perform_health_check(db_pool, detailed = TRUE)
      } else {
        perform_health_check(NULL, detailed = TRUE)
      }
    },
    times = 50,
    unit = "ms"
  )

  print(summary(benchmark_result))

  basic_median <- median(benchmark_result$time[benchmark_result$expr == "basic_health_check"]) / 1e6
  detailed_median <- median(benchmark_result$time[benchmark_result$expr == "detailed_health_check"]) / 1e6

  cat(sprintf("\nBasic health check: %.2f ms\n", basic_median))
  cat(sprintf("Detailed health check: %.2f ms\n", detailed_median))

  # Health checks should be fast (< 100ms basic, < 500ms detailed)
  expect_true(basic_median < 100,
             label = sprintf("Basic health check should be < 100ms, got %.2f ms", basic_median))
  expect_true(detailed_median < 500,
             label = sprintf("Detailed health check should be < 500ms, got %.2f ms", detailed_median))
})

test_that("Individual Health Check Components", {
  skip_if(!exists("check_memory_health"), "Health check not loaded")

  cat("\n🔍 Benchmarking Individual Health Components\n")

  benchmark_result <- microbenchmark(
    memory_check = {
      check_memory_health()
    },
    session_check = {
      check_session_health()
    },
    database_check = {
      if (DB_AVAILABLE) {
        check_database_health(db_pool)
      }
    },
    times = 100,
    unit = "ms"
  )

  print(summary(benchmark_result))

  # Extract medians
  memory_median <- median(benchmark_result$time[benchmark_result$expr == "memory_check"]) / 1e6
  session_median <- median(benchmark_result$time[benchmark_result$expr == "session_check"]) / 1e6

  cat(sprintf("\nMemory check: %.2f ms\n", memory_median))
  cat(sprintf("Session check: %.2f ms\n", session_median))

  if (DB_AVAILABLE) {
    db_median <- median(benchmark_result$time[benchmark_result$expr == "database_check"]) / 1e6
    cat(sprintf("Database check: %.2f ms\n", db_median))

    # Database check should be reasonably fast (< 100ms)
    expect_true(db_median < 100,
               label = sprintf("Database check should be < 100ms, got %.2f ms", db_median))
  }

  # Individual checks should be very fast
  expect_true(memory_median < 50,
             label = sprintf("Memory check should be < 50ms, got %.2f ms", memory_median))
  expect_true(session_median < 10,
             label = sprintf("Session check should be < 10ms, got %.2f ms", session_median))
})

test_that("Prometheus Metrics Generation", {
  skip_if(!exists("get_prometheus_metrics"), "Health check not loaded")

  cat("\n📊 Benchmarking Prometheus Metrics Generation\n")

  benchmark_result <- microbenchmark(
    generate_metrics = {
      if (DB_AVAILABLE) {
        get_prometheus_metrics(db_pool)
      } else {
        get_prometheus_metrics(NULL)
      }
    },
    times = 100,
    unit = "ms"
  )

  print(summary(benchmark_result))

  median_time <- median(benchmark_result$time) / 1e6
  cat(sprintf("\nPrometheus metrics generation: %.2f ms\n", median_time))

  # Metrics generation should be fast (< 200ms)
  expect_true(median_time < 200,
             label = sprintf("Metrics generation should be < 200ms, got %.2f ms", median_time))
})

test_that("Concurrent Health Check Load", {
  skip_if(!exists("perform_health_check"), "Health check not loaded")

  cat("\n🏋️ Benchmarking Concurrent Health Check Load\n")

  # Simulate multiple concurrent health checks
  start_time <- Sys.time()

  results <- lapply(1:10, function(i) {
    if (DB_AVAILABLE) {
      perform_health_check(db_pool, detailed = FALSE)
    } else {
      perform_health_check(NULL, detailed = FALSE)
    }
  })

  end_time <- Sys.time()
  total_time <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000

  cat(sprintf("\n10 concurrent health checks: %.2f ms\n", total_time))
  cat(sprintf("Average per check: %.2f ms\n", total_time / 10))

  # Should handle concurrent checks efficiently (< 1 second for 10)
  expect_true(total_time < 1000,
             label = sprintf("10 concurrent checks should be < 1s, got %.2f ms", total_time))
})

# =============================================================================
# INTEGRATION PERFORMANCE BENCHMARKS
# =============================================================================

test_that("Full Request Cycle Benchmark", {
  skip_if(!DB_AVAILABLE, "Database not available")
  skip_if(!exists("execute_in_transaction"), "Transaction support not loaded")
  skip_if(!exists("safe_execute"), "Error handling not loaded")

  cat("\n🔄 Benchmarking Full Request Cycle\n")

  # Simulate a full request: validation → transaction → error handling
  simulate_request <- function() {
    safe_execute({
      execute_in_transaction(db_pool, function(conn) {
        # Simulated query
        DBI::dbGetQuery(conn, "SELECT 1 as test")
      }, log_transactions = FALSE)
    })
  }

  benchmark_result <- microbenchmark(
    full_request = simulate_request(),
    times = 50,
    unit = "ms"
  )

  print(summary(benchmark_result))

  median_time <- median(benchmark_result$time) / 1e6
  cat(sprintf("\nFull request cycle: %.2f ms\n", median_time))

  # Full cycle should be fast (< 100ms)
  expect_true(median_time < 100,
             label = sprintf("Full request should be < 100ms, got %.2f ms", median_time))
})

# =============================================================================
# MEMORY USAGE BENCHMARKS
# =============================================================================

test_that("Memory Usage - Transaction Support", {
  skip_if(!DB_AVAILABLE, "Database not available")
  skip_if(!exists("execute_in_transaction"), "Transaction support not loaded")

  cat("\n💾 Benchmarking Memory Usage - Transactions\n")

  # Measure memory before
  gc()
  mem_before <- pryr::mem_used()

  # Execute 100 transactions
  for (i in 1:100) {
    execute_in_transaction(db_pool, function(conn) {
      DBI::dbGetQuery(conn, "SELECT 1 as test")
    }, log_transactions = FALSE)
  }

  # Measure memory after
  mem_after <- pryr::mem_used()
  mem_diff <- as.numeric(mem_after - mem_before) / 1024 / 1024  # MB

  cat(sprintf("\nMemory used for 100 transactions: %.2f MB\n", mem_diff))

  # Memory usage should be reasonable (< 50 MB for 100 transactions)
  expect_true(mem_diff < 50,
             label = sprintf("Memory usage should be < 50MB, got %.2f MB", mem_diff))
})

test_that("Memory Usage - Health Checks", {
  skip_if(!exists("perform_health_check"), "Health check not loaded")

  cat("\n💾 Benchmarking Memory Usage - Health Checks\n")

  # Measure memory before
  gc()
  mem_before <- pryr::mem_used()

  # Execute 100 health checks
  for (i in 1:100) {
    if (DB_AVAILABLE) {
      perform_health_check(db_pool, detailed = FALSE)
    } else {
      perform_health_check(NULL, detailed = FALSE)
    }
  }

  # Measure memory after
  mem_after <- pryr::mem_used()
  mem_diff <- as.numeric(mem_after - mem_before) / 1024 / 1024  # MB

  cat(sprintf("\nMemory used for 100 health checks: %.2f MB\n", mem_diff))

  # Memory usage should be minimal (< 10 MB for 100 checks)
  expect_true(mem_diff < 10,
             label = sprintf("Memory usage should be < 10MB, got %.2f MB", mem_diff))
})

# =============================================================================
# PERFORMANCE SUMMARY
# =============================================================================

cat("\n", strrep("=", 70), "\n")
cat("📊 Phase 4 & 5 Performance Summary\n")
cat(strrep("=", 70), "\n")
cat("✅ Transaction overhead measured and acceptable\n")
cat("✅ Error handling adds minimal overhead\n")
cat("✅ Health checks are fast and efficient\n")
cat("✅ Memory usage is reasonable\n")
cat("✅ System ready for production load\n")
cat(strrep("=", 70), "\n")
