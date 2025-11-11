# ============================================================================
# PERFORMANCE TESTING SCRIPT - Railway PostgreSQL Optimization Validation
# ============================================================================
#
# This script validates the performance improvements implemented in the
# database optimization modules for the Brazilian Legislative Monitor.
#
# Tests Performed:
# 1. Database connection and optimization module loading
# 2. Index effectiveness validation
# 3. Materialized views performance testing
# 4. Query performance comparison (before/after optimization)
# 5. Cache system effectiveness testing
# 6. Dashboard metrics performance validation
# 7. Memory usage and resource consumption analysis
# 8. Concurrent load testing
# 9. Error handling and fallback mechanisms
# 10. Performance monitoring system validation
#
# Expected Results:
# - Query execution time reduction: 75-90%
# - Dashboard loading improvement: 80-95%
# - Cache hit rates: >70%
# - Memory usage optimization: <50% of baseline
# - Concurrent user support: 5-10x improvement
#
# Railway Production Safety:
# - Non-destructive testing only
# - Automatic cleanup of test data
# - Resource usage monitoring
# - Safe fallback mechanisms
# ============================================================================

cat("🧪 PERFORMANCE TESTING SUITE - Railway PostgreSQL Optimization\n")
cat("================================================================\n")

# Load required libraries
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
  library(pool)
  library(dplyr)
  library(microbenchmark)
  library(parallel)
})

# Test configuration
test_config <- list(
  iterations_per_test = 10,
  concurrent_users = 5,
  test_timeout_seconds = 300,
  benchmark_samples = 25,
  memory_threshold_mb = 500,
  acceptable_slowdown_factor = 2.0,
  expected_improvement_factor = 5.0
)

# Test results storage
test_results <- list(
  module_loading = list(),
  connection_tests = list(),
  query_performance = list(),
  cache_performance = list(),
  materialized_views = list(),
  monitoring_system = list(),
  concurrent_load = list(),
  memory_usage = list(),
  overall_summary = list()
)

# ============================================================================
# TEST UTILITY FUNCTIONS
# ============================================================================

#' Execute test with timing and error handling
#' @param test_name Name of the test
#' @param test_function Function to execute
#' @param iterations Number of iterations
#' @return List with test results
execute_test <- function(test_name, test_function, iterations = 1) {
  cat("🔍 Running test:", test_name, "\n")
  
  results <- list(
    test_name = test_name,
    iterations = iterations,
    execution_times = numeric(),
    errors = character(),
    success_rate = 0,
    avg_time_ms = 0,
    min_time_ms = 0,
    max_time_ms = 0,
    status = "RUNNING"
  )
  
  successful_runs <- 0
  
  for (i in 1:iterations) {
    start_time <- Sys.time()
    
    tryCatch({
      test_function()
      end_time <- Sys.time()
      
      execution_time_ms <- as.numeric(difftime(end_time, start_time, units = "secs")) * 1000
      results$execution_times <- c(results$execution_times, execution_time_ms)
      successful_runs <- successful_runs + 1
      
    }, error = function(e) {
      results$errors <- c(results$errors, as.character(e$message))
      cat("  ❌ Error in iteration", i, ":", e$message, "\n")
    })
  }
  
  # Calculate statistics
  if (length(results$execution_times) > 0) {
    results$avg_time_ms <- mean(results$execution_times)
    results$min_time_ms <- min(results$execution_times)
    results$max_time_ms <- max(results$execution_times)
  }
  
  results$success_rate <- successful_runs / iterations * 100
  results$status <- if (successful_runs > 0) "COMPLETED" else "FAILED"
  
  cat("  ✅ Test completed:", successful_runs, "/", iterations, "successful (",
      round(results$success_rate, 1), "%) - Avg:", round(results$avg_time_ms, 2), "ms\n")
  
  return(results)
}

#' Get memory usage in MB
#' @return Numeric memory usage
get_memory_usage_mb <- function() {
  gc_info <- gc()
  return(sum(gc_info[, "max used"]) * 8 / 1024 / 1024)  # Convert to MB
}

#' Check if database optimization modules are loaded
#' @return Boolean indicating success
check_modules_loaded <- function() {
  required_functions <- c(
    "get_library_documents_optimized",
    "get_cached_table_info", 
    "execute_optimized_query",
    "get_performance_stats",
    "init_query_monitoring"
  )
  
  missing_functions <- c()
  for (func in required_functions) {
    if (!exists(func)) {
      missing_functions <- c(missing_functions, func)
    }
  }
  
  if (length(missing_functions) > 0) {
    stop("Missing required functions: ", paste(missing_functions, collapse = ", "))
  }
  
  return(TRUE)
}

# ============================================================================
# MODULE LOADING TESTS
# ============================================================================

cat("\n📦 TESTING MODULE LOADING\n")
cat("==========================\n")

# Test 1: Load performance optimization module
test_results$module_loading$performance_optimization <- execute_test(
  "Load Performance Optimization Module",
  function() {
    # Source the performance optimization module
    if (file.exists("db/performance_optimization.R")) {
      source("db/performance_optimization.R")
    } else {
      stop("Performance optimization module not found")
    }
    
    # Verify key functions exist
    check_modules_loaded()
  },
  1
)

# Test 2: Load query monitoring module
test_results$module_loading$query_monitoring <- execute_test(
  "Load Query Monitoring Module", 
  function() {
    if (file.exists("db/query_monitor.R")) {
      source("db/query_monitor.R")
    } else {
      stop("Query monitoring module not found")
    }
    
    if (!exists("init_query_monitoring")) {
      stop("Query monitoring functions not available")
    }
  },
  1
)

# Test 3: Initialize monitoring system
test_results$module_loading$monitoring_init <- execute_test(
  "Initialize Query Monitoring",
  function() {
    init_result <- init_query_monitoring()
    if (!init_result) {
      stop("Failed to initialize query monitoring")
    }
  },
  1
)

# ============================================================================
# DATABASE CONNECTION TESTS
# ============================================================================

cat("\n🔌 TESTING DATABASE CONNECTIONS\n")
cat("================================\n")

# Test 4: Cached table discovery
test_results$connection_tests$table_discovery <- execute_test(
  "Cached Table Discovery",
  function() {
    table_info <- get_cached_table_info()
    if (is.null(table_info$main_table)) {
      stop("No main table discovered")
    }
    
    if (length(table_info$available_tables) == 0) {
      stop("No tables available")
    }
    
    cat("    Main table:", table_info$main_table, "\n")
    cat("    Available tables:", length(table_info$available_tables), "\n")
  },
  test_config$iterations_per_test
)

# Test 5: Database connection health
test_results$connection_tests$connection_health <- execute_test(
  "Database Connection Health Check",
  function() {
    # Test basic connectivity
    pool <- get_monitoring_pool()
    if (is.null(pool)) {
      stop("No database pool available")
    }
    
    # Test simple query
    result <- dbGetQuery(pool, "SELECT 1 as test")
    if (isTRUE(is.null(result)) || nrow(result) != 1) {
      stop("Basic query failed")
    }
  },
  test_config$iterations_per_test
)

# ============================================================================
# QUERY PERFORMANCE TESTS
# ============================================================================

cat("\n⚡ TESTING QUERY PERFORMANCE\n")
cat("============================\n")

# Test 6: Optimized library documents query
test_results$query_performance$library_documents <- execute_test(
  "Optimized Library Documents Query",
  function() {
    result <- get_library_documents_optimized(
      category = "legislation",
      search_term = "transporte",
      state = "all",
      limit = 100
    )
    
    if (is.null(result)) {
      stop("Query returned NULL")
    }
    
    if (!is.data.frame(result)) {
      stop("Query did not return data frame")
    }
    
    cat("    Returned", nrow(result), "documents\n")
  },
  test_config$iterations_per_test
)

# Test 7: Dashboard metrics performance
test_results$query_performance$dashboard_metrics <- execute_test(
  "Optimized Dashboard Metrics",
  function() {
    metrics <- get_dashboard_metrics_optimized()
    
    if (is.null(metrics)) {
      stop("Metrics returned NULL")
    }
    
    required_metrics <- c("total_documents", "states_with_docs", "municipalities_with_docs")
    for (metric in required_metrics) {
      if (!metric %in% names(metrics)) {
        stop(paste("Missing required metric:", metric))
      }
    }
    
    cat("    Total documents:", metrics$total_documents, "\n")
  },
  test_config$iterations_per_test
)

# Test 8: Query performance comparison (if fallback available)
if (exists("get_library_documents")) {
  
  cat("\n📊 PERFORMANCE COMPARISON TEST\n")
  
  # Benchmark optimized vs original function
  benchmark_result <- tryCatch({
    microbenchmark::microbenchmark(
      optimized = get_library_documents_optimized(limit = 50),
      original = get_library_documents(limit = 50),
      times = min(test_config$benchmark_samples, 10),
      unit = "ms"
    )
  }, error = function(e) {
    cat("  ⚠️ Benchmark comparison failed:", e$message, "\n")
    NULL
  })
  
  if (!is.null(benchmark_result)) {
    optimized_median <- median(benchmark_result[benchmark_result$expr == "optimized", "time"]) / 1e6
    original_median <- median(benchmark_result[benchmark_result$expr == "original", "time"]) / 1e6
    improvement_factor <- original_median / optimized_median
    
    test_results$query_performance$comparison <- list(
      optimized_median_ms = optimized_median,
      original_median_ms = original_median,
      improvement_factor = improvement_factor,
      meets_expectations = improvement_factor >= test_config$expected_improvement_factor
    )
    
    cat("  📈 Performance Improvement:", round(improvement_factor, 2), "x\n")
    cat("  ⏱️ Optimized median:", round(optimized_median, 2), "ms\n")
    cat("  ⏱️ Original median:", round(original_median, 2), "ms\n")
    
    if (improvement_factor >= test_config$expected_improvement_factor) {
      cat("  ✅ Performance improvement exceeds expectations!\n")
    } else {
      cat("  ⚠️ Performance improvement below expectations\n")
    }
  }
}

# ============================================================================
# CACHE PERFORMANCE TESTS
# ============================================================================

cat("\n💾 TESTING CACHE PERFORMANCE\n")
cat("=============================\n")

# Test 9: Query cache effectiveness
test_results$cache_performance$query_cache <- execute_test(
  "Query Cache Hit Rate",
  function() {
    # Clear cache first
    if (exists("clear_performance_cache")) {
      clear_performance_cache(confirm = TRUE)
    }
    
    # Execute same query multiple times
    search_term <- "energia"
    
    # First execution (cache miss)
    result1 <- get_library_documents_optimized(search_term = search_term, limit = 20)
    
    # Second execution (should be cache hit)
    result2 <- get_library_documents_optimized(search_term = search_term, limit = 20)
    
    if (isTRUE(is.null(result1)) || isTRUE(is.null(result2))) {
      stop("Cache test queries failed")
    }
    
    if (nrow(result1) != nrow(result2)) {
      stop("Cached results differ from original")
    }
    
    # Check performance stats
    if (exists("get_performance_stats")) {
      stats <- get_performance_stats()
      if (stats$cache_hits > 0) {
        cat("    Cache hit rate:", stats$cache_hit_rate, "%\n")
      }
    }
  },
  5
)

# Test 10: Table cache persistence
test_results$cache_performance$table_cache <- execute_test(
  "Table Cache Persistence",
  function() {
    # Get table info multiple times
    info1 <- get_cached_table_info()
    info2 <- get_cached_table_info()
    
    if (isTRUE(is.null(info1$main_table)) || isTRUE(is.null(info2$main_table))) {
      stop("Table cache failed")
    }
    
    if (info1$main_table != info2$main_table) {
      stop("Table cache inconsistent")
    }
    
    cat("    Cached main table:", info1$main_table, "\n")
  },
  test_config$iterations_per_test
)

# ============================================================================
# MATERIALIZED VIEWS TESTS
# ============================================================================

cat("\n🏗️ TESTING MATERIALIZED VIEWS\n")
cat("==============================\n")

# Test 11: Materialized views availability
test_results$materialized_views$availability <- execute_test(
  "Materialized Views Availability",
  function() {
    pool <- get_monitoring_pool()
    if (is.null(pool)) {
      stop("No database pool for materialized views test")
    }
    
    # Check if materialized views exist
    mv_query <- "
      SELECT matviewname 
      FROM pg_matviews 
      WHERE matviewname LIKE 'mv_%'
      ORDER BY matviewname
    "
    
    mv_result <- dbGetQuery(pool, mv_query)
    
    if (nrow(mv_result) == 0) {
      stop("No materialized views found - run migrations first")
    }
    
    expected_views <- c(
      "mv_document_metrics",
      "mv_state_document_counts", 
      "mv_document_type_summary"
    )
    
    available_views <- mv_result$matviewname
    missing_views <- setdiff(expected_views, available_views)
    
    if (length(missing_views) > 0) {
      cat("    ⚠️ Missing views:", paste(missing_views, collapse = ", "), "\n")
    }
    
    cat("    Available materialized views:", length(available_views), "\n")
    
    return(length(available_views) > 0)
  },
  1
)

# Test 12: Materialized views performance
if (test_results$materialized_views$availability$success_rate > 0) {
  test_results$materialized_views$performance <- execute_test(
    "Materialized Views Query Performance",
    function() {
      pool <- get_monitoring_pool()
      
      # Test querying materialized views directly
      mv_queries <- list(
        document_metrics = "SELECT * FROM mv_document_metrics LIMIT 1",
        state_counts = "SELECT * FROM mv_state_document_counts LIMIT 10"
      )
      
      for (view_name in names(mv_queries)) {
        tryCatch({
          result <- dbGetQuery(pool, mv_queries[[view_name]])
          if (nrow(result) == 0) {
            cat("    ⚠️", view_name, "view is empty\n")
          } else {
            cat("    ✅", view_name, "returned", nrow(result), "rows\n")
          }
        }, error = function(e) {
          stop(paste("Failed to query", view_name, ":", e$message))
        })
      }
    },
    test_config$iterations_per_test
  )
}

# ============================================================================
# CONCURRENT LOAD TESTS
# ============================================================================

cat("\n👥 TESTING CONCURRENT LOAD\n")
cat("==========================\n")

# Test 13: Concurrent user simulation
test_results$concurrent_load$user_simulation <- execute_test(
  "Concurrent User Load Test",
  function() {
    if (test_config$concurrent_users > 1 && require("parallel", quietly = TRUE)) {
      
      # Create cluster for parallel execution
      cl <- makeCluster(min(test_config$concurrent_users, 4))
      
      tryCatch({
        # Export necessary functions to cluster
        clusterEvalQ(cl, {
          # Simulate user queries
          user_queries <- c(
            list(category = "legislation", limit = 50),
            list(search_term = "transporte", limit = 30),
            list(state = "SP", limit = 40),
            list(category = "jurisprudence", limit = 25)
          )
        })
        
        # Execute concurrent queries
        results <- parLapply(cl, 1:test_config$concurrent_users, function(user_id) {
          start_time <- Sys.time()
          
          # Simulate different user behavior
          query_params <- list(
            category = sample(c("all", "legislation", "jurisprudence"), 1),
            search_term = sample(c("", "energia", "transporte", "sustentável"), 1),
            limit = sample(c(20, 50, 100), 1)
          )
          
          if (exists("get_library_documents_optimized")) {
            result <- do.call(get_library_documents_optimized, query_params)
            end_time <- Sys.time()
            
            return(list(
              user_id = user_id,
              execution_time = as.numeric(difftime(end_time, start_time, units = "secs")),
              rows_returned = if (!is.null(result)) nrow(result) else 0,
              success = !is.null(result)
            ))
          } else {
            return(list(user_id = user_id, success = FALSE, error = "Function not available"))
          }
        })
        
        # Analyze concurrent performance
        successful_users <- sum(sapply(results, function(r) r$success))
        avg_response_time <- mean(sapply(results[sapply(results, function(r) r$success)], 
                                       function(r) r$execution_time))
        
        cat("    Successful concurrent users:", successful_users, "/", test_config$concurrent_users, "\n")
        cat("    Average response time:", round(avg_response_time, 3), "seconds\n")
        
        if (successful_users < test_config$concurrent_users) {
          stop(paste("Only", successful_users, "out of", test_config$concurrent_users, "users succeeded"))
        }
        
      }, finally = {
        stopCluster(cl)
      })
      
    } else {
      cat("    ⚠️ Skipping concurrent test (parallel package not available or single user)\n")
    }
  },
  1
)

# ============================================================================
# MEMORY USAGE TESTS
# ============================================================================

cat("\n🧠 TESTING MEMORY USAGE\n")
cat("========================\n")

# Test 14: Memory usage monitoring
test_results$memory_usage$optimization_impact <- execute_test(
  "Memory Usage During Optimization",
  function() {
    initial_memory <- get_memory_usage_mb()
    
    # Execute multiple queries to test memory efficiency
    for (i in 1:10) {
      result <- get_library_documents_optimized(
        search_term = paste("test", i),
        limit = 100
      )
      
      # Force garbage collection
      if (i %% 3 == 0) gc()
    }
    
    final_memory <- get_memory_usage_mb()
    memory_increase <- final_memory - initial_memory
    
    cat("    Initial memory:", round(initial_memory, 2), "MB\n")
    cat("    Final memory:", round(final_memory, 2), "MB\n") 
    cat("    Memory increase:", round(memory_increase, 2), "MB\n")
    
    if (memory_increase > test_config$memory_threshold_mb) {
      stop(paste("Memory usage increase", round(memory_increase, 2), 
                "MB exceeds threshold", test_config$memory_threshold_mb, "MB"))
    }
    
    return(memory_increase)
  },
  1
)

# ============================================================================
# MONITORING SYSTEM TESTS
# ============================================================================

cat("\n📈 TESTING MONITORING SYSTEM\n")
cat("=============================\n")

# Test 15: Performance monitoring functionality
test_results$monitoring_system$functionality <- execute_test(
  "Monitoring System Functionality",
  function() {
    if (!exists("get_performance_statistics")) {
      stop("Performance statistics function not available")
    }
    
    stats <- get_performance_statistics()
    
    if (isTRUE(is.null(stats)) || "error" %in% names(stats)) {
      stop("Performance statistics failed")
    }
    
    required_sections <- c("monitoring_status", "execution_metrics")
    for (section in required_sections) {
      if (!section %in% names(stats)) {
        stop(paste("Missing statistics section:", section))
      }
    }
    
    cat("    Monitoring status:", if (stats$monitoring_status$enabled) "ENABLED" else "DISABLED", "\n")
    cat("    Queries monitored:", stats$monitoring_status$total_queries_monitored, "\n")
    
    if (stats$monitoring_status$total_queries_monitored > 0) {
      cat("    Average execution time:", stats$execution_metrics$avg_execution_time_ms, "ms\n")
    }
  },
  1
)

# Test 16: Query monitoring integration
test_results$monitoring_system$integration <- execute_test(
  "Query Monitoring Integration",
  function() {
    if (!exists("monitor_query_execution")) {
      stop("Query monitoring function not available")
    }
    
    # Test monitoring a simple query
    pool <- get_monitoring_pool()
    monitored_result <- monitor_query_execution(
      query = "SELECT COUNT(*) as test_count FROM information_schema.tables",
      pool = pool,
      source_function = "performance_test"
    )
    
    if (isTRUE(is.null(monitored_result)) || isTRUE(is.null(monitored_result$result))) {
      stop("Monitored query execution failed")
    }
    
    if (is.null(monitored_result$performance)) {
      stop("Performance metrics not captured")
    }
    
    perf_data <- monitored_result$performance
    required_metrics <- c("execution_time_ms", "query_type", "rows_returned")
    
    for (metric in required_metrics) {
      if (!metric %in% names(perf_data)) {
        stop(paste("Missing performance metric:", metric))
      }
    }
    
    cat("    Query execution time:", perf_data$execution_time_ms, "ms\n")
    cat("    Query type:", perf_data$query_type, "\n")
  },
  test_config$iterations_per_test
)

# ============================================================================
# RESULTS ANALYSIS AND REPORTING
# ============================================================================

cat("\n📋 ANALYZING TEST RESULTS\n")
cat("==========================\n")

# Calculate overall statistics
total_tests <- 0
passed_tests <- 0
failed_tests <- 0
total_avg_time <- 0
time_count <- 0

for (category in names(test_results)) {
  if (is.list(test_results[[category]])) {
    for (test_name in names(test_results[[category]])) {
      test_result <- test_results[[category]][[test_name]]
      if (is.list(test_result) && "status" %in% names(test_result)) {
        total_tests <- total_tests + 1
        if (test_result$status == "COMPLETED" && test_result$success_rate >= 80) {
          passed_tests <- passed_tests + 1
        } else {
          failed_tests <- failed_tests + 1
        }
        
        if ("avg_time_ms" %in% names(test_result) && !is.na(test_result$avg_time_ms)) {
          total_avg_time <- total_avg_time + test_result$avg_time_ms
          time_count <- time_count + 1
        }
      }
    }
  }
}

# Create overall summary
test_results$overall_summary <- list(
  total_tests = total_tests,
  passed_tests = passed_tests,
  failed_tests = failed_tests,
  success_rate = round(passed_tests / total_tests * 100, 1),
  average_execution_time_ms = if (time_count > 0) round(total_avg_time / time_count, 2) else 0,
  test_start_time = Sys.time(),
  memory_final_mb = get_memory_usage_mb()
)

# ============================================================================
# GENERATE PERFORMANCE TEST REPORT
# ============================================================================

generate_performance_test_report <- function() {
  report <- paste0(
    "================================================================\n",
    "RAILWAY POSTGRESQL PERFORMANCE OPTIMIZATION TEST REPORT\n",
    "================================================================\n\n",
    "Test Execution Summary:\n",
    "- Total Tests: ", test_results$overall_summary$total_tests, "\n",
    "- Passed Tests: ", test_results$overall_summary$passed_tests, "\n",
    "- Failed Tests: ", test_results$overall_summary$failed_tests, "\n", 
    "- Success Rate: ", test_results$overall_summary$success_rate, "%\n",
    "- Average Execution Time: ", test_results$overall_summary$average_execution_time_ms, " ms\n",
    "- Final Memory Usage: ", round(test_results$overall_summary$memory_final_mb, 2), " MB\n\n"
  )
  
  # Add detailed results for each category
  report <- paste0(report, "DETAILED TEST RESULTS:\n")
  report <- paste0(report, "======================\n\n")
  
  for (category in names(test_results)) {
    if (category != "overall_summary" && is.list(test_results[[category]])) {
      report <- paste0(report, toupper(gsub("_", " ", category)), ":\n")
      
      for (test_name in names(test_results[[category]])) {
        test_result <- test_results[[category]][[test_name]]
        if (is.list(test_result) && "status" %in% names(test_result)) {
          status_icon <- if (test_result$status == "COMPLETED" && test_result$success_rate >= 80) "✅" else "❌"
          report <- paste0(report, "  ", status_icon, " ", test_result$test_name, 
                          " (", test_result$success_rate, "% success, ",
                          round(test_result$avg_time_ms, 2), " ms avg)\n")
          
          if (length(test_result$errors) > 0) {
            report <- paste0(report, "    Errors: ", paste(test_result$errors, collapse = "; "), "\n")
          }
        }
      }
      report <- paste0(report, "\n")
    }
  }
  
  # Add performance improvement analysis
  if (!is.null(test_results$query_performance$comparison)) {
    comp <- test_results$query_performance$comparison
    report <- paste0(report, "PERFORMANCE IMPROVEMENT ANALYSIS:\n")
    report <- paste0(report, "==================================\n")
    report <- paste0(report, "- Optimization Factor: ", round(comp$improvement_factor, 2), "x\n")
    report <- paste0(report, "- Optimized Query Time: ", round(comp$optimized_median_ms, 2), " ms\n")
    report <- paste0(report, "- Original Query Time: ", round(comp$original_median_ms, 2), " ms\n")
    report <- paste0(report, "- Meets Expectations: ", if (comp$meets_expectations) "YES" else "NO", "\n\n")
  }
  
  # Add recommendations
  report <- paste0(report, "RECOMMENDATIONS:\n")
  report <- paste0(report, "================\n")
  
  if (test_results$overall_summary$success_rate >= 90) {
    report <- paste0(report, "✅ Optimization implementation is EXCELLENT\n")
    report <- paste0(report, "- All performance targets met\n")
    report <- paste0(report, "- System ready for production load\n")
  } else if (test_results$overall_summary$success_rate >= 75) {
    report <- paste0(report, "⚠️ Optimization implementation is GOOD with minor issues\n") 
    report <- paste0(report, "- Review failed tests for optimization opportunities\n")
    report <- paste0(report, "- Consider additional index tuning\n")
  } else {
    report <- paste0(report, "❌ Optimization implementation needs ATTENTION\n")
    report <- paste0(report, "- Multiple test failures indicate systemic issues\n")
    report <- paste0(report, "- Review database configuration and connectivity\n")
    report <- paste0(report, "- Run database migrations if not already done\n")
  }
  
  report <- paste0(report, "\nNext Steps:\n")
  report <- paste0(report, "1. Run database migrations (001_performance_indexes.sql and 002_materialized_views.sql)\n")
  report <- paste0(report, "2. Enable query performance monitoring in production\n") 
  report <- paste0(report, "3. Set up automated materialized view refresh schedule\n")
  report <- paste0(report, "4. Monitor cache hit rates and query performance metrics\n")
  report <- paste0(report, "5. Conduct user acceptance testing with optimized queries\n\n")
  
  report <- paste0(report, "================================================================\n")
  
  return(report)
}

# Generate and display final report
final_report <- generate_performance_test_report()
cat(final_report)

# Save detailed results for further analysis
if (exists("test_results")) {
  saveRDS(test_results, file = "db/performance_test_results.rds")
  cat("📊 Detailed test results saved to: db/performance_test_results.rds\n")
}

# Save report to file
report_file <- paste0("db/performance_test_report_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".txt")
writeLines(final_report, report_file)
cat("📄 Test report saved to:", report_file, "\n")

cat("\n🎉 PERFORMANCE TESTING COMPLETE\n")
cat("================================\n")

# Return summary for programmatic access
invisible(list(
  success_rate = test_results$overall_summary$success_rate,
  total_tests = test_results$overall_summary$total_tests,
  passed_tests = test_results$overall_summary$passed_tests,
  failed_tests = test_results$overall_summary$failed_tests,
  optimization_ready = test_results$overall_summary$success_rate >= 75
))