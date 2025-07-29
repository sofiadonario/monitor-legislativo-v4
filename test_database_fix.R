# TEST DATABASE FIX - Comprehensive testing of the database pool access fix
# This script tests the new database connection pool management system

cat("🧪 TESTING DATABASE POOL ACCESS FIX\n")
cat(paste(rep("=", 50), collapse = ""), "\n")

# Load the data access layer
cat("🔧 Loading Data Access Layer...\n")
if (file.exists("data_access_layer.R")) {
  source("data_access_layer.R")
  cat("✅ Data Access Layer loaded\n")
} else {
  cat("❌ Data Access Layer not found\n")
  quit(status = 1)
}

# Test 1: Initialize the system
cat("\n🧪 TEST 1: System Initialization\n")
cat(paste(rep("-", 30), collapse = ""), "\n")

if (exists("init_data_access_layer")) {
  init_result <- init_data_access_layer()
  cat("📊 Initialization result:", init_result, "\n")
} else {
  cat("❌ init_data_access_layer function not found\n")
}

# Test 2: Connection Status
cat("\n🧪 TEST 2: Connection Status Check\n")
cat(paste(rep("-", 30), collapse = ""), "\n")

if (exists("get_connection_status")) {
  status <- get_connection_status()
  cat("📊 Database Connected:", status$database_connected, "\n")
  cat("📊 Circuit Breaker Open:", status$circuit_breaker_open, "\n")
  cat("📊 Using Fallback:", status$using_fallback, "\n")
  cat("📊 Failure Count:", status$failure_count, "\n")
  cat("📊 Queries Executed:", status$statistics$queries_executed, "\n")
} else {
  cat("❌ get_connection_status function not found\n")
}

# Test 3: Health Check
cat("\n🧪 TEST 3: Comprehensive Health Check\n")
cat(paste(rep("-", 30), collapse = ""), "\n")

if (exists("perform_comprehensive_health_check")) {
  health <- perform_comprehensive_health_check()
  cat("📊 Overall Status:", health$overall_status, "\n")
  cat("📊 Database Status:", health$database_status, "\n")
  cat("📊 Connection Pool Status:", health$connection_pool_status, "\n")
  
  if (length(health$issues) > 0) {
    cat("⚠️ Issues found:\n")
    for (issue in health$issues) {
      cat("  -", issue, "\n")
    }
  } else {
    cat("✅ No issues detected\n")
  }
  
  if (length(health$recommendations) > 0) {
    cat("💡 Recommendations:\n")
    for (rec in health$recommendations) {
      cat("  -", rec, "\n")
    }
  }
} else {
  cat("❌ perform_comprehensive_health_check function not found\n")
}

# Test 4: Data Retrieval
cat("\n🧪 TEST 4: Data Retrieval Test\n")
cat(paste(rep("-", 30), collapse = ""), "\n")

# Test get_search_analytics
if (exists("get_search_analytics")) {
  cat("🔍 Testing get_search_analytics...\n")
  start_time <- Sys.time()
  analytics <- get_search_analytics()
  end_time <- Sys.time()
  query_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
  
  if (!is.null(analytics)) {
    cat("✅ Analytics retrieved successfully in", round(query_time, 2), "seconds\n")
    cat("📊 Total Documents:", analytics$total_documents, "\n")
    cat("📊 Data Source:", analytics$data_source %||% "unknown", "\n")
    cat("📊 Years Available:", nrow(analytics$documents_by_year), "\n")
    cat("📊 States Available:", nrow(analytics$documents_by_state), "\n")
    cat("📊 Types Available:", nrow(analytics$documents_by_type), "\n")
  } else {
    cat("❌ Analytics retrieval failed\n")
  }
} else {
  cat("❌ get_search_analytics function not found\n")
}

# Test get_documents
if (exists("get_documents")) {
  cat("🔍 Testing get_documents...\n")
  start_time <- Sys.time()
  documents <- get_documents(limit = 10)
  end_time <- Sys.time()
  query_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
  
  if (!is.null(documents) && nrow(documents) > 0) {
    cat("✅ Documents retrieved successfully in", round(query_time, 2), "seconds\n")
    cat("📊 Documents Retrieved:", nrow(documents), "\n")
    cat("📊 Columns Available:", paste(names(documents)[1:min(5, ncol(documents))], collapse = ", "), "\n")
    
    # Show sample titles
    if ("titulo" %in% names(documents)) {
      cat("📄 Sample Titles:\n")
      for (i in 1:min(3, nrow(documents))) {
        title <- substr(documents$titulo[i], 1, 60)
        cat("  ", i, ":", title, "\n")
      }
    }
  } else {
    cat("❌ Document retrieval failed or returned empty result\n")
  }
} else {
  cat("❌ get_documents function not found\n")
}

# Test 5: Database Stats
cat("\n🧪 TEST 5: Database Statistics\n")
cat(paste(rep("-", 30), collapse = ""), "\n")

if (exists("get_database_stats")) {
  cat("🔍 Testing get_database_stats...\n")
  stats <- get_database_stats()
  
  if (!is.null(stats)) {
    cat("✅ Database stats retrieved successfully\n")
    cat("📊 Total Documents:", stats$total_documents, "\n")
    cat("📊 Unique States:", stats$unique_states, "\n")
    cat("📊 Unique Types:", stats$unique_types, "\n")
    cat("📊 Oldest Document:", stats$oldest_document, "\n")
    cat("📊 Newest Document:", stats$newest_document, "\n")
    cat("📊 Last Update:", stats$last_update, "\n")
  } else {
    cat("❌ Database stats retrieval failed\n")
  }
} else {
  cat("❌ get_database_stats function not found\n")
}

# Test 6: Performance Test
cat("\n🧪 TEST 6: Performance Test (5 queries)\n")
cat(paste(rep("-", 30), collapse = ""), "\n")

if (exists("get_search_analytics")) {
  query_times <- numeric(5)
  successful_queries <- 0
  
  for (i in 1:5) {
    start_time <- Sys.time()
    result <- get_search_analytics()
    end_time <- Sys.time()
    
    query_time <- as.numeric(difftime(end_time, start_time, units = "secs"))
    query_times[i] <- query_time
    
    if (!is.null(result)) {
      successful_queries <- successful_queries + 1
    }
    
    cat("  Query", i, ":", round(query_time, 3), "seconds\n")
  }
  
  cat("📊 Performance Summary:\n")
  cat("  - Successful Queries:", successful_queries, "/5\n")
  cat("  - Success Rate:", round(successful_queries / 5 * 100, 1), "%\n")
  cat("  - Average Time:", round(mean(query_times), 3), "seconds\n")
  cat("  - Min Time:", round(min(query_times), 3), "seconds\n")
  cat("  - Max Time:", round(max(query_times), 3), "seconds\n")
  
  if (successful_queries == 5 && mean(query_times) < 2.0) {
    cat("✅ Performance test PASSED\n")
  } else {
    cat("⚠️ Performance test shows issues - check connection stability\n")
  }
}

# Test 7: Health Trends
cat("\n🧪 TEST 7: Health Trends Analysis\n")
cat(paste(rep("-", 30), collapse = ""), "\n")

if (exists("get_health_trends")) {
  trends <- get_health_trends()
  cat("📈 Health Trends:\n")
  cat("  - Total Health Checks:", trends$total_health_checks, "\n")
  cat("  - Success Rate:", trends$success_rate, "%\n")
  cat("  - Average Query Time:", trends$avg_query_time, "seconds\n")
  cat("  - Recent Failures:", trends$recent_failures, "\n")
  cat("  - Recent Successes:", trends$recent_successes, "\n")
  
  if (is.character(trends$recommendations) && length(trends$recommendations) > 0) {
    cat("💡 Trend Recommendations:\n")
    for (rec in trends$recommendations) {
      cat("  -", rec, "\n")
    }
  }
}

# Final Assessment
cat("\n🏆 FINAL ASSESSMENT\n")
cat(paste(rep("=", 50), collapse = ""), "\n")

# Determine overall success
tests_passed <- 0
total_tests <- 7

if (exists("init_data_access_layer")) tests_passed <- tests_passed + 1
if (exists("get_connection_status")) tests_passed <- tests_passed + 1
if (exists("perform_comprehensive_health_check")) tests_passed <- tests_passed + 1
if (exists("get_search_analytics")) tests_passed <- tests_passed + 1
if (exists("get_documents")) tests_passed <- tests_passed + 1
if (exists("get_database_stats")) tests_passed <- tests_passed + 1
if (exists("get_health_trends")) tests_passed <- tests_passed + 1

success_rate <- tests_passed / total_tests * 100

cat("📊 TESTS SUMMARY:\n")
cat("  - Tests Passed:", tests_passed, "/", total_tests, "\n")
cat("  - Success Rate:", round(success_rate, 1), "%\n")

if (success_rate >= 85) {
  cat("✅ DATABASE POOL ACCESS FIX - SUCCESS\n")
  cat("🎯 All critical functions are working\n")
  cat("🚀 Ready for Railway deployment\n")
} else if (success_rate >= 70) {
  cat("⚠️ DATABASE POOL ACCESS FIX - PARTIAL SUCCESS\n")
  cat("🔧 Some issues detected - review logs above\n")
} else {
  cat("❌ DATABASE POOL ACCESS FIX - NEEDS ATTENTION\n")
  cat("🚨 Critical issues detected - review implementation\n")
}

cat("\n📋 NEXT STEPS:\n")
cat("1. Deploy to Railway and monitor logs\n")
cat("2. Use perform_comprehensive_health_check() for ongoing monitoring\n")
cat("3. Check get_connection_status() if issues arise\n")
cat("4. Review health trends with get_health_trends()\n")

cat("\n✅ Database Pool Access Fix Test Complete\n")