# Dashboard Consistency Test Script
# This script tests the data consistency across all dashboard components

cat("🧪 TESTING DASHBOARD CONSISTENCY...\n")

library(testthat)

# Test function to verify unified data access
test_unified_data_access <- function() {
  cat("\n📊 Testing Unified Data Access Layer...\n")
  
  test_that("Unified data access functions exist", {
    expect_true(exists("get_unified_dashboard_metrics"))
    expect_true(exists("get_total_documents"))
    expect_true(exists("get_documents_by_state"))
    expect_true(exists("get_documents_by_type"))
  })
  
  test_that("Functions return consistent data", {
    # Get metrics from different sources
    tryCatch({
      unified_metrics <- get_unified_dashboard_metrics()
      lexml_metrics <- get_lexml_dashboard_metrics()
      total_docs <- get_total_documents()
      
      # Test data types
      expect_is(unified_metrics, "list")
      expect_is(lexml_metrics, "list")
      expect_is(total_docs, "numeric")
      
      # Test consistency
      expect_true(abs(unified_metrics$total_documents - lexml_metrics$total_documents) <= 100,
                  info = sprintf("Unified: %d, LexML: %d", 
                                unified_metrics$total_documents, 
                                lexml_metrics$total_documents))
      
      expect_true(unified_metrics$total_documents == total_docs,
                  info = sprintf("Unified metrics: %d, Direct function: %d",
                                unified_metrics$total_documents,
                                total_docs))
      
      cat("✅ Data consistency tests passed\n")
      
    }, error = function(e) {
      cat("❌ Error in consistency test:", e$message, "\n")
      fail(paste("Consistency test failed:", e$message))
    })
  })
}

# Test function to verify data validation
test_data_validation <- function() {
  cat("\n🔍 Testing Data Validation Pipeline...\n")
  
  test_that("Validation functions exist", {
    expect_true(exists("validate_dashboard_consistency"))
    expect_true(exists("get_validation_summary"))
  })
  
  test_that("Validation functions work correctly", {
    tryCatch({
      validation_result <- validate_dashboard_consistency()
      validation_summary <- get_validation_summary()
      
      # Test validation result structure
      expect_is(validation_result, "list")
      expect_true("is_consistent" %in% names(validation_result))
      expect_true("issues" %in% names(validation_result))
      expect_true("timestamp" %in% names(validation_result))
      
      # Test summary structure
      expect_is(validation_summary, "list")
      expect_true("status" %in% names(validation_summary))
      expect_true("message" %in% names(validation_summary))
      
      cat("✅ Validation pipeline tests passed\n")
      
    }, error = function(e) {
      cat("❌ Error in validation test:", e$message, "\n")
      fail(paste("Validation test failed:", e$message))
    })
  })
}

# Test function to verify dashboard UI consistency
test_dashboard_ui_consistency <- function() {
  cat("\n🎨 Testing Dashboard UI Component Consistency...\n")
  
  test_that("Dashboard metrics are consistent", {
    tryCatch({
      # Simulate getting metrics for different UI components
      overview_metrics <- get_lexml_dashboard_metrics()
      map_data <- get_documents_by_state(limit = 50)
      analytics_stats <- get_database_stats()
      
      # Check that all return non-zero values
      expect_gt(overview_metrics$total_documents, 0, 
               info = "Overview shows 0 documents")
      
      expect_gt(nrow(map_data), 0,
               info = "Map data is empty")
      
      expect_gt(analytics_stats$total_documents, 0,
               info = "Analytics shows 0 documents")
      
      # Check consistency between components
      expect_equal(overview_metrics$total_documents, analytics_stats$total_documents,
                  tolerance = 100,
                  info = sprintf("Overview: %d, Analytics: %d",
                                overview_metrics$total_documents,
                                analytics_stats$total_documents))
      
      cat("✅ Dashboard UI consistency tests passed\n")
      
    }, error = function(e) {
      cat("❌ Error in UI consistency test:", e$message, "\n")
      fail(paste("UI consistency test failed:", e$message))
    })
  })
}

# Test function to verify map data consistency
test_map_data_consistency <- function() {
  cat("\n🗺️ Testing Map Data Consistency...\n")
  
  test_that("Map data is consistent across all maps", {
    tryCatch({
      # Get data for different map components
      total_map_data <- get_documents_by_state()
      
      # Verify map data structure
      expect_is(total_map_data, "data.frame")
      expect_true("estado" %in% names(total_map_data))
      expect_true("count" %in% names(total_map_data))
      
      # Verify no negative counts
      expect_true(all(total_map_data$count >= 0),
                 info = "Map contains negative document counts")
      
      # Verify valid state codes
      valid_states <- c("AC", "AL", "AP", "AM", "BA", "CE", "DF", "ES", "GO", "MA", 
                       "MT", "MS", "MG", "PA", "PB", "PR", "PE", "PI", "RJ", "RN", 
                       "RS", "RO", "RR", "SC", "SP", "SE", "TO")
      
      invalid_states <- setdiff(total_map_data$estado, valid_states)
      expect_equal(length(invalid_states), 0,
                  info = paste("Invalid state codes found:", paste(invalid_states, collapse = ", ")))
      
      cat("✅ Map data consistency tests passed\n")
      
    }, error = function(e) {
      cat("❌ Error in map consistency test:", e$message, "\n")
      fail(paste("Map consistency test failed:", e$message))
    })
  })
}

# Test function to verify SQL fixes
test_sql_fixes <- function() {
  cat("\n🔧 Testing SQL Type Casting Fixes...\n")
  
  test_that("SQL queries work without type errors", {
    tryCatch({
      # Test the problematic query that was failing before
      if (exists(".db_pool") && inherits(.db_pool, "Pool")) {
        test_query <- "
          SELECT 
            EXTRACT(YEAR FROM COALESCE(data_publicacao, created_at)) as year, 
            COUNT(*) as count 
          FROM documents 
          WHERE COALESCE(data_publicacao, created_at) IS NOT NULL 
          GROUP BY year 
          ORDER BY year DESC
          LIMIT 5
        "
        
        result <- dbGetQuery(.db_pool, test_query)
        
        expect_is(result, "data.frame")
        expect_gt(nrow(result), 0, info = "Query returned no results")
        expect_true("year" %in% names(result))
        expect_true("count" %in% names(result))
        
        cat("✅ SQL type casting fix verified\n")
      } else {
        cat("⚠️ Database pool not available - skipping SQL tests\n")
      }
      
    }, error = function(e) {
      cat("❌ SQL query still failing:", e$message, "\n")
      fail(paste("SQL fix test failed:", e$message))
    })
  })
}

# Main test execution function
run_all_tests <- function() {
  cat("🚀 RUNNING COMPREHENSIVE DASHBOARD CONSISTENCY TESTS...\n")
  cat("=" * 60, "\n")
  
  tests_passed <- 0
  tests_failed <- 0
  
  # Run all test suites
  test_suites <- list(
    "Unified Data Access" = test_unified_data_access,
    "Data Validation" = test_data_validation,
    "Dashboard UI Consistency" = test_dashboard_ui_consistency,
    "Map Data Consistency" = test_map_data_consistency,
    "SQL Fixes" = test_sql_fixes
  )
  
  results <- list()
  
  for (suite_name in names(test_suites)) {
    cat(sprintf("\n🧪 Running %s tests...\n", suite_name))
    
    tryCatch({
      test_suites[[suite_name]]()
      results[[suite_name]] <- "PASSED"
      tests_passed <- tests_passed + 1
      cat(sprintf("✅ %s tests: PASSED\n", suite_name))
    }, error = function(e) {
      results[[suite_name]] <- paste("FAILED:", e$message)
      tests_failed <- tests_failed + 1
      cat(sprintf("❌ %s tests: FAILED - %s\n", suite_name, e$message))
    })
  }
  
  # Print summary
  cat("\n" * 2)
  cat("=" * 60, "\n")
  cat("📊 TEST SUMMARY\n")
  cat("=" * 60, "\n")
  
  for (suite_name in names(results)) {
    status_icon <- if (grepl("PASSED", results[[suite_name]])) "✅" else "❌"
    cat(sprintf("%s %s: %s\n", status_icon, suite_name, results[[suite_name]]))
  }
  
  cat("\n")
  cat(sprintf("Tests Passed: %d\n", tests_passed))
  cat(sprintf("Tests Failed: %d\n", tests_failed))
  cat(sprintf("Success Rate: %.1f%%\n", (tests_passed / (tests_passed + tests_failed)) * 100))
  
  if (tests_failed == 0) {
    cat("\n🎉 ALL TESTS PASSED! Dashboard consistency has been achieved.\n")
    return(TRUE)
  } else {
    cat("\n⚠️ Some tests failed. Please review the issues above.\n")
    return(FALSE)
  }
}

# Export functions for external use
export_test_functions <- function() {
  list(
    run_all_tests = run_all_tests,
    test_unified_data_access = test_unified_data_access,
    test_data_validation = test_data_validation,
    test_dashboard_ui_consistency = test_dashboard_ui_consistency,
    test_map_data_consistency = test_map_data_consistency,
    test_sql_fixes = test_sql_fixes
  )
}

# Execute tests if script is run directly
if (interactive() || !exists("test_mode")) {
  cat("🧪 Dashboard Consistency Test Suite Loaded\n")
  cat("Run run_all_tests() to execute all tests\n")
  cat("Or run individual test functions:\n")
  cat("  - test_unified_data_access()\n")
  cat("  - test_data_validation()\n")
  cat("  - test_dashboard_ui_consistency()\n")
  cat("  - test_map_data_consistency()\n")
  cat("  - test_sql_fixes()\n")
}