# ============================================================================
# R APPLICATION COMPATIBILITY TEST FOR ADVANCED SEARCH ENGINE
# ============================================================================
# 
# This script tests the compatibility between the existing R Shiny application
# and the newly deployed advanced search PostgreSQL schema.
# 
# Tests include:
# - Database connection with advanced search tables
# - Query compatibility between old and new schemas
# - Performance comparison
# - Data format consistency
# - Error handling and fallback mechanisms
#
# Author: Senior Database Engineer - Brazilian Legislative Analytics Team
# Date: January 2025
# Version: 1.0 - R Application Compatibility Testing
# ============================================================================

cat("🔧 R Application Compatibility Test for Advanced Search Engine\n")
cat("================================================================\n")

# Source the database connection module
tryCatch({
  source("db/connection.R")
}, error = function(e) {
  cat("❌ Error loading db/connection.R:", e$message, "\n")
  stop("Cannot proceed without database connection module")
})

# Test results tracking
compatibility_results <- list(
  tests_run = 0,
  tests_passed = 0,
  tests_failed = 0,
  tests_warnings = 0,
  details = list()
)

# Test logging function
log_test_result <- function(test_name, status, message = "", details = NULL) {
  compatibility_results$tests_run <<- compatibility_results$tests_run + 1
  
  if (status == "PASS") {
    compatibility_results$tests_passed <<- compatibility_results$tests_passed + 1
    cat("✅", test_name, "- PASSED\n")
  } else if (status == "FAIL") {
    compatibility_results$tests_failed <<- compatibility_results$tests_failed + 1
    cat("❌", test_name, "- FAILED:", message, "\n")
  } else if (status == "WARNING") {
    compatibility_results$tests_warnings <<- compatibility_results$tests_warnings + 1
    cat("⚠️", test_name, "- WARNING:", message, "\n")
  }
  
  # Store detailed results
  compatibility_results$details[[test_name]] <<- list(
    status = status,
    message = message,
    details = details,
    timestamp = Sys.time()
  )
}

# ============================================================================
# TEST 1: DATABASE CONNECTION COMPATIBILITY
# ============================================================================
cat("\n=== TEST 1: DATABASE CONNECTION COMPATIBILITY ===\n")

test_database_connection <- function() {
  tryCatch({
    # Test if advanced search tables exist
    if (!is.null(secure_db_pool)) {
      tables_check <- dbGetQuery(secure_db_pool, "
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_name IN ('documents_search_optimized', 'legal_terms_dictionary', 'search_analytics')
      ")
      
      if (nrow(tables_check) == 3) {
        log_test_result("advanced_search_tables_exist", "PASS", 
                       "All advanced search tables found")
      } else {
        log_test_result("advanced_search_tables_exist", "FAIL", 
                       paste("Only", nrow(tables_check), "out of 3 tables found"))
      }
      
      # Test Portuguese configuration
      portuguese_config <- dbGetQuery(secure_db_pool, "
        SELECT cfgname FROM pg_ts_config WHERE cfgname = 'portuguese_legal'
      ")
      
      if (nrow(portuguese_config) > 0) {
        log_test_result("portuguese_search_config", "PASS", 
                       "Portuguese legal search configuration found")
      } else {
        log_test_result("portuguese_search_config", "FAIL", 
                       "Portuguese legal search configuration not found")
      }
      
    } else {
      log_test_result("database_connection", "FAIL", "secure_db_pool is NULL")
    }
    
  }, error = function(e) {
    log_test_result("database_connection", "FAIL", e$message)
  })
}

test_database_connection()

# ============================================================================
# TEST 2: BACKWARD COMPATIBILITY WITH EXISTING QUERIES
# ============================================================================
cat("\n=== TEST 2: BACKWARD COMPATIBILITY TESTS ===\n")

test_backward_compatibility <- function() {
  if (is.null(secure_db_pool)) {
    log_test_result("backward_compatibility", "FAIL", "No database connection")
    return()
  }
  
  tryCatch({
    # Test 2.1: Check if original documents table/view exists
    original_tables <- dbGetQuery(secure_db_pool, "
      SELECT table_name, table_type 
      FROM information_schema.tables 
      WHERE table_name IN ('documents', 'documents_unified', 'documents_enhanced')
    ")
    
    if (nrow(original_tables) > 0) {
      log_test_result("original_documents_view", "PASS", 
                     paste("Found", nrow(original_tables), "compatible document tables/views"))
      
      # Test query on original view
      tryCatch({
        original_count <- dbGetQuery(secure_db_pool, "SELECT COUNT(*) as count FROM documents LIMIT 1")
        log_test_result("original_documents_query", "PASS", 
                       paste("Original documents query works:", original_count$count, "documents"))
      }, error = function(e) {
        log_test_result("original_documents_query", "FAIL", e$message)
      })
      
    } else {
      log_test_result("original_documents_view", "WARNING", 
                     "No original document tables found - may need compatibility view")
    }
    
    # Test 2.2: Check column compatibility
    tryCatch({
      search_columns <- dbGetQuery(secure_db_pool, "
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = 'documents_search_optimized'
        ORDER BY column_name
      ")
      
      expected_columns <- c("id", "titulo", "ementa", "tipo", "species", "estado", 
                           "data_publicacao", "url", "autor")
      missing_columns <- expected_columns[!expected_columns %in% search_columns$column_name]
      
      if (length(missing_columns) == 0) {
        log_test_result("column_compatibility", "PASS", 
                       "All expected columns present in search table")
      } else {
        log_test_result("column_compatibility", "WARNING", 
                       paste("Missing columns:", paste(missing_columns, collapse = ", ")))
      }
      
    }, error = function(e) {
      log_test_result("column_compatibility", "FAIL", e$message)
    })
    
  }, error = function(e) {
    log_test_result("backward_compatibility", "FAIL", e$message)
  })
}

test_backward_compatibility()

# ============================================================================
# TEST 3: EXISTING R FUNCTION COMPATIBILITY
# ============================================================================
cat("\n=== TEST 3: R FUNCTION COMPATIBILITY ===\n")

test_r_function_compatibility <- function() {
  # Test 3.1: get_library_documents function
  tryCatch({
    # Test with default parameters
    docs <- get_library_documents(limit = 5)
    
    if (is.data.frame(docs) && nrow(docs) > 0) {
      log_test_result("get_library_documents_basic", "PASS", 
                     paste("Function returned", nrow(docs), "documents"))
      
      # Check expected columns in result
      expected_cols <- c("title", "category", "state", "date")
      missing_cols <- expected_cols[!expected_cols %in% names(docs)]
      
      if (length(missing_cols) == 0) {
        log_test_result("get_library_documents_columns", "PASS", 
                       "All expected result columns present")
      } else {
        log_test_result("get_library_documents_columns", "WARNING", 
                       paste("Missing result columns:", paste(missing_cols, collapse = ", ")))
      }
      
    } else {
      log_test_result("get_library_documents_basic", "FAIL", 
                     "Function returned empty or invalid result")
    }
    
    # Test 3.2: Search functionality
    search_docs <- get_library_documents(search_term = "lei", state = "SP", limit = 3)
    
    if (is.data.frame(search_docs) && nrow(search_docs) >= 0) {
      log_test_result("get_library_documents_search", "PASS", 
                     paste("Search returned", nrow(search_docs), "documents"))
    } else {
      log_test_result("get_library_documents_search", "FAIL", 
                     "Search function failed")
    }
    
  }, error = function(e) {
    log_test_result("get_library_documents_basic", "FAIL", e$message)
  })
  
  # Test 3.3: Total documents function
  tryCatch({
    total_docs <- get_total_documents()
    
    if (is.numeric(total_docs) && total_docs > 0) {
      log_test_result("get_total_documents", "PASS", 
                     paste("Total documents:", format(total_docs, big.mark = ",")))
    } else {
      log_test_result("get_total_documents", "FAIL", 
                     paste("Invalid total documents result:", total_docs))
    }
    
  }, error = function(e) {
    log_test_result("get_total_documents", "FAIL", e$message)
  })
  
  # Test 3.4: Dashboard metrics function
  tryCatch({
    metrics <- get_lexml_dashboard_metrics()
    
    if (is.list(metrics) && "total_documents" %in% names(metrics)) {
      log_test_result("get_lexml_dashboard_metrics", "PASS", 
                     "Dashboard metrics function working")
    } else {
      log_test_result("get_lexml_dashboard_metrics", "FAIL", 
                     "Dashboard metrics function returned invalid result")
    }
    
  }, error = function(e) {
    log_test_result("get_lexml_dashboard_metrics", "FAIL", e$message)
  })
}

test_r_function_compatibility()

# ============================================================================
# TEST 4: ADVANCED SEARCH FUNCTIONALITY
# ============================================================================
cat("\n=== TEST 4: ADVANCED SEARCH FUNCTIONALITY ===\n")

test_advanced_search_functionality <- function() {
  if (is.null(secure_db_pool)) {
    log_test_result("advanced_search", "FAIL", "No database connection")
    return()
  }
  
  tryCatch({
    # Test 4.1: Portuguese full-text search
    fts_result <- dbGetQuery(secure_db_pool, "
      SELECT COUNT(*) as count 
      FROM documents_search_optimized 
      WHERE search_vector_combined @@ plainto_tsquery('portuguese_legal', 'transporte')
    ")
    
    if (is.data.frame(fts_result) && fts_result$count > 0) {
      log_test_result("portuguese_fulltext_search", "PASS", 
                     paste("Portuguese FTS found", fts_result$count, "documents"))
    } else {
      log_test_result("portuguese_fulltext_search", "WARNING", 
                     "Portuguese FTS returned no results - may need data or search vectors")
    }
    
    # Test 4.2: Advanced search function
    advanced_result <- dbGetQuery(secure_db_pool, "
      SELECT COUNT(*) as count 
      FROM advanced_search_documents('lei', 'SP', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 5, 0)
    ")
    
    if (is.data.frame(advanced_result) && advanced_result$count >= 0) {
      log_test_result("advanced_search_function", "PASS", 
                     paste("Advanced search function returned", advanced_result$count, "results"))
    } else {
      log_test_result("advanced_search_function", "FAIL", 
                     "Advanced search function failed")
    }
    
    # Test 4.3: Search analytics
    analytics_test <- dbGetQuery(secure_db_pool, "
      SELECT COUNT(*) as count FROM search_analytics
    ")
    
    log_test_result("search_analytics_table", "PASS", 
                   paste("Search analytics table accessible with", analytics_test$count, "records"))
    
  }, error = function(e) {
    log_test_result("advanced_search_functionality", "FAIL", e$message)
  })
}

test_advanced_search_functionality()

# ============================================================================
# TEST 5: PERFORMANCE COMPARISON
# ============================================================================
cat("\n=== TEST 5: PERFORMANCE COMPARISON ===\n")

test_performance_comparison <- function() {
  if (is.null(secure_db_pool)) {
    log_test_result("performance_comparison", "FAIL", "No database connection")
    return()
  }
  
  tryCatch({
    # Test old vs new query performance (if both exist)
    
    # Test new search performance
    start_time <- Sys.time()
    new_result <- get_library_documents(search_term = "lei", limit = 10)
    new_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
    
    if (is.data.frame(new_result) && nrow(new_result) > 0) {
      log_test_result("search_performance_new", "PASS", 
                     paste("New search took", round(new_time, 3), "seconds for", nrow(new_result), "results"))
      
      # Performance benchmark
      if (new_time < 5.0) {
        log_test_result("search_performance_benchmark", "PASS", 
                       "Search performance meets benchmark (< 5 seconds)")
      } else {
        log_test_result("search_performance_benchmark", "WARNING", 
                       "Search performance slower than benchmark")
      }
      
    } else {
      log_test_result("search_performance_new", "FAIL", "New search returned no results")
    }
    
  }, error = function(e) {
    log_test_result("performance_comparison", "FAIL", e$message)
  })
}

test_performance_comparison()

# ============================================================================
# TEST 6: DATA CONSISTENCY
# ============================================================================
cat("\n=== TEST 6: DATA CONSISTENCY ===\n")

test_data_consistency <- function() {
  if (is.null(secure_db_pool)) {
    log_test_result("data_consistency", "FAIL", "No database connection")
    return()
  }
  
  tryCatch({
    # Check document count consistency between old and new tables
    old_count <- 0
    new_count <- 0
    
    # Try to get old table count
    tryCatch({
      old_result <- dbGetQuery(secure_db_pool, "SELECT COUNT(*) as count FROM documents_unified")
      old_count <- old_result$count
    }, error = function(e) {
      # Try alternative table names
      tryCatch({
        alt_result <- dbGetQuery(secure_db_pool, "SELECT COUNT(*) as count FROM documents")
        old_count <- alt_result$count
      }, error = function(e2) {
        log_test_result("old_table_count", "WARNING", "Could not access original document table")
      })
    })
    
    # Get new table count
    new_result <- dbGetQuery(secure_db_pool, "SELECT COUNT(*) as count FROM documents_search_optimized")
    new_count <- new_result$count
    
    if (old_count > 0 && new_count > 0) {
      consistency_ratio <- new_count / old_count
      
      if (consistency_ratio >= 0.95 && consistency_ratio <= 1.05) {
        log_test_result("document_count_consistency", "PASS", 
                       paste("Document counts consistent: old =", old_count, "new =", new_count))
      } else {
        log_test_result("document_count_consistency", "WARNING", 
                       paste("Document count mismatch: old =", old_count, "new =", new_count))
      }
    } else if (new_count > 0) {
      log_test_result("new_table_populated", "PASS", 
                     paste("New search table has", new_count, "documents"))
    } else {
      log_test_result("data_consistency", "FAIL", 
                     "New search table is empty")
    }
    
  }, error = function(e) {
    log_test_result("data_consistency", "FAIL", e$message)
  })
}

test_data_consistency()

# ============================================================================
# COMPATIBILITY TEST SUMMARY
# ============================================================================
cat("\n=== COMPATIBILITY TEST SUMMARY ===\n")

generate_compatibility_report <- function() {
  cat("📊 R Application Compatibility Test Results\n")
  cat("==========================================\n")
  cat("Tests Run:     ", compatibility_results$tests_run, "\n")
  cat("Tests Passed:  ", compatibility_results$tests_passed, "\n") 
  cat("Tests Failed:  ", compatibility_results$tests_failed, "\n")
  cat("Warnings:      ", compatibility_results$tests_warnings, "\n")
  
  success_rate <- round((compatibility_results$tests_passed / compatibility_results$tests_run) * 100, 1)
  cat("Success Rate:  ", success_rate, "%\n")
  
  # Overall status
  if (compatibility_results$tests_failed == 0 && compatibility_results$tests_warnings == 0) {
    cat("\n✅ OVERALL STATUS: FULLY COMPATIBLE\n")
    cat("The R application is fully compatible with the advanced search engine.\n")
  } else if (compatibility_results$tests_failed == 0) {
    cat("\n⚠️ OVERALL STATUS: COMPATIBLE WITH WARNINGS\n") 
    cat("The R application is compatible but has some warnings that should be reviewed.\n")
  } else if (compatibility_results$tests_failed <= 2) {
    cat("\n🔧 OVERALL STATUS: MOSTLY COMPATIBLE\n")
    cat("The R application needs minor adjustments for full compatibility.\n")
  } else {
    cat("\n❌ OVERALL STATUS: COMPATIBILITY ISSUES\n")
    cat("The R application requires significant updates for compatibility.\n")
  }
  
  # Detailed results
  cat("\n📋 Detailed Test Results:\n")
  for (test_name in names(compatibility_results$details)) {
    result <- compatibility_results$details[[test_name]]
    status_icon <- switch(result$status,
                         "PASS" = "✅",
                         "FAIL" = "❌", 
                         "WARNING" = "⚠️")
    cat(sprintf("%s %s: %s\n", status_icon, test_name, result$message))
  }
  
  # Recommendations
  cat("\n💡 Recommendations:\n")
  
  if (compatibility_results$tests_failed > 0) {
    cat("1. Address failed tests before deploying to production\n")
    cat("2. Review error messages and update R code as needed\n")
  }
  
  if (compatibility_results$tests_warnings > 0) {
    cat("3. Review warning messages for potential improvements\n")
    cat("4. Consider implementing suggested compatibility enhancements\n")
  }
  
  cat("5. Test all Shiny application functionality after deployment\n")
  cat("6. Monitor performance and adjust queries as needed\n")
  cat("7. Set up regular compatibility testing schedule\n")
  
  # Save results to file
  results_file <- paste0("logs/r_compatibility_test_", format(Sys.time(), "%Y%m%d_%H%M%S"), ".txt")
  dir.create("logs", showWarnings = FALSE)
  
  capture.output({
    generate_compatibility_report()
  }, file = results_file)
  
  cat("\n📄 Full results saved to:", results_file, "\n")
}

generate_compatibility_report()

cat("\n🎯 R Application Compatibility Testing Complete!\n")
cat("Review the results above and address any issues before production deployment.\n")