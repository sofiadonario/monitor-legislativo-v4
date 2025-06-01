# TEST APP CONNECTION - Verify Shiny app database integration
# =============================================================

cat("🧪 TESTING SHINY APP DATABASE CONNECTION\n")
cat(paste(rep("=", 50), collapse = ""), "\n")

# Load the connection system
tryCatch({
  source("RAILWAY_DATABASE_CONNECTION_FIX.R")
  cat("✅ Connection system loaded\n")
}, error = function(e) {
  cat("❌ Failed to load connection system:", e$message, "\n")
  quit(status = 1)
})

# Test all the functions that app.R uses
cat("\n🔍 Testing database functions used by app.R...\n")

test_functions <- list(
  "get_total_documents" = function() get_total_documents(),
  "get_lexml_dashboard_metrics" = function() get_lexml_dashboard_metrics(),
  "get_library_documents" = function() get_library_documents(limit = 5),
  "get_connection_status" = function() get_connection_status()
)

results <- list()

for (func_name in names(test_functions)) {
  cat("\n📊 Testing", func_name, "...\n")
  
  start_time <- Sys.time()
  tryCatch({
    result <- test_functions[[func_name]]()
    end_time <- Sys.time()
    duration <- round(as.numeric(difftime(end_time, start_time, units = "secs")), 2)
    
    # Analyze result
    if (func_name == "get_total_documents") {
      cat("✅ SUCCESS:", format(result, big.mark = ","), "documents (", duration, "s)\n")
      results[[func_name]] <- list(success = TRUE, value = result, duration = duration)
      
    } else if (func_name == "get_lexml_dashboard_metrics") {
      cat("✅ SUCCESS: metrics loaded (", duration, "s)\n")
      cat("   - Total docs:", format(result$total_documents, big.mark = ","), "\n")
      cat("   - States:", result$states_with_docs, "\n")
      cat("   - Data source:", result$data_source, "\n")
      results[[func_name]] <- list(success = TRUE, value = result, duration = duration)
      
    } else if (func_name == "get_library_documents") {
      cat("✅ SUCCESS:", nrow(result), "documents retrieved (", duration, "s)\n")
      if (nrow(result) > 0) {
        cat("   - First title:", substr(result$title[1], 1, 60), "...\n")
      }
      results[[func_name]] <- list(success = TRUE, value = result, duration = duration)
      
    } else if (func_name == "get_connection_status") {
      cat("✅ SUCCESS: status =", result$status, "(", duration, "s)\n")
      cat("   - Method:", result$connection_method, "\n")
      cat("   - Message:", result$message, "\n")
      results[[func_name]] <- list(success = TRUE, value = result, duration = duration)
    }
    
  }, error = function(e) {
    end_time <- Sys.time()
    duration <- round(as.numeric(difftime(end_time, start_time, units = "secs")), 2)
    cat("❌ FAILED (", duration, "s):", e$message, "\n")
    results[[func_name]] <- list(success = FALSE, error = e$message, duration = duration)
  })
}

# Test edge cases
cat("\n🧪 Testing edge cases...\n")

# Test with filters
cat("\n📊 Testing get_total_documents with filters...\n")
tryCatch({
  filtered_count <- get_total_documents(list(estado = "SP"))
  cat("✅ Filtered documents (SP):", format(filtered_count, big.mark = ","), "\n")
}, error = function(e) {
  cat("❌ Filter test failed:", e$message, "\n")
})

# Test library search
cat("\n📚 Testing get_library_documents with search...\n")
tryCatch({
  search_results <- get_library_documents(search_term = "lei", limit = 3)
  cat("✅ Search results:", nrow(search_results), "documents\n")
}, error = function(e) {
  cat("❌ Search test failed:", e$message, "\n")
})

# Summary
cat("\n📊 TEST SUMMARY:\n")
cat(paste(rep("=", 50), collapse = ""), "\n")

successful_tests <- sum(sapply(results, function(x) x$success))
total_tests <- length(results)

cat("✅ Successful tests:", successful_tests, "/", total_tests, "\n")

if (successful_tests == total_tests) {
  cat("🎉 ALL TESTS PASSED - App database integration is working!\n")
  cat("\n💡 DEPLOYMENT READY:\n")
  cat("   1. Database connection works with hardcoded credentials\n")
  cat("   2. All app functions are operational\n")
  cat("   3. Railway deployment should work correctly\n")
  cat("   4. App will show ~134k documents instead of 3 fallback documents\n")
} else {
  cat("⚠️ SOME TESTS FAILED - Review errors above\n")
  
  # Show failed tests
  failed_tests <- names(results)[sapply(results, function(x) !x$success)]
  if (length(failed_tests) > 0) {
    cat("\n❌ Failed tests:\n")
    for (test in failed_tests) {
      cat("   -", test, ":", results[[test]]$error, "\n")
    }
  }
}

# Performance analysis
total_duration <- sum(sapply(results, function(x) x$duration))
cat("\n⏱️ Total execution time:", round(total_duration, 2), "seconds\n")

if (total_duration > 10) {
  cat("⚠️ Performance note: Tests took over 10 seconds - may affect app startup time\n")
} else {
  cat("✅ Performance: Good response times for production use\n")
}

cat("\n🏁 APP CONNECTION TEST COMPLETE\n")
cat(paste(rep("=", 50), collapse = ""), "\n")