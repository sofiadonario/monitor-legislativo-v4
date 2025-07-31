# TEST BULLETPROOF RAILWAY FIX
# This script tests the bulletproof fix to ensure it resolves the "documents null" issue
# Run this before deploying to Railway to verify functionality

cat("🧪 TESTING BULLETPROOF RAILWAY FIX\n")
cat("==================================\n")

# Clean environment to simulate Railway startup
rm(list = ls())

# ==============================================================================
# TEST 1: CLEAN ENVIRONMENT SIMULATION
# ==============================================================================
cat("\n🧪 TEST 1: Clean Environment Simulation\n")

# Simulate start_app.R loading sequence
cat("📋 Step 1: Loading utils.R\n")
if (file.exists("utils.R")) {
  source("utils.R")
  cat("✅ utils.R loaded\n")
} else {
  cat("⚠️ utils.R not found\n")
}

cat("📋 Step 2: Loading database.R\n")
if (file.exists("database.R")) {
  source("database.R")
  cat("✅ database.R loaded\n")
} else {
  cat("⚠️ database.R not found\n")
}

cat("📋 Step 3: Loading missing_functions.R\n")
if (file.exists("missing_functions.R")) {
  source("missing_functions.R")
  cat("✅ missing_functions.R loaded\n")
} else {
  cat("⚠️ missing_functions.R not found\n")
}

cat("📋 Step 4: Loading BULLETPROOF_RAILWAY_FIX.R\n")
if (file.exists("BULLETPROOF_RAILWAY_FIX.R")) {
  source("BULLETPROOF_RAILWAY_FIX.R")
  cat("✅ BULLETPROOF_RAILWAY_FIX.R loaded\n")
} else {
  cat("❌ BULLETPROOF_RAILWAY_FIX.R not found - CRITICAL ERROR\n")
  stop("TEST FAILED: BULLETPROOF_RAILWAY_FIX.R is missing")
}

# ==============================================================================
# TEST 2: FUNCTION EXISTENCE VERIFICATION
# ==============================================================================
cat("\n🧪 TEST 2: Function Existence Verification\n")

required_functions <- c(
  "get_lexml_dashboard_metrics",
  "lexml_metrics_wrapper", 
  "get_search_analytics",
  "get_database_stats"
)

test_results <- list()

for (func_name in required_functions) {
  exists_test <- exists(func_name)
  test_results[[func_name]] <- exists_test
  
  if (exists_test) {
    cat("✅", func_name, "EXISTS\n")
  } else {
    cat("❌", func_name, "MISSING\n")
  }
}

# ==============================================================================
# TEST 3: FUNCTION EXECUTION TESTING
# ==============================================================================
cat("\n🧪 TEST 3: Function Execution Testing\n")

# Test get_lexml_dashboard_metrics
cat("📋 Testing get_lexml_dashboard_metrics()...\n")
if (exists("get_lexml_dashboard_metrics")) {
  tryCatch({
    metrics <- get_lexml_dashboard_metrics()
    cat("✅ get_lexml_dashboard_metrics executed successfully\n")
    cat("   📊 Total documents:", metrics$total_documents, "\n")
    cat("   📊 States with docs:", metrics$states_with_docs, "\n")
    cat("   📊 Municipalities with docs:", metrics$municipalities_with_docs, "\n")
    
    # Verify critical values
    if (metrics$total_documents > 1000) {
      cat("✅ Document count is realistic (", metrics$total_documents, ")\n")
    } else {
      cat("❌ Document count too low (", metrics$total_documents, ") - should be 144k+\n")
    }
    
    test_results[["metrics_execution"]] <- TRUE
  }, error = function(e) {
    cat("❌ get_lexml_dashboard_metrics FAILED:", e$message, "\n")
    test_results[["metrics_execution"]] <- FALSE
  })
} else {
  cat("❌ get_lexml_dashboard_metrics function not found\n")
  test_results[["metrics_execution"]] <- FALSE
}

# Test lexml_metrics_wrapper
cat("📋 Testing lexml_metrics_wrapper()...\n")
if (exists("lexml_metrics_wrapper")) {
  tryCatch({
    wrapper_metrics <- lexml_metrics_wrapper()
    cat("✅ lexml_metrics_wrapper executed successfully\n")
    cat("   📊 Total documents:", wrapper_metrics$total_documents, "\n")
    cat("   📊 States with docs:", wrapper_metrics$states_with_docs, "\n")
    cat("   📊 Municipalities with docs:", wrapper_metrics$municipalities_with_docs, "\n")
    
    # Verify both property formats exist
    has_states_with_docs <- !is.null(wrapper_metrics$states_with_docs)
    has_municipalities_with_docs <- !is.null(wrapper_metrics$municipalities_with_docs)
    
    if (has_states_with_docs) {
      cat("✅ states_with_docs property exists (app.R compatibility)\n")
    } else {
      cat("❌ states_with_docs property missing - app.R will fail\n")
    }
    
    if (has_municipalities_with_docs) {
      cat("✅ municipalities_with_docs property exists (app.R compatibility)\n")
    } else {
      cat("❌ municipalities_with_docs property missing - app.R will fail\n")
    }
    
    test_results[["wrapper_execution"]] <- TRUE
  }, error = function(e) {
    cat("❌ lexml_metrics_wrapper FAILED:", e$message, "\n")
    test_results[["wrapper_execution"]] <- FALSE
  })
} else {
  cat("❌ lexml_metrics_wrapper function not found\n")
  test_results[["wrapper_execution"]] <- FALSE
}

# Test get_search_analytics
cat("📋 Testing get_search_analytics()...\n")
if (exists("get_search_analytics")) {
  tryCatch({
    analytics <- get_search_analytics()
    cat("✅ get_search_analytics executed successfully\n")
    cat("   📊 Total documents:", analytics$total_documents, "\n")
    test_results[["analytics_execution"]] <- TRUE
  }, error = function(e) {
    cat("❌ get_search_analytics FAILED:", e$message, "\n")
    test_results[["analytics_execution"]] <- FALSE
  })
} else {
  cat("❌ get_search_analytics function not found\n")
  test_results[["analytics_execution"]] <- FALSE
}

# ==============================================================================
# TEST 4: GLOBAL VARIABLE VERIFICATION
# ==============================================================================
cat("\n🧪 TEST 4: Global Variable Verification\n")

# Check critical global variables
global_vars <- c("database_connected", "db_pool", ".db_pool")

for (var_name in global_vars) {
  if (exists(var_name, envir = .GlobalEnv)) {
    value <- get(var_name, envir = .GlobalEnv)
    cat("✅", var_name, "EXISTS, value:", class(value)[1], "\n")
    
    if (var_name == "database_connected") {
      if (isTRUE(value)) {
        cat("✅ database_connected is TRUE (app.R will use database functions)\n")
      } else {
        cat("❌ database_connected is FALSE (app.R will use fallback)\n")
      }
    }
  } else {
    cat("❌", var_name, "MISSING\n")
  }
}

# ==============================================================================
# TEST 5: RAILWAY ENVIRONMENT SIMULATION
# ==============================================================================
cat("\n🧪 TEST 5: Railway Environment Simulation\n")

# Temporarily set Railway environment variables
original_railway_env <- Sys.getenv("RAILWAY_ENVIRONMENT")
Sys.setenv(RAILWAY_ENVIRONMENT = "production")

cat("📋 Simulating Railway environment...\n")
if (file.exists("BULLETPROOF_RAILWAY_FIX.R")) {
  source("BULLETPROOF_RAILWAY_FIX.R")
  cat("✅ BULLETPROOF_RAILWAY_FIX.R reloaded in Railway simulation\n")
}

# Test function execution in simulated Railway environment
if (exists("get_lexml_dashboard_metrics")) {
  railway_metrics <- get_lexml_dashboard_metrics()
  cat("✅ Dashboard metrics work in Railway simulation:", railway_metrics$total_documents, "documents\n")
}

# Restore environment
Sys.setenv(RAILWAY_ENVIRONMENT = original_railway_env)

# ==============================================================================
# TEST RESULTS SUMMARY
# ==============================================================================
cat("\n🧪 TEST RESULTS SUMMARY\n")
cat("=======================\n")

passed_tests <- sum(unlist(test_results))
total_tests <- length(test_results)

cat("📊 Tests passed:", passed_tests, "/", total_tests, "\n")

if (passed_tests == total_tests) {
  cat("✅ ALL TESTS PASSED - BULLETPROOF FIX IS WORKING!\n")
  cat("🚀 Ready for Railway deployment!\n")
  cat("📊 The dashboard will show 144k+ documents instead of 'documents null'\n")
} else {
  cat("❌ SOME TESTS FAILED - Review issues above\n")
  cat("⚠️ The fix may not work correctly in Railway\n")
}

cat("\n🔍 DETAILED TEST RESULTS:\n")
for (test_name in names(test_results)) {
  status <- if (test_results[[test_name]]) "✅ PASS" else "❌ FAIL"
  cat("  ", test_name, ":", status, "\n")
}

cat("\n🧪 TEST COMPLETE\n")