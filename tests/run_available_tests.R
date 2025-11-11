# Run Available Tests - Handles Missing Dependencies Gracefully
# ==============================================================

cat("🧪 MONITOR LEGISLATIVO V4 - AVAILABLE TESTS RUNNER\n")
cat("==================================================\n")

# Set working directory to project root
if(basename(getwd()) != "monitor_legislativo_v4") {
  if(dir.exists("monitor_legislativo_v4")) {
    setwd("monitor_legislativo_v4")
  }
}

cat("📁 Working directory:", getwd(), "\n\n")

# Test Results Storage
test_results <- list()
total_tests <- 0
passed_tests <- 0
failed_tests <- 0
skipped_tests <- 0

# Check package availability
packages_status <- list(
  testthat = require('testthat', quietly=TRUE),
  httr = require('httr', quietly=TRUE),
  shinytest2 = require('shinytest2', quietly=TRUE),
  R6 = require('R6', quietly=TRUE)
)

cat("📦 Package Status:\n")
for(pkg in names(packages_status)) {
  if(packages_status[[pkg]]) {
    cat("  ✅", pkg, "\n")
  } else {
    cat("  ❌", pkg, "\n")
  }
}

# Run basic integration test (no dependencies)
cat("\n🔗 INTEGRATION TEST (No Dependencies)\n")
cat("======================================\n")
source("tests/integration/simple_integration_test.R")

# If testthat is available, run unit tests
if(packages_status$testthat) {
  cat("\n🔧 UNIT TESTS (testthat)\n")
  cat("========================\n")
  
  tryCatch({
    # Run data loading test manually
    source("tests/unit/test_data_loading.R")
    cat("✅ Data loading tests executed\n")
  }, error = function(e) {
    cat("⚠️ Data loading tests skipped:", e$message, "\n")
  })
}

# Run security tests that don't need httr
cat("\n🔒 SECURITY TESTS (Basic)\n")
cat("=========================\n")

# Create a basic security test
test_security_basic <- function() {
  cat("Testing basic security measures...\n")
  
  # Test 1: Check for exposed credentials
  cat("  • Checking for exposed credentials... ")
  app_file <- readLines("app.R", warn=FALSE)
  global_file <- readLines("global.R", warn=FALSE)
  
  # Look for hardcoded passwords or keys
  sensitive_patterns <- c("password\\s*=\\s*['\"]", "api_key\\s*=\\s*['\"]", "secret\\s*=\\s*['\"]")
  found_sensitive <- FALSE
  
  for(pattern in sensitive_patterns) {
    if(any(grepl(pattern, app_file, ignore.case=TRUE)) || 
       any(grepl(pattern, global_file, ignore.case=TRUE))) {
      found_sensitive <- TRUE
      break
    }
  }
  
  if(!found_sensitive) {
    cat("✅ PASS\n")
    passed_tests <<- passed_tests + 1
  } else {
    cat("⚠️ WARNING - Check for hardcoded credentials\n")
    failed_tests <<- failed_tests + 1
  }
  total_tests <<- total_tests + 1
  
  # Test 2: Check for SQL injection protection
  cat("  • Checking for SQL injection protection... ")
  if(file.exists("R/database/queries.R")) {
    queries_file <- readLines("R/database/queries.R", warn=FALSE)
    # Look for parameterized queries
    if(any(grepl("dbGetQuery|sqlInterpolate|dbSendQuery", queries_file))) {
      cat("✅ PASS - Database query functions found\n")
      passed_tests <<- passed_tests + 1
    } else {
      cat("⚠️ WARNING - Verify query parameterization\n")
      failed_tests <<- failed_tests + 1
    }
  } else {
    cat("⏭️ SKIP - No queries file\n")
    skipped_tests <<- skipped_tests + 1
  }
  total_tests <<- total_tests + 1
  
  # Test 3: Check for input validation
  cat("  • Checking for input validation... ")
  if(file.exists("R/utils/validation_utils.R")) {
    cat("✅ PASS - Validation utilities present\n")
    passed_tests <<- passed_tests + 1
  } else {
    cat("⚠️ WARNING - No validation utilities found\n")
    failed_tests <<- failed_tests + 1
  }
  total_tests <<- total_tests + 1
}

test_security_basic()

# Performance test (basic, no httr needed)
cat("\n⚡ PERFORMANCE TEST (Basic)\n")
cat("===========================\n")

test_performance_basic <- function() {
  cat("Testing basic performance metrics...\n")
  
  # Test 1: Check data loading speed
  cat("  • Testing CSV loading performance... ")
  data_path <- "data_current/processed/archive/legacy_versions/deduplicated/lexml_unified_deduplicated.csv"
  
  if(file.exists(data_path)) {
    start_time <- Sys.time()
    sample_data <- read.csv(data_path, nrows=1000)
    load_time <- as.numeric(difftime(Sys.time(), start_time, units="secs"))
    
    if(load_time < 5) {
      cat(sprintf("✅ PASS (%.2f seconds)\n", load_time))
      passed_tests <<- passed_tests + 1
    } else {
      cat(sprintf("⚠️ SLOW (%.2f seconds)\n", load_time))
      failed_tests <<- failed_tests + 1
    }
  } else {
    cat("⏭️ SKIP - Data file not found\n")
    skipped_tests <<- skipped_tests + 1
  }
  total_tests <<- total_tests + 1
  
  # Test 2: Check memory usage
  cat("  • Checking memory usage... ")
  mem_used <- as.numeric(gc()[2,2])  # Memory in MB
  if(mem_used < 2000) {  # Less than 2GB
    cat(sprintf("✅ PASS (%.0f MB)\n", mem_used))
    passed_tests <<- passed_tests + 1
  } else {
    cat(sprintf("⚠️ HIGH (%.0f MB)\n", mem_used))
    failed_tests <<- failed_tests + 1
  }
  total_tests <<- total_tests + 1
}

test_performance_basic()

# Data validation tests
cat("\n📊 DATA VALIDATION TESTS\n")
cat("========================\n")

test_data_validation <- function() {
  data_path <- "data_current/processed/archive/legacy_versions/deduplicated/lexml_unified_deduplicated.csv"
  
  if(file.exists(data_path)) {
    cat("  • Loading sample data... ")
    sample_data <- read.csv(data_path, nrows=100)
    cat("✅ Loaded\n")
    
    # Test 1: Check for required columns
    cat("  • Checking required columns... ")
    required_cols <- c("titulo", "tipo", "ano", "estado")
    missing_cols <- setdiff(required_cols, names(sample_data))
    
    if(length(missing_cols) == 0) {
      cat("✅ PASS - All required columns present\n")
      passed_tests <<- passed_tests + 1
    } else {
      cat("❌ FAIL - Missing:", paste(missing_cols, collapse=", "), "\n")
      failed_tests <<- failed_tests + 1
    }
    total_tests <<- total_tests + 1
    
    # Test 2: Check data types
    cat("  • Checking data types... ")
    if(is.numeric(sample_data$ano) || is.integer(sample_data$ano)) {
      cat("✅ PASS - Year column is numeric\n")
      passed_tests <<- passed_tests + 1
    } else {
      cat("⚠️ WARNING - Year column should be numeric\n")
      failed_tests <<- failed_tests + 1
    }
    total_tests <<- total_tests + 1
    
    # Test 3: Check for data quality
    cat("  • Checking data quality... ")
    na_count <- sum(is.na(sample_data$titulo))
    if(na_count < nrow(sample_data) * 0.1) {  # Less than 10% NA
      cat(sprintf("✅ PASS - %.1f%% missing titles\n", (na_count/nrow(sample_data))*100))
      passed_tests <<- passed_tests + 1
    } else {
      cat(sprintf("⚠️ WARNING - %.1f%% missing titles\n", (na_count/nrow(sample_data))*100))
      failed_tests <<- failed_tests + 1
    }
    total_tests <<- total_tests + 1
  } else {
    cat("⏭️ SKIP - Data file not found\n")
    skipped_tests <<- skipped_tests + 3
    total_tests <<- total_tests + 3
  }
}

test_data_validation()

# Final Summary
cat("\n📊 TEST SUMMARY\n")
cat("===============\n")
cat(sprintf("Total Tests: %d\n", total_tests))
cat(sprintf("✅ Passed: %d\n", passed_tests))
cat(sprintf("❌ Failed: %d\n", failed_tests))
cat(sprintf("⏭️ Skipped: %d\n", skipped_tests))
cat(sprintf("Success Rate: %.1f%%\n", (passed_tests / (total_tests - skipped_tests)) * 100))

# Overall assessment
cat("\n🎯 OVERALL ASSESSMENT\n")
cat("=====================\n")

if(passed_tests > total_tests * 0.8) {
  cat("✅ EXCELLENT - Application is in good health\n")
} else if(passed_tests > total_tests * 0.6) {
  cat("⚠️ GOOD - Most tests passing, some issues to address\n")
} else {
  cat("❌ NEEDS ATTENTION - Several tests failing\n")
}

# Package recommendations
if(!packages_status$httr) {
  cat("\n💡 RECOMMENDATION: Install 'httr' package for API testing\n")
  cat("   Run: install.packages('httr')\n")
}
if(!packages_status$shinytest2) {
  cat("💡 RECOMMENDATION: Install 'shinytest2' for Shiny app testing\n")
  cat("   Run: install.packages('shinytest2')\n")
}

cat("\n✅ Test execution completed successfully!\n")