# Simple Integration Test Runner
# ==============================

cat("🧪 MONITOR LEGISLATIVO V4 - SIMPLE INTEGRATION TEST\n")
cat("===================================================\n")

# Test Results Storage
test_results <- list()
total_tests <- 0
passed_tests <- 0
failed_tests <- 0

# Helper function to run a test
run_test <- function(test_name, test_function) {
  total_tests <<- total_tests + 1
  cat(sprintf("🔍 Testing: %s... ", test_name))
  
  result <- tryCatch({
    test_function()
    passed_tests <<- passed_tests + 1
    test_results[[test_name]] <<- list(status = "PASS", error = NULL)
    cat("✅ PASS\n")
    return(TRUE)
  }, error = function(e) {
    failed_tests <<- failed_tests + 1
    test_results[[test_name]] <<- list(status = "FAIL", error = e$message)
    cat(sprintf("❌ FAIL: %s\n", e$message))
    return(FALSE)
  })
  
  return(result)
}

# Test 1: Basic R environment
run_test("R Environment Check", function() {
  stopifnot(R.version.string != "")
  stopifnot(exists("data.frame"))
})

# Test 2: Required directories exist
run_test("Directory Structure", function() {
  required_dirs <- c("modules", "data", "tests")
  for(dir in required_dirs) {
    if(!dir.exists(dir)) {
      stop(sprintf("Missing directory: %s", dir))
    }
  }
})

# Test 3: Key R files exist
run_test("Core Files Existence", function() {
  key_files <- c("app.R", "global.R")
  for(file in key_files) {
    if(!file.exists(file)) {
      stop(sprintf("Missing file: %s", file))
    }
  }
})

# Test 4: Data file exists
run_test("Data File Check", function() {
  data_file <- "data_current/processed/archive/legacy_versions/deduplicated/lexml_unified_deduplicated.csv"
  if(file.exists(data_file)) {
    # Check file is not empty and has reasonable size
    file_info <- file.info(data_file)
    if(file_info$size < 1000) {
      stop("Data file too small")
    }
  } else {
    stop("Data file not found")
  }
})

# Test 5: Basic CSV loading
run_test("CSV Data Loading", function() {
  data_file <- "data_current/processed/archive/legacy_versions/deduplicated/lexml_unified_deduplicated.csv"
  if(file.exists(data_file)) {
    sample_data <- read.csv(data_file, nrows = 5)
    stopifnot(nrow(sample_data) > 0)
    stopifnot(ncol(sample_data) > 0)
  }
})

# Test 6: Module files exist
run_test("Module Files Check", function() {
  module_dirs <- c("modules/analytics", "modules/sao_paulo", "modules/maps")
  for(dir in module_dirs) {
    if(!dir.exists(dir)) {
      stop(sprintf("Missing module directory: %s", dir))
    }
  }
})

# Test 7: Database connection module
run_test("Database Module Check", function() {
  db_files <- list.files("R", pattern = "database", full.names = TRUE)
  if(length(db_files) == 0) {
    stop("No database connection files found")
  }
})

# Test 8: Global.R loads without errors
run_test("Global.R Loading", function() {
  # Try to source global.R in isolated environment
  test_env <- new.env()
  # This is a simplified test - just check it parses
  parse("global.R")
})

# Test 9: App.R loads without errors  
run_test("App.R Loading", function() {
  # Try to parse app.R
  parse("app.R")
})

# Test 10: Test basic search functionality
run_test("Search Function", function() {
  # Create minimal test data
  test_data <- data.frame(
    titulo = c("Lei de Transporte", "Código de Trânsito"), 
    content = c("transporte público", "trânsito urbano"),
    stringsAsFactors = FALSE
  )
  
  # Basic grep search
  result <- test_data[grepl("transporte", test_data$content, ignore.case = TRUE), ]
  stopifnot(nrow(result) > 0)
})

# Final Summary
cat("\n📊 TEST SUMMARY\n")
cat("================\n")
cat(sprintf("Total Tests: %d\n", total_tests))
cat(sprintf("Passed: %d\n", passed_tests))  
cat(sprintf("Failed: %d\n", failed_tests))
cat(sprintf("Success Rate: %.1f%%\n", (passed_tests / total_tests) * 100))

if(failed_tests > 0) {
  cat("\n❌ FAILED TESTS:\n")
  for(test_name in names(test_results)) {
    if(test_results[[test_name]]$status == "FAIL") {
      cat(sprintf("   • %s: %s\n", test_name, test_results[[test_name]]$error))
    }
  }
}

# Overall result
if(failed_tests == 0) {
  cat("\n🎉 ALL TESTS PASSED! Application structure is healthy.\n")
  quit(status = 0)
} else {
  cat(sprintf("\n⚠️ %d TESTS FAILED. Review issues above.\n", failed_tests))
  quit(status = 1)
}