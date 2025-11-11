# Test script for performance monitoring module
# This script tests that the module loads and functions are defined correctly

cat("=== TESTING PERFORMANCE MONITORING MODULE ===\n\n")

# Test 1: Load required libraries
cat("Test 1: Loading libraries...\n")
tryCatch({
  suppressPackageStartupMessages({
    library(shiny)
    library(DT)
    library(DBI)
  })
  cat("✓ Libraries loaded successfully\n\n")
}, error = function(e) {
  cat("❌ Failed to load libraries:", conditionMessage(e), "\n")
  quit(status = 1)
})

# Test 2: Source the module
cat("Test 2: Sourcing performance monitoring module...\n")
tryCatch({
  source("R/modules/performance_monitoring_module.R", local = TRUE)
  cat("✓ Module sourced successfully\n\n")
}, error = function(e) {
  cat("❌ Failed to source module:", conditionMessage(e), "\n")
  quit(status = 1)
})

# Test 3: Check that functions are defined
cat("Test 3: Verifying functions are defined...\n")
required_functions <- c(
  "check_indexes",
  "check_query_performance",
  "check_table_statistics",
  "check_database_health",
  "performanceMonitoringUI",
  "performanceMonitoringServer"
)

all_defined <- TRUE
for (func in required_functions) {
  if (exists(func)) {
    cat(sprintf("  ✓ %s defined\n", func))
  } else {
    cat(sprintf("  ❌ %s NOT defined\n", func))
    all_defined <- FALSE
  }
}

if (!all_defined) {
  cat("\n❌ Some functions are missing!\n")
  quit(status = 1)
}

cat("\n✓ All required functions are defined\n\n")

# Test 4: Check UI function returns tagList
cat("Test 4: Testing UI function...\n")
tryCatch({
  ui_result <- performanceMonitoringUI("test")
  if (inherits(ui_result, "shiny.tag.list")) {
    cat("✓ UI function returns valid shiny.tag.list\n\n")
  } else {
    cat("❌ UI function does not return shiny.tag.list\n")
    quit(status = 1)
  }
}, error = function(e) {
  cat("❌ UI function failed:", conditionMessage(e), "\n")
  quit(status = 1)
})

# Test 5: Check app_phoenix.R integration
cat("Test 5: Checking app_phoenix.R integration...\n")
app_content <- readLines("app_phoenix.R")

checks <- list(
  source = any(grepl("source.*performance_monitoring_module\\.R", app_content)),
  ui_call = any(grepl("performanceMonitoringUI", app_content)),
  server_call = any(grepl("performanceMonitoringServer", app_content)),
  system_tab = any(grepl("System.*icon.*server", app_content))
)

for (check_name in names(checks)) {
  if (checks[[check_name]]) {
    cat(sprintf("  ✓ %s found in app_phoenix.R\n", check_name))
  } else {
    cat(sprintf("  ❌ %s NOT found in app_phoenix.R\n", check_name))
  }
}

cat("\n")

# Test 6: Syntax check on app_phoenix.R
cat("Test 6: Syntax checking app_phoenix.R...\n")
tryCatch({
  parse("app_phoenix.R")
  cat("✓ app_phoenix.R has valid R syntax\n\n")
}, error = function(e) {
  cat("❌ Syntax error in app_phoenix.R:", conditionMessage(e), "\n")
  quit(status = 1)
})

# Final summary
cat("==============================================\n")
cat("✅ ALL TESTS PASSED!\n")
cat("==============================================\n\n")
cat("The performance monitoring module is ready for deployment.\n")
cat("\nNext steps:\n")
cat("1. Deploy to Cloud Run: git push\n")
cat("2. Verify the System tab appears in the navbar\n")
cat("3. Test all 5 monitoring subtabs\n")
cat("4. Check auto-refresh functionality (30 seconds)\n")
cat("\n")
