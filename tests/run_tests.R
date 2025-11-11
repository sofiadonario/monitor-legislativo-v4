#!/usr/bin/env Rscript
# run_tests.R - Test runner for Monitor Legislativo v4
# ============================================================================

cat("═══════════════════════════════════════════════════════════════\n")
cat("Monitor Legislativo v4 - Test Suite\n")
cat("═══════════════════════════════════════════════════════════════\n\n")

# Load required packages
required_packages <- c("testthat", "R6", "stringi", "digest", "DBI")

for (pkg in required_packages) {
  if (!requireNamespace(pkg, quietly = TRUE)) {
    cat(sprintf("Installing required package: %s\n", pkg))
    install.packages(pkg, repos = "https://cloud.r-project.org/")
  }
}

library(testthat)

# Set working directory to project root
if (basename(getwd()) == "tests") {
  setwd("..")
}

# Run tests
test_results <- list()

cat("Running Security Tests...\n")
cat("───────────────────────────────────────────────────────────────\n")

# Test secure configuration
if (file.exists("tests/testthat/test_secure_config.R")) {
  cat("✓ Testing secure configuration...\n")
  result <- test_file("tests/testthat/test_secure_config.R")
  test_results$secure_config <- result
}

# Test search service
if (file.exists("tests/testthat/test_search_service.R")) {
  cat("✓ Testing search service...\n")
  result <- test_file("tests/testthat/test_search_service.R")
  test_results$search_service <- result
}

# Test search sanitizer
if (file.exists("tests/testthat/test_search_sanitizer.R")) {
  cat("✓ Testing search sanitizer...\n")
  result <- test_file("tests/testthat/test_search_sanitizer.R")
  test_results$search_sanitizer <- result
}

cat("\n")
cat("═══════════════════════════════════════════════════════════════\n")
cat("Test Summary\n")
cat("═══════════════════════════════════════════════════════════════\n")

# Calculate totals
total_tests <- 0
total_passed <- 0
total_failed <- 0

for (name in names(test_results)) {
  result <- test_results[[name]]
  if (!is.null(result)) {
    n_tests <- length(result)
    n_passed <- sum(sapply(result, function(x) {
      if (inherits(x$results[[1]], "expectation_success")) 1 else 0
    }))
    n_failed <- n_tests - n_passed

    total_tests <- total_tests + n_tests
    total_passed <- total_passed + n_passed
    total_failed <- total_failed + n_failed

    cat(sprintf("\n%s:\n", name))
    cat(sprintf("  Tests: %d | Passed: %d | Failed: %d\n",
                n_tests, n_passed, n_failed))
  }
}

cat("\n───────────────────────────────────────────────────────────────\n")
cat(sprintf("TOTAL: %d tests | %d passed | %d failed\n",
            total_tests, total_passed, total_failed))

if (total_failed == 0) {
  cat("\n✅ All tests passed successfully!\n")
  quit(status = 0)
} else {
  cat(sprintf("\n❌ %d test(s) failed. Please review the output above.\n", total_failed))
  quit(status = 1)
}