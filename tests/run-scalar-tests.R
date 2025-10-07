# Run Scalar Safety Tests
# Quick test runner to verify all scalar guards are working

# Load required packages
if (!require("testthat", quietly = TRUE)) {
  stop("testthat package is required. Install with: install.packages('testthat')")
}

cat("\n═══════════════════════════════════════════════════════════\n")
cat("  SCALAR SAFETY TEST SUITE\n")
cat("═══════════════════════════════════════════════════════════\n\n")

# Set working directory to project root
if (basename(getwd()) == "tests") {
  setwd("..")
}

# Source the scalar utilities
source("R/utils/scalar_utils.R", local = TRUE)
source("R/utils/ui_utils.R", local = TRUE)

# Load shinydashboard for valueBox function
library(shinydashboard)

# Run the test suite
cat("Running scalar safety tests...\n\n")

test_results <- test_file(
  "tests/testthat/test-scalar-safety.R",
  reporter = "progress"
)

cat("\n═══════════════════════════════════════════════════════════\n")
cat("  TEST SUMMARY\n")
cat("═══════════════════════════════════════════════════════════\n\n")

# Print summary
if (inherits(test_results, "testthat_results")) {
  n_tests <- length(test_results)
  n_failed <- sum(vapply(test_results, function(x) {
    inherits(x, "expectation_failure") || inherits(x, "expectation_error")
  }, logical(1)))
  n_passed <- n_tests - n_failed

  cat(sprintf("Total tests: %d\n", n_tests))
  cat(sprintf("Passed: %d\n", n_passed))
  cat(sprintf("Failed: %d\n", n_failed))

  if (n_failed == 0) {
    cat("\n✅ ALL TESTS PASSED!\n")
    cat("All scalar guards are working correctly.\n")
  } else {
    cat("\n❌ SOME TESTS FAILED\n")
    cat("Please review the errors above.\n")
  }
} else {
  cat("Test results format unexpected. Please check output above.\n")
}

cat("\n═══════════════════════════════════════════════════════════\n\n")

# Return invisible test results for programmatic use
invisible(test_results)
