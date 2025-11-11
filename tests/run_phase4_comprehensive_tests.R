# MONITOR LEGISLATIVO V4 - PHASE 4 COMPREHENSIVE TEST RUNNER
# ===========================================================
# Production-Ready Testing Framework for Railway Deployment
# Brazilian Legislative Monitoring System - Academic Institution Ready

cat("🧪 MONITOR LEGISLATIVO V4 - PHASE 4 COMPREHENSIVE TESTING\n")
cat("==========================================================\n")
cat("🚂 Railway Production Deployment | 🇧🇷 Brazilian Academic Standards\n")
cat("💰 Budget: $15-30/month | 📊 Documents: 134k+ | 🎓 Academic Ready\n\n")

# Test Suite Configuration
# ========================
test_suite_config <- list(
  phase = "4",
  environment = "production",
  deployment_target = "railway",
  budget_tier = "15-30-usd-month",
  academic_context = TRUE,
  brazilian_compliance = TRUE,

  # Test execution settings
  parallel_testing = FALSE,    # Railway resource constraints
  timeout_minutes = 30,
  comprehensive_mode = TRUE,

  # Validation thresholds
  minimum_pass_rate = 85,      # 85% tests must pass
  critical_failure_tolerance = 0,  # No critical failures allowed
  performance_threshold = 90,   # 90% performance targets
  security_threshold = 80,     # 80% security tests

  # Output settings
  detailed_reporting = TRUE,
  json_export = TRUE,
  ci_cd_integration = TRUE
)

# Global test results
phase4_results <- list(
  timestamp = Sys.time(),
  config = test_suite_config,
  test_suites = list(),
  overall_metrics = list(),
  deployment_ready = FALSE,
  critical_issues = list(),
  recommendations = list()
)

# Utility Functions
# =================
log_suite_result <- function(suite_name, status, details = "", duration = 0) {
  timestamp <- format(Sys.time(), "%Y-%m-%d %H:%M:%S")

  if (status == "PASS") {
    cat("✅", timestamp, "- Suite:", suite_name, "- PASSED\n")
  } else if (status == "FAIL") {
    cat("❌", timestamp, "- Suite:", suite_name, "- FAILED:", details, "\n")
  } else {
    cat("⚠️", timestamp, "- Suite:", suite_name, "- WARNING:", details, "\n")
  }

  phase4_results$test_suites[[suite_name]] <<- list(
    status = status,
    details = details,
    duration = duration,
    timestamp = timestamp
  )
}

# Test suite execution wrapper
run_test_suite <- function(suite_name, test_script, critical = FALSE) {
  cat(sprintf("\n🔧 EXECUTING: %s\n", suite_name))
  cat(sprintf("📁 Script: %s\n", test_script))

  if (!file.exists(test_script)) {
    log_suite_result(suite_name, "FAIL", paste("Test script not found:", test_script))
    if (critical) {
      phase4_results$critical_issues[[suite_name]] <<- "Test script missing"
    }
    return(FALSE)
  }

  start_time <- Sys.time()

  tryCatch({
    # Execute test script
    result_code <- system2("Rscript", args = test_script, stdout = TRUE, stderr = TRUE)

    end_time <- Sys.time()
    duration <- as.numeric(difftime(end_time, start_time, units = "mins"))

    # Check if script executed successfully (exit code 0)
    if (is.null(attr(result_code, "status")) || attr(result_code, "status") == 0) {
      log_suite_result(suite_name, "PASS", "All tests completed successfully", duration)
      return(TRUE)
    } else {
      log_suite_result(suite_name, "FAIL", "Test suite failed with errors", duration)
      if (critical) {
        phase4_results$critical_issues[[suite_name]] <<- "Critical test suite failed"
      }
      return(FALSE)
    }

  }, error = function(e) {
    end_time <- Sys.time()
    duration <- as.numeric(difftime(end_time, start_time, units = "mins"))

    log_suite_result(suite_name, "FAIL", e$message, duration)
    if (critical) {
      phase4_results$critical_issues[[suite_name]] <<- e$message
    }
    return(FALSE)
  })
}

# Load detailed test results
load_test_results <- function(results_file) {
  if (file.exists(results_file)) {
    tryCatch({
      if (grepl("\\.rds$", results_file)) {
        return(readRDS(results_file))
      } else if (grepl("\\.json$", results_file)) {
        return(jsonlite::fromJSON(results_file))
      }
    }, error = function(e) {
      cat("⚠️ Could not load test results from:", results_file, "\n")
      return(NULL)
    })
  }
  return(NULL)
}

sanitize_for_json <- function(obj) {
  if (inherits(obj, "difftime")) {
    return(as.numeric(obj))
  }

  if (is.list(obj)) {
    return(lapply(obj, sanitize_for_json))
  }

  obj
}

# =================================
# PHASE 4 TEST EXECUTION SEQUENCE
# =================================

cat("🚀 PHASE 4 TEST EXECUTION SEQUENCE\n")
cat("==================================\n")

# Test Suite 1: Comprehensive Production Tests (Critical)
cat("\n1️⃣ COMPREHENSIVE PRODUCTION VALIDATION\n")
cat("======================================\n")

suite1_success <- run_test_suite(
  "Comprehensive Production Tests",
  "tests/production/comprehensive_production_test_suite.R",
  critical = TRUE
)

# Load detailed results
if (suite1_success) {
  production_results <- load_test_results("tests/production/test_results_comprehensive.rds")
  if (!is.null(production_results)) {
    phase4_results$test_suites$production_detailed <- production_results
    cat("   📊 Production Tests:", production_results$tests_passed, "/", production_results$tests_run, "passed\n")
    cat("   🚨 Critical Failures:", production_results$critical_failures, "\n")
  }
}

# Test Suite 2: Performance and Load Testing
cat("\n2️⃣ PERFORMANCE & LOAD TESTING\n")
cat("=============================\n")

# Check if load testing file exists in the correct location
load_test_file <- "tests/performance/railway_load_testing.R"
if (!file.exists(load_test_file)) {
  # Try alternative location
  alt_load_test_file <- "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegrativo/monitor_legislativo_v4/tests/performance/railway_load_testing.R"
  if (file.exists(alt_load_test_file)) {
    # Copy to correct location
    file.copy(alt_load_test_file, load_test_file)
  }
}

suite2_success <- run_test_suite(
  "Performance and Load Testing",
  load_test_file,
  critical = FALSE
)

# Load performance results
if (suite2_success) {
  performance_results <- load_test_results("tests/performance/railway_load_test_results.rds")
  if (!is.null(performance_results)) {
    phase4_results$test_suites$performance_detailed <- performance_results
    cat("   ⚡ Performance Status:", performance_results$final_status, "\n")
    if (!is.null(performance_results$performance_summary)) {
      cat("   📈 Scenarios Passed:", performance_results$performance_summary$scenarios_passed, "/",
          performance_results$performance_summary$total_scenarios, "\n")
    }
  }
}

# Test Suite 3: Security Validation (Critical)
cat("\n3️⃣ SECURITY & COMPLIANCE VALIDATION\n")
cat("====================================\n")

suite3_success <- run_test_suite(
  "Security and Compliance Validation",
  "tests/security/comprehensive_security_validation.R",
  critical = TRUE
)

# Load security results
if (suite3_success) {
  security_results <- load_test_results("tests/security/security_validation_results.rds")
  if (!is.null(security_results)) {
    phase4_results$test_suites$security_detailed <- security_results
    cat("   🔒 Security Status:", security_results$security_status, "\n")
    cat("   🛡️ Security Score:", round(security_results$total_score, 1), "%\n")
    cat("   🚨 Critical Vulnerabilities:", security_results$critical_vulnerabilities, "\n")
  }
}

# Test Suite 4: Integration Tests (if available)
cat("\n4️⃣ INTEGRATION TESTING\n")
cat("=====================\n")

integration_test_file <- "tests/integration/simple_integration_test.R"
suite4_success <- TRUE  # Default to success if no integration tests

if (file.exists(integration_test_file)) {
  suite4_success <- run_test_suite(
    "Integration Testing",
    integration_test_file,
    critical = FALSE
  )
} else {
  cat("⚠️ No integration tests found - skipping\n")
  log_suite_result("Integration Testing", "SKIP", "No integration test file found")
}

# =============================
# OVERALL ASSESSMENT & REPORTING
# =============================
cat("\n📊 OVERALL PHASE 4 ASSESSMENT\n")
cat("=============================\n")

# Calculate overall metrics
suite_entries <- phase4_results$test_suites
suite_statuses <- vapply(suite_entries, function(suite) {
  status <- suite$status
  if (is.null(status)) NA_character_ else status
}, character(1), USE.NAMES = FALSE)

valid_status_mask <- !is.na(suite_statuses)

total_suites <- sum(valid_status_mask)
passed_suites <- sum(suite_statuses[valid_status_mask] == "PASS")
failed_suites <- sum(suite_statuses[valid_status_mask] == "FAIL")
skipped_suites <- sum(suite_statuses[valid_status_mask] == "SKIP")
critical_failures <- length(phase4_results$critical_issues)

success_rate <- if (total_suites > 0) (passed_suites / total_suites) * 100 else 0
execution_time_minutes <- as.numeric(difftime(Sys.time(), phase4_results$timestamp, units = "mins"))

phase4_results$overall_metrics <- list(
  total_test_suites = total_suites,
  passed_suites = passed_suites,
  failed_suites = failed_suites,
  skipped_suites = skipped_suites,
  success_rate = success_rate,
  critical_failures = critical_failures,
  execution_time_minutes = execution_time_minutes
)

# Display summary
cat("🧪 Test Suites Run:", total_suites, "\n")
cat("✅ Suites Passed:", passed_suites, "\n")
cat("❌ Suites Failed:", failed_suites, "\n")
cat("⏭️ Suites Skipped:", skipped_suites, "\n")
cat("📈 Success Rate:", round(phase4_results$overall_metrics$success_rate, 1), "%\n")
cat("🚨 Critical Issues:", critical_failures, "\n")
cat("⏱️ Total Execution Time:", round(phase4_results$overall_metrics$execution_time_minutes, 1), "minutes\n")

# Deployment readiness assessment
deployment_criteria <- list(
  critical_suites_pass = suite1_success && suite3_success,  # Production and Security must pass
  overall_pass_rate = phase4_results$overall_metrics$success_rate >= test_suite_config$minimum_pass_rate,
  no_critical_failures = critical_failures == 0,
  performance_acceptable = suite2_success || !is.null(performance_results)
)

phase4_results$deployment_ready <- all(unlist(deployment_criteria))

# Generate recommendations
recommendations <- list()

if (!deployment_criteria$critical_suites_pass) {
  recommendations <- c(recommendations,
    "🚨 CRITICAL: Production or Security test suites failed - resolve before deployment")
}

if (!deployment_criteria$overall_pass_rate) {
  recommendations <- c(recommendations,
    paste("📊 Overall pass rate", round(phase4_results$overall_metrics$success_rate, 1),
          "% is below threshold of", test_suite_config$minimum_pass_rate, "%"))
}

if (!deployment_criteria$no_critical_failures) {
  recommendations <- c(recommendations,
    paste("🚨 Critical failures detected:", paste(names(phase4_results$critical_issues), collapse = ", ")))
}

if (!deployment_criteria$performance_acceptable) {
  recommendations <- c(recommendations,
    "⚡ Performance testing issues detected - review load testing results")
}

# Railway-specific recommendations
recommendations <- c(recommendations,
  "🚂 Railway Deployment: Ensure all environment variables are properly configured",
  "💰 Budget Optimization: Monitor resource usage to stay within $15-30/month budget",
  "🇧🇷 Brazilian Compliance: Verify LGPD compliance and academic standards are met",
  "🎓 Academic Features: Ensure all academic institution features are functional")

phase4_results$recommendations <- recommendations

# Final deployment decision
if (phase4_results$deployment_ready) {
  final_status <- "READY_FOR_DEPLOYMENT"
  cat("\n✅ PHASE 4 TESTING COMPLETED SUCCESSFULLY\n")
  cat("🚀 MONITOR LEGISLATIVO V4 IS READY FOR RAILWAY PRODUCTION DEPLOYMENT\n")
} else {
  final_status <- "NOT_READY_FOR_DEPLOYMENT"
  cat("\n❌ PHASE 4 TESTING FAILED\n")
  cat("🛑 RESOLVE CRITICAL ISSUES BEFORE DEPLOYMENT\n")
}

phase4_results$final_status <- final_status

# Export comprehensive results
phase4_results$end_time <- Sys.time()

# Save results
saveRDS(phase4_results, "tests/phase4_comprehensive_test_results.rds")

# Create JSON report for CI/CD
json_report <- jsonlite::toJSON(sanitize_for_json(phase4_results), pretty = TRUE, auto_unbox = TRUE)
writeLines(json_report, "tests/phase4_comprehensive_test_results.json")

# Create summary report
summary_report <- sprintf(
  "MONITOR LEGISLATIVO V4 - PHASE 4 TEST SUMMARY
==============================================
Timestamp: %s
Environment: %s
Deployment Target: %s

TEST SUITE RESULTS:
- Total Suites: %d
- Passed: %d
- Failed: %d
- Success Rate: %.1f%%
- Critical Failures: %d

DEPLOYMENT STATUS: %s

NEXT STEPS:
%s",
  as.character(phase4_results$timestamp),
  test_suite_config$environment,
  test_suite_config$deployment_target,
  phase4_results$overall_metrics$total_test_suites,
  phase4_results$overall_metrics$passed_suites,
  phase4_results$overall_metrics$failed_suites,
  phase4_results$overall_metrics$success_rate,
  phase4_results$overall_metrics$critical_failures,
  final_status,
  paste(phase4_results$recommendations, collapse = "\n- ")
)

writeLines(summary_report, "tests/PHASE4_TEST_SUMMARY.md")

cat("\n💾 Test results saved to:\n")
cat("   - tests/phase4_comprehensive_test_results.rds\n")
cat("   - tests/phase4_comprehensive_test_results.json\n")
cat("   - tests/PHASE4_TEST_SUMMARY.md\n")

# Display recommendations
if (length(recommendations) > 0) {
  cat("\n🔧 RECOMMENDATIONS:\n")
  for (i in seq_along(recommendations)) {
    cat(sprintf("%d. %s\n", i, recommendations[i]))
  }
}

cat(sprintf("\n🎯 FINAL STATUS: %s\n", final_status))

# Exit with appropriate status code for CI/CD integration
if (phase4_results$deployment_ready) {
  cat("✅ Phase 4 testing successful - ready for Railway deployment\n")
  quit(status = 0)
} else {
  cat("❌ Phase 4 testing failed - resolve issues before deployment\n")
  quit(status = 1)
}
