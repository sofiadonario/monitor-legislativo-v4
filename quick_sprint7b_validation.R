# ==============================================================================
# QUICK SPRINT 7B VALIDATION SCRIPT
# ==============================================================================
# Rapid validation of Sprint 7B modules without heavy package installation

cat("🚀 Quick Sprint 7B Validation\n")
cat("=============================\n")

# Initialize test results
results <- list()

# Test 1: Check Sprint 7B files exist
cat("\n📁 Checking Sprint 7B file structure...\n")

required_files <- c(
  "R/modules/analytics/regional_analysis.R",
  "R/modules/analytics/usage_dashboard.R", 
  "R/modules/collaboration/research_tools.R",
  "R/sprint7b_integration_loader.R",
  "api/endpoints/analytics_sprint7b.R"
)

file_check_results <- sapply(required_files, function(file) {
  exists <- file.exists(file)
  cat(ifelse(exists, "✅", "❌"), file, "\n")
  return(exists)
})

results$files_exist <- all(file_check_results)

# Test 2: Check file sizes (indicating substantial code)
cat("\n📊 Checking file sizes...\n")

file_sizes <- sapply(required_files, function(file) {
  if (file.exists(file)) {
    size_kb <- round(file.info(file)$size / 1024, 2)
    cat("📄", file, ":", size_kb, "KB\n")
    return(size_kb)
  } else {
    return(0)
  }
})

total_size_kb <- sum(file_sizes)
results$total_size_kb <- total_size_kb
results$substantial_code <- total_size_kb > 100 # At least 100KB of code

# Test 3: Check main app.R integration points
cat("\n🔗 Checking app.R integration...\n")

if (file.exists("app.R")) {
  app_content <- readLines("app.R")
  
  integration_checks <- list(
    sprint7b_loader = any(grepl("sprint7b_integration_loader", app_content)),
    sprint7b_system_loaded = any(grepl("sprint7b_system_loaded", app_content)),
    usage_dashboard = any(grepl("Usage Metrics Dashboard", app_content)),
    regional_analysis = any(grepl("Regional Analysis Tools", app_content)),
    collaboration = any(grepl("Research Collaboration Features", app_content)),
    api_endpoints = any(grepl("Extended API Endpoints", app_content))
  )
  
  for (check_name in names(integration_checks)) {
    result <- integration_checks[[check_name]]
    cat(ifelse(result, "✅", "❌"), "Integration check:", check_name, "\n")
  }
  
  results$app_integration <- all(unlist(integration_checks))
} else {
  cat("❌ app.R not found\n")
  results$app_integration <- FALSE
}

# Test 4: Memory estimation
cat("\n💾 Estimating memory requirements...\n")

# Basic memory check
initial_memory <- gc()
memory_mb <- round(sum(initial_memory[,2] * c(8, 8)) / 1024, 2)
cat("Current R session memory:", memory_mb, "MB\n")

results$memory_within_limits <- memory_mb < 500 # Conservative estimate

# Test 5: Check Railway deployment files
cat("\n🚂 Checking Railway deployment compatibility...\n")

railway_files <- c("Dockerfile", "railway.toml", ".railway-deploy")
railway_check <- sapply(railway_files, function(file) {
  exists <- file.exists(file)
  cat(ifelse(exists, "✅", "❌"), file, "\n")
  return(exists)
})

results$railway_ready <- sum(railway_check) >= 2 # At least 2/3 files

# Final assessment
cat("\n🎯 SPRINT 7B VALIDATION SUMMARY\n")
cat("================================\n")

overall_tests <- c(
  "Files exist" = results$files_exist,
  "Substantial code" = results$substantial_code, 
  "App integration" = results$app_integration,
  "Memory limits" = results$memory_within_limits,
  "Railway ready" = results$railway_ready
)

for (test_name in names(overall_tests)) {
  result <- overall_tests[[test_name]]
  cat(ifelse(result, "✅", "❌"), test_name, "\n")
}

results$overall_success <- all(overall_tests)

cat("\n📈 VALIDATION METRICS:\n")
cat("- Total code size:", total_size_kb, "KB\n") 
cat("- Files deployed:", sum(file_check_results), "/", length(file_check_results), "\n")
cat("- Memory usage:", memory_mb, "MB\n")
cat("- Overall status:", ifelse(results$overall_success, "✅ PASSED", "❌ FAILED"), "\n")

# Save results for monitoring
saveRDS(results, "sprint7b_validation_results.rds")

cat("\n✨ Sprint 7B validation completed!\n")