# SIMPLIFIED LEGISLATIVE DATA SCIENCE VALIDATION
# ==============================================
# Railway deployment validation with memory monitoring

cat("🔍 Legislative Data Science System Validation\n")
cat("==============================================\n")

# Memory monitoring function
monitor_memory <- function() {
  gc_info <- gc()
  round(sum(gc_info[, "used"]) * 8 / 1024, 2)  # Estimate MB
}

# Validation results
validation_results <- list(
  timestamp = Sys.time(),
  modules = list(),
  memory_usage = list(),
  railway_compliance = FALSE
)

# Record initial memory
initial_memory <- monitor_memory()
validation_results$memory_usage$initial <- initial_memory
cat("Initial memory usage:", initial_memory, "MB\n")

# Test module loading
cat("\n📦 Testing Module Loading...\n")

# Test Integration Module
tryCatch({
  source("modules/legislative_data_science_integration.R")
  validation_results$modules$integration <- TRUE
  cat("✅ Integration module loaded\n")
}, error = function(e) {
  validation_results$modules$integration <- FALSE
  cat("❌ Integration module failed:", e$message, "\n")
})

# Record memory after loading
post_loading_memory <- monitor_memory()
validation_results$memory_usage$post_loading <- post_loading_memory
memory_increase <- post_loading_memory - initial_memory
cat("Memory after loading:", post_loading_memory, "MB (+", memory_increase, "MB)\n")

# Test UI Components
cat("\n🎨 Testing UI Components...\n")
tryCatch({
  source("modules/ui/legislative_analytics_ui.R")
  validation_results$modules$ui <- TRUE
  cat("✅ UI components loaded\n")
}, error = function(e) {
  validation_results$modules$ui <- FALSE
  cat("❌ UI components failed:", e$message, "\n")
})

# Test basic functionality with small sample
cat("\n🧪 Testing Basic Functionality...\n")

sample_data <- data.frame(
  id = 1:3,
  text = c(
    "Lei federal sobre transporte sustentável",
    "Resolução ANTT sobre veículos",
    "Decreto sobre infraestrutura"
  ),
  year = c(2021, 2022, 2023),
  stringsAsFactors = FALSE
)

# Test integration function if available
if (validation_results$modules$integration && exists("run_comprehensive_legislative_analysis")) {
  cat("Testing integration function...\n")
  
  memory_before_test <- monitor_memory()
  
  test_result <- tryCatch({
    run_comprehensive_legislative_analysis(
      connection = NULL,
      sample_size = 3,
      analysis_modules = "nlp"  # Test just one module
    )
  }, error = function(e) {
    list(status = "error", message = e$message)
  })
  
  memory_after_test <- monitor_memory()
  test_memory_increase <- memory_after_test - memory_before_test
  
  validation_results$functionality_test <- list(
    status = test_result$metadata$status %||% "error",
    memory_increase = test_memory_increase,
    modules_run = test_result$metadata$modules_completed %||% 0
  )
  
  cat("   Test status:", validation_results$functionality_test$status, "\n")
  cat("   Memory increase:", test_memory_increase, "MB\n")
  cat("   Modules completed:", validation_results$functionality_test$modules_run, "\n")
} else {
  cat("Integration function not available for testing\n")
  validation_results$functionality_test <- list(status = "not_available")
}

# Final memory assessment
final_memory <- monitor_memory()
validation_results$memory_usage$final <- final_memory
total_memory_increase <- final_memory - initial_memory

cat("\n📊 Memory Assessment\n")
cat("Initial memory:", initial_memory, "MB\n")
cat("Final memory:", final_memory, "MB\n")
cat("Total increase:", total_memory_increase, "MB\n")

# Railway compliance check (1500MB limit)
railway_limit <- 1500
memory_percentage <- (final_memory / railway_limit) * 100
within_railway_limits <- final_memory < (railway_limit * 0.8)  # 80% safety margin

validation_results$railway_compliance <- within_railway_limits
validation_results$memory_usage$percentage_of_limit <- memory_percentage

cat("Railway limit: 1500 MB\n")
cat("Current usage:", round(memory_percentage, 1), "% of limit\n")
cat("Railway compliance:", if(within_railway_limits) "✅ PASS" else "❌ FAIL", "\n")

# Module availability summary
modules_loaded <- sum(unlist(validation_results$modules))
total_modules <- length(validation_results$modules)

cat("\n📋 Validation Summary\n")
cat("====================\n")
cat("Modules loaded:", modules_loaded, "/", total_modules, "\n")
cat("Memory usage: ", final_memory, "MB\n")
cat("Railway compliance:", if(within_railway_limits) "✅ PASS" else "❌ FAIL", "\n")

# Overall system status
overall_status <- if(modules_loaded >= 2 && within_railway_limits) "READY" else "NEEDS_ATTENTION"
cat("Overall status:", overall_status, "\n")

validation_results$overall_status <- overall_status
validation_results$summary <- list(
  modules_loaded = modules_loaded,
  memory_compliant = within_railway_limits,
  functionality_working = validation_results$functionality_test$status == "complete"
)

# Save results
tryCatch({
  saveRDS(validation_results, "validation_results.rds")
  cat("\n💾 Results saved to validation_results.rds\n")
}, error = function(e) {
  cat("\n⚠️ Could not save results:", e$message, "\n")
})

# Check for specific functions
cat("\n🔧 Function Availability Check\n")
functions_to_check <- c(
  "run_comprehensive_legislative_analysis",
  "get_legislative_dashboard_data", 
  "create_legislative_analytics_tab",
  "legislative_analytics_server"
)

for (func in functions_to_check) {
  available <- exists(func)
  cat("  ", func, ":", if(available) "✅" else "❌", "\n")
}

cat("\n✅ Validation Complete!\n")
cat("System is", overall_status, "for Railway deployment.\n")

# Return results
invisible(validation_results)