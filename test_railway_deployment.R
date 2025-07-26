# Test Railway Deployment Status
# Quick diagnostic script to check what's working
# Date: 2025-07-26

cat("🔍 RAILWAY DEPLOYMENT DIAGNOSTIC TEST\n")
cat("=====================================\n")

# Test 1: Check if files exist
cat("\n1. FILE EXISTENCE CHECK:\n")
files_to_check <- c(
  "railway_deployment_fix.R",
  "comprehensive_framework_patch.R", 
  "install_packages.R",
  "comprehensive_app_integration.R",
  "parquet_data_loader.R"
)

for (file in files_to_check) {
  if (file.exists(file)) {
    cat("✅", file, "exists\n")
  } else {
    cat("❌", file, "NOT FOUND\n")
  }
}

# Test 2: Try loading files
cat("\n2. FILE LOADING TEST:\n")
tryCatch({
  if (file.exists("railway_deployment_fix.R")) {
    source("railway_deployment_fix.R")
    cat("✅ railway_deployment_fix.R loaded successfully\n")
  }
}, error = function(e) {
  cat("❌ Error loading railway_deployment_fix.R:", e$message, "\n")
})

tryCatch({
  if (file.exists("comprehensive_framework_patch.R")) {
    source("comprehensive_framework_patch.R") 
    cat("✅ comprehensive_framework_patch.R loaded successfully\n")
  }
}, error = function(e) {
  cat("❌ Error loading comprehensive_framework_patch.R:", e$message, "\n")
})

# Test 3: Check package availability
cat("\n3. PACKAGE AVAILABILITY:\n")
required_packages <- c("shiny", "shinydashboard", "DT", "dplyr", "arrow", "data.table")
for (pkg in required_packages) {
  if (require(pkg, quietly = TRUE, character.only = TRUE)) {
    cat("✅", pkg, "available\n")
  } else {
    cat("❌", pkg, "NOT AVAILABLE\n")
  }
}

# Test 4: Test core functions
cat("\n4. FUNCTION TEST:\n")
tryCatch({
  if (exists("load_main_parquet_dataset")) {
    test_data <- load_main_parquet_dataset(columns = c("titulo"))
    cat("✅ load_main_parquet_dataset works:", nrow(test_data), "records\n")
  } else {
    cat("❌ load_main_parquet_dataset function not found\n")
  }
}, error = function(e) {
  cat("❌ Error testing load_main_parquet_dataset:", e$message, "\n")
})

tryCatch({
  if (exists("get_comprehensive_dashboard_metrics")) {
    test_metrics <- get_comprehensive_dashboard_metrics()
    cat("✅ get_comprehensive_dashboard_metrics works:", test_metrics$total_documents, "docs\n")
  } else {
    cat("❌ get_comprehensive_dashboard_metrics function not found\n")
  }
}, error = function(e) {
  cat("❌ Error testing get_comprehensive_dashboard_metrics:", e$message, "\n")
})

# Test 5: Environment check
cat("\n5. ENVIRONMENT CHECK:\n")
cat("Working directory:", getwd(), "\n")
cat("R version:", R.version.string, "\n")
cat("Platform:", R.version$platform, "\n")

# Test 6: Check if we're in Railway
cat("\n6. RAILWAY DETECTION:\n")
railway_vars <- c("RAILWAY_ENVIRONMENT", "PORT", "RAILWAY_PROJECT_ID")
railway_detected <- FALSE
for (var in railway_vars) {
  val <- Sys.getenv(var)
  if (val != "") {
    cat("✅ Railway variable", var, "=", val, "\n")
    railway_detected <- TRUE
  }
}

if (!railway_detected) {
  cat("❌ No Railway environment variables detected\n")
  cat("💡 This might be running locally, not on Railway\n")
}

cat("\n=====================================\n")
cat("🔍 DIAGNOSTIC COMPLETE\n")

# Output summary for easy debugging
cat("\nSUMMARY FOR DEBUGGING:\n")
cat("- Files exist:", sum(sapply(files_to_check, file.exists)), "/", length(files_to_check), "\n")
cat("- Packages available:", sum(sapply(required_packages, function(pkg) require(pkg, quietly = TRUE, character.only = TRUE))), "/", length(required_packages), "\n")
cat("- Railway environment:", ifelse(railway_detected, "YES", "NO"), "\n")
cat("- Working directory:", getwd(), "\n")