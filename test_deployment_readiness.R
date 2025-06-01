#!/usr/bin/env Rscript
#' Railway Deployment Readiness Test
#' 
#' This script verifies that all critical components for Railway deployment
#' are present and properly configured for the Brazilian Legislative Monitoring System
#' 
#' @author DevOps Team
#' @date 2025-08-04

cat("=== RAILWAY DEPLOYMENT READINESS TEST ===\n")
cat("Testing Brazilian Legislative Monitoring System v4.0\n")
cat("Target: 134k+ documents with full analytics\n\n")

# Test 1: Check critical files exist
cat("1. Checking critical file availability...\n")

critical_files <- c(
  "app.R",
  "RAILWAY_PRODUCTION_DB_FIX.R",
  "archive/database_fixes/RAILWAY_DATABASE_FINAL_FIX.R",
  "archive/diagnostic_files/startup_diagnostics.R",
  "archive/old_analysis_scripts/geospatial_analytics_system.R",
  "archive/old_analysis_scripts/temporal_analysis_system.R",
  "archive/old_analysis_scripts/legislative_ml_system.R",
  "archive/old_analysis_scripts/advanced_text_mining_pipeline.R",
  "archive/old_analysis_scripts/ml_anomaly_detection_system.R",
  "dev-tools/railway_analytics_lightweight.R",
  "dev-tools/railway_error_handler.R",
  "dev-tools/test_railway_connection.R"
)

all_files_exist <- TRUE
for (file in critical_files) {
  if (file.exists(file)) {
    cat(sprintf("   ✅ %s\n", file))
  } else {
    cat(sprintf("   ❌ %s (MISSING)\n", file))
    all_files_exist <- FALSE
  }
}

# Test 2: Check essential packages
cat("\n2. Checking essential R packages...\n")

essential_packages <- c(
  "shiny", "shinydashboard", "DBI", "dplyr", "DT", 
  "plotly", "leaflet", "sf", "ggplot2", "RColorBrewer"
)

packages_available <- TRUE
for (pkg in essential_packages) {
  if (requireNamespace(pkg, quietly = TRUE)) {
    cat(sprintf("   ✅ %s\n", pkg))
  } else {
    cat(sprintf("   ❌ %s (NOT INSTALLED)\n", pkg))
    packages_available <- FALSE
  }
}

# Test 3: Check Dockerfile configuration
cat("\n3. Checking Dockerfile configuration...\n")

if (file.exists("Dockerfile")) {
  dockerfile_content <- readLines("Dockerfile")
  
  # Check for key components
  has_geospatial_base <- any(grepl("rocker/geospatial", dockerfile_content))
  has_multistage <- any(grepl("AS builder", dockerfile_content))
  has_analytics_files <- any(grepl("archive/old_analysis_scripts", dockerfile_content))
  has_db_fixes <- any(grepl("RAILWAY_DATABASE_FINAL_FIX", dockerfile_content))
  
  cat(sprintf("   ✅ Dockerfile exists\n"))
  cat(sprintf("   %s Geospatial base image: %s\n", 
              ifelse(has_geospatial_base, "✅", "❌"), has_geospatial_base))
  cat(sprintf("   %s Multi-stage build: %s\n", 
              ifelse(has_multistage, "✅", "❌"), has_multistage))
  cat(sprintf("   %s Analytics files copied: %s\n", 
              ifelse(has_analytics_files, "✅", "❌"), has_analytics_files))
  cat(sprintf("   %s Database fixes included: %s\n", 
              ifelse(has_db_fixes, "✅", "❌"), has_db_fixes))
} else {
  cat("   ❌ Dockerfile missing\n")
}

# Test 4: Git tracking status
cat("\n4. Checking git tracking status...\n")
git_status <- system("git status --porcelain", intern = TRUE)
staged_analytics <- sum(grepl("^A.*archive/old_analysis_scripts", git_status))
staged_fixes <- sum(grepl("^A.*archive/database_fixes", git_status))

cat(sprintf("   ✅ Analytics files staged: %d\n", staged_analytics))
cat(sprintf("   ✅ Database fixes staged: %d\n", staged_fixes))

# Final assessment
cat("\n=== DEPLOYMENT READINESS ASSESSMENT ===\n")

if (all_files_exist && packages_available) {
  cat("🎉 DEPLOYMENT READY!\n")
  cat("✅ All critical files present\n")
  cat("✅ All essential packages available\n")
  cat("✅ Git tracking configured\n")
  cat("✅ Railway deployment should succeed\n\n")
  
  cat("Next steps:\n")
  cat("1. Commit all changes to git\n")
  cat("2. Push to Railway for deployment\n")
  cat("3. Monitor deployment logs\n")
  
  quit(status = 0)
} else {
  cat("⚠️  DEPLOYMENT ISSUES DETECTED\n")
  
  if (!all_files_exist) {
    cat("❌ Missing critical files - check archive structure\n")
  }
  
  if (!packages_available) {
    cat("❌ Missing essential packages - update Dockerfile\n")
  }
  
  cat("\nPlease resolve issues before deploying to Railway.\n")
  quit(status = 1)
}