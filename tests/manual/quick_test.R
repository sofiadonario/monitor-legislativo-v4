#!/usr/bin/env Rscript

# Quick test to verify the fixes

cat("==================================================\n")
cat("Quick Test - Monitor Legislativo v4\n")
cat("==================================================\n\n")

# Load environment variables
readRenviron(".Renviron")

# Test 1: Check database configuration
cat("1. Database Configuration:\n")
cat("   PGHOST:", Sys.getenv("PGHOST"), "\n")
cat("   PGDATABASE:", Sys.getenv("PGDATABASE"), "\n\n")

# Test 2: Check for GeoJSON file
cat("2. Geographic Data:\n")
if (file.exists("data/brazil_states.geojson")) {
  size_mb <- round(file.info("data/brazil_states.geojson")$size / 1024 / 1024, 2)
  cat("   ✅ brazil_states.geojson found (", size_mb, "MB)\n\n", sep = "")
} else {
  cat("   ❌ brazil_states.geojson not found\n")
  cat("   Run: source('download_geo_data.R')\n\n")
}

# Test 3: Try to run the app
cat("3. Starting Application:\n")
cat("   If everything is configured correctly, the app should start.\n")
cat("   Check the console for status messages.\n\n")

answer <- readline("Start the application now? (y/n): ")
if (tolower(answer) == "y") {
  source("app_phoenix.R")
} else {
  cat("\nTo start manually, run:\n")
  cat("  source('app_phoenix.R')\n")
}

cat("\n==================================================\n")
