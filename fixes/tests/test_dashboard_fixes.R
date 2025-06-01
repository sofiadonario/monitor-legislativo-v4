#!/usr/bin/env Rscript
# Test script to verify dashboard fixes are working properly

cat("=== TESTING DASHBOARD FIXES ===\n\n")

# Source required files
cat("1. Loading database connection...\n")
tryCatch({
  source("database.R")
  database_connected <<- init_database()
  cat("✓ Database connection status:", database_connected, "\n")
}, error = function(e) {
  cat("✗ Error loading database:", e$message, "\n")
  database_connected <<- FALSE
})

cat("\n2. Loading missing functions...\n")
tryCatch({
  source("missing_functions.R")
  cat("✓ Missing functions loaded successfully\n")
}, error = function(e) {
  cat("✗ Error loading missing functions:", e$message, "\n")
})

cat("\n3. Testing get_lexml_dashboard_metrics()...\n")
tryCatch({
  metrics <- get_lexml_dashboard_metrics()
  cat("✓ Total documents:", metrics$total_documents, "\n")
  cat("✓ States percentage:", metrics$states_percentage, "%\n")
  cat("✓ Municipalities percentage:", metrics$municipalities_percentage, "%\n")
  cat("✓ Date range years:", metrics$date_range_years, "\n")
}, error = function(e) {
  cat("✗ Error testing dashboard metrics:", e$message, "\n")
})

cat("\n4. Testing get_search_analytics()...\n")
tryCatch({
  analytics <- get_search_analytics()
  cat("✓ Total documents:", analytics$total_documents, "\n")
  cat("✓ Years available:", nrow(analytics$documents_by_year), "\n")
  cat("✓ States with documents:", nrow(analytics$documents_by_state), "\n")
  cat("✓ Document types:", nrow(analytics$documents_by_type), "\n")
}, error = function(e) {
  cat("✗ Error testing search analytics:", e$message, "\n")
})

cat("\n5. Testing get_database_stats()...\n")
tryCatch({
  stats <- get_database_stats()
  cat("✓ Total documents:", stats$total_documents, "\n")
  cat("✓ Years in database:", nrow(stats$documents_by_year), "\n")
  cat("✓ States in database:", nrow(stats$documents_by_state), "\n")
}, error = function(e) {
  cat("✗ Error testing database stats:", e$message, "\n")
})

cat("\n=== DASHBOARD FIXES TEST COMPLETE ===\n")