#!/usr/bin/env Rscript

# Simple test to check if we can read the CSV without complex dependencies
cat("Testing basic CSV reading...\n")

csv_path <- "data_current/processed/lexml_latest_results.csv"

if (file.exists(csv_path)) {
  cat("✅ CSV file exists at:", csv_path, "\n")
  
  # Try to read with base R
  tryCatch({
    data <- read.csv(csv_path, stringsAsFactors = FALSE)
    cat("✅ CSV loaded successfully with base R!\n")
    cat("📊 Number of rows:", nrow(data), "\n")
    cat("📊 Number of columns:", ncol(data), "\n")
    cat("📊 Column names:", paste(names(data), collapse = ", "), "\n")
    
    # Check for key columns
    if ("title" %in% names(data)) {
      cat("✅ 'title' column found\n")
    } else {
      cat("❌ 'title' column missing\n")
    }
    
    if ("urn" %in% names(data)) {
      cat("✅ 'urn' column found\n")
    } else {
      cat("❌ 'urn' column missing\n")
    }
    
    cat("\n📋 First row:\n")
    print(data[1,])
    
  }, error = function(e) {
    cat("❌ Error reading CSV:", e$message, "\n")
  })
  
} else {
  cat("❌ CSV file does not exist at:", csv_path, "\n")
}

cat("\nTest completed.\n")