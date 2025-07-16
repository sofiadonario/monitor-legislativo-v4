#!/usr/bin/env Rscript

# Test script to check LexML data loading
library(dplyr)
library(readr)

# Source the LexML loader
source("R/lexml_data_loader.R")

cat("Testing LexML data loader...\n")

# Test loading data
cat("1. Loading LexML data...\n")
data <- load_lexml_data()

if (!is.null(data)) {
  cat("✅ LexML data loaded successfully!\n")
  cat("📊 Number of documents:", nrow(data), "\n")
  cat("📊 Number of columns:", ncol(data), "\n")
  cat("📊 Column names:", paste(names(data), collapse = ", "), "\n")
  
  # Check for required columns
  required_cols <- c("titulo", "tipo", "estado", "data_publicacao", "urn", "search_term")
  missing_cols <- setdiff(required_cols, names(data))
  if (length(missing_cols) > 0) {
    cat("⚠️ Missing required columns:", paste(missing_cols, collapse = ", "), "\n")
  } else {
    cat("✅ All required columns present\n")
  }
  
  # Show sample data
  cat("\n📋 Sample data (first 3 rows):\n")
  print(head(data, 3))
  
} else {
  cat("❌ Failed to load LexML data\n")
}

# Test loading metadata
cat("\n2. Loading LexML metadata...\n")
metadata <- load_lexml_metadata()

if (!is.null(metadata)) {
  cat("✅ LexML metadata loaded successfully!\n")
  cat("📊 Metadata keys:", paste(names(metadata), collapse = ", "), "\n")
} else {
  cat("❌ Failed to load LexML metadata\n")
}

cat("\nTest completed.\n")