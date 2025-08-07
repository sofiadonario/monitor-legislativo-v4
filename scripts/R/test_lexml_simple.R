#!/usr/bin/env Rscript
# Simple test script for LexML integration using only base R
# Verifies that LexML data files exist and are accessible

cat("=== Simple LexML Integration Test ===\n")

# Test 1: Check if LexML data files exist
csv_path <- "data_current/processed/lexml_latest_results.csv"
metadata_path <- "data_current/processed/lexml_metadata.json"
statistics_path <- "data_current/processed/lexml_statistics.json"

cat("🔄 Checking LexML data files...\n")

if (file.exists(csv_path)) {
  cat("✅ LexML CSV file exists:", csv_path, "\n")
  # Get file size
  file_size <- file.size(csv_path)
  cat("📊 File size:", round(file_size / 1024 / 1024, 2), "MB\n")
} else {
  cat("❌ LexML CSV file not found:", csv_path, "\n")
}

if (file.exists(metadata_path)) {
  cat("✅ LexML metadata file exists:", metadata_path, "\n")
  file_size <- file.size(metadata_path)
  cat("📊 File size:", round(file_size / 1024, 2), "KB\n")
} else {
  cat("❌ LexML metadata file not found:", metadata_path, "\n")
}

if (file.exists(statistics_path)) {
  cat("✅ LexML statistics file exists:", statistics_path, "\n")
  file_size <- file.size(statistics_path)
  cat("📊 File size:", round(file_size / 1024, 2), "KB\n")
} else {
  cat("❌ LexML statistics file not found:", statistics_path, "\n")
}

# Test 2: Try to read CSV file with base R
cat("\n🔄 Testing CSV file reading...\n")
tryCatch({
  # Read first few lines to check structure
  csv_lines <- readLines(csv_path, n = 5)
  cat("✅ CSV file can be read\n")
  cat("📊 First line (header):", csv_lines[1], "\n")
  cat("📊 Number of columns:", length(strsplit(csv_lines[1], ",")[[1]]), "\n")
}, error = function(e) {
  cat("❌ Error reading CSV file:", e$message, "\n")
})

# Test 3: Try to read JSON files with base R
cat("\n🔄 Testing JSON file reading...\n")
tryCatch({
  # Read metadata JSON
  metadata_content <- readLines(metadata_path)
  cat("✅ Metadata JSON file can be read\n")
  cat("📊 File content length:", length(metadata_content), "lines\n")
  
  # Check if it contains expected fields
  content_text <- paste(metadata_content, collapse = "")
  if (grepl("total_documents", content_text)) {
    cat("✅ Metadata contains 'total_documents' field\n")
  }
  if (grepl("search_terms", content_text)) {
    cat("✅ Metadata contains 'search_terms' field\n")
  }
}, error = function(e) {
  cat("❌ Error reading JSON file:", e$message, "\n")
})

# Test 4: Check if R/lexml_data_loader.R exists
cat("\n🔄 Checking LexML data loader...\n")
loader_path <- "R/lexml_data_loader.R"
if (file.exists(loader_path)) {
  cat("✅ LexML data loader exists:", loader_path, "\n")
  file_size <- file.size(loader_path)
  cat("📊 File size:", round(file_size / 1024, 2), "KB\n")
} else {
  cat("❌ LexML data loader not found:", loader_path, "\n")
}

# Test 5: Check if the data files are accessible from the application
cat("\n🔄 Checking application integration...\n")
app_path <- "app.R"
if (file.exists(app_path)) {
  cat("✅ Main application file exists:", app_path, "\n")
  
  # Check if app.R references LexML
  app_content <- readLines(app_path)
  lexml_references <- sum(grepl("lexml", tolower(app_content)))
  cat("📊 LexML references in app.R:", lexml_references, "\n")
  
  if (lexml_references > 0) {
    cat("✅ Application has LexML integration\n")
  } else {
    cat("⚠️ No LexML references found in app.R\n")
  }
} else {
  cat("❌ Main application file not found:", app_path, "\n")
}

cat("\n=== Test Summary ===\n")
csv_exists <- file.exists(csv_path)
metadata_exists <- file.exists(metadata_path)
statistics_exists <- file.exists(statistics_path)
loader_exists <- file.exists(loader_path)
app_exists <- file.exists(app_path)

cat("CSV file:", ifelse(csv_exists, "✅", "❌"), "\n")
cat("Metadata file:", ifelse(metadata_exists, "✅", "❌"), "\n")
cat("Statistics file:", ifelse(statistics_exists, "✅", "❌"), "\n")
cat("Data loader:", ifelse(loader_exists, "✅", "❌"), "\n")
cat("Application file:", ifelse(app_exists, "✅", "❌"), "\n")

if (csv_exists && metadata_exists && statistics_exists && loader_exists && app_exists) {
  cat("✅ All LexML integration components are present!\n")
  cat("📊 LexML data is ready for application integration\n")
} else {
  cat("⚠️ Some LexML integration components are missing\n")
}

cat("=== Test Complete ===\n") 