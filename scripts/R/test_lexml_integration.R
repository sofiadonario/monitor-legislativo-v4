#!/usr/bin/env Rscript
# Test script for LexML integration
# Verifies that LexML data is properly loaded and accessible

cat("=== LexML Integration Test ===\n")

# Load required libraries
library(dplyr)
library(readr)
library(jsonlite)

# Source the LexML data loader
source("R/lexml_data_loader.R")

cat("🔄 Testing LexML data loading...\n")

# Test 1: Load LexML data
lexml_data <- load_lexml_data()
if (!is.null(lexml_data)) {
  cat("✅ LexML data loaded successfully\n")
  cat("📊 Number of documents:", nrow(lexml_data), "\n")
  cat("📊 Document types:", paste(unique(lexml_data$tipo), collapse = ", "), "\n")
  cat("📊 Transport categories:", paste(unique(lexml_data$transport_category), collapse = ", "), "\n")
} else {
  cat("❌ Failed to load LexML data\n")
}

# Test 2: Load metadata
lexml_meta <- load_lexml_metadata()
if (!is.null(lexml_meta)) {
  cat("✅ LexML metadata loaded successfully\n")
  if (!is.null(lexml_meta$statistics)) {
    cat("📊 Total documents:", lexml_meta$statistics$collection_info$total_documents, "\n")
    cat("📊 Search terms:", lexml_meta$statistics$collection_info$unique_search_terms, "\n")
  }
} else {
  cat("❌ Failed to load LexML metadata\n")
}

# Test 3: Enhanced analytics
analytics <- get_enhanced_lexml_analytics()
if (!is.null(analytics)) {
  cat("✅ Enhanced analytics generated successfully\n")
  cat("📊 Total documents:", analytics$total_documents, "\n")
  cat("📊 Unique search terms:", analytics$unique_search_terms, "\n")
  cat("📊 Date range:", paste(analytics$date_range, collapse = " to "), "\n")
} else {
  cat("❌ Failed to generate enhanced analytics\n")
}

# Test 4: Quality metrics
quality_metrics <- get_lexml_quality_metrics()
if (!is.null(quality_metrics)) {
  cat("✅ Quality metrics calculated successfully\n")
  cat("📊 Quality score:", round(quality_metrics$quality_score * 100, 1), "%\n")
  cat("📊 Quality grade:", quality_metrics$quality_grade, "\n")
  cat("📊 Completeness:", round(quality_metrics$completeness$overall_completeness * 100, 1), "%\n")
  cat("📊 Relevance:", round(quality_metrics$relevance$transport_related * 100, 1), "%\n")
} else {
  cat("❌ Failed to calculate quality metrics\n")
}

# Test 5: Subject categories
subject_categories <- get_lexml_subject_categories()
if (!is.null(subject_categories)) {
  cat("✅ Subject categories loaded successfully\n")
  cat("📊 Number of categories:", nrow(subject_categories), "\n")
  cat("📊 Top categories:", paste(head(subject_categories$category, 3), collapse = ", "), "\n")
} else {
  cat("❌ Failed to load subject categories\n")
}

# Test 6: Regulatory agencies
agencies <- get_lexml_regulatory_agencies()
if (!is.null(agencies)) {
  cat("✅ Regulatory agencies loaded successfully\n")
  cat("📊 Number of agencies:", length(agencies), "\n")
  cat("📊 Agencies:", paste(agencies, collapse = ", "), "\n")
} else {
  cat("❌ Failed to load regulatory agencies\n")
}

# Test 7: Search effectiveness
search_effectiveness <- get_lexml_search_effectiveness()
if (!is.null(search_effectiveness)) {
  cat("✅ Search effectiveness calculated successfully\n")
  cat("📊 Number of search terms:", nrow(search_effectiveness), "\n")
  cat("📊 Top search terms:", paste(head(search_effectiveness$search_term, 3), collapse = ", "), "\n")
} else {
  cat("❌ Failed to calculate search effectiveness\n")
}

cat("\n=== Test Summary ===\n")
cat("LexML data available:", !is.null(lexml_data), "\n")
cat("Metadata available:", !is.null(lexml_meta), "\n")
cat("Analytics available:", !is.null(analytics), "\n")
cat("Quality metrics available:", !is.null(quality_metrics), "\n")

if (!isTRUE(is.null(lexml_data)) && !isTRUE(is.null(lexml_meta)) && !isTRUE(is.null(analytics)) && !is.null(quality_metrics)) {
  cat("✅ All LexML integration tests passed!\n")
} else {
  cat("⚠️ Some LexML integration tests failed\n")
}

cat("=== Test Complete ===\n") 