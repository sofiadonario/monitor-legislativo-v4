# ============================================================================
# TEST CATEGORY MAPPING LOGIC
# ============================================================================
# This script tests the corrected category mapping logic using local CSV data

cat("🧪 TESTING CORRECTED CATEGORY MAPPING LOGIC\n")
cat("===========================================\n")

# Check if CSV file exists
csv_path <- "data_current/processed/production/lexml_enhanced_simple.csv"

if (!file.exists(csv_path)) {
  cat("❌ CSV file not found:", csv_path, "\n")
  cat("Available files in data_current/processed/production/:\n")
  list.files("data_current/processed/production/", full.names = TRUE)
  stop("Cannot test without data file")
}

cat("✅ Loading data from:", csv_path, "\n")

# Read the CSV file
tryCatch({
  data <- read.csv(csv_path, stringsAsFactors = FALSE, nrows = 10000)  # Test with sample
  cat("📊 Loaded", nrow(data), "documents for testing\n")
  
  # Check column names
  cat("📋 Columns available:", paste(names(data), collapse = ", "), "\n")
  
  # Check if categoria column exists
  if ("categoria" %in% names(data)) {
    cat("\n🔍 CATEGORY ANALYSIS\n")
    cat("===================\n")
    
    # Get unique category values
    unique_categories <- table(data$categoria, useNA = "ifany")
    cat("📊 Unique categories found:\n")
    for (i in 1:length(unique_categories)) {
      cat(sprintf("  - %-20s: %s documents\n", names(unique_categories)[i], unique_categories[i]))
    }
    
    # Test the corrected mapping
    cat("\n🧪 TESTING CORRECTED MAPPING\n")
    cat("============================\n")
    
    category_mapping <- list(
      "legislation" = c("Legislação", "Proposições"),
      "jurisprudence" = c("Jurisprudência"),
      "doctrine" = c("Doutrina", "Outros")
    )
    
    for (sublibrary in names(category_mapping)) {
      target_categories <- category_mapping[[sublibrary]]
      filtered_data <- data[data$categoria %in% target_categories, ]
      cat(sprintf("📚 %s: %s documents (from categories: %s)\n", 
                 toupper(sublibrary), 
                 nrow(filtered_data),
                 paste(target_categories, collapse = ", ")))
      
      if (nrow(filtered_data) > 0) {
        cat(sprintf("   ✅ SUCCESS: %s sublibrary has documents\n", sublibrary))
      } else {
        cat(sprintf("   ❌ ERROR: %s sublibrary is empty!\n", sublibrary))
      }
    }
    
    # Calculate total mapped documents
    total_mapped <- 0
    for (sublibrary in names(category_mapping)) {
      target_categories <- category_mapping[[sublibrary]]
      filtered_data <- data[data$categoria %in% target_categories, ]
      total_mapped <- total_mapped + nrow(filtered_data)
    }
    
    cat(sprintf("\n📈 SUMMARY\n"))
    cat(sprintf("==========\n"))
    cat(sprintf("Total documents in sample: %s\n", nrow(data)))
    cat(sprintf("Total mapped documents: %s\n", total_mapped))
    cat(sprintf("Mapping coverage: %.1f%%\n", (total_mapped / nrow(data)) * 100))
    
    if (total_mapped > 0) {
      cat("✅ SUCCESS: Category mapping is working!\n")
      cat("🎯 All 3 sublibraries should now show documents\n")
    } else {
      cat("❌ ERROR: Category mapping failed - no documents mapped\n")
    }
    
  } else {
    cat("❌ ERROR: 'categoria' column not found in data\n")
    cat("Available columns:", paste(names(data), collapse = ", "), "\n")
  }
  
}, error = function(e) {
  cat("❌ Error loading CSV:", e$message, "\n")
})

cat("\n🎯 NEXT STEPS\n")
cat("=============\n")
cat("1. If test shows SUCCESS, the category mapping is fixed\n")
cat("2. Deploy the updated app.R and RAILWAY_PRODUCTION_DB_FIX.R\n")
cat("3. Test all 3 sublibraries in the web interface\n")
cat("4. Verify document counts match expected values\n")