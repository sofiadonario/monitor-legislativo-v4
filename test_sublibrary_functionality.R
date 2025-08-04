# ============================================================================
# TEST SUBLIBRARY FUNCTIONALITY
# ============================================================================
# This script tests the sublibrary filtering functionality to ensure all 3 
# sublibraries work correctly after the category mapping fix

cat("🧪 TESTING SUBLIBRARY FUNCTIONALITY\n")
cat("===================================\n")

# Load the database connection functions
tryCatch({
  source("RAILWAY_PRODUCTION_DB_FIX.R")
  cat("✅ Database connection module loaded\n")
}, error = function(e) {
  cat("❌ Error loading database module:", e$message, "\n")
  stop("Cannot proceed without database functions")
})

# Test function to check sublibrary document counts
test_sublibrary <- function(category_name) {
  cat(sprintf("\n🔍 TESTING %s SUBLIBRARY\n", toupper(category_name)))
  cat(paste(rep("=", 30 + nchar(category_name)), collapse = ""), "\n")
  
  tryCatch({
    # Get documents for this category
    docs <- get_library_documents(category = category_name, limit = 1000)
    
    cat(sprintf("📊 Documents found: %s\n", nrow(docs)))
    
    if (nrow(docs) > 0) {
      cat("✅ SUCCESS: Sublibrary has documents\n")
      
      # Show column names
      cat("📋 Columns:", paste(names(docs), collapse = ", "), "\n")
      
      # Show sample document titles
      cat("📄 Sample documents:\n")
      for (i in 1:min(3, nrow(docs))) {
        title <- substr(docs$title[i], 1, 80)
        category <- if ("category" %in% names(docs)) docs$category[i] else "N/A"
        cat(sprintf("  %d. [%s] %s\n", i, category, title))
      }
      
      # Check category distribution in results
      if ("category" %in% names(docs)) {
        cat("📊 Category breakdown:\n")
        category_counts <- table(docs$category, useNA = "ifany")
        for (j in 1:length(category_counts)) {
          cat(sprintf("  - %-15s: %s docs\n", names(category_counts)[j], category_counts[j]))
        }
      }
      
      return(TRUE)
    } else {
      cat("❌ ERROR: Sublibrary is empty!\n")
      return(FALSE)
    }
    
  }, error = function(e) {
    cat(sprintf("❌ ERROR: %s\n", e$message))
    return(FALSE)
  })
}

# Test all 3 sublibraries
cat("🚀 Starting sublibrary functionality tests...\n")

test_results <- list()
sublibraries <- c("legislation", "jurisprudence", "doctrine")

for (sublibrary in sublibraries) {
  test_results[[sublibrary]] <- test_sublibrary(sublibrary)
}

# Summary
cat("\n📈 TEST SUMMARY\n")
cat("===============\n")

all_passed <- TRUE
for (sublibrary in sublibraries) {
  status <- if (test_results[[sublibrary]]) "✅ PASS" else "❌ FAIL"
  cat(sprintf("%-15s: %s\n", toupper(sublibrary), status))
  if (!test_results[[sublibrary]]) all_passed <- FALSE
}

cat(sprintf("\n🎯 OVERALL RESULT: %s\n", if (all_passed) "✅ ALL TESTS PASSED" else "❌ SOME TESTS FAILED"))

if (all_passed) {
  cat("🎉 SUCCESS: All 3 sublibraries are working correctly!\n")
  cat("📚 Users can now browse documents in:\n")
  cat("   - Legislation (laws, bills, regulations)\n")
  cat("   - Jurisprudence (court decisions, case law)\n") 
  cat("   - Doctrine (academic works, legal opinions)\n")
} else {
  cat("🚨 ISSUE: Some sublibraries are not working correctly\n")
  cat("🔧 Check the category mapping logic and database connection\n")
}

cat("\n🔗 Next step: Test the web interface at the Railway deployment URL\n")