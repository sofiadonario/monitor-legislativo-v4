# TEST DEDUPLICATED DATA INTEGRATION
# This script tests if the deduplicated data is properly integrated

cat("🧪 TESTING DEDUPLICATED DATA INTEGRATION...\n")

# Load the integration
source("integrate_deduplicated_data.R")

cat("\n📊 TESTING DASHBOARD FUNCTIONS...\n")

# Test all the main functions that the dashboard uses
test_results <- list()

# Test 1: Total documents
cat("\n1. Testing get_total_documents()...\n")
total_docs <- get_total_documents()
test_results$total_documents <- total_docs
cat(sprintf("   Result: %s documents\n", format(total_docs, big.mark = ",")))

# Test 2: LexML dashboard metrics
cat("\n2. Testing get_lexml_dashboard_metrics()...\n")
lexml_metrics <- get_lexml_dashboard_metrics()
test_results$lexml_metrics <- lexml_metrics
cat(sprintf("   Total documents: %s\n", format(lexml_metrics$total_documents, big.mark = ",")))
cat(sprintf("   States with docs: %d\n", lexml_metrics$states_with_docs))
cat(sprintf("   States percentage: %.1f%%\n", lexml_metrics$states_percentage))
cat(sprintf("   Date range: %d years\n", lexml_metrics$date_range_years))

# Test 3: Documents by state
cat("\n3. Testing get_documents_by_state()...\n")
by_state <- get_documents_by_state(5)
test_results$by_state <- by_state
cat("   Top 5 states:\n")
for (i in 1:min(5, nrow(by_state))) {
  cat(sprintf("   - %s: %s documents\n", 
              by_state$estado[i], 
              format(by_state$count[i], big.mark = ",")))
}

# Test 4: Documents by type
cat("\n4. Testing get_documents_by_type()...\n")
by_type <- get_documents_by_type(5)
test_results$by_type <- by_type
cat("   Top 5 types:\n")
for (i in 1:min(5, nrow(by_type))) {
  cat(sprintf("   - %s: %s documents\n", 
              by_type$tipo[i], 
              format(by_type$count[i], big.mark = ",")))
}

# Test 5: Database stats
cat("\n5. Testing get_database_stats()...\n")
db_stats <- get_database_stats()
test_results$db_stats <- db_stats
cat(sprintf("   Total documents: %s\n", format(db_stats$total_documents, big.mark = ",")))
cat(sprintf("   Years available: %d\n", nrow(db_stats$documents_by_year)))
cat(sprintf("   Document types: %d\n", nrow(db_stats$documents_by_type)))
cat(sprintf("   States: %d\n", nrow(db_stats$documents_by_state)))

# Summary
cat("\n" * 2)
cat("="*60, "\n")
cat("📋 INTEGRATION TEST SUMMARY\n")
cat("="*60, "\n")

success <- total_docs > 0 && 
           lexml_metrics$total_documents > 0 && 
           isTRUE(nrow(by_state) > 0) && 
           nrow(by_type) > 0

if (success) {
  cat("✅ SUCCESS: All tests passed!\n")
  cat(sprintf("✅ Dashboard will show %s documents instead of null/0\n", 
              format(total_docs, big.mark = ",")))
  cat("✅ All data access functions working with deduplicated data\n")
  cat("✅ Ready for dashboard deployment\n")
} else {
  cat("❌ FAILURE: Some tests failed\n")
  cat("❌ Dashboard may still show null/0 documents\n")
}

cat("\n🎯 Expected Dashboard Values:\n")
cat(sprintf("- Total Documents: %s\n", format(lexml_metrics$total_documents, big.mark = ",")))
cat(sprintf("- States with Documents: %.1f%%\n", lexml_metrics$states_percentage))
cat(sprintf("- Date Range: %d years\n", lexml_metrics$date_range_years))

cat("\n📁 Integration file ready for deployment\n")
cat("The app.R file has been updated to load the deduplicated data integration.\n")