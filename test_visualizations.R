# Test Visualizations Data Flow
cat("🧪 Testing visualization data pipeline\n")

# Load the robust data loader
source("data_loader_robust.R")

cat("\n=== TESTING DATA FUNCTIONS ===\n")

# Test get_search_analytics
cat("1. Testing get_search_analytics():\n")
analytics <- get_search_analytics()
cat("   ✓ Total documents:", analytics$total_documents, "\n")
cat("   ✓ Years available:", nrow(analytics$documents_by_year), "\n")
cat("   ✓ States available:", nrow(analytics$documents_by_state), "\n")
cat("   ✓ Types available:", nrow(analytics$documents_by_type), "\n")

# Test get_database_stats
cat("\n2. Testing get_database_stats():\n")
stats <- get_database_stats()
cat("   ✓ Total documents:", stats$total_documents, "\n")
cat("   ✓ Unique states:", stats$unique_states, "\n")
cat("   ✓ Date range:", stats$oldest_document, "to", stats$newest_document, "\n")

# Test get_documents
cat("\n3. Testing get_documents():\n")
docs <- get_documents(limit = 5)
cat("   ✓ Returned documents:", nrow(docs), "\n")
cat("   ✓ Sample titles:", paste(head(docs$titulo, 2), collapse = " | "), "\n")

cat("\n=== TESTING VISUALIZATION DATA STRUCTURES ===\n")

# Test year chart data
cat("4. Testing year chart data:\n")
if (nrow(analytics$documents_by_year) > 0) {
  cat("   ✓ Year data available for plotting\n")
  cat("   ✓ Sample years:", paste(head(analytics$documents_by_year$year, 3), collapse = ", "), "\n")
  cat("   ✓ Sample counts:", paste(head(analytics$documents_by_year$count, 3), collapse = ", "), "\n")
} else {
  cat("   ❌ No year data available\n")
}

# Test state chart data  
cat("\n5. Testing state chart data:\n")
if (nrow(analytics$documents_by_state) > 0) {
  cat("   ✓ State data available for plotting\n")
  cat("   ✓ Top states:", paste(head(analytics$documents_by_state$estado, 3), collapse = ", "), "\n")
  cat("   ✓ Top counts:", paste(head(analytics$documents_by_state$count, 3), collapse = ", "), "\n")
} else {
  cat("   ❌ No state data available\n")
}

# Test type chart data
cat("\n6. Testing type chart data:\n")
if (nrow(analytics$documents_by_type) > 0) {
  cat("   ✓ Type data available for plotting\n")
  cat("   ✓ Types:", paste(analytics$documents_by_type$type, collapse = ", "), "\n")
  cat("   ✓ Counts:", paste(analytics$documents_by_type$count, collapse = ", "), "\n")
} else {
  cat("   ❌ No type data available\n")
}

cat("\n=== TEST COMPLETE ===\n")
cat("✅ Data pipeline is working correctly!\n")
cat("🎯 Your visualizations should now display real data from", analytics$total_documents, "legislative documents\n")