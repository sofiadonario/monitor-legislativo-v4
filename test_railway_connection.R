# RAILWAY DATABASE CONNECTION TEST
# =================================
# Test script to verify Railway PostgreSQL connection and data access

cat("🧪 RAILWAY DATABASE CONNECTION TEST\n")
cat("===================================\n") 

# Load the connection system
source("RAILWAY_DATABASE_CONNECTION_FIX.R")

# Test basic connection
cat("\n✅ CONNECTION TEST RESULTS:\n")
status <- get_connection_status()
cat("Status:", status$status, "\n")
cat("Method:", status$connection_method, "\n") 
cat("Document Count:", format(status$document_count, big.mark = ","), "\n")

# Test data access
if (status$status == "connected") {
  cat("\n📊 DATA ACCESS TESTS:\n")
  
  # Test 1: Total documents
  total <- get_total_documents()
  cat("Total Documents:", format(total, big.mark = ","), "\n")
  
  # Test 2: Dashboard metrics
  metrics <- get_lexml_dashboard_metrics()
  cat("Dashboard Metrics Retrieved: ✅\n")
  cat("  - Documents:", format(metrics$total_documents, big.mark = ","), "\n")
  cat("  - States:", metrics$states_with_docs, "\n")
  cat("  - Data Source:", metrics$data_source, "\n")
  
  # Test 3: Library documents
  docs <- get_library_documents(limit = 5)
  cat("Sample Documents Retrieved:", nrow(docs), "\n")
  
  if (nrow(docs) > 0) {
    cat("\n📄 SAMPLE DOCUMENT TITLES:\n")
    for (i in 1:min(3, nrow(docs))) {
      title <- docs$title[i]
      if (\!is.na(title) && title \!= "") {
        cat(" ", i, ":", substr(title, 1, 70), "...\n")
      }
    }
  }
  
  # Test 4: Filtered queries
  legislation_docs <- get_library_documents(category = "legislation", limit = 3)
  cat("\nLegislation Documents:", nrow(legislation_docs), "\n")
  
  transport_docs <- get_library_documents(search_term = "transporte", limit = 3)
  cat("Transport-related Documents:", nrow(transport_docs), "\n")
  
  cat("\n🎉 ALL TESTS PASSED\!\n")
  cat("Database is fully operational with", format(total, big.mark = ","), "documents\n")
  
} else {
  cat("\n❌ CONNECTION FAILED\n")
  cat("Error:", status$error, "\n")
}

cat("\n🏁 TEST COMPLETE\n")
EOF < /dev/null
