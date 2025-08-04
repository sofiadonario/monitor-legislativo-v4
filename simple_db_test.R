#!/usr/bin/env Rscript
# Simple database connection test without external dependencies

cat("🔍 SIMPLE DATABASE CONNECTION TEST\n")
cat("==================================\n")

# Check if we can at least test the connection logic
tryCatch({
  # Try to source the railway connection file
  source("RAILWAY_PRODUCTION_DB_FIX.R")
  
  cat("✅ Railway connection file loaded\n")
  
  # Check connection status
  if(exists("get_connection_status")) {
    status <- get_connection_status()
    cat("📊 Connection Status:", status$status, "\n")
    cat("🔌 Connection Method:", status$connection_method, "\n")
    cat("📄 Document Count:", format(status$document_count, big.mark = ","), "\n")
    cat("💬 Message:", status$message, "\n")
    
    if(status$status != "connected") {
      cat("🚨 DATABASE IS NOT CONNECTED - This explains why only 5 documents show!\n")
    }
  }
  
  # Test library function
  if(exists("get_library_documents")) {
    cat("\n📚 Testing library function...\n")
    docs <- get_library_documents(limit = 10)
    cat("📊 Library function returned:", nrow(docs), "documents\n")
    
    if(nrow(docs) == 5) {
      cat("🚨 CONFIRMED: Only 5 documents returned (fallback mode)\n")
    }
  }
  
}, error = function(e) {
  cat("❌ Error loading railway connection:", e$message, "\n")
})

cat("\n✅ Test complete\n")