#!/usr/bin/env Rscript
# Test Database Connection Script
# ================================

cat("🧪 Testing Railway Database Connection...\n")
cat("=====================================\n\n")

# Load the database connection module
tryCatch({
  source("RAILWAY_PRODUCTION_DB_FIX.R")
  cat("✅ Database module loaded successfully\n\n")
}, error = function(e) {
  cat("❌ Failed to load database module:", e$message, "\n")
  quit(status = 1)
})

# Test 1: Check connection status
cat("📋 Test 1: Connection Status\n")
status <- get_connection_status()
cat("  - Status:", status$status, "\n")
cat("  - Method:", status$connection_method, "\n")
cat("  - Document Count:", format(status$document_count, big.mark = ","), "\n")
cat("  - Last Check:", as.character(status$last_check), "\n")
if (!is.null(status$error)) {
  cat("  - Error:", status$error, "\n")
}
cat("\n")

# Test 2: Get total documents
cat("📋 Test 2: Total Documents\n")
total <- get_total_documents()
cat("  - Total documents in database:", format(total, big.mark = ","), "\n\n")

# Test 3: Fetch sample documents
cat("📋 Test 3: Fetch Sample Documents\n")
docs <- get_library_documents(limit = 5)
cat("  - Documents retrieved:", nrow(docs), "\n")
if (nrow(docs) > 0) {
  cat("  - Columns:", paste(names(docs), collapse = ", "), "\n")
  cat("  - First document title:", substr(docs$title[1], 1, 50), "...\n")
}
cat("\n")

# Test 4: Test with filters
cat("📋 Test 4: Test Filters\n")

# Test category filter
cat("  a) Testing category filter (Legislation)...\n")
legislation_docs <- get_library_documents(category = "Legislation", limit = 3)
cat("     - Legislation documents found:", nrow(legislation_docs), "\n")

# Test state filter
cat("  b) Testing state filter (SP)...\n")
sp_docs <- get_library_documents(state = "SP", limit = 3)
cat("     - SP documents found:", nrow(sp_docs), "\n")

# Test search filter
cat("  c) Testing search filter ('lei')...\n")
search_docs <- get_library_documents(search_term = "lei", limit = 3)
cat("     - Documents with 'lei' found:", nrow(search_docs), "\n")
cat("\n")

# Test 5: Connection recovery
cat("📋 Test 5: Connection Recovery\n")
cat("  - Simulating connection loss...\n")
if (!is.null(.railway_connection_state$connection)) {
  tryCatch({
    dbDisconnect(.railway_connection_state$connection)
    .railway_connection_state$connection <<- NULL
    .railway_connection_state$status <<- "disconnected"
    cat("  - Connection closed\n")
  }, error = function(e) {
    cat("  - Error closing connection:", e$message, "\n")
  })
  
  cat("  - Testing automatic reconnection...\n")
  recovery_docs <- get_library_documents(limit = 1)
  if (nrow(recovery_docs) > 0) {
    cat("  ✅ Connection recovered successfully!\n")
  } else {
    cat("  ❌ Connection recovery failed\n")
  }
} else {
  cat("  - No active connection to test recovery\n")
}
cat("\n")

# Summary
cat("📊 Test Summary\n")
cat("=====================================\n")
final_status <- get_connection_status()
if (final_status$status == "connected") {
  cat("✅ Database connection is working properly!\n")
  cat("   - Method:", final_status$connection_method, "\n")
  cat("   - Documents available:", format(final_status$document_count, big.mark = ","), "\n")
} else {
  cat("❌ Database connection issues detected\n")
  cat("   - Status:", final_status$status, "\n")
  if (!is.null(final_status$error)) {
    cat("   - Error:", final_status$error, "\n")
  }
  cat("\n⚠️  The application will use fallback data sources\n")
}

cat("\n🏁 Test completed\n")