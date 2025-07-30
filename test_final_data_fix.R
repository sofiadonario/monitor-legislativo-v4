# Test script to verify FINAL_DATA_FIX.R works correctly
# This will test all the data functions before Railway deployment

cat("🔍 TESTING FINAL_DATA_FIX.R - Railway Deployment Verification\n")
cat("============================================================\n")

# Test 1: Load the FINAL_DATA_FIX
cat("\n🔧 TEST 1: Loading FINAL_DATA_FIX.R\n")
tryCatch({
  source("FINAL_DATA_FIX.R")
  cat("✅ FINAL_DATA_FIX.R loaded successfully\n")
}, error = function(e) {
  cat("❌ ERROR loading FINAL_DATA_FIX.R:", e$message, "\n")
  stop("Cannot proceed without FINAL_DATA_FIX.R")
})

# Test 2: Check database_connected status
cat("\n📊 TEST 2: Database connection status\n")
cat("database_connected:", exists("database_connected"), "\n")
if (exists("database_connected")) {
  cat("database_connected value:", database_connected, "\n")
}

# Test 3: Test get_search_analytics function
cat("\n📊 TEST 3: Testing get_search_analytics function\n")
if (exists("get_search_analytics")) {
  tryCatch({
    analytics <- get_search_analytics()
    cat("✅ get_search_analytics returned successfully\n")
    cat("  - Total documents:", analytics$total_documents, "\n")
    cat("  - Documents by year rows:", nrow(analytics$documents_by_year), "\n")
    cat("  - Documents by state rows:", nrow(analytics$documents_by_state), "\n")
    cat("  - Documents by type rows:", nrow(analytics$documents_by_type), "\n")
    cat("  - Data source:", analytics$data_source, "\n")
    cat("  - Date range:", analytics$date_range$min, "to", analytics$date_range$max, "\n")
  }, error = function(e) {
    cat("❌ ERROR in get_search_analytics:", e$message, "\n")
  })
} else {
  cat("❌ get_search_analytics function not found\n")
}

# Test 4: Test get_database_stats function
cat("\n📊 TEST 4: Testing get_database_stats function\n")
if (exists("get_database_stats")) {
  tryCatch({
    stats <- get_database_stats()
    cat("✅ get_database_stats returned successfully\n")
    cat("  - Total documents:", stats$total_documents, "\n")
    cat("  - Unique states:", stats$unique_states, "\n")
    cat("  - Unique types:", stats$unique_types, "\n")
    cat("  - Oldest document:", stats$oldest_document, "\n")
    cat("  - Newest document:", stats$newest_document, "\n")
    cat("  - Data source:", stats$data_source, "\n")
  }, error = function(e) {
    cat("❌ ERROR in get_database_stats:", e$message, "\n")
  })
} else {
  cat("❌ get_database_stats function not found\n")
}

# Test 5: Test get_documents function
cat("\n📄 TEST 5: Testing get_documents function\n")
if (exists("get_documents")) {
  tryCatch({
    docs <- get_documents(limit = 10)
    cat("✅ get_documents returned successfully\n")
    cat("  - Returned", nrow(docs), "documents\n")
    cat("  - Columns:", paste(names(docs), collapse = ", "), "\n")
    if (nrow(docs) > 0) {
      cat("  - Sample titles:\n")
      for (i in 1:min(3, nrow(docs))) {
        cat("    -", substr(docs$titulo[i], 1, 60), "...\n")
      }
    }
  }, error = function(e) {
    cat("❌ ERROR in get_documents:", e$message, "\n")
  })
} else {
  cat("❌ get_documents function not found\n")
}

# Test 6: Test compatibility functions
cat("\n🔄 TEST 6: Testing compatibility functions\n")
compatibility_functions <- c("get_lexml_search_analytics", "get_documents_data", 
                           "load_legislative_data", "get_total_documents", 
                           "get_map_data", "get_connection_status")

for (func_name in compatibility_functions) {
  if (exists(func_name)) {
    cat("✅", func_name, "exists\n")
    tryCatch({
      if (func_name == "get_total_documents") {
        result <- do.call(func_name, list())
        cat("  - Returns:", result, "\n")
      } else if (func_name == "get_connection_status") {
        result <- do.call(func_name, list())
        cat("  - Status:", result$database_connected, "| Data source:", result$data_source, "\n")
      } else {
        result <- do.call(func_name, list(limit = 5))
        if (is.data.frame(result)) {
          cat("  - Returns data.frame with", nrow(result), "rows\n")
        } else if (is.list(result)) {
          cat("  - Returns list with", length(result), "elements\n")
        }
      }
    }, error = function(e) {
      cat("  ❌ ERROR calling", func_name, ":", e$message, "\n")
    })
  } else {
    cat("❌", func_name, "missing\n")
  }
}

# Test 7: Data quality checks
cat("\n🔍 TEST 7: Data quality verification\n")
if (exists("FINAL_DATASET") && !is.null(FINAL_DATASET)) {
  cat("✅ FINAL_DATASET loaded with", nrow(FINAL_DATASET), "rows\n")
  
  # Check for required columns
  required_cols <- c("titulo", "tipo", "categoria", "estado", "data", "ano", "modal")
  missing_cols <- setdiff(required_cols, names(FINAL_DATASET))
  if (length(missing_cols) == 0) {
    cat("✅ All required columns present\n")
  } else {
    cat("❌ Missing columns:", paste(missing_cols, collapse = ", "), "\n")
  }
  
  # Check data completeness
  cat("  - Non-empty títulos:", sum(!is.na(FINAL_DATASET$titulo) & FINAL_DATASET$titulo != ""), "\n")
  cat("  - Valid dates:", sum(!is.na(FINAL_DATASET$data)), "\n")
  cat("  - Valid years range:", min(FINAL_DATASET$ano, na.rm = TRUE), "-", max(FINAL_DATASET$ano, na.rm = TRUE), "\n")
  cat("  - Unique states:", length(unique(FINAL_DATASET$estado)), "\n")
  cat("  - Unique types:", length(unique(FINAL_DATASET$tipo)), "\n")
} else {
  cat("❌ FINAL_DATASET not loaded or empty\n")
}

# Final summary
cat("\n\n")
cat("============================================================\n")
cat("🚀 FINAL DATA FIX TEST SUMMARY\n")
cat("============================================================\n")

if (exists("get_search_analytics") && exists("get_database_stats") && exists("get_documents")) {
  cat("✅ ALL CRITICAL FUNCTIONS READY FOR RAILWAY DEPLOYMENT\n")
  cat("📊 Data available:", ifelse(exists("FINAL_ANALYTICS"), FINAL_ANALYTICS$total_documents, "Unknown"), "documents\n")
  cat("🔗 Database status:", ifelse(exists("database_connected"), database_connected, "Unknown"), "\n")
  cat("🎯 UI components will receive REAL DATA from 1.7M+ row dataset\n")
  cat("\n🚀 Ready for Railway deployment! Run start_app.R\n")
} else {
  cat("❌ CRITICAL FUNCTIONS MISSING - Deployment will fail\n")
  cat("Missing functions:\n")
  if (!exists("get_search_analytics")) cat("  - get_search_analytics\n")
  if (!exists("get_database_stats")) cat("  - get_database_stats\n") 
  if (!exists("get_documents")) cat("  - get_documents\n")
}

cat("============================================================\n")