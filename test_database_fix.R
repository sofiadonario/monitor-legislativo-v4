#!/usr/bin/env Rscript

# Test script to verify the database fix is working
cat("=== TESTING DATABASE FIX ===\n")

# Load required libraries
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
  library(dplyr)
})

# Load utility functions first
if (file.exists("utils.R")) {
  source("utils.R")
  cat("✅ utils.R loaded\n")
}

# Load the database fix
if (file.exists("railway_database_fix.R")) {
  source("railway_database_fix.R")
  cat("✅ railway_database_fix.R loaded\n")
} else {
  cat("❌ railway_database_fix.R not found\n")
  quit(status = 1)
}

# Load the data access layer
if (file.exists("data_access_layer.R")) {
  source("data_access_layer.R")
  cat("✅ data_access_layer.R loaded\n")
}

# Load database functions
if (file.exists("database.R")) {
  source("database.R")
  cat("✅ database.R loaded\n")
  
  # Reload the fix to ensure it overrides
  source("railway_database_fix.R")
  cat("✅ railway_database_fix.R reloaded to override functions\n")
}

cat("\n=== TESTING DATABASE CONNECTION ===\n")

# Test 1: Check if DATABASE_URL is available
database_url <- Sys.getenv("DATABASE_URL", "")
if (database_url != "") {
  cat("✅ DATABASE_URL is set\n")
} else {
  cat("❌ DATABASE_URL is not set - using fallback mode\n")
}

# Test 2: Test get_database_stats function
cat("\n=== TESTING get_database_stats() ===\n")
if (exists("get_database_stats")) {
  stats <- get_database_stats()
  
  if (!is.null(stats)) {
    cat("✅ get_database_stats() returned data:\n")
    cat("  Total documents:", stats$total_documents, "\n")
    cat("  Unique states:", stats$unique_states, "\n")
    cat("  Unique types:", stats$unique_types, "\n")
    cat("  Date range:", stats$oldest_document, "to", stats$newest_document, "\n")
    
    if (stats$total_documents > 1000) {
      cat("✅ SUCCESS: Large dataset detected (not sample data)\n")
    } else {
      cat("⚠️ WARNING: Small dataset detected, may be sample data\n")
    }
  } else {
    cat("❌ get_database_stats() returned NULL\n")
  }
} else {
  cat("❌ get_database_stats() function not found\n")
}

# Test 3: Test load_legislative_data function
cat("\n=== TESTING load_legislative_data() ===\n")
if (exists("load_legislative_data")) {
  data <- load_legislative_data(limit = 10)
  
  if (!is.null(data) && nrow(data) > 0) {
    cat("✅ load_legislative_data() returned", nrow(data), "rows\n")
    cat("  Columns:", paste(names(data), collapse = ", "), "\n")
    cat("  Sample titles:\n")
    for (i in 1:min(3, nrow(data))) {
      cat("   ", i, ":", substr(data$titulo[i], 1, 60), "...\n")
    }
  } else {
    cat("❌ load_legislative_data() returned no data\n")
  }
} else {
  cat("❌ load_legislative_data() function not found\n")
}

# Test 4: Test data access layer functions
cat("\n=== TESTING DATA ACCESS LAYER ===\n")
if (exists("get_search_analytics")) {
  analytics <- get_search_analytics()
  
  if (!is.null(analytics) && analytics$total_documents > 0) {
    cat("✅ get_search_analytics() working:\n")
    cat("  Total:", analytics$total_documents, "\n")
    cat("  By year entries:", nrow(analytics$documents_by_year), "\n")
    cat("  By state entries:", nrow(analytics$documents_by_state), "\n")
    cat("  By type entries:", nrow(analytics$documents_by_type), "\n")
  } else {
    cat("⚠️ get_search_analytics() returned minimal data\n")
  }
} else {
  cat("❌ get_search_analytics() function not found\n")
}

# Test 5: Direct database connection test
cat("\n=== TESTING DIRECT DATABASE CONNECTION ===\n")
if (database_url != "") {
  tryCatch({
    con <- dbConnect(RPostgres::Postgres(), database_url)
    tables <- dbListTables(con)
    cat("✅ Direct connection successful\n")
    cat("  Tables found:", length(tables), "\n")
    
    # Count documents in main tables
    for (table_name in c("lexml_documents", "documents", "lexml_parsed_enhanced_fixed")) {
      if (table_name %in% tables) {
        tryCatch({
          count <- dbGetQuery(con, paste("SELECT COUNT(*) as count FROM", table_name))$count[1]
          cat("   ", table_name, ":", count, "rows\n")
        }, error = function(e) {
          cat("   ", table_name, ": error counting rows\n")
        })
      }
    }
    
    dbDisconnect(con)
  }, error = function(e) {
    cat("❌ Direct connection failed:", e$message, "\n")
  })
} else {
  cat("❌ Cannot test direct connection without DATABASE_URL\n")
}

cat("\n=== TEST SUMMARY ===\n")
if (exists("get_database_stats")) {
  final_stats <- get_database_stats()
  if (!is.null(final_stats) && final_stats$total_documents > 1000) {
    cat("🎉 SUCCESS: Database fix is working!\n")
    cat("   App will show", final_stats$total_documents, "documents instead of 3\n")
    cat("   UI components will be populated with real data\n")
  } else {
    cat("⚠️ PARTIAL SUCCESS: Fix loaded but using fallback data\n")
    cat("   Check DATABASE_URL and database connectivity\n")
  }
} else {
  cat("❌ FAILURE: Fix not properly loaded\n")
}

cat("=== END TEST ===\n")