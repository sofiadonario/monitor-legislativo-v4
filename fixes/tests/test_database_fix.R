# TEST DATABASE FIX - Quick diagnostic for Railway PostgreSQL integration
# Run this script to verify the database connection and function overrides

cat("🧪 TESTING DATABASE FIX\n")
cat("========================\n")

# Test 1: Check if DATABASE_URL exists
cat("1. Checking DATABASE_URL...\n")
database_url <- Sys.getenv("DATABASE_URL", "")
if (nchar(database_url) > 0) {
  cat("✅ DATABASE_URL present (", nchar(database_url), " characters)\n")
} else {
  cat("❌ DATABASE_URL missing - this needs to be set in Railway\n")
}

# Test 2: Load the fix
cat("\n2. Loading Railway PostgreSQL fix...\n")
if (file.exists("RAILWAY_POSTGRESQL_FIX.R")) {
  tryCatch({
    source("RAILWAY_POSTGRESQL_FIX.R")
    cat("✅ Fix loaded successfully\n")
  }, error = function(e) {
    cat("❌ Error loading fix:", e$message, "\n")
  })
} else {
  cat("❌ RAILWAY_POSTGRESQL_FIX.R not found\n")
}

# Test 3: Check if functions exist
cat("\n3. Checking dashboard functions...\n")
functions_to_check <- c("get_lexml_dashboard_metrics", "get_search_analytics", "get_database_stats")

for (func in functions_to_check) {
  if (exists(func)) {
    cat("✅", func, "exists\n")
  } else {
    cat("❌", func, "missing\n")
  }
}

# Test 4: Check database pool
cat("\n4. Checking database pool...\n")
if (exists(".db_pool")) {
  pool_obj <- get(".db_pool")
  if (inherits(pool_obj, "Pool")) {
    cat("✅ .db_pool is a real Pool object\n")
  } else {
    cat("⚠️ .db_pool exists but is:", class(pool_obj), "\n")
  }
} else {
  cat("❌ .db_pool not found\n")
}

# Test 5: Test functions if possible
cat("\n5. Testing functions (if database is available)...\n")
if (exists("get_lexml_dashboard_metrics")) {
  tryCatch({
    metrics <- get_lexml_dashboard_metrics()
    cat("✅ Dashboard metrics test successful\n")
    cat("   Total documents:", format(metrics$total_documents, big.mark = ","), "\n")
    
    if (metrics$total_documents > 100000) {
      cat("🎉 SUCCESS: Document count looks correct\!\n")
    } else {
      cat("⚠️ Document count seems low\n")
    }
    
  }, error = function(e) {
    cat("❌ Dashboard metrics test failed:", e$message, "\n")
  })
}

if (exists("get_search_analytics")) {
  tryCatch({
    analytics <- get_search_analytics()
    cat("✅ Analytics test successful\n")
    cat("   Total documents:", format(analytics$total_documents, big.mark = ","), "\n")
    cat("   Data source:", analytics$data_source, "\n")
    
  }, error = function(e) {
    cat("❌ Analytics test failed:", e$message, "\n")
  })
}

cat("\n🏁 TEST COMPLETED\n")
cat("If you see correct document counts above, the fix is working\!\n")
EOF < /dev/null
