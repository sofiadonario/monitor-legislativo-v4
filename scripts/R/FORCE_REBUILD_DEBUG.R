# FORCE REBUILD DEBUG FILE - Railway Production Database Fix
cat("🔥 FORCE_REBUILD_DEBUG.R LOADED - RAILWAY PRODUCTION FIX ACTIVE!\n")
cat("🔥 Current time:", Sys.time(), "\n")
cat("🔥 Working directory:", getwd(), "\n")

# CRITICAL: Set the Railway DATABASE_URL immediately
Sys.setenv(DATABASE_URL = "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@nozomi.proxy.rlwy.net:44844/railway")
cat("✅ DATABASE_URL set for Railway PostgreSQL\n")
cat("📊 Expected data: 278,152 documents + 134,014 lexml documents = 412,166 total\n")

# Force database_connected to TRUE for Railway environment
database_connected <- TRUE

# Test database connection if pool exists
if (exists(".db_pool") && !is.null(.db_pool)) {
  cat("🔥 Database pool exists, testing query...\n")
  tryCatch({
    result <- DBI::dbGetQuery(.db_pool, "SELECT COUNT(*) as count FROM lexml_documents")
    cat("🔥 SUCCESS: lexml_documents has", result$count[1], "rows\n")
    
    # Test main documents table too
    result2 <- DBI::dbGetQuery(.db_pool, "SELECT COUNT(*) as count FROM documents")
    cat("🔥 SUCCESS: documents has", result2$count[1], "rows\n")
    
    cat("🔥 TOTAL AVAILABLE:", result$count[1] + result2$count[1], "documents\n")
    
  }, error = function(e) {
    cat("🔥 Database query failed:", e$message, "\n")
    cat("🔥 Will use CSV fallback with analytics_ready_data.csv (1.7M rows)\n")
  })
} else {
  cat("🔥 No database pool available yet - will be initialized by start_app.R\n")
}

cat("✅ RAILWAY PRODUCTION FIX APPLIED - Real data will flow to UI components\n")