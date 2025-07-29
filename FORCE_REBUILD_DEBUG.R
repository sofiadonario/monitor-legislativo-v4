# FORCE REBUILD DEBUG FILE - This should appear in logs if Railway picks up latest code
cat("🔥 FORCE_REBUILD_DEBUG.R LOADED - THIS MEANS RAILWAY HAS LATEST CODE!\n")
cat("🔥 Current time:", Sys.time(), "\n")
cat("🔥 Working directory:", getwd(), "\n")
cat("🔥 Files in directory:\n")
print(list.files())

# Test database connection immediately
if (exists(".db_pool") && !is.null(.db_pool)) {
  cat("🔥 Database pool exists, testing query...\n")
  tryCatch({
    result <- DBI::dbGetQuery(.db_pool, "SELECT COUNT(*) as count FROM lexml_documents")
    cat("🔥 CRITICAL: lexml_documents has", result$count[1], "rows\n")
    
    sample <- DBI::dbGetQuery(.db_pool, "SELECT titulo, tipo FROM lexml_documents LIMIT 2")
    cat("🔥 SAMPLE DATA:\n")
    print(sample)
  }, error = function(e) {
    cat("🔥 Database query failed:", e$message, "\n")
  })
} else {
  cat("🔥 No database pool available yet\n")
}