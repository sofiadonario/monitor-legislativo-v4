# Database Migration Script
# Adds municipio column to documents table

source("R/database_connection.R")

run_migration <- function() {
  cat("🔄 Running database migration to add municipio column...\n")
  
  if (is.null(db_pool)) {
    init_result <- init_database()
    if (!init_result) {
      cat("❌ Failed to initialize database connection\n")
      return(FALSE)
    }
  }
  
  tryCatch({
    # Read migration SQL
    migration_sql <- readLines("database/migrations/add_municipio_column.sql")
    migration_sql <- paste(migration_sql, collapse = "\n")
    
    # Execute migration
    dbExecute(db_pool, migration_sql)
    
    cat("✅ Migration completed successfully\n")
    cat("📍 municipio column added to documents table\n")
    
    # Test the migration
    test_result <- dbGetQuery(db_pool, "SELECT COUNT(*) as count FROM documents WHERE municipio IS NOT NULL")
    cat("🏙️ Documents with municipality data:", test_result$count, "\n")
    
    return(TRUE)
    
  }, error = function(e) {
    cat("❌ Migration failed:", e$message, "\n")
    return(FALSE)
  })
}

# Run migration if script is executed directly
if (!interactive()) {
  cat("🚀 Database Migration Runner\n")
  cat("=============================\n")
  
  if (run_migration()) {
    cat("\n🎉 Migration completed successfully!\n")
  } else {
    cat("\n❌ Migration failed!\n")
    quit(status = 1)
  }
}