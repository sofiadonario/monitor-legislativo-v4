#!/usr/bin/env Rscript

# Railway Database Initialization Script
# Run this AFTER deployment on Railway to populate the database
# The internal URL only works from within Railway's network

cat("=== RAILWAY DATABASE INITIALIZATION ===\n")
cat("This script must be run from within Railway deployment\n\n")

# Load required packages
library(DBI)
library(RPostgres)

# Use internal Railway URL (only works from within Railway)
DATABASE_URL <- "postgresql://postgres:smNCedRjMKeNsoqpurLWXjGEUZxORwVY@postgres.railway.internal:5432/railway"

cat("Connecting to Railway PostgreSQL (internal URL)...\n")

tryCatch({
  # Connect to database
  con <- dbConnect(
    RPostgres::Postgres(),
    host = "postgres.railway.internal",
    port = 5432,
    dbname = "railway",
    user = "postgres",
    password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY"
  )
  
  cat("✅ Connected to Railway PostgreSQL\n")
  
  # Check existing tables
  tables <- dbListTables(con)
  cat("Existing tables:", paste(tables, collapse = ", "), "\n")
  
  # Check if documents table exists and has data
  if ("documents" %in% tables) {
    count <- dbGetQuery(con, "SELECT COUNT(*) as count FROM documents")
    cat("Documents table exists with", count$count, "records\n")
    
    if (count$count >= 100000) {
      cat("✅ Database already populated with", count$count, "documents\n")
      dbDisconnect(con)
      quit(status = 0)
    }
  }
  
  # Load CSV data
  csv_file <- "data_current/processed/production/lexml_unified_dataset.csv"
  
  if (!file.exists(csv_file)) {
    cat("❌ CSV file not found:", csv_file, "\n")
    cat("Make sure the CSV file is deployed with the application\n")
    dbDisconnect(con)
    quit(status = 1)
  }
  
  cat("Loading CSV data from:", csv_file, "\n")
  legislative_data <- read.csv(csv_file, stringsAsFactors = FALSE)
  cat("Loaded", nrow(legislative_data), "records from CSV\n")
  
  # Create or replace documents table
  cat("Creating documents table...\n")
  
  dbExecute(con, "DROP TABLE IF EXISTS documents CASCADE")
  
  # Write data to database
  cat("Writing data to PostgreSQL...\n")
  dbWriteTable(con, "documents", legislative_data, row.names = FALSE)
  
  # Create indexes
  cat("Creating indexes for performance...\n")
  dbExecute(con, "CREATE INDEX idx_documents_titulo ON documents (titulo)")
  dbExecute(con, "CREATE INDEX idx_documents_estado ON documents (estado)")
  dbExecute(con, "CREATE INDEX idx_documents_data ON documents (data)")
  dbExecute(con, "CREATE INDEX idx_documents_categoria ON documents (categoria)")
  
  # Verify
  final_count <- dbGetQuery(con, "SELECT COUNT(*) as count FROM documents")
  cat("✅ Database populated with", final_count$count, "documents\n")
  
  dbDisconnect(con)
  cat("\n🎉 DATABASE INITIALIZATION COMPLETE!\n")
  
}, error = function(e) {
  cat("❌ Database initialization failed:", e$message, "\n")
  cat("\nPossible reasons:\n")
  cat("- Not running from within Railway deployment\n")
  cat("- Database service not available\n")
  cat("- Incorrect credentials\n")
  quit(status = 1)
})