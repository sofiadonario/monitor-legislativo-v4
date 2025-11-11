#!/usr/bin/env Rscript

# Test database connection and check table names

cat("===============================================\n")
cat("Database Connection Test\n")
cat("===============================================\n\n")

# Load required libraries
library(DBI)
library(RPostgres)

# Read .Renviron to get database credentials
readRenviron(".Renviron")

cat("Database Configuration:\n")
cat("  Host:", Sys.getenv("PGHOST"), "\n")
cat("  Port:", Sys.getenv("PGPORT"), "\n")
cat("  Database:", Sys.getenv("PGDATABASE"), "\n")
cat("  User:", Sys.getenv("PGUSER"), "\n")
cat("  Password:", if(nchar(Sys.getenv("PGPASSWORD")) > 0) "***SET***" else "NOT SET", "\n\n")

# Try to connect
conn <- NULL
tryCatch({
  conn <- dbConnect(
    RPostgres::Postgres(),
    host = Sys.getenv("PGHOST"),
    port = as.integer(Sys.getenv("PGPORT")),
    dbname = Sys.getenv("PGDATABASE"),
    user = Sys.getenv("PGUSER"),
    password = Sys.getenv("PGPASSWORD"),
    connect_timeout = 10
  )
  
  cat("✅ Successfully connected to database!\n\n")
  
  # List all tables
  tables <- dbListTables(conn)
  cat("Available tables (", length(tables), "):\n", sep = "")
  for (table in tables) {
    cat("  -", table, "\n")
  }
  
  # Check for document-related tables
  doc_tables <- tables[grepl("doc|lexml", tables, ignore.case = TRUE)]
  if (length(doc_tables) > 0) {
    cat("\nDocument-related tables found:\n")
    for (table in doc_tables) {
      cat("\n  Table:", table, "\n")
      # Get column names
      cols <- dbListFields(conn, table)
      cat("  Columns:", paste(cols, collapse = ", "), "\n")
      # Get row count
      count_query <- paste("SELECT COUNT(*) as n FROM", table)
      count <- dbGetQuery(conn, count_query)
      cat("  Row count:", count$n, "\n")
      
      # Show sample data
      if (count$n > 0) {
        sample_query <- paste("SELECT * FROM", table, "LIMIT 2")
        sample <- dbGetQuery(conn, sample_query)
        cat("  Sample data:\n")
        print(sample)
      }
    }
  } else {
    cat("\n⚠️ No document-related tables found!\n")
    cat("Looking for any table with data...\n\n")
    
    # Check all tables for content
    for (table in tables[1:min(10, length(tables))]) {
      count_query <- paste("SELECT COUNT(*) as n FROM", table)
      count <- tryCatch(
        dbGetQuery(conn, count_query),
        error = function(e) list(n = 0)
      )
      if (count$n > 0) {
        cat("  Table", table, "has", count$n, "rows\n")
      }
    }
  }
  
}, error = function(e) {
  cat("❌ Database connection failed:\n")
  cat("   Error:", e$message, "\n\n")
  cat("Troubleshooting tips:\n")
  cat("1. Check if the database server is accessible from your network\n")
  cat("2. Verify the credentials in .Renviron are correct\n")
  cat("3. Ensure PostgreSQL port 5432 is not blocked by firewall\n")
  cat("4. Try connecting with psql:\n")
  cat("   psql -h", Sys.getenv("PGHOST"), "-p", Sys.getenv("PGPORT"), 
      "-d", Sys.getenv("PGDATABASE"), "-U", Sys.getenv("PGUSER"), "\n")
}, finally = {
  if (!is.null(conn)) {
    dbDisconnect(conn)
    cat("\n✅ Connection closed\n")
  }
})

cat("\n===============================================\n")
