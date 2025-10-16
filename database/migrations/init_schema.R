#!/usr/bin/env Rscript
# Initialize database schema on Railway startup
# This script runs automatically when the container starts
# It's safe to run multiple times (all statements use IF NOT EXISTS)

cat("================================================================================\n")
cat("RAILWAY DATABASE SCHEMA INITIALIZATION\n")
cat("================================================================================\n\n")

# Only run if DATABASE_URL is set (Railway environment)
database_url <- Sys.getenv("DATABASE_URL", "")
if (database_url == "") {
  cat("ℹ️  DATABASE_URL not set - skipping schema initialization (local development mode)\n")
  quit(status = 0, save = "no")
}

cat("✅ DATABASE_URL detected - proceeding with schema initialization\n\n")

# Load required packages
suppressPackageStartupMessages({
  if (!require("DBI", quietly = TRUE)) {
    cat("📦 Installing DBI package...\n")
    install.packages("DBI", repos = "https://cloud.r-project.org/")
    library(DBI)
  } else {
    library(DBI)
  }

  if (!require("RPostgres", quietly = TRUE)) {
    cat("📦 Installing RPostgres package...\n")
    install.packages("RPostgres", repos = "https://cloud.r-project.org/")
    library(RPostgres)
  } else {
    library(RPostgres)
  }
})

cat("📚 Database packages loaded\n\n")

# Connect to Railway PostgreSQL
cat("🔌 Connecting to Railway PostgreSQL...\n")

conn <- tryCatch({
  dbConnect(
    RPostgres::Postgres(),
    dbname = database_url,  # RPostgres can parse full URLs
    connect_timeout = 60
  )
}, error = function(e) {
  cat("❌ Failed to connect to database:", e$message, "\n")
  quit(status = 1, save = "no")
})

cat("✅ Connected successfully\n\n")

# Check if schema is already initialized
already_initialized <- tryCatch({
  result <- dbGetQuery(conn, "
    SELECT EXISTS (
      SELECT FROM information_schema.tables
      WHERE table_schema = 'public'
      AND table_name = 'legis_docs'
    ) AS exists
  ")
  result$exists
}, error = function(e) {
  FALSE
})

if (already_initialized) {
  cat("ℹ️  Database schema already initialized - skipping\n")
  cat("   (To force reinitialization, drop the legis_docs table manually)\n\n")
  dbDisconnect(conn)
  quit(status = 0, save = "no")
}

cat("🏗️  Initializing database schema...\n")
cat("   This may take 30-60 seconds for first-time setup\n\n")

# Read SQL schema file
sql_file <- "database/migrations/high_performance_search_schema.sql"

if (!file.exists(sql_file)) {
  cat("❌ Schema file not found:", sql_file, "\n")
  cat("   Current directory:", getwd(), "\n")
  dbDisconnect(conn)
  quit(status = 1, save = "no")
}

sql_content <- paste(readLines(sql_file, warn = FALSE), collapse = "\n")
cat(sprintf("📄 Schema loaded (%d bytes)\n\n", nchar(sql_content)))

# Execute schema
tryCatch({
  dbExecute(conn, sql_content)
  cat("✅ Schema deployed successfully!\n\n")

  # Verify installation
  cat("================================================================================\n")
  cat("VERIFYING INSTALLATION\n")
  cat("================================================================================\n\n")

  # Check tables
  tables <- dbGetQuery(conn, "
    SELECT COUNT(*) as count
    FROM information_schema.tables
    WHERE table_schema = 'public'
    AND table_name IN ('legis_docs', 'ingest_control')
  ")
  cat(sprintf("✅ Tables created: %d/2\n", tables$count))

  # Check materialized views
  mvs <- dbGetQuery(conn, "
    SELECT COUNT(*) as count
    FROM pg_matviews
    WHERE schemaname = 'public'
  ")
  cat(sprintf("✅ Materialized views: %d\n", mvs$count))

  # Check indexes
  indexes <- dbGetQuery(conn, "
    SELECT COUNT(*) as count
    FROM pg_indexes
    WHERE schemaname = 'public'
    AND tablename = 'legis_docs'
  ")
  cat(sprintf("✅ Indexes on legis_docs: %d\n", indexes$count))

  # Check extensions
  extensions <- dbGetQuery(conn, "
    SELECT COUNT(*) as count
    FROM pg_extension
    WHERE extname IN ('postgis', 'unaccent', 'pg_trgm', 'btree_gin', 'pg_stat_statements')
  ")
  cat(sprintf("✅ Extensions installed: %d/5\n\n", extensions$count))

  cat("================================================================================\n")
  cat("SCHEMA INITIALIZATION COMPLETE!\n")
  cat("================================================================================\n\n")

}, error = function(e) {
  cat(sprintf("❌ Schema deployment failed: %s\n", e$message))
  dbDisconnect(conn)
  quit(status = 1, save = "no")
})

dbDisconnect(conn)
cat("✅ Connection closed\n")
cat("🚀 Application ready to start\n\n")
