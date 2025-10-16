#!/usr/bin/env Rscript
# ============================================================================
# INITIALIZE DEMOGRAPHICS (Railway Auto-Run)
# ============================================================================
# This script runs automatically on Railway startup via start_with_db_init.sh
# No manual intervention needed!

cat("================================================================================\n")
cat("DEMOGRAPHICS INITIALIZATION (Auto-Run)\n")
cat("================================================================================\n\n")

# Only run if DATABASE_URL is set (Railway environment)
database_url <- Sys.getenv("DATABASE_URL", "")
if (database_url == "") {
  cat("ℹ️  DATABASE_URL not set - skipping demographics initialization\n")
  quit(status = 0, save = "no")
}

# Load required packages
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
})

cat("📋 Connecting to PostgreSQL...\n")

conn <- tryCatch(
  dbConnect(RPostgres::Postgres(), database_url),
  error = function(e) {
    cat("⚠️  Failed to connect:", e$message, "\n")
    quit(status = 0, save = "no")
  }
)

cat("✅ Connected to PostgreSQL\n\n")

# Check if demographics table already exists
already_initialized <- tryCatch(
  {
    result <- dbGetQuery(conn, "
      SELECT EXISTS (
        SELECT FROM information_schema.tables
        WHERE table_schema = 'public' AND table_name = 'demographics'
      ) AS exists
    ")
    result$exists
  },
  error = function(e) FALSE
)

if (already_initialized) {
  cat("ℹ️  Demographics table already initialized - skipping\n")
  cat("   (This is normal - schema already exists)\n")
  dbDisconnect(conn)
  quit(status = 0, save = "no")
}

cat("🔧 Demographics table not found - initializing...\n\n")

# Read migration SQL file
sql_file <- "database/migrations/add_demographics_and_density.sql"

if (!file.exists(sql_file)) {
  cat("⚠️  Migration file not found:", sql_file, "\n")
  cat("   Skipping demographics initialization\n")
  dbDisconnect(conn)
  quit(status = 0, save = "no")
}

cat("📄 Reading migration file...\n")
sql_content <- paste(readLines(sql_file, warn = FALSE), collapse = "\n")

# Execute migration
cat("🚀 Creating demographics table and bills_per_100k view...\n\n")

result <- tryCatch(
  {
    dbExecute(conn, sql_content)
    TRUE
  },
  error = function(e) {
    cat("⚠️  Migration failed:", e$message, "\n")
    cat("   Continuing startup (non-fatal)\n")
    FALSE
  }
)

if (result) {
  cat("✅ Demographics initialized successfully!\n\n")

  # Quick verification
  demo_count <- tryCatch(
    dbGetQuery(conn, "SELECT COUNT(*) AS count FROM demographics")$count,
    error = function(e) 0
  )

  cat(sprintf("   Demographics: %d rows (27 states × 5 years)\n", demo_count))
  cat("   Materialized view: mv_docs_state_density created\n")
  cat("   API endpoint ready: /api/v1/map/choropleth?metric=bills_per_100k\n\n")
}

dbDisconnect(conn)
cat("✅ Demographics initialization complete\n\n")
