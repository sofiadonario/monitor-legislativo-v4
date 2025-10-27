#!/usr/bin/env Rscript
# ============================================================================
# ADD DEMOGRAPHICS AND BILLS PER 100K METRIC
# ============================================================================
# Adds Brazilian state population data and creates bills per capita metric
# for choropleth map visualization

cat("================================================================================\n")
cat("ADDING DEMOGRAPHICS AND BILLS PER 100K METRIC\n")
cat("================================================================================\n\n")

# Load required packages
suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
})

# Get database connection details from environment
database_url <- Sys.getenv("DATABASE_URL", "")
if (database_url == "") {
  # Try individual PostgreSQL environment variables
  pgdatabase <- Sys.getenv("PGDATABASE", "")
  pghost <- Sys.getenv("PGHOST", "")
  pguser <- Sys.getenv("PGUSER", "")
  pgpassword <- Sys.getenv("PGPASSWORD", "")
  pgport <- Sys.getenv("PGPORT", "5432")

  if (pgdatabase == "" || pghost == "") {
    cat("❌ Error: No database connection details found\n")
    cat("   Set DATABASE_URL or PGDATABASE/PGHOST environment variables\n")
    quit(status = 1, save = "no")
  }

  cat("📋 Connecting to PostgreSQL...\n")
  cat(sprintf("   Database: %s\n", pgdatabase))
  cat(sprintf("   Host: %s\n", pghost))
  cat(sprintf("   Port: %s\n\n", pgport))

  conn <- tryCatch(
    dbConnect(
      RPostgres::Postgres(),
      dbname = pgdatabase,
      host = pghost,
      user = pguser,
      password = pgpassword,
      port = as.integer(pgport)
    ),
    error = function(e) {
      cat("❌ Failed to connect to PostgreSQL:", e$message, "\n")
      quit(status = 1, save = "no")
    }
  )
} else {
  cat("📋 Connecting to PostgreSQL using DATABASE_URL...\n\n")

  conn <- tryCatch(
    dbConnect(RPostgres::Postgres(), database_url),
    error = function(e) {
      cat("❌ Failed to connect to PostgreSQL:", e$message, "\n")
      quit(status = 1, save = "no")
    }
  )
}

cat("✅ Connected to PostgreSQL\n\n")

# Check if demographics table already exists
already_exists <- tryCatch(
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

if (already_exists) {
  cat("ℹ️  Demographics table already exists\n")
  cat("   Would you like to recreate it? This will delete existing data.\n")
  cat("   To proceed, run this script with FORCE_RECREATE=true\n\n")

  if (Sys.getenv("FORCE_RECREATE", "false") != "true") {
    cat("✅ Skipping migration (use FORCE_RECREATE=true to override)\n")
    dbDisconnect(conn)
    quit(status = 0, save = "no")
  }

  cat("⚠️  FORCE_RECREATE=true - Recreating demographics table...\n\n")
}

# Read migration SQL file
sql_file <- "database/migrations/add_demographics_and_density.sql"

if (!file.exists(sql_file)) {
  cat("❌ Migration file not found:", sql_file, "\n")
  dbDisconnect(conn)
  quit(status = 1, save = "no")
}

cat("📄 Reading migration file...\n")
sql_content <- paste(readLines(sql_file, warn = FALSE), collapse = "\n")

# Execute migration
cat("🔧 Running migration...\n\n")

result <- tryCatch(
  {
    dbExecute(conn, sql_content)
    TRUE
  },
  error = function(e) {
    cat("❌ Migration failed:", e$message, "\n")
    FALSE
  }
)

if (!result) {
  dbDisconnect(conn)
  quit(status = 1, save = "no")
}

cat("\n✅ Migration completed successfully!\n\n")

# Verify the migration
cat("🔍 Verifying migration...\n\n")

# Check demographics table
demo_count <- tryCatch(
  dbGetQuery(conn, "SELECT COUNT(*) AS count FROM demographics")$count,
  error = function(e) 0
)

cat(sprintf("   Demographics table: %d rows\n", demo_count))

# Check density view
density_count <- tryCatch(
  dbGetQuery(conn, "SELECT COUNT(*) AS count FROM mv_docs_state_density")$count,
  error = function(e) 0
)

cat(sprintf("   Density view: %d rows\n\n", density_count))

# Show sample data
if (density_count > 0) {
  cat("📊 Sample data (top 5 states by bills per 100k in 2023):\n\n")

  sample_data <- tryCatch(
    dbGetQuery(conn, "
      SELECT state, year, n_docs, population, bills_per_100k
      FROM mv_docs_state_density
      WHERE year = 2023
      ORDER BY bills_per_100k DESC
      LIMIT 5
    "),
    error = function(e) NULL
  )

  if (!isTRUE(is.null(sample_data)) && nrow(sample_data) > 0) {
    print(sample_data)
  }
}

cat("\n")
cat("================================================================================\n")
cat("MIGRATION COMPLETE\n")
cat("================================================================================\n\n")
cat("✅ Demographics table created with population data (2020-2024)\n")
cat("✅ Materialized view mv_docs_state_density created\n")
cat("✅ Bills per 100k population metric available\n\n")
cat("API Endpoint:\n")
cat("  GET /api/v1/map/choropleth?metric=bills_per_100k&year=2023\n\n")
cat("To refresh the density view after data changes:\n")
cat("  REFRESH MATERIALIZED VIEW CONCURRENTLY mv_docs_state_density;\n\n")

# Disconnect
dbDisconnect(conn)
