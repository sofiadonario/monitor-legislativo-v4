#!/usr/bin/env Rscript
# Deploy high-performance schema to Railway PostgreSQL using R
# Uses the same connection setup as your Shiny app

library(DBI)
library(RPostgres)

cat("================================================================================\n")
cat("DEPLOYING HIGH-PERFORMANCE SCHEMA TO RAILWAY\n")
cat("================================================================================\n\n")

# Connection parameters
cat("Connecting to Railway PostgreSQL...\n")

# Try DATABASE_PUBLIC_URL first (for local connections)
database_url <- Sys.getenv("DATABASE_PUBLIC_URL", "")

if (database_url == "") {
  # Fallback to manual construction
  conn <- dbConnect(
    RPostgres::Postgres(),
    host = "nozomi.proxy.rlwy.net",
    port = 44844,
    dbname = "railway",
    user = "postgres",
    password = "smNCedRjMKeNsoqpurLWXjGEUZxORwVY",
    connect_timeout = 60
  )
} else {
  conn <- dbConnect(RPostgres::Postgres(), database_url)
}

cat("✓ Connected successfully\n\n")

# Read SQL file
sql_file <- "high_performance_search_schema.sql"
cat(sprintf("Reading %s...\n", sql_file))

sql_content <- paste(readLines(sql_file, warn = FALSE), collapse = "\n")
cat(sprintf("✓ Loaded %d bytes\n\n", nchar(sql_content)))

# Execute SQL
cat("Executing SQL (this may take 30-60 seconds)...\n")
cat("This will create tables, indexes, and materialized views...\n\n")

tryCatch({
  dbExecute(conn, sql_content)
  cat("✓ Schema deployed successfully!\n\n")

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
  cat(sprintf("✓ Tables created: %d/2\n", tables$count))

  # Check materialized views
  mvs <- dbGetQuery(conn, "
    SELECT COUNT(*) as count
    FROM pg_matviews
    WHERE schemaname = 'public'
  ")
  cat(sprintf("✓ Materialized views: %d\n", mvs$count))

  # Check indexes
  indexes <- dbGetQuery(conn, "
    SELECT COUNT(*) as count
    FROM pg_indexes
    WHERE schemaname = 'public'
    AND tablename = 'legis_docs'
  ")
  cat(sprintf("✓ Indexes on legis_docs: %d\n", indexes$count))

  # Check extensions
  extensions <- dbGetQuery(conn, "
    SELECT COUNT(*) as count
    FROM pg_extension
    WHERE extname IN ('postgis', 'unaccent', 'pg_trgm', 'btree_gin', 'pg_stat_statements')
  ")
  cat(sprintf("✓ Extensions installed: %d/5\n\n", extensions$count))

  cat("================================================================================\n")
  cat("DEPLOYMENT COMPLETE!\n")
  cat("================================================================================\n\n")

  cat("Next steps:\n")
  cat("1. Insert test data to verify:\n")
  cat("   INSERT INTO legis_docs (id, title, full_text, jurisdiction, state, date)\n")
  cat("   VALUES ('test-001', 'Lei Teste', 'Conteúdo de teste', 'federal', 'SP', CURRENT_DATE);\n\n")
  cat("2. Test full-text search:\n")
  cat("   SELECT * FROM legis_docs WHERE search_vector @@ to_tsquery('portuguese', 'teste');\n\n")

}, error = function(e) {
  cat(sprintf("❌ Error: %s\n", e$message))
  dbDisconnect(conn)
  quit(status = 1)
})

dbDisconnect(conn)
cat("✓ Connection closed\n")
