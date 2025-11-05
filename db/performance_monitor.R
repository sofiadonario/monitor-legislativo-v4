# ==============================================================================
# PERFORMANCE MONITORING SCRIPT
# ==============================================================================
# This R script monitors database performance and can be run from the Shiny app
# or as a standalone script in the Cloud Run environment
# ==============================================================================

library(DBI)
library(RPostgres)

# Connect to database (uses environment variables from Cloud Run)
get_db_connection <- function() {
  # Try DATABASE_URL first (Railway/Cloud format)
  if (Sys.getenv("DATABASE_URL") != "") {
    return(dbConnect(
      RPostgres::Postgres(),
      Sys.getenv("DATABASE_URL")
    ))
  }

  # Fall back to individual environment variables
  return(dbConnect(
    RPostgres::Postgres(),
    host = Sys.getenv("PGHOST", "/cloudsql/mackmonitor:southamerica-east1:mackmonitor-db"),
    dbname = Sys.getenv("PGDATABASE", "monitor_legislativo"),
    user = Sys.getenv("PGUSER", "monitor_user"),
    password = Sys.getenv("PGPASSWORD")
  ))
}

# ==============================================================================
# PERFORMANCE MONITORING FUNCTIONS
# ==============================================================================

check_indexes <- function(conn) {
  cat("\n=== INDEX STATUS ===\n")

  query <- "
    SELECT
      indexname,
      pg_size_pretty(pg_relation_size(indexrelid)) as size,
      idx_scan as scans,
      idx_tup_read as tuples_read,
      idx_tup_fetch as tuples_fetched
    FROM pg_indexes
    JOIN pg_stat_user_indexes USING (schemaname, tablename, indexname)
    WHERE tablename = 'documents'
    ORDER BY indexname;
  "

  result <- dbGetQuery(conn, query)
  print(result)

  # Check for missing recommended indexes
  required_indexes <- c(
    "idx_documents_tipo",
    "idx_documents_data_desc",
    "idx_documents_tipo_data",
    "idx_documents_titulo_gin"
  )

  existing_indexes <- result$indexname
  missing_indexes <- setdiff(required_indexes, existing_indexes)

  if (length(missing_indexes) > 0) {
    cat("\n⚠️  MISSING RECOMMENDED INDEXES:\n")
    cat(paste0("  - ", missing_indexes, "\n"))
    cat("\nRun db/apply_optimizations.sql to create them.\n")
  } else {
    cat("\n✓ All recommended indexes are present\n")
  }

  invisible(result)
}

check_query_performance <- function(conn) {
  cat("\n=== QUERY PERFORMANCE ===\n")

  # Test typical Library tab query
  cat("\nTesting: Filter by tipo + sort by data...\n")
  start <- Sys.time()
  result1 <- dbGetQuery(conn, "
    SELECT id, titulo, tipo, data_publicacao
    FROM documents
    WHERE tipo = 'Lei'
    ORDER BY data_publicacao DESC
    LIMIT 100;
  ")
  time1 <- as.numeric(difftime(Sys.time(), start, units = "secs"))
  cat(sprintf("  Time: %.3f seconds (%d rows)\n", time1, nrow(result1)))

  # Test text search query
  cat("\nTesting: Text search on titulo...\n")
  start <- Sys.time()
  result2 <- dbGetQuery(conn, "
    SELECT id, titulo, tipo, data_publicacao
    FROM documents
    WHERE titulo ILIKE '%transporte%'
    ORDER BY data_publicacao DESC
    LIMIT 100;
  ")
  time2 <- as.numeric(difftime(Sys.time(), start, units = "secs"))
  cat(sprintf("  Time: %.3f seconds (%d rows)\n", time2, nrow(result2)))

  # Test count query
  cat("\nTesting: Count by tipo...\n")
  start <- Sys.time()
  result3 <- dbGetQuery(conn, "
    SELECT tipo, COUNT(*) as count
    FROM documents
    GROUP BY tipo
    ORDER BY count DESC;
  ")
  time3 <- as.numeric(difftime(Sys.time(), start, units = "secs"))
  cat(sprintf("  Time: %.3f seconds (%d rows)\n", time3, nrow(result3)))

  # Performance assessment
  cat("\n=== PERFORMANCE ASSESSMENT ===\n")
  if (time1 < 0.05) {
    cat("✓ Filter queries: EXCELLENT (< 50ms)\n")
  } else if (time1 < 0.2) {
    cat("⚠️  Filter queries: GOOD (50-200ms) - could be faster with indexes\n")
  } else {
    cat("❌ Filter queries: SLOW (> 200ms) - indexes needed!\n")
  }

  if (time2 < 0.1) {
    cat("✓ Text search: EXCELLENT (< 100ms)\n")
  } else if (time2 < 0.5) {
    cat("⚠️  Text search: MODERATE (100-500ms) - full-text index recommended\n")
  } else {
    cat("❌ Text search: SLOW (> 500ms) - full-text index urgently needed!\n")
  }

  invisible(list(filter_time = time1, search_time = time2, count_time = time3))
}

check_table_statistics <- function(conn) {
  cat("\n=== TABLE STATISTICS ===\n")

  query <- "
    SELECT
      pg_size_pretty(pg_total_relation_size('documents')) as total_size,
      pg_size_pretty(pg_relation_size('documents')) as table_size,
      pg_size_pretty(pg_indexes_size('documents')) as indexes_size,
      (SELECT COUNT(*) FROM documents) as row_count,
      (SELECT COUNT(DISTINCT tipo) FROM documents) as unique_tipos;
  "

  result <- dbGetQuery(conn, query)
  print(result)

  invisible(result)
}

check_database_health <- function(conn) {
  cat("\n=== DATABASE HEALTH ===\n")

  query <- "
    SELECT
      schemaname,
      relname as table_name,
      n_live_tup as live_tuples,
      n_dead_tup as dead_tuples,
      ROUND(100.0 * n_dead_tup / NULLIF(n_live_tup + n_dead_tup, 0), 2) as dead_tuple_pct,
      last_vacuum,
      last_autovacuum,
      last_analyze,
      last_autoanalyze
    FROM pg_stat_user_tables
    WHERE relname = 'documents';
  "

  result <- dbGetQuery(conn, query)
  print(result)

  # Health assessment
  if (!is.na(result$dead_tuple_pct) && result$dead_tuple_pct > 10) {
    cat(sprintf("\n⚠️  Dead tuple percentage is %.1f%% - consider VACUUM\n", result$dead_tuple_pct))
  } else {
    cat("\n✓ Table health is good\n")
  }

  invisible(result)
}

# ==============================================================================
# MAIN MONITORING FUNCTION
# ==============================================================================

monitor_performance <- function() {
  cat("================================================================================\n")
  cat("MONITOR LEGISLATIVO - DATABASE PERFORMANCE MONITORING\n")
  cat("Time:", format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "\n")
  cat("================================================================================\n")

  conn <- tryCatch({
    get_db_connection()
  }, error = function(e) {
    cat("\n❌ DATABASE CONNECTION FAILED\n")
    cat("Error:", conditionMessage(e), "\n")
    return(NULL)
  })

  if (is.null(conn)) {
    return(invisible(NULL))
  }

  on.exit(dbDisconnect(conn))

  # Run all checks
  indexes <- check_indexes(conn)
  performance <- check_query_performance(conn)
  stats <- check_table_statistics(conn)
  health <- check_database_health(conn)

  cat("\n================================================================================\n")
  cat("MONITORING COMPLETE\n")
  cat("================================================================================\n")

  # Return results invisibly
  invisible(list(
    indexes = indexes,
    performance = performance,
    statistics = stats,
    health = health,
    timestamp = Sys.time()
  ))
}

# ==============================================================================
# RUN IF EXECUTED AS SCRIPT
# ==============================================================================

if (!interactive()) {
  monitor_performance()
}
