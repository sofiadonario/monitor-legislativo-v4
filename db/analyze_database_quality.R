# ==============================================================================
# POSTGRESQL DATABASE ANALYSIS FOR MONITOR LEGISLATIVO
# ==============================================================================
# This script performs comprehensive data quality and performance analysis
# on the Monitor Legislativo PostgreSQL database.
#
# Analysis includes:
# 1. Data Statistics (document counts, type distribution)
# 2. Data Quality Issues (NULL values, duplicates, text quality)
# 3. Performance Considerations (indexes, query optimization)
# ==============================================================================

suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
})

# ==============================================================================
# DATABASE CONNECTION
# ==============================================================================

get_database_config <- function() {
  # Check for environment variables
  if (Sys.getenv("PGHOST") != "") {
    cat("Using environment variables for connection\n")
    return(list(
      host = Sys.getenv("PGHOST", "localhost"),
      port = as.integer(Sys.getenv("PGPORT", "5432")),
      dbname = Sys.getenv("PGDATABASE", "monitor_legislativo"),
      user = Sys.getenv("PGUSER", "postgres"),
      password = Sys.getenv("PGPASSWORD", "")
    ))
  }

  # Check for DATABASE_URL (Railway format)
  database_url <- Sys.getenv("DATABASE_URL", "")
  if (database_url != "") {
    cat("Using DATABASE_URL for connection\n")
    # Parse DATABASE_URL: postgresql://user:password@host:port/dbname
    url_parts <- sub("^postgres(?:ql)?://", "", database_url)
    auth_parts <- strsplit(url_parts, "@")[[1]]
    user_pass <- strsplit(auth_parts[1], ":")[[1]]
    host_db <- strsplit(auth_parts[2], "/")[[1]]
    host_port <- strsplit(host_db[1], ":")[[1]]

    return(list(
      host = host_port[1],
      port = as.integer(host_port[2]),
      dbname = host_db[2],
      user = user_pass[1],
      password = user_pass[2]
    ))
  }

  # Default to local development
  cat("Using default local configuration\n")
  return(list(
    host = "localhost",
    port = 5432,
    dbname = "monitor_legislativo",
    user = "postgres",
    password = "postgres"
  ))
}

connect_to_database <- function() {
  config <- get_database_config()

  tryCatch({
    conn <- dbConnect(
      RPostgres::Postgres(),
      host = config$host,
      port = config$port,
      dbname = config$dbname,
      user = config$user,
      password = config$password,
      sslmode = "prefer",
      connect_timeout = 30
    )

    cat("\n✅ DATABASE CONNECTION ESTABLISHED\n")
    cat("   Host:", config$host, "\n")
    cat("   Port:", config$port, "\n")
    cat("   Database:", config$dbname, "\n")
    cat("   User:", config$user, "\n\n")

    return(conn)

  }, error = function(e) {
    cat("\n❌ DATABASE CONNECTION FAILED\n")
    cat("   Error:", e$message, "\n\n")
    cat("   Please ensure:\n")
    cat("   1. PostgreSQL is running\n")
    cat("   2. Database credentials are correct\n")
    cat("   3. Network connectivity is available\n\n")
    return(NULL)
  })
}

# ==============================================================================
# 1. DATA STATISTICS ANALYSIS
# ==============================================================================

analyze_data_statistics <- function(conn) {
  cat("================================================================================\n")
  cat("1. DATA STATISTICS ANALYSIS\n")
  cat("================================================================================\n\n")

  # Total document count
  cat("--- TOTAL DOCUMENT COUNT ---\n")
  total_query <- "SELECT COUNT(*) as total_documents FROM documents"
  total_result <- dbGetQuery(conn, total_query)
  cat("Total Documents:", format(total_result$total_documents, big.mark = ","), "\n\n")

  # Document type distribution
  cat("--- DOCUMENT TYPE DISTRIBUTION ---\n")
  type_query <- "
    SELECT
      tipo,
      COUNT(*) as count,
      ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 2) as percentage
    FROM documents
    GROUP BY tipo
    ORDER BY count DESC
  "
  type_result <- dbGetQuery(conn, type_query)
  print(type_result)
  cat("\n")

  # Check unique document types
  cat("--- UNIQUE DOCUMENT TYPES ---\n")
  unique_types_query <- "SELECT DISTINCT tipo FROM documents ORDER BY tipo"
  unique_types <- dbGetQuery(conn, unique_types_query)
  cat("Total unique types:", nrow(unique_types), "\n")
  cat("Types:", paste(unique_types$tipo, collapse = ", "), "\n\n")

  # Compare with app filter types
  cat("--- APP FILTER COMPARISON ---\n")
  app_filter_types <- c("Todos", "Lei", "Decreto", "Projeto de Lei")
  cat("App filter types:", paste(app_filter_types[-1], collapse = ", "), "\n")  # Exclude "Todos"

  db_types <- unique_types$tipo
  missing_in_app <- setdiff(db_types, app_filter_types)
  missing_in_db <- setdiff(app_filter_types[-1], db_types)  # Exclude "Todos"

  if (length(missing_in_app) > 0) {
    cat("⚠️ Types in DB but NOT in app filters:", paste(missing_in_app, collapse = ", "), "\n")
  }
  if (length(missing_in_db) > 0) {
    cat("⚠️ Types in app filters but NOT in DB:", paste(missing_in_db, collapse = ", "), "\n")
  }
  if (length(missing_in_app) == 0 && length(missing_in_db) == 0) {
    cat("✅ All document types match app filters\n")
  }
  cat("\n")

  # Date range analysis
  cat("--- DATE RANGE ANALYSIS ---\n")
  date_query <- "
    SELECT
      MIN(data) as oldest_date,
      MAX(data) as newest_date,
      MAX(data) - MIN(data) as date_range_days
    FROM documents
  "
  date_result <- dbGetQuery(conn, date_query)
  cat("Oldest document:", format(as.Date(date_result$oldest_date), "%d/%m/%Y"), "\n")
  cat("Newest document:", format(as.Date(date_result$newest_date), "%d/%m/%Y"), "\n")
  cat("Date range:", date_result$date_range_days, "days\n\n")

  # Documents per year
  cat("--- DOCUMENTS PER YEAR ---\n")
  year_query <- "
    SELECT
      EXTRACT(YEAR FROM data) as year,
      COUNT(*) as count
    FROM documents
    GROUP BY year
    ORDER BY year DESC
    LIMIT 10
  "
  year_result <- dbGetQuery(conn, year_query)
  print(year_result)
  cat("\n")

  return(list(
    total = total_result,
    types = type_result,
    unique_types = unique_types,
    date_range = date_result,
    yearly = year_result,
    missing_in_app = missing_in_app,
    missing_in_db = missing_in_db
  ))
}

# ==============================================================================
# 2. DATA QUALITY ANALYSIS
# ==============================================================================

analyze_data_quality <- function(conn) {
  cat("================================================================================\n")
  cat("2. DATA QUALITY ANALYSIS\n")
  cat("================================================================================\n\n")

  # NULL value analysis
  cat("--- NULL VALUE ANALYSIS ---\n")
  null_query <- "
    SELECT
      COUNT(*) as total_records,
      COUNT(*) FILTER (WHERE id IS NULL) as null_id,
      COUNT(*) FILTER (WHERE titulo IS NULL) as null_titulo,
      COUNT(*) FILTER (WHERE tipo IS NULL) as null_tipo,
      COUNT(*) FILTER (WHERE data IS NULL) as null_data,
      COUNT(*) FILTER (WHERE titulo = '') as empty_titulo,
      COUNT(*) FILTER (WHERE tipo = '') as empty_tipo
    FROM documents
  "
  null_result <- dbGetQuery(conn, null_query)
  print(null_result)

  if (null_result$null_titulo > 0 || null_result$empty_titulo > 0) {
    cat("\n⚠️ WARNING: Found NULL or empty titulo values\n")
  }
  if (null_result$null_tipo > 0 || null_result$empty_tipo > 0) {
    cat("⚠️ WARNING: Found NULL or empty tipo values\n")
  }
  cat("\n")

  # Text quality - check for problematic characters
  cat("--- TEXT QUALITY ANALYSIS ---\n")
  text_quality_query <- "
    SELECT
      COUNT(*) FILTER (WHERE titulo LIKE '%  %') as double_spaces_titulo,
      COUNT(*) FILTER (WHERE titulo LIKE '% ,%' OR titulo LIKE '% .%') as space_before_punct,
      COUNT(*) FILTER (WHERE titulo ~ '[^\x00-\x7F]') as non_ascii_titulo,
      COUNT(*) FILTER (WHERE LENGTH(titulo) < 10) as very_short_titulo,
      COUNT(*) FILTER (WHERE LENGTH(titulo) > 500) as very_long_titulo
    FROM documents
  "
  text_quality_result <- dbGetQuery(conn, text_quality_query)
  print(text_quality_result)

  if (text_quality_result$double_spaces_titulo > 0) {
    cat("\n⚠️ Found", text_quality_result$double_spaces_titulo, "titles with double spaces\n")
  }
  if (text_quality_result$space_before_punct > 0) {
    cat("⚠️ Found", text_quality_result$space_before_punct, "titles with space before punctuation\n")
  }
  cat("\n")

  # Sample problematic titles
  cat("--- SAMPLE PROBLEMATIC TITLES ---\n")
  problematic_query <- "
    SELECT id, titulo, tipo, data
    FROM documents
    WHERE titulo LIKE '%  %'
       OR LENGTH(titulo) < 10
       OR titulo LIKE '% ,%'
    LIMIT 5
  "
  problematic_result <- dbGetQuery(conn, problematic_query)
  if (nrow(problematic_result) > 0) {
    print(problematic_result)
  } else {
    cat("✅ No problematic titles found in sample\n")
  }
  cat("\n")

  # Duplicate detection
  cat("--- DUPLICATE DETECTION ---\n")
  duplicate_query <- "
    SELECT
      COUNT(*) as total_duplicates
    FROM (
      SELECT titulo, tipo, data, COUNT(*) as dup_count
      FROM documents
      GROUP BY titulo, tipo, data
      HAVING COUNT(*) > 1
    ) AS duplicates
  "
  duplicate_result <- dbGetQuery(conn, duplicate_query)
  cat("Total duplicate groups:", duplicate_result$total_duplicates, "\n")

  if (duplicate_result$total_duplicates > 0) {
    cat("\n⚠️ WARNING: Found duplicate documents\n")

    # Show sample duplicates
    sample_duplicates_query <- "
      SELECT titulo, tipo, data, COUNT(*) as count
      FROM documents
      GROUP BY titulo, tipo, data
      HAVING COUNT(*) > 1
      ORDER BY count DESC
      LIMIT 5
    "
    sample_duplicates <- dbGetQuery(conn, sample_duplicates_query)
    cat("\nSample duplicate groups:\n")
    print(sample_duplicates)
  } else {
    cat("✅ No duplicates found\n")
  }
  cat("\n")

  # Check for inconsistent tipo formatting
  cat("--- TIPO FORMATTING CONSISTENCY ---\n")
  tipo_format_query <- "
    SELECT
      tipo,
      COUNT(*) FILTER (WHERE tipo != TRIM(tipo)) as has_whitespace,
      COUNT(*) FILTER (WHERE tipo ~ '^[A-Z]') as starts_uppercase,
      COUNT(*) FILTER (WHERE tipo ~ '^[a-z]') as starts_lowercase
    FROM documents
    GROUP BY tipo
    ORDER BY tipo
  "
  tipo_format_result <- dbGetQuery(conn, tipo_format_query)
  print(tipo_format_result)
  cat("\n")

  return(list(
    null_analysis = null_result,
    text_quality = text_quality_result,
    duplicates = duplicate_result,
    tipo_format = tipo_format_result
  ))
}

# ==============================================================================
# 3. PERFORMANCE ANALYSIS
# ==============================================================================

analyze_performance <- function(conn) {
  cat("================================================================================\n")
  cat("3. PERFORMANCE ANALYSIS\n")
  cat("================================================================================\n\n")

  # Check existing indexes
  cat("--- EXISTING INDEXES ---\n")
  index_query <- "
    SELECT
      schemaname,
      tablename,
      indexname,
      indexdef
    FROM pg_indexes
    WHERE tablename = 'documents'
    ORDER BY indexname
  "
  index_result <- dbGetQuery(conn, index_query)
  if (nrow(index_result) > 0) {
    print(index_result)
  } else {
    cat("⚠️ No indexes found on documents table\n")
  }
  cat("\n")

  # Table size analysis
  cat("--- TABLE SIZE ANALYSIS ---\n")
  size_query <- "
    SELECT
      pg_size_pretty(pg_total_relation_size('documents')) as total_size,
      pg_size_pretty(pg_relation_size('documents')) as table_size,
      pg_size_pretty(pg_indexes_size('documents')) as indexes_size
  "
  size_result <- dbGetQuery(conn, size_query)
  print(size_result)
  cat("\n")

  # Query plan analysis for common queries
  cat("--- QUERY PLAN ANALYSIS: Library Search Query ---\n")
  explain_query <- "
    EXPLAIN ANALYZE
    SELECT id, titulo, tipo, data
    FROM documents
    WHERE tipo = 'Lei'
    ORDER BY data DESC
    LIMIT 100
  "
  explain_result <- dbGetQuery(conn, explain_query)
  cat("\nQuery plan for filtered search (tipo = 'Lei', LIMIT 100):\n")
  print(explain_result)
  cat("\n")

  # Compare performance: 100 vs ALL records
  cat("--- PERFORMANCE COMPARISON: LIMIT 100 vs ALL RECORDS ---\n")

  # Time for 100 records
  cat("Testing LIMIT 100...\n")
  start_time <- Sys.time()
  result_100 <- dbGetQuery(conn, "SELECT id, titulo, tipo, data FROM documents ORDER BY data DESC LIMIT 100")
  time_100 <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
  cat("  Query time:", round(time_100 * 1000, 2), "ms\n")
  cat("  Records returned:", nrow(result_100), "\n")

  # Time for 1000 records
  cat("Testing LIMIT 1000...\n")
  start_time <- Sys.time()
  result_1000 <- dbGetQuery(conn, "SELECT id, titulo, tipo, data FROM documents ORDER BY data DESC LIMIT 1000")
  time_1000 <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
  cat("  Query time:", round(time_1000 * 1000, 2), "ms\n")
  cat("  Records returned:", nrow(result_1000), "\n")

  # Time for ALL records
  cat("Testing ALL records (no LIMIT)...\n")
  start_time <- Sys.time()
  result_all <- dbGetQuery(conn, "SELECT id, titulo, tipo, data FROM documents ORDER BY data DESC")
  time_all <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
  cat("  Query time:", round(time_all * 1000, 2), "ms\n")
  cat("  Records returned:", nrow(result_all), "\n")

  # Calculate size of result sets
  size_100 <- object.size(result_100)
  size_1000 <- object.size(result_1000)
  size_all <- object.size(result_all)

  cat("\n--- MEMORY USAGE ---\n")
  cat("100 records:", format(size_100, units = "auto"), "\n")
  cat("1000 records:", format(size_1000, units = "auto"), "\n")
  cat("ALL records:", format(size_all, units = "auto"), "\n")

  cat("\n--- PERFORMANCE IMPACT SUMMARY ---\n")
  cat("Time increase (100 -> ALL):", round(time_all / time_100, 2), "x slower\n")
  cat("Memory increase (100 -> ALL):", round(as.numeric(size_all) / as.numeric(size_100), 2), "x larger\n")

  if (time_all / time_100 > 10) {
    cat("\n⚠️ RECOMMENDATION: Loading ALL records is significantly slower (", round(time_all / time_100, 1), "x)\n")
    cat("   Consider implementing pagination or default LIMIT for better UX\n")
  } else {
    cat("\n✅ Performance impact is acceptable for loading all records\n")
  }
  cat("\n")

  # Test search query performance
  cat("--- SEARCH QUERY PERFORMANCE ---\n")
  search_query <- "
    SELECT id, titulo, tipo, data
    FROM documents
    WHERE titulo ILIKE '%tributário%'
    ORDER BY data DESC
    LIMIT 100
  "
  start_time <- Sys.time()
  search_result <- dbGetQuery(conn, search_query)
  search_time <- as.numeric(difftime(Sys.time(), start_time, units = "secs"))
  cat("Search query time (ILIKE):", round(search_time * 1000, 2), "ms\n")
  cat("Records found:", nrow(search_result), "\n")

  if (search_time > 1) {
    cat("\n⚠️ RECOMMENDATION: Text search is slow (", round(search_time * 1000, 2), "ms)\n")
    cat("   Consider adding full-text search index (GIN index on titulo)\n")
  } else {
    cat("\n✅ Search performance is acceptable\n")
  }
  cat("\n")

  return(list(
    indexes = index_result,
    table_size = size_result,
    performance = data.frame(
      query = c("100 records", "1000 records", "ALL records", "Search query"),
      time_ms = c(time_100 * 1000, time_1000 * 1000, time_all * 1000, search_time * 1000),
      record_count = c(nrow(result_100), nrow(result_1000), nrow(result_all), nrow(search_result)),
      memory_kb = c(as.numeric(size_100) / 1024, as.numeric(size_1000) / 1024,
                    as.numeric(size_all) / 1024, as.numeric(object.size(search_result)) / 1024)
    )
  ))
}

# ==============================================================================
# 4. GENERATE RECOMMENDATIONS
# ==============================================================================

generate_recommendations <- function(stats, quality, performance) {
  cat("================================================================================\n")
  cat("4. RECOMMENDATIONS\n")
  cat("================================================================================\n\n")

  cat("--- DATA CLEANING RECOMMENDATIONS ---\n")

  # Check for missing types in app
  if (length(stats$missing_in_app) > 0) {
    cat("1. ADD MISSING DOCUMENT TYPES TO APP FILTER\n")
    cat("   Missing types:", paste(stats$missing_in_app, collapse = ", "), "\n")
    cat("   Location: app_phoenix.R, line 170\n")
    cat("   Current: selectInput(\"library_tipo\", \"Tipo de Documento:\", choices = c(\"Todos\", \"Lei\", \"Decreto\", \"Projeto de Lei\"))\n")
    cat("   Suggested: Add", paste(stats$missing_in_app, collapse = ", "), "\n\n")
  }

  # Check for text quality issues
  if (quality$text_quality$double_spaces_titulo > 0 ||
      quality$text_quality$space_before_punct > 0) {
    cat("2. CLEAN TEXT FORMATTING ISSUES\n")
    cat("   SQL to fix double spaces:\n")
    cat("   UPDATE documents SET titulo = REGEXP_REPLACE(titulo, ' +', ' ', 'g');\n\n")
    cat("   SQL to fix space before punctuation:\n")
    cat("   UPDATE documents SET titulo = REGEXP_REPLACE(titulo, ' ([,.])', '\\1', 'g');\n\n")
  }

  # Check for duplicates
  if (quality$duplicates$total_duplicates > 0) {
    cat("3. HANDLE DUPLICATE DOCUMENTS\n")
    cat("   Total duplicate groups:", quality$duplicates$total_duplicates, "\n")
    cat("   SQL to identify duplicates:\n")
    cat("   SELECT titulo, tipo, data, COUNT(*) as count\n")
    cat("   FROM documents GROUP BY titulo, tipo, data HAVING COUNT(*) > 1;\n\n")
    cat("   SQL to remove duplicates (keeping oldest ID):\n")
    cat("   DELETE FROM documents WHERE id NOT IN (\n")
    cat("     SELECT MIN(id) FROM documents GROUP BY titulo, tipo, data\n")
    cat("   );\n\n")
  }

  cat("--- PERFORMANCE OPTIMIZATION RECOMMENDATIONS ---\n")

  # Check if indexes exist
  if (nrow(performance$indexes) == 0 ||
      !any(grepl("tipo", performance$indexes$indexdef)) ||
      !any(grepl("data", performance$indexes$indexdef))) {
    cat("4. ADD INDEXES FOR COMMON QUERIES\n")
    cat("   The Library tab filters by tipo and sorts by data\n")
    cat("   SQL to create indexes:\n")
    cat("   CREATE INDEX idx_documents_tipo ON documents(tipo);\n")
    cat("   CREATE INDEX idx_documents_data ON documents(data DESC);\n")
    cat("   CREATE INDEX idx_documents_tipo_data ON documents(tipo, data DESC);\n\n")
  }

  # Check for slow search
  search_time <- performance$performance$time_ms[performance$performance$query == "Search query"]
  if (search_time > 1000) {
    cat("5. ADD FULL-TEXT SEARCH INDEX\n")
    cat("   Text search (ILIKE) is slow:", round(search_time, 2), "ms\n")
    cat("   SQL to create full-text search index:\n")
    cat("   CREATE INDEX idx_documents_titulo_gin ON documents USING GIN (to_tsvector('portuguese', titulo));\n\n")
    cat("   Then modify search query to use full-text search:\n")
    cat("   WHERE to_tsvector('portuguese', titulo) @@ plainto_tsquery('portuguese', 'search_term')\n\n")
  }

  # Check for ALL records performance
  all_time <- performance$performance$time_ms[performance$performance$query == "ALL records"]
  limit_100_time <- performance$performance$time_ms[performance$performance$query == "100 records"]
  if (all_time / limit_100_time > 10) {
    cat("6. IMPLEMENT DEFAULT LIMIT IN LIBRARY TAB\n")
    cat("   Loading ALL records is", round(all_time / limit_100_time, 1), "x slower than 100 records\n")
    cat("   Current default in app: 100 records (good!)\n")
    cat("   But app allows 999999 (ALL) which could cause performance issues\n")
    cat("   Recommendation: Cap maximum at 10,000 or implement server-side pagination\n\n")
  }

  cat("--- SQL SCRIPT FOR DATA CLEANING ---\n")
  cat("Save this as: db/clean_data.sql\n\n")
  cat("BEGIN;\n\n")
  cat("-- Fix double spaces in titulo\n")
  cat("UPDATE documents SET titulo = REGEXP_REPLACE(titulo, ' +', ' ', 'g');\n\n")
  cat("-- Fix space before punctuation\n")
  cat("UPDATE documents SET titulo = REGEXP_REPLACE(titulo, ' ([,.])', '\\1', 'g');\n\n")
  cat("-- Trim whitespace from tipo\n")
  cat("UPDATE documents SET tipo = TRIM(tipo);\n\n")
  if (quality$duplicates$total_duplicates > 0) {
    cat("-- Remove duplicates (keeping oldest ID)\n")
    cat("DELETE FROM documents WHERE id NOT IN (\n")
    cat("  SELECT MIN(id) FROM documents GROUP BY titulo, tipo, data\n")
    cat(");\n\n")
  }
  cat("COMMIT;\n\n")

  cat("--- SQL SCRIPT FOR PERFORMANCE OPTIMIZATION ---\n")
  cat("Save this as: db/optimize_indexes.sql\n\n")
  cat("BEGIN;\n\n")
  cat("-- Create indexes for tipo filter\n")
  cat("CREATE INDEX IF NOT EXISTS idx_documents_tipo ON documents(tipo);\n\n")
  cat("-- Create index for date sorting\n")
  cat("CREATE INDEX IF NOT EXISTS idx_documents_data ON documents(data DESC);\n\n")
  cat("-- Create composite index for filtered + sorted queries\n")
  cat("CREATE INDEX IF NOT EXISTS idx_documents_tipo_data ON documents(tipo, data DESC);\n\n")
  cat("-- Create full-text search index for titulo\n")
  cat("CREATE INDEX IF NOT EXISTS idx_documents_titulo_gin \n")
  cat("  ON documents USING GIN (to_tsvector('portuguese', titulo));\n\n")
  cat("-- Analyze table to update query planner statistics\n")
  cat("ANALYZE documents;\n\n")
  cat("COMMIT;\n\n")
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================

main <- function() {
  cat("\n")
  cat("================================================================================\n")
  cat("MONITOR LEGISLATIVO - DATABASE ANALYSIS REPORT\n")
  cat("Generated:", format(Sys.time(), "%Y-%m-%d %H:%M:%S"), "\n")
  cat("================================================================================\n\n")

  # Connect to database
  conn <- connect_to_database()
  if (is.null(conn)) {
    cat("\n❌ Cannot proceed without database connection\n")
    cat("   Please check your database configuration and try again\n\n")
    return(invisible(NULL))
  }

  # Run analyses
  tryCatch({
    stats <- analyze_data_statistics(conn)
    quality <- analyze_data_quality(conn)
    performance <- analyze_performance(conn)
    generate_recommendations(stats, quality, performance)

    cat("================================================================================\n")
    cat("ANALYSIS COMPLETE\n")
    cat("================================================================================\n\n")

    # Save results summary
    results <- list(
      timestamp = Sys.time(),
      statistics = stats,
      quality = quality,
      performance = performance
    )

    # Optionally save to RDS file
    output_file <- "/Users/sofiadonario/Library/CloudStorage/OneDrive-Personal/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/db/analysis_results.rds"
    saveRDS(results, output_file)
    cat("Results saved to:", output_file, "\n\n")

    return(results)

  }, error = function(e) {
    cat("\n❌ ERROR during analysis:", e$message, "\n\n")
    return(NULL)
  }, finally = {
    # Close connection
    if (!is.null(conn)) {
      dbDisconnect(conn)
      cat("Database connection closed\n\n")
    }
  })
}

# Run the analysis
if (!interactive()) {
  main()
}
