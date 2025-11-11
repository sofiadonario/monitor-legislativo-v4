-- ==============================================================================
-- POSTGRESQL DATABASE ANALYSIS FOR MONITOR LEGISLATIVO
-- ==============================================================================
-- This SQL script performs comprehensive data quality and performance analysis
-- Run these queries in psql, pgAdmin, DBeaver, or any PostgreSQL client
-- ==============================================================================

\echo '================================================================================'
\echo '1. DATA STATISTICS ANALYSIS'
\echo '================================================================================'

-- Total document count
\echo '\n--- TOTAL DOCUMENT COUNT ---'
SELECT COUNT(*) as total_documents FROM documents;

-- Document type distribution
\echo '\n--- DOCUMENT TYPE DISTRIBUTION ---'
SELECT
  tipo,
  COUNT(*) as count,
  ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 2) as percentage
FROM documents
GROUP BY tipo
ORDER BY count DESC;

-- Unique document types
\echo '\n--- UNIQUE DOCUMENT TYPES ---'
SELECT DISTINCT tipo FROM documents ORDER BY tipo;

-- Date range analysis
\echo '\n--- DATE RANGE ANALYSIS ---'
SELECT
  MIN(data) as oldest_date,
  MAX(data) as newest_date,
  MAX(data) - MIN(data) as date_range_days
FROM documents;

-- Documents per year
\echo '\n--- DOCUMENTS PER YEAR ---'
SELECT
  EXTRACT(YEAR FROM data) as year,
  COUNT(*) as count
FROM documents
GROUP BY year
ORDER BY year DESC
LIMIT 10;

-- Documents per month (recent 12 months)
\echo '\n--- DOCUMENTS PER MONTH (Recent 12 months) ---'
SELECT
  TO_CHAR(data, 'YYYY-MM') as year_month,
  COUNT(*) as count
FROM documents
WHERE data >= CURRENT_DATE - INTERVAL '12 months'
GROUP BY year_month
ORDER BY year_month DESC;

\echo '================================================================================'
\echo '2. DATA QUALITY ANALYSIS'
\echo '================================================================================'

-- NULL value analysis
\echo '\n--- NULL VALUE ANALYSIS ---'
SELECT
  COUNT(*) as total_records,
  COUNT(*) FILTER (WHERE id IS NULL) as null_id,
  COUNT(*) FILTER (WHERE titulo IS NULL) as null_titulo,
  COUNT(*) FILTER (WHERE tipo IS NULL) as null_tipo,
  COUNT(*) FILTER (WHERE data IS NULL) as null_data,
  COUNT(*) FILTER (WHERE titulo = '') as empty_titulo,
  COUNT(*) FILTER (WHERE tipo = '') as empty_tipo
FROM documents;

-- Text quality analysis
\echo '\n--- TEXT QUALITY ANALYSIS ---'
SELECT
  COUNT(*) FILTER (WHERE titulo LIKE '%  %') as double_spaces_titulo,
  COUNT(*) FILTER (WHERE titulo LIKE '% ,%' OR titulo LIKE '% .%') as space_before_punct,
  COUNT(*) FILTER (WHERE titulo ~ '[^\x00-\x7F]') as non_ascii_titulo,
  COUNT(*) FILTER (WHERE LENGTH(titulo) < 10) as very_short_titulo,
  COUNT(*) FILTER (WHERE LENGTH(titulo) > 500) as very_long_titulo,
  AVG(LENGTH(titulo)) as avg_titulo_length,
  MIN(LENGTH(titulo)) as min_titulo_length,
  MAX(LENGTH(titulo)) as max_titulo_length
FROM documents;

-- Sample problematic titles (short)
\echo '\n--- SAMPLE VERY SHORT TITLES (< 10 characters) ---'
SELECT id, titulo, tipo, data, LENGTH(titulo) as length
FROM documents
WHERE LENGTH(titulo) < 10
LIMIT 10;

-- Sample problematic titles (double spaces)
\echo '\n--- SAMPLE TITLES WITH DOUBLE SPACES ---'
SELECT id, titulo, tipo, data
FROM documents
WHERE titulo LIKE '%  %'
LIMIT 10;

-- Duplicate detection
\echo '\n--- DUPLICATE DETECTION ---'
SELECT
  COUNT(*) as total_duplicate_groups,
  SUM(dup_count - 1) as total_duplicate_records
FROM (
  SELECT titulo, tipo, data, COUNT(*) as dup_count
  FROM documents
  GROUP BY titulo, tipo, data
  HAVING COUNT(*) > 1
) AS duplicates;

-- Sample duplicates
\echo '\n--- SAMPLE DUPLICATE GROUPS ---'
SELECT titulo, tipo, data, COUNT(*) as count
FROM documents
GROUP BY titulo, tipo, data
HAVING COUNT(*) > 1
ORDER BY count DESC
LIMIT 10;

-- Check for inconsistent tipo formatting
\echo '\n--- TIPO FORMATTING CONSISTENCY ---'
SELECT
  tipo,
  COUNT(*) as total_count,
  COUNT(*) FILTER (WHERE tipo != TRIM(tipo)) as has_whitespace,
  COUNT(*) FILTER (WHERE tipo ~ '^[A-Z]') as starts_uppercase,
  COUNT(*) FILTER (WHERE tipo ~ '^[a-z]') as starts_lowercase,
  COUNT(*) FILTER (WHERE tipo ~ '[0-9]') as contains_numbers
FROM documents
GROUP BY tipo
ORDER BY total_count DESC;

-- Check for special characters in tipo
\echo '\n--- TIPO SPECIAL CHARACTERS ---'
SELECT DISTINCT tipo, LENGTH(tipo) as length
FROM documents
WHERE tipo ~ '[^A-Za-z0-9 àáâãçéêíóôõúü-]'
ORDER BY tipo;

\echo '================================================================================'
\echo '3. PERFORMANCE ANALYSIS'
\echo '================================================================================'

-- Existing indexes
\echo '\n--- EXISTING INDEXES ---'
SELECT
  schemaname,
  tablename,
  indexname,
  indexdef
FROM pg_indexes
WHERE tablename = 'documents'
ORDER BY indexname;

-- Table size analysis
\echo '\n--- TABLE SIZE ANALYSIS ---'
SELECT
  pg_size_pretty(pg_total_relation_size('documents')) as total_size,
  pg_size_pretty(pg_relation_size('documents')) as table_size,
  pg_size_pretty(pg_indexes_size('documents')) as indexes_size,
  (SELECT COUNT(*) FROM documents) as row_count,
  pg_size_pretty(pg_total_relation_size('documents') / NULLIF((SELECT COUNT(*) FROM documents), 0)) as avg_row_size
FROM documents
LIMIT 1;

-- Index usage statistics
\echo '\n--- INDEX USAGE STATISTICS ---'
SELECT
  schemaname,
  tablename,
  indexname,
  idx_scan as index_scans,
  idx_tup_read as tuples_read,
  idx_tup_fetch as tuples_fetched
FROM pg_stat_user_indexes
WHERE tablename = 'documents'
ORDER BY idx_scan DESC;

-- Table statistics
\echo '\n--- TABLE STATISTICS ---'
SELECT
  schemaname,
  relname,
  n_tup_ins as inserts,
  n_tup_upd as updates,
  n_tup_del as deletes,
  n_live_tup as live_tuples,
  n_dead_tup as dead_tuples,
  last_vacuum,
  last_autovacuum,
  last_analyze,
  last_autoanalyze
FROM pg_stat_user_tables
WHERE relname = 'documents';

-- Query plan for typical Library search (tipo filter + date sort)
\echo '\n--- QUERY PLAN: Library Search (tipo filter) ---'
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT id, titulo, tipo, data
FROM documents
WHERE tipo = 'Lei'
ORDER BY data DESC
LIMIT 100;

-- Query plan for text search (ILIKE)
\echo '\n--- QUERY PLAN: Text Search (ILIKE) ---'
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT id, titulo, tipo, data
FROM documents
WHERE titulo ILIKE '%tributário%'
ORDER BY data DESC
LIMIT 100;

-- Query plan for loading all records (worst case)
\echo '\n--- QUERY PLAN: Load ALL Records ---'
EXPLAIN (ANALYZE, BUFFERS, VERBOSE)
SELECT id, titulo, tipo, data
FROM documents
ORDER BY data DESC;

\echo '================================================================================'
\echo '4. MISSING INDEX RECOMMENDATIONS'
\echo '================================================================================'

-- Check if recommended indexes exist
\echo '\n--- RECOMMENDED INDEXES CHECK ---'
SELECT
  CASE
    WHEN EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'documents' AND indexname LIKE '%tipo%')
    THEN '✓ Index on tipo exists'
    ELSE '✗ MISSING: Index on tipo (recommended for filter queries)'
  END as tipo_index_status,
  CASE
    WHEN EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'documents' AND indexname LIKE '%data%')
    THEN '✓ Index on data exists'
    ELSE '✗ MISSING: Index on data (recommended for sorting)'
  END as data_index_status,
  CASE
    WHEN EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'documents' AND indexdef LIKE '%gin%' AND indexdef LIKE '%titulo%')
    THEN '✓ Full-text index on titulo exists'
    ELSE '✗ MISSING: Full-text index on titulo (recommended for search)'
  END as fulltext_index_status;

\echo '================================================================================'
\echo '5. DATA INTEGRITY CHECKS'
\echo '================================================================================'

-- Check for orphaned or inconsistent data
\echo '\n--- DATA INTEGRITY CHECKS ---'
SELECT
  COUNT(*) FILTER (WHERE id IS NULL) as null_ids,
  COUNT(*) FILTER (WHERE id < 1) as invalid_ids,
  COUNT(*) FILTER (WHERE data > CURRENT_DATE) as future_dates,
  COUNT(*) FILTER (WHERE data < '1900-01-01') as ancient_dates,
  COUNT(*) FILTER (WHERE LENGTH(TRIM(titulo)) = 0) as blank_titles
FROM documents;

-- Check for ID gaps (may indicate deleted records)
\echo '\n--- ID SEQUENCE ANALYSIS ---'
SELECT
  MIN(id) as min_id,
  MAX(id) as max_id,
  COUNT(*) as total_records,
  MAX(id) - MIN(id) + 1 as expected_records,
  (MAX(id) - MIN(id) + 1) - COUNT(*) as missing_ids
FROM documents;

\echo '================================================================================'
\echo 'ANALYSIS COMPLETE'
\echo '================================================================================'
