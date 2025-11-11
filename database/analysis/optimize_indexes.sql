-- ==============================================================================
-- DATABASE OPTIMIZATION SCRIPT FOR MONITOR LEGISLATIVO
-- ==============================================================================
-- This script creates indexes and optimizations for the documents table
-- to improve query performance in the Library tab and search functionality
--
-- Target queries:
-- 1. Library tab: Filter by tipo + sort by data DESC
-- 2. Search: ILIKE search on titulo
-- 3. Home tab: Aggregations by tipo, date ranges
--
-- Estimated improvement:
-- - Tipo filter queries: 10-100x faster
-- - Date sorting: 5-50x faster
-- - Text search: 50-500x faster (with full-text index)
-- ==============================================================================

BEGIN;

\echo '================================================================================'
\echo 'MONITOR LEGISLATIVO - DATABASE OPTIMIZATION'
\echo 'Started:', current_timestamp
\echo '================================================================================'

-- ==============================================================================
-- 1. CHECK CURRENT STATE
-- ==============================================================================

\echo '\n--- CURRENT INDEX STATE ---'
SELECT
  schemaname,
  tablename,
  indexname,
  indexdef
FROM pg_indexes
WHERE tablename = 'documents'
ORDER BY indexname;

\echo '\n--- TABLE SIZE (BEFORE OPTIMIZATION) ---'
SELECT
  pg_size_pretty(pg_total_relation_size('documents')) as total_size,
  pg_size_pretty(pg_relation_size('documents')) as table_size,
  pg_size_pretty(pg_indexes_size('documents')) as indexes_size
FROM documents
LIMIT 1;

-- ==============================================================================
-- 2. CREATE B-TREE INDEXES FOR FILTERING AND SORTING
-- ==============================================================================

\echo '\n--- CREATING INDEX ON TIPO (for filter queries) ---'
-- This index speeds up queries like: WHERE tipo = 'Lei'
CREATE INDEX IF NOT EXISTS idx_documents_tipo ON documents(tipo);
\echo '✓ Created idx_documents_tipo';

\echo '\n--- CREATING INDEX ON DATA (for sorting) ---'
-- This index speeds up: ORDER BY data DESC
-- DESC order is important for queries that sort newest-first
CREATE INDEX IF NOT EXISTS idx_documents_data_desc ON documents(data DESC);
\echo '✓ Created idx_documents_data_desc';

\echo '\n--- CREATING COMPOSITE INDEX (tipo + data) ---'
-- This index is optimal for queries that both filter by tipo AND sort by data
-- Example: WHERE tipo = 'Lei' ORDER BY data DESC LIMIT 100
-- PostgreSQL can use this single index for both operations
CREATE INDEX IF NOT EXISTS idx_documents_tipo_data ON documents(tipo, data DESC);
\echo '✓ Created idx_documents_tipo_data';

-- ==============================================================================
-- 3. CREATE FULL-TEXT SEARCH INDEX (GIN)
-- ==============================================================================

\echo '\n--- CREATING FULL-TEXT SEARCH INDEX ON TITULO ---'
-- This dramatically speeds up text searches
-- Instead of ILIKE '%term%' which requires full table scan,
-- use: WHERE to_tsvector('portuguese', titulo) @@ plainto_tsquery('portuguese', 'term')

-- GIN index for Portuguese full-text search
CREATE INDEX IF NOT EXISTS idx_documents_titulo_gin
  ON documents
  USING GIN (to_tsvector('portuguese', titulo));
\echo '✓ Created idx_documents_titulo_gin (Portuguese full-text)';

-- Optional: Add trigram index for fuzzy/partial matching (if pg_trgm extension is available)
-- This is useful for autocomplete and typo-tolerant search
DO $$
BEGIN
  -- Check if pg_trgm extension exists
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') THEN
    -- Create trigram index
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_documents_titulo_trgm ON documents USING GIN (titulo gin_trgm_ops)';
    RAISE NOTICE '✓ Created idx_documents_titulo_trgm (trigram index for fuzzy search)';
  ELSE
    RAISE NOTICE 'ℹ pg_trgm extension not available - skipping trigram index';
    RAISE NOTICE 'To enable fuzzy search, install extension: CREATE EXTENSION pg_trgm;';
  END IF;
END $$;

-- ==============================================================================
-- 4. CREATE INDEX ON ID (if not already primary key)
-- ==============================================================================

\echo '\n--- CHECKING PRIMARY KEY ON ID ---'
-- Ensure id has a B-tree index (usually automatic with PRIMARY KEY)
-- This is important for JOIN operations and single-record lookups
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conrelid = 'documents'::regclass
    AND contype = 'p'  -- primary key
  ) THEN
    RAISE NOTICE '⚠️ No PRIMARY KEY found on documents table';
    RAISE NOTICE 'Creating index on id...';
    EXECUTE 'CREATE UNIQUE INDEX IF NOT EXISTS idx_documents_id ON documents(id)';
    RAISE NOTICE '✓ Created idx_documents_id';
  ELSE
    RAISE NOTICE '✓ PRIMARY KEY exists on documents table';
  END IF;
END $$;

-- ==============================================================================
-- 5. ANALYZE TABLE FOR QUERY PLANNER
-- ==============================================================================

\echo '\n--- UPDATING TABLE STATISTICS ---'
-- ANALYZE gathers statistics about the table's content
-- This helps PostgreSQL's query planner choose the best indexes
ANALYZE documents;
\echo '✓ Table statistics updated';

-- ==============================================================================
-- 6. VERIFY NEW INDEXES
-- ==============================================================================

\echo '\n--- NEW INDEX STATE ---'
SELECT
  schemaname,
  tablename,
  indexname,
  pg_size_pretty(pg_relation_size(indexrelid)) as index_size,
  indexdef
FROM pg_indexes
JOIN pg_class ON pg_class.relname = indexname
WHERE tablename = 'documents'
ORDER BY indexname;

\echo '\n--- TABLE SIZE (AFTER OPTIMIZATION) ---'
SELECT
  pg_size_pretty(pg_total_relation_size('documents')) as total_size,
  pg_size_pretty(pg_relation_size('documents')) as table_size,
  pg_size_pretty(pg_indexes_size('documents')) as indexes_size
FROM documents
LIMIT 1;

-- ==============================================================================
-- 7. TEST QUERY PERFORMANCE
-- ==============================================================================

\echo '\n--- TESTING QUERY PERFORMANCE ---'

\echo '\nTest 1: Filter by tipo + sort by data (Library tab query)'
EXPLAIN (ANALYZE, BUFFERS, TIMING)
SELECT id, titulo, tipo, data
FROM documents
WHERE tipo = 'Lei'
ORDER BY data DESC
LIMIT 100;

\echo '\nTest 2: Full-text search (using new GIN index)'
EXPLAIN (ANALYZE, BUFFERS, TIMING)
SELECT id, titulo, tipo, data
FROM documents
WHERE to_tsvector('portuguese', titulo) @@ plainto_tsquery('portuguese', 'tributário')
ORDER BY data DESC
LIMIT 100;

\echo '\nTest 3: Sort all documents by date (Home tab query)'
EXPLAIN (ANALYZE, BUFFERS, TIMING)
SELECT id, titulo, tipo, data
FROM documents
ORDER BY data DESC
LIMIT 10;

-- ==============================================================================
-- 8. RECOMMENDATIONS FOR APP CODE
-- ==============================================================================

\echo '\n================================================================================'
\echo 'OPTIMIZATION COMPLETE'
\echo 'Finished:', current_timestamp
\echo '================================================================================'
\echo ''
\echo 'NEXT STEPS:'
\echo ''
\echo '1. COMMIT CHANGES:'
\echo '   If tests look good, run: COMMIT;'
\echo '   If not satisfied, run: ROLLBACK;'
\echo ''
\echo '2. UPDATE APP CODE TO USE FULL-TEXT SEARCH:'
\echo '   In app_phoenix.R, replace ILIKE with full-text search:'
\echo ''
\echo '   OLD CODE (line 272):'
\echo '   conditions <- c(conditions, paste0("titulo ILIKE ''%", search_term, "%''"))'
\echo ''
\echo '   NEW CODE:'
\echo '   conditions <- c(conditions, paste0("to_tsvector(''portuguese'', titulo) @@ plainto_tsquery(''portuguese'', ''", search_term, "'')"))'
\echo ''
\echo '3. UPDATE APP FILTERS TO INCLUDE ALL TIPO VALUES:'
\echo '   Run this query to get all tipo values:'
\echo '   SELECT DISTINCT tipo FROM documents ORDER BY tipo;'
\echo ''
\echo '   Then update app_phoenix.R line 170:'
\echo '   selectInput("library_tipo", "Tipo de Documento:", choices = c("Todos", ...all_tipos...))'
\echo ''
\echo '4. MONITOR INDEX USAGE:'
\echo '   SELECT * FROM pg_stat_user_indexes WHERE tablename = ''documents'';'
\echo ''
\echo '5. MAINTENANCE:'
\echo '   Set up automatic VACUUM and ANALYZE (usually done by autovacuum)'
\echo '   For large updates, manually run: VACUUM ANALYZE documents;'
\echo ''
\echo '================================================================================'

-- DO NOT AUTO-COMMIT - Let user review and decide
-- User must manually run COMMIT or ROLLBACK
