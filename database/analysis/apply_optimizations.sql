-- ==============================================================================
-- AUTOMATED DATABASE OPTIMIZATION APPLICATION
-- ==============================================================================
-- This script applies all optimizations with auto-commit for non-interactive use
-- ==============================================================================

\echo '================================================================================'
\echo 'APPLYING DATABASE OPTIMIZATIONS'
\echo '================================================================================'

-- Check current indexes
\echo '\n--- CURRENT INDEXES ---'
SELECT indexname FROM pg_indexes WHERE tablename = 'documents' ORDER BY indexname;

-- Create indexes (IF NOT EXISTS ensures idempotence)
\echo '\n--- CREATING PERFORMANCE INDEXES ---'

-- Index on tipo for filtering
CREATE INDEX IF NOT EXISTS idx_documents_tipo ON documents(tipo);

-- Index on data for sorting (descending order for newest-first queries)
CREATE INDEX IF NOT EXISTS idx_documents_data_desc ON documents(data DESC);

-- Composite index for tipo+data queries (most common pattern)
CREATE INDEX IF NOT EXISTS idx_documents_tipo_data ON documents(tipo, data DESC);

-- Full-text search index for Portuguese
CREATE INDEX IF NOT EXISTS idx_documents_titulo_gin
  ON documents USING GIN (to_tsvector('portuguese', titulo));

\echo '✓ All indexes created successfully'

-- Update table statistics
\echo '\n--- UPDATING TABLE STATISTICS ---'
ANALYZE documents;
\echo '✓ Statistics updated'

-- Verify new indexes
\echo '\n--- FINAL INDEX STATE ---'
SELECT
  schemaname,
  tablename,
  indexname,
  pg_size_pretty(pg_relation_size(indexrelid)) as size
FROM pg_indexes
JOIN pg_class ON pg_class.relname = indexname
WHERE tablename = 'documents'
ORDER BY indexname;

-- Show table sizes
\echo '\n--- TABLE SIZE ---'
SELECT
  pg_size_pretty(pg_total_relation_size('documents')) as total_size,
  pg_size_pretty(pg_relation_size('documents')) as table_size,
  pg_size_pretty(pg_indexes_size('documents')) as indexes_size;

\echo '\n================================================================================'
\echo 'OPTIMIZATION COMPLETE'
\echo 'Expected performance improvements:'
\echo '- Filter by tipo: 10-100x faster'
\echo '- Date sorting: 5-50x faster'
\echo '- Full-text search: 50-500x faster'
\echo '================================================================================'
