-- create_library_indexes.sql
-- Database Performance Indexes for Library Tab Optimization
-- ============================================================================
-- Purpose: Create indexes to optimize library tab query performance
-- Target: <200ms query response time for 90th percentile
-- Created: 2025
-- ============================================================================

-- Check if we're connected to the right database
\echo 'Creating performance indexes for Monitor Legislativo v4...'

-- ============================================================================
-- 1. CORE SEARCH INDEXES
-- ============================================================================

-- Index for category/tipo filtering
CREATE INDEX IF NOT EXISTS idx_documents_tipo
ON documents(tipo);

-- Index for state/estado filtering
CREATE INDEX IF NOT EXISTS idx_documents_estado
ON documents(estado);

-- Index for date filtering and sorting
CREATE INDEX IF NOT EXISTS idx_documents_data
ON documents(data DESC);

-- Composite index for estado + data (common filter combination)
CREATE INDEX IF NOT EXISTS idx_documents_estado_data
ON documents(estado, data DESC);

-- Composite index for tipo + data (common filter combination)
CREATE INDEX IF NOT EXISTS idx_documents_tipo_data
ON documents(tipo, data DESC);

-- ============================================================================
-- 2. FULL-TEXT SEARCH INDEXES
-- ============================================================================

-- Full-text search index for titulo (Portuguese language support)
CREATE INDEX IF NOT EXISTS idx_documents_titulo_fulltext
ON documents USING gin(to_tsvector('portuguese', titulo));

-- Full-text search index for combined titulo + content (if content column exists)
-- Note: This will only work if 'conteudo' or 'content' column exists
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'documents'
        AND column_name IN ('conteudo', 'content', 'ementa', 'summary')
    ) THEN
        -- Create index on titulo + content
        EXECUTE 'CREATE INDEX IF NOT EXISTS idx_documents_fulltext
                 ON documents USING gin(
                     to_tsvector(''portuguese'',
                         COALESCE(titulo, '''') || '' '' ||
                         COALESCE(conteudo, '''') || '' '' ||
                         COALESCE(content, '''') || '' '' ||
                         COALESCE(ementa, '''') || '' '' ||
                         COALESCE(summary, '''')
                     )
                 )';
    END IF;
END $$;

-- ============================================================================
-- 3. ADVANCED FILTERING INDEXES
-- ============================================================================

-- Index for year extraction (common in year range filters)
CREATE INDEX IF NOT EXISTS idx_documents_year
ON documents(EXTRACT(YEAR FROM data));

-- Index for URN/identifier lookups (if urn column exists)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'documents'
        AND column_name = 'urn'
    ) THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS idx_documents_urn
                 ON documents(urn)';
    END IF;
END $$;

-- Index for document ID (primary key performance)
CREATE INDEX IF NOT EXISTS idx_documents_id
ON documents(id);

-- ============================================================================
-- 4. THEME/CATEGORY INDEXES (if columns exist)
-- ============================================================================

-- Index for tema/theme column
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'documents'
        AND column_name IN ('tema', 'theme', 'categoria')
    ) THEN
        EXECUTE 'CREATE INDEX IF NOT EXISTS idx_documents_tema
                 ON documents(tema)';
        EXECUTE 'CREATE INDEX IF NOT EXISTS idx_documents_theme
                 ON documents(theme)';
        EXECUTE 'CREATE INDEX IF NOT EXISTS idx_documents_categoria
                 ON documents(categoria)';
    END IF;
END $$;

-- ============================================================================
-- 5. PARTIAL INDEXES FOR COMMON QUERIES
-- ============================================================================

-- Partial index for recent documents (last 2 years)
CREATE INDEX IF NOT EXISTS idx_documents_recent
ON documents(data DESC)
WHERE data >= CURRENT_DATE - INTERVAL '2 years';

-- Partial index for federal documents
CREATE INDEX IF NOT EXISTS idx_documents_federal
ON documents(data DESC)
WHERE estado = 'BR' OR estado = 'Federal';

-- ============================================================================
-- 6. PERFORMANCE MONITORING
-- ============================================================================

-- Create a function to check index usage
CREATE OR REPLACE FUNCTION check_library_index_usage()
RETURNS TABLE(
    index_name TEXT,
    table_name TEXT,
    index_size TEXT,
    scans BIGINT,
    tuples_read BIGINT,
    tuples_fetched BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        i.indexrelname::TEXT AS index_name,
        t.relname::TEXT AS table_name,
        pg_size_pretty(pg_relation_size(i.indexrelid))::TEXT AS index_size,
        s.idx_scan AS scans,
        s.idx_tup_read AS tuples_read,
        s.idx_tup_fetch AS tuples_fetched
    FROM pg_stat_user_indexes s
    JOIN pg_index i ON s.indexrelid = i.indexrelid
    JOIN pg_class t ON i.indrelid = t.oid
    WHERE t.relname = 'documents'
    ORDER BY s.idx_scan DESC;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 7. ANALYZE TABLES
-- ============================================================================

-- Update table statistics for query planner
ANALYZE documents;

-- ============================================================================
-- 8. VACUUM OPTIMIZATION
-- ============================================================================

-- Vacuum table to reclaim space and update statistics
VACUUM ANALYZE documents;

-- ============================================================================
-- OUTPUT SUMMARY
-- ============================================================================

\echo ''
\echo 'Index creation completed successfully!'
\echo ''
\echo 'Created indexes:'
\echo '  - idx_documents_tipo (document type filtering)'
\echo '  - idx_documents_estado (state/jurisdiction filtering)'
\echo '  - idx_documents_data (date sorting and filtering)'
\echo '  - idx_documents_estado_data (composite state + date)'
\echo '  - idx_documents_tipo_data (composite type + date)'
\echo '  - idx_documents_titulo_fulltext (full-text search - Portuguese)'
\echo '  - idx_documents_year (year range filtering)'
\echo '  - idx_documents_id (primary key performance)'
\echo '  - idx_documents_recent (partial index for recent docs)'
\echo '  - idx_documents_federal (partial index for federal docs)'
\echo ''
\echo 'Performance monitoring function created:'
\echo '  - check_library_index_usage() - Run to check index effectiveness'
\echo ''
\echo 'To check index usage, run:'
\echo '  SELECT * FROM check_library_index_usage();'
\echo ''
\echo 'Expected performance improvements:'
\echo '  - Query response time: <200ms (90th percentile)'
\echo '  - Category filtering: <100ms'
\echo '  - Geographic filtering: <150ms'
\echo '  - Full-text search: <500ms'
\echo ''

-- ============================================================================
-- 9. RECOMMENDATIONS
-- ============================================================================

\echo 'Recommendations:'
\echo '  1. Monitor index usage with check_library_index_usage()'
\echo '  2. Run VACUUM ANALYZE documents weekly'
\echo '  3. Consider pg_stat_statements for query performance tracking'
\echo '  4. Monitor disk space - indexes require additional storage'
\echo '  5. Test query performance before and after index creation'
\echo ''
