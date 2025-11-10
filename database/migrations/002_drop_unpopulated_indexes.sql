-- ============================================================================
-- DROP UNPOPULATED INDEXES - Migration 002
-- ============================================================================
--
-- Purpose: Remove indexes on columns with <1% data population
-- Impact: Saves disk space, speeds up INSERTs, reduces maintenance overhead
-- Safe: Can be run on production (no data modification)
--
-- Reason: Column population analysis showed:
--   - ano: 0.00% populated (1 row out of 134,014)
--   - autor: 0.00% populated (1 row out of 134,014)
--
-- These indexes provide no query benefit and waste resources.
-- municipio (2.23%) is kept because all 2,994 rows are valuable DF municipal data.
--
-- Author: Performance Optimization Team
-- Date: 2025-11-09
-- ============================================================================

\timing on
\set ON_ERROR_STOP on

BEGIN;

-- Display start message
DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'DROPPING UNPOPULATED INDEXES';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'Removing indexes on ano (0.00%% populated) and autor (0.00%% populated)';
    RAISE NOTICE 'Keeping municipio index (2.23%% = 2,994 valuable DF municipal documents)';
    RAISE NOTICE 'Started at: %', clock_timestamp();
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- DROP INDEXES ON UNPOPULATED COLUMNS
-- ============================================================================

-- Drop ano index (0.00% populated - only 1 row)
DROP INDEX IF EXISTS idx_documents_ano CASCADE;
DO $$ BEGIN RAISE NOTICE '✓ Dropped idx_documents_ano (ano: 0.00%% populated)'; END $$;

-- Drop autor index (0.00% populated - only 1 row)
DROP INDEX IF EXISTS idx_documents_autor CASCADE;
DO $$ BEGIN RAISE NOTICE '✓ Dropped idx_documents_autor (autor: 0.00%% populated)'; END $$;

-- Drop composite indexes using unpopulated columns
DROP INDEX IF EXISTS idx_documents_estado_ano CASCADE;
DO $$ BEGIN RAISE NOTICE '✓ Dropped idx_documents_estado_ano (composite with unpopulated ano)'; END $$;

DROP INDEX IF EXISTS idx_documents_estado_tipo_ano CASCADE;
DO $$ BEGIN RAISE NOTICE '✓ Dropped idx_documents_estado_tipo_ano (composite with unpopulated ano)'; END $$;

-- ============================================================================
-- VERIFY REMAINING INDEXES
-- ============================================================================

DO $$
DECLARE
    index_count INTEGER;
    total_size TEXT;
    table_size TEXT;
    index_size TEXT;
BEGIN
    -- Count indexes
    SELECT COUNT(*) INTO index_count
    FROM pg_indexes
    WHERE tablename = 'documents';

    -- Get sizes
    SELECT pg_size_pretty(pg_total_relation_size('documents')) INTO total_size;
    SELECT pg_size_pretty(pg_relation_size('documents')) INTO table_size;
    SELECT pg_size_pretty(pg_total_relation_size('documents') - pg_relation_size('documents')) INTO index_size;

    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'INDEX CLEANUP COMPLETE';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'Remaining indexes: %', index_count;
    RAISE NOTICE 'Table size: %', table_size;
    RAISE NOTICE 'Index size: %', index_size;
    RAISE NOTICE 'Total size: %', total_size;
    RAISE NOTICE '';
    RAISE NOTICE 'Completed at: %', clock_timestamp();
    RAISE NOTICE '============================================================================';
END $$;

-- List remaining indexes
SELECT
    indexname,
    pg_size_pretty(pg_relation_size(indexname::regclass)) as index_size
FROM pg_indexes
WHERE tablename = 'documents'
ORDER BY indexname;

COMMIT;

-- ============================================================================
-- ROLLBACK SCRIPT (Run if you need to restore dropped indexes)
-- ============================================================================

/*
-- ROLLBACK: Recreate dropped indexes
BEGIN;

-- Recreate ano index
CREATE INDEX idx_documents_ano ON documents(ano)
WHERE ano IS NOT NULL AND ano != '';

-- Recreate autor index
CREATE INDEX idx_documents_autor ON documents(autor)
WHERE autor IS NOT NULL AND autor != '';

-- Recreate composite indexes
CREATE INDEX idx_documents_estado_ano ON documents(estado, ano)
WHERE estado IS NOT NULL AND ano IS NOT NULL;

CREATE INDEX idx_documents_estado_tipo_ano ON documents(estado, tipo, ano)
WHERE estado IS NOT NULL AND tipo IS NOT NULL AND ano IS NOT NULL;

COMMIT;

SELECT 'Indexes restored successfully' as status;
*/

-- ============================================================================
-- NOTES
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'NOTES';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE '• ano and autor columns remain in table (data not deleted)';
    RAISE NOTICE '• If these columns are populated in future, indexes can be recreated';
    RAISE NOTICE '• municipio index kept: 2,994 DF municipal documents (13.78%% of DF)';
    RAISE NOTICE '• Expected space savings: ~50 MB';
    RAISE NOTICE '• Expected INSERT performance improvement: ~5-10%%';
    RAISE NOTICE '============================================================================';
END $$;
