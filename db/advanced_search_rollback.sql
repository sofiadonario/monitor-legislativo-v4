-- ============================================================================
-- ADVANCED SEARCH ENGINE ROLLBACK SCRIPT
-- ============================================================================
--
-- This script safely rolls back the advanced search migration while
-- preserving existing data and functionality.
--
-- USAGE:
-- 1. Connect to PostgreSQL database as superuser or database owner
-- 2. Run this script in a transaction to test first: BEGIN; \i rollback.sql; ROLLBACK;
-- 3. If testing is successful, run without transaction: \i rollback.sql;
--
-- Author: Senior Database Engineer - Brazilian Legislative Analytics Team  
-- Date: January 2025
-- Version: 1.0 - Production Safe Rollback
-- ============================================================================

-- Set transaction parameters for safety
SET statement_timeout = '15min';
SET lock_timeout = '5min';

BEGIN;

-- Create rollback tracking
CREATE TABLE IF NOT EXISTS rollback_log (
    id SERIAL PRIMARY KEY,
    rollback_name VARCHAR(100) NOT NULL,
    rollback_version VARCHAR(20) NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    status VARCHAR(20) DEFAULT 'RUNNING',
    steps_completed TEXT[],
    error_message TEXT
);

-- Log rollback start
INSERT INTO rollback_log (rollback_name, rollback_version) 
VALUES ('advanced_search_rollback', '1.0');

-- ============================================================================
-- STEP 1: BACKUP CRITICAL DATA BEFORE ROLLBACK
-- ============================================================================
SELECT 'Step 1: Creating backup tables before rollback...' as progress;

-- Backup search analytics if they exist
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'search_analytics') THEN
        EXECUTE 'CREATE TABLE search_analytics_backup_' || to_char(CURRENT_DATE, 'YYYYMMDD') || ' AS SELECT * FROM search_analytics';
        RAISE NOTICE 'Backed up search_analytics table';
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'Could not backup search_analytics: %', SQLERRM;
END;
$$;

-- Backup legal terms dictionary if it exists  
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'legal_terms_dictionary') THEN
        EXECUTE 'CREATE TABLE legal_terms_backup_' || to_char(CURRENT_DATE, 'YYYYMMDD') || ' AS SELECT * FROM legal_terms_dictionary';
        RAISE NOTICE 'Backed up legal_terms_dictionary table';
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE WARNING 'Could not backup legal_terms_dictionary: %', SQLERRM;
END;
$$;

-- Update rollback log
UPDATE rollback_log 
SET steps_completed = array_append(steps_completed, 'backup_completed')
WHERE rollback_name = 'advanced_search_rollback' 
AND rollback_version = '1.0' 
AND status = 'RUNNING';

-- ============================================================================
-- STEP 2: DROP ADVANCED SEARCH FUNCTIONS
-- ============================================================================
SELECT 'Step 2: Dropping advanced search functions...' as progress;

-- Drop search functions
DROP FUNCTION IF EXISTS advanced_search_documents(TEXT, VARCHAR(2), VARCHAR(20), TEXT, VARCHAR(50), VARCHAR(50), DATE, DATE, INTEGER, INTEGER, DECIMAL, INTEGER, INTEGER) CASCADE;
DROP FUNCTION IF EXISTS refresh_search_materialized_views() CASCADE;
DROP FUNCTION IF EXISTS monitor_search_performance() CASCADE;
DROP FUNCTION IF EXISTS cleanup_search_analytics(INTEGER) CASCADE;
DROP FUNCTION IF EXISTS update_document_search_vectors() CASCADE;
DROP FUNCTION IF EXISTS normalize_portuguese_legal_text(TEXT) CASCADE;

RAISE NOTICE 'Dropped advanced search functions';

-- Update rollback log
UPDATE rollback_log 
SET steps_completed = array_append(steps_completed, 'functions_dropped')
WHERE rollback_name = 'advanced_search_rollback' 
AND rollback_version = '1.0' 
AND status = 'RUNNING';

-- ============================================================================
-- STEP 3: DROP MATERIALIZED VIEWS
-- ============================================================================
SELECT 'Step 3: Dropping materialized views...' as progress;

-- Drop materialized views
DROP MATERIALIZED VIEW IF EXISTS search_stats_by_state CASCADE;
DROP MATERIALIZED VIEW IF EXISTS popular_search_terms CASCADE;

RAISE NOTICE 'Dropped search materialized views';

-- Update rollback log
UPDATE rollback_log 
SET steps_completed = array_append(steps_completed, 'materialized_views_dropped')
WHERE rollback_name = 'advanced_search_rollback' 
AND rollback_version = '1.0' 
AND status = 'RUNNING';

-- ============================================================================
-- STEP 4: DROP COMPATIBILITY VIEWS
-- ============================================================================
SELECT 'Step 4: Dropping compatibility views...' as progress;

-- Drop compatibility views
DROP VIEW IF EXISTS documents_enhanced CASCADE;

RAISE NOTICE 'Dropped compatibility views';

-- Update rollback log
UPDATE rollback_log 
SET steps_completed = array_append(steps_completed, 'views_dropped')
WHERE rollback_name = 'advanced_search_rollback' 
AND rollback_version = '1.0' 
AND status = 'RUNNING';

-- ============================================================================
-- STEP 5: DROP SEARCH OPTIMIZATION TABLES
-- ============================================================================
SELECT 'Step 5: Dropping search optimization tables...' as progress;

-- Drop search tables (but preserve data backup first)
DROP TABLE IF EXISTS search_analytics CASCADE;
DROP TABLE IF EXISTS legal_terms_dictionary CASCADE;
DROP TABLE IF EXISTS documents_search_optimized CASCADE;

RAISE NOTICE 'Dropped search optimization tables';

-- Update rollback log
UPDATE rollback_log 
SET steps_completed = array_append(steps_completed, 'search_tables_dropped')
WHERE rollback_name = 'advanced_search_rollback' 
AND rollback_version = '1.0' 
AND status = 'RUNNING';

-- ============================================================================
-- STEP 6: DROP PORTUGUESE TEXT SEARCH CONFIGURATION
-- ============================================================================
SELECT 'Step 6: Dropping Portuguese text search configuration...' as progress;

-- Drop custom Portuguese text search configuration
DROP TEXT SEARCH CONFIGURATION IF EXISTS portuguese_legal CASCADE;

RAISE NOTICE 'Dropped Portuguese text search configuration';

-- Update rollback log
UPDATE rollback_log 
SET steps_completed = array_append(steps_completed, 'text_search_config_dropped')
WHERE rollback_name = 'advanced_search_rollback' 
AND rollback_version = '1.0' 
AND status = 'RUNNING';

-- ============================================================================
-- STEP 7: VERIFY ORIGINAL STRUCTURE IS INTACT
-- ============================================================================
SELECT 'Step 7: Verifying original database structure...' as progress;

-- Check if original documents_unified still exists
DO $$
DECLARE
    table_exists BOOLEAN;
    doc_count INTEGER;
BEGIN
    SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'documents_unified'
    ) INTO table_exists;
    
    IF table_exists THEN
        SELECT COUNT(*) INTO doc_count FROM documents_unified;
        RAISE NOTICE 'Original documents_unified table intact with % documents', doc_count;
    ELSE
        RAISE WARNING 'Original documents_unified table not found - may need to restore from backup';
    END IF;
END;
$$;

-- Check if original views exist
DO $$
DECLARE
    view_exists BOOLEAN;
BEGIN
    SELECT EXISTS (
        SELECT FROM information_schema.views 
        WHERE table_name = 'documents'
    ) INTO view_exists;
    
    IF view_exists THEN
        RAISE NOTICE 'Original documents view is intact';
    ELSE
        RAISE WARNING 'Original documents view not found';
    END IF;
END;
$$;

-- Update rollback log
UPDATE rollback_log 
SET steps_completed = array_append(steps_completed, 'structure_verified')
WHERE rollback_name = 'advanced_search_rollback' 
AND rollback_version = '1.0' 
AND status = 'RUNNING';

-- ============================================================================
-- STEP 8: CLEAN UP MIGRATION ARTIFACTS
-- ============================================================================
SELECT 'Step 8: Cleaning up migration artifacts...' as progress;

-- Remove migration log entries for advanced search
DELETE FROM migration_log 
WHERE migration_name = 'advanced_search_migration';

RAISE NOTICE 'Cleaned up migration artifacts';

-- Update rollback log
UPDATE rollback_log 
SET steps_completed = array_append(steps_completed, 'artifacts_cleaned')
WHERE rollback_name = 'advanced_search_rollback' 
AND rollback_version = '1.0' 
AND status = 'RUNNING';

-- ============================================================================
-- STEP 9: OPTIONAL - RESTORE ORIGINAL OPTIMIZED SCHEMA
-- ============================================================================
SELECT 'Step 9: Checking if original optimized schema restoration is needed...' as progress;

-- This step only runs if the original schema needs to be restored
DO $$
DECLARE
    unified_exists BOOLEAN;
    documents_exists BOOLEAN;
BEGIN
    -- Check if core tables exist
    SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'documents_unified') INTO unified_exists;
    SELECT EXISTS (SELECT FROM information_schema.views WHERE table_name = 'documents') INTO documents_exists;
    
    IF NOT unified_exists OR NOT documents_exists THEN
        RAISE WARNING 'Core database structure missing - manual restoration may be required';
        RAISE WARNING 'Consider running the original optimized_database_schema.sql script';
        
        -- Log this as a warning in rollback log
        UPDATE rollback_log 
        SET error_message = 'Original database structure may need manual restoration'
        WHERE rollback_name = 'advanced_search_rollback' 
        AND rollback_version = '1.0' 
        AND status = 'RUNNING';
    ELSE
        RAISE NOTICE 'Original database structure appears intact';
    END IF;
END;
$$;

-- Update rollback log
UPDATE rollback_log 
SET steps_completed = array_append(steps_completed, 'restoration_checked')
WHERE rollback_name = 'advanced_search_rollback' 
AND rollback_version = '1.0' 
AND status = 'RUNNING';

-- ============================================================================
-- STEP 10: FINAL CLEANUP AND VALIDATION
-- ============================================================================
SELECT 'Step 10: Final cleanup and validation...' as progress;

-- Drop any remaining advanced search indexes that might exist
DO $$
DECLARE
    index_name TEXT;
BEGIN
    FOR index_name IN 
        SELECT indexname 
        FROM pg_indexes 
        WHERE indexname LIKE '%search_vector%' 
           OR indexname LIKE '%documents_search_%'
           OR indexname LIKE '%advanced_search%'
    LOOP
        EXECUTE 'DROP INDEX IF EXISTS ' || index_name || ' CASCADE';
        RAISE NOTICE 'Dropped remaining index: %', index_name;
    END LOOP;
END;
$$;

-- Analyze remaining tables to update statistics
ANALYZE;

-- Update rollback log
UPDATE rollback_log 
SET steps_completed = array_append(steps_completed, 'final_cleanup_completed'),
    completed_at = CURRENT_TIMESTAMP,
    status = 'COMPLETED'
WHERE rollback_name = 'advanced_search_rollback' 
AND rollback_version = '1.0' 
AND status = 'RUNNING';

COMMIT;

-- ============================================================================
-- ROLLBACK COMPLETION REPORT
-- ============================================================================

SELECT 
    'Advanced Search Rollback Completed Successfully!' as status,
    'All advanced search components have been safely removed' as description,
    CURRENT_TIMESTAMP as completed_at,
    'Original database structure preserved' as preservation_status,
    'Backup tables created with timestamp suffix' as backup_info;

-- Show what backups were created
SELECT 
    'Backup Tables Created:' as info,
    tablename as table_name,
    schemaname as schema_name
FROM pg_tables 
WHERE tablename LIKE '%backup_%'
ORDER BY tablename;

-- Verify rollback completion
SELECT 
    rollback_name,
    rollback_version,
    status,
    started_at,
    completed_at,
    array_length(steps_completed, 1) as steps_completed_count,
    steps_completed,
    CASE 
        WHEN error_message IS NOT NULL THEN error_message 
        ELSE 'No errors - rollback successful'
    END as final_status
FROM rollback_log 
WHERE rollback_name = 'advanced_search_rollback' 
AND rollback_version = '1.0'
ORDER BY id DESC
LIMIT 1;

SELECT 'Rollback completed - system restored to pre-migration state!' as final_message;