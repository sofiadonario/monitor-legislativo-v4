-- ============================================================================
-- POSTGRESQL COLLATION FIX FOR BRAZILIAN LEGISLATIVE MONITORING SYSTEM
-- ============================================================================
--
-- This SQL script addresses common PostgreSQL collation issues that may occur
-- in Railway deployments or when migrating Brazilian Portuguese text data
-- between different PostgreSQL installations.
--
-- COMMON ISSUES ADDRESSED:
-- 1. Missing pt_BR.UTF-8 collation
-- 2. Inconsistent text sorting for Portuguese text
-- 3. Case-insensitive search problems with accented characters
-- 4. Index corruption due to collation mismatches
--
-- USAGE:
-- Connect to your PostgreSQL database as a superuser and execute this script:
-- psql -h your-host -U your-user -d your-database -f postgres_collation_fix.sql
--
-- Railway Usage:
-- railway connect postgres
-- \i docs/postgres_collation_fix.sql
--
-- ============================================================================

-- Display current database and connection info
SELECT current_database() as database_name,
       version() as postgres_version,
       current_timestamp as execution_time;

-- ============================================================================
-- STEP 1: CHECK EXISTING COLLATIONS
-- ============================================================================

-- List all available collations (especially Portuguese ones)
SELECT
    collname as collation_name,
    collcollate as lc_collate,
    collctype as lc_ctype,
    collisdeterministic as is_deterministic
FROM pg_collation
WHERE collname LIKE '%pt%' OR collname LIKE '%BR%' OR collname LIKE '%portuguese%'
ORDER BY collname;

-- Check current database default collation
SELECT
    datname as database_name,
    datcollate as default_collate,
    datctype as default_ctype,
    encoding
FROM pg_database
WHERE datname = current_database();

-- ============================================================================
-- STEP 2: CREATE MISSING PORTUGUESE COLLATIONS (IF NEEDED)
-- ============================================================================

-- Create pt_BR collation if it doesn't exist
-- Note: This may fail on some systems where pt_BR locale is not installed
-- In such cases, we'll fall back to available alternatives

DO $$
BEGIN
    -- Try to create pt_BR.UTF-8 collation
    IF NOT EXISTS (SELECT 1 FROM pg_collation WHERE collname = 'pt_BR_utf8') THEN
        BEGIN
            CREATE COLLATION pt_BR_utf8 (
                provider = 'libc',
                locale = 'pt_BR.UTF-8'
            );
            RAISE NOTICE 'Created pt_BR_utf8 collation successfully';
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'Could not create pt_BR_utf8 collation: %', SQLERRM;
            RAISE NOTICE 'This is likely because pt_BR.UTF-8 locale is not installed on the system';
        END;
    ELSE
        RAISE NOTICE 'pt_BR_utf8 collation already exists';
    END IF;

    -- Try to create case-insensitive Portuguese collation
    IF NOT EXISTS (SELECT 1 FROM pg_collation WHERE collname = 'pt_BR_ci') THEN
        BEGIN
            CREATE COLLATION pt_BR_ci (
                provider = 'icu',
                locale = 'pt-BR-x-icu',
                deterministic = false
            );
            RAISE NOTICE 'Created pt_BR_ci case-insensitive collation successfully';
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'Could not create pt_BR_ci collation: %', SQLERRM;
            RAISE NOTICE 'ICU provider may not be available or pt-BR locale not found';
        END;
    ELSE
        RAISE NOTICE 'pt_BR_ci collation already exists';
    END IF;
END
$$;

-- ============================================================================
-- STEP 3: IDENTIFY PROBLEMATIC TEXT COLUMNS
-- ============================================================================

-- Find all text columns in user tables that might need collation fixes
SELECT
    t.table_schema,
    t.table_name,
    c.column_name,
    c.data_type,
    c.collation_name,
    CASE
        WHEN c.collation_name IS NULL THEN 'Using database default'
        WHEN c.collation_name LIKE '%C%' OR c.collation_name LIKE '%POSIX%' THEN 'May cause issues with Portuguese text'
        ELSE 'OK'
    END as collation_status
FROM information_schema.tables t
JOIN information_schema.columns c ON t.table_name = c.table_name
    AND t.table_schema = c.table_schema
WHERE t.table_type = 'BASE TABLE'
    AND t.table_schema NOT IN ('information_schema', 'pg_catalog')
    AND c.data_type IN ('text', 'varchar', 'character varying', 'char', 'character')
ORDER BY t.table_name, c.column_name;

-- ============================================================================
-- STEP 4: COMMON FIXES FOR BRAZILIAN LEGISLATIVE DATA
-- ============================================================================

-- Fix common issues with legislative document tables
-- These are examples - adjust table and column names as needed

-- Example: Fix collation for document titles
-- ALTER TABLE documents ALTER COLUMN titulo TYPE text COLLATE "pt_BR_utf8";

-- Example: Fix collation for document summaries
-- ALTER TABLE documents ALTER COLUMN ementa TYPE text COLLATE "pt_BR_utf8";

-- Example: Fix collation for state names
-- ALTER TABLE documents ALTER COLUMN estado TYPE text COLLATE "pt_BR_utf8";

-- Example: Fix collation for municipality names
-- ALTER TABLE documents ALTER COLUMN municipio TYPE text COLLATE "pt_BR_utf8";

-- ============================================================================
-- STEP 5: REBUILD INDEXES AFTER COLLATION CHANGES
-- ============================================================================

-- After changing collations, you should rebuild indexes that depend on text columns
-- This prevents index corruption and ensures proper sorting

-- Example commands (uncomment and modify as needed):
-- REINDEX INDEX CONCURRENTLY idx_documents_titulo;
-- REINDEX INDEX CONCURRENTLY idx_documents_estado;
-- REINDEX TABLE CONCURRENTLY documents;

-- ============================================================================
-- STEP 6: VERIFICATION TESTS
-- ============================================================================

-- Test Portuguese text sorting with different collations
-- This helps verify that collations are working correctly

CREATE TEMP TABLE test_portuguese_sort AS
SELECT * FROM (VALUES
    ('João'),
    ('jose'),
    ('José'),
    ('joao'),
    ('Àlex'),
    ('alex'),
    ('Ângela'),
    ('angela'),
    ('Ação'),
    ('acao')
) AS t(name);

-- Test default collation sorting
SELECT 'Default Database Collation' as test_type, name
FROM test_portuguese_sort
ORDER BY name;

-- Test with C collation (ASCII sorting - may not handle accents properly)
SELECT 'C Collation (ASCII)' as test_type, name
FROM test_portuguese_sort
ORDER BY name COLLATE "C";

-- Test with Portuguese collation (if available)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_collation WHERE collname = 'pt_BR_utf8') THEN
        RAISE NOTICE 'Testing pt_BR_utf8 collation...';
        -- This would need to be executed separately:
        -- SELECT 'pt_BR_utf8 Collation' as test_type, name FROM test_portuguese_sort ORDER BY name COLLATE "pt_BR_utf8";
    END IF;
END
$$;

-- ============================================================================
-- STEP 7: MONITORING AND MAINTENANCE
-- ============================================================================

-- Query to monitor collation usage across the database
CREATE OR REPLACE VIEW collation_usage AS
SELECT
    schemaname,
    tablename,
    attname as column_name,
    atttypid::regtype as data_type,
    attcollation::regcollation as collation
FROM pg_attribute a
JOIN pg_class c ON a.attrelid = c.oid
JOIN pg_namespace n ON c.relnamespace = n.oid
JOIN pg_stat_user_tables s ON c.oid = s.relid
WHERE a.attnum > 0
    AND NOT a.attisdropped
    AND a.attcollation <> 0  -- Only show columns with explicit collations
    AND n.nspname = 'public';  -- Adjust schema as needed

-- Query to identify potential collation mismatches
CREATE OR REPLACE VIEW collation_issues AS
SELECT
    t.table_name,
    c.column_name,
    c.collation_name,
    CASE
        WHEN c.collation_name IS NULL THEN 'No explicit collation - using database default'
        WHEN c.collation_name IN ('C', 'POSIX') THEN 'WARNING: ASCII collation may not handle Portuguese text properly'
        WHEN c.collation_name LIKE '%en_%' THEN 'WARNING: English collation used for potentially Portuguese text'
        ELSE 'OK'
    END as issue_description,
    CASE
        WHEN c.collation_name IN ('C', 'POSIX') THEN 'HIGH'
        WHEN c.collation_name LIKE '%en_%' THEN 'MEDIUM'
        WHEN c.collation_name IS NULL THEN 'LOW'
        ELSE 'NONE'
    END as priority
FROM information_schema.tables t
JOIN information_schema.columns c ON t.table_name = c.table_name
WHERE t.table_schema = 'public'
    AND c.data_type IN ('text', 'varchar', 'character varying')
    AND (c.column_name ILIKE '%titulo%'
         OR c.column_name ILIKE '%ementa%'
         OR c.column_name ILIKE '%estado%'
         OR c.column_name ILIKE '%municipio%'
         OR c.column_name ILIKE '%autor%'
         OR c.column_name ILIKE '%assunto%')
ORDER BY
    CASE priority
        WHEN 'HIGH' THEN 1
        WHEN 'MEDIUM' THEN 2
        WHEN 'LOW' THEN 3
        ELSE 4
    END;

-- ============================================================================
-- EXECUTION SUMMARY
-- ============================================================================

SELECT
    'PostgreSQL Collation Fix Script Completed' as status,
    current_timestamp as completion_time,
    'Check the views collation_usage and collation_issues for ongoing monitoring' as next_steps;

-- Display any remaining issues
SELECT * FROM collation_issues WHERE priority IN ('HIGH', 'MEDIUM');

-- ============================================================================
-- NOTES FOR RAILWAY DEPLOYMENT:
-- ============================================================================
--
-- 1. Railway PostgreSQL uses UTF-8 encoding by default, which is good for Brazilian text
-- 2. The default collation is usually en_US.UTF-8, which works reasonably well but may not
--    provide optimal sorting for Portuguese text with accents
-- 3. For production systems, consider using ICU collations if available, as they provide
--    better Unicode support
-- 4. Always test collation changes in a development environment first
-- 5. Monitor query performance after collation changes, as some indexes may need rebuilding
-- 6. Consider application-level changes (like using ILIKE with unaccent() function)
--    as alternatives to database-level collation changes
--
-- EXAMPLE RAILWAY MIGRATION COMMAND:
-- railway connect postgres --database your-database
-- \i docs/postgres_collation_fix.sql
--
-- ============================================================================