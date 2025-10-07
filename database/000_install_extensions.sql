-- ============================================================================
-- POSTGRESQL EXTENSIONS SETUP FOR MONITOR LEGISLATIVO V4
-- ============================================================================
--
-- This script installs all required and recommended PostgreSQL extensions
-- for the Brazilian legislative monitoring system.
--
-- PRIORITY: Run this FIRST before any other database setup scripts
-- SAFE: Can be run multiple times (idempotent with IF NOT EXISTS)
--
-- Railway Production Deployment: Run via Railway PostgreSQL Extensions UI
-- Development: Run this script manually
-- ============================================================================

-- Display setup header
DO $$
BEGIN
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'MONITOR LEGISLATIVO V4 - POSTGRESQL EXTENSIONS INSTALLATION';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'Installing required and recommended extensions...';
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- CRITICAL EXTENSIONS (REQUIRED - Application will fail without these)
-- ============================================================================

DO $$
BEGIN
    -- 1. pg_trgm: Trigram-based fuzzy text search and similarity matching
    --    Used by: database/advanced_search_setup.sql (line 14)
    --    Features: LIKE '%text%' index optimization, similarity search, fuzzy matching
    --    Impact: Search functionality FAILS without this extension
    RAISE NOTICE 'Installing pg_trgm (trigram text search)...';
END $$;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

DO $$
BEGIN
    -- 2. unaccent: Remove accents from text (critical for Brazilian Portuguese)
    --    Used by: database/advanced_search_setup.sql (line 13)
    --    Features: Accent-insensitive search ("sao paulo" finds "são paulo")
    --    Impact: Portuguese text search configuration FAILS without this
    RAISE NOTICE 'Installing unaccent (accent-insensitive search)...';
END $$;
CREATE EXTENSION IF NOT EXISTS unaccent;

-- ============================================================================
-- HIGHLY RECOMMENDED EXTENSIONS (Production Best Practices)
-- ============================================================================

DO $$
BEGIN
    -- 3. pg_stat_statements: Query performance monitoring and optimization
    --    Used by: Production monitoring, performance optimization
    --    Features: Track slow queries, execution stats, query optimization insights
    --    Impact: Cannot identify performance bottlenecks without this
    --    Config required in postgresql.conf:
    --      shared_preload_libraries = 'pg_stat_statements'
    --      pg_stat_statements.track = all
    RAISE NOTICE 'Installing pg_stat_statements (query performance monitoring)...';
END $$;
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

DO $$
BEGIN
    -- 4. btree_gin: Combine B-tree and GIN indexes for composite queries
    --    Used by: Complex search filters (text + date + location + type)
    --    Features: Single GIN index can handle text search + other columns
    --    Impact: Improved performance for composite search queries
    RAISE NOTICE 'Installing btree_gin (composite index optimization)...';
END $$;
CREATE EXTENSION IF NOT EXISTS btree_gin;

-- ============================================================================
-- OPTIONAL EXTENSIONS (Consider for future features)
-- ============================================================================

DO $$
BEGIN
    -- 5. pgcrypto: Cryptographic functions for data security
    --    Used by: LGPD compliance, sensitive data encryption
    --    Features: Password hashing, data encryption, LGPD compliance helpers
    --    Impact: Required if database-level encryption is needed
    --    Note: Currently using application-level encryption, may need later
    RAISE NOTICE 'Installing pgcrypto (cryptographic functions - optional)...';
END $$;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- EXTENSION VERIFICATION
-- ============================================================================

-- Display installed extensions
RAISE NOTICE '';
RAISE NOTICE '============================================================================';
RAISE NOTICE 'INSTALLED EXTENSIONS VERIFICATION';
RAISE NOTICE '============================================================================';

-- Query and display all installed extensions
DO $$
DECLARE
    ext_record RECORD;
BEGIN
    FOR ext_record IN
        SELECT extname, extversion
        FROM pg_extension
        WHERE extname != 'plpgsql'  -- Skip default extension
        ORDER BY extname
    LOOP
        RAISE NOTICE '✓ % (version %)', ext_record.extname, ext_record.extversion;
    END LOOP;
END $$;

-- ============================================================================
-- EXTENSION REQUIREMENTS CHECKLIST
-- ============================================================================

DO $$
DECLARE
    missing_extensions TEXT[] := ARRAY[]::TEXT[];
    ext_name TEXT;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'EXTENSION REQUIREMENTS CHECKLIST';
    RAISE NOTICE '============================================================================';

    -- Check critical extensions
    FOREACH ext_name IN ARRAY ARRAY['pg_trgm', 'unaccent'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = ext_name) THEN
            missing_extensions := array_append(missing_extensions, ext_name);
            RAISE WARNING '✗ CRITICAL: % is MISSING - application will fail!', ext_name;
        ELSE
            RAISE NOTICE '✓ CRITICAL: % is installed', ext_name;
        END IF;
    END LOOP;

    -- Check recommended extensions
    FOREACH ext_name IN ARRAY ARRAY['pg_stat_statements', 'btree_gin'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = ext_name) THEN
            RAISE NOTICE '⚠ RECOMMENDED: % is missing - install for best performance', ext_name;
        ELSE
            RAISE NOTICE '✓ RECOMMENDED: % is installed', ext_name;
        END IF;
    END LOOP;

    -- Check optional extensions
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto') THEN
        RAISE NOTICE '✓ OPTIONAL: pgcrypto is installed';
    ELSE
        RAISE NOTICE '○ OPTIONAL: pgcrypto is not installed (ok)';
    END IF;

    -- Fail if critical extensions are missing
    IF array_length(missing_extensions, 1) > 0 THEN
        RAISE EXCEPTION 'CRITICAL EXTENSIONS MISSING: %. Install them via Railway PostgreSQL Extensions UI!',
                        array_to_string(missing_extensions, ', ');
    END IF;

    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'STATUS: All critical extensions installed successfully!';
    RAISE NOTICE '============================================================================';
END $$;

-- ============================================================================
-- CONFIGURATION NOTES FOR RAILWAY
-- ============================================================================

COMMENT ON EXTENSION pg_trgm IS
'Trigram-based text search and similarity. REQUIRED for search functionality.';

COMMENT ON EXTENSION unaccent IS
'Accent removal for Brazilian Portuguese. REQUIRED for Portuguese text search.';

COMMENT ON EXTENSION pg_stat_statements IS
'Query performance monitoring. RECOMMENDED for production optimization.';

COMMENT ON EXTENSION btree_gin IS
'Composite index optimization. RECOMMENDED for complex search queries.';

-- ============================================================================
-- PERFORMANCE MONITORING SETUP (if pg_stat_statements is installed)
-- ============================================================================

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements') THEN
        -- Create view for easy query performance analysis
        CREATE OR REPLACE VIEW v_slow_queries AS
        SELECT
            query,
            calls,
            total_exec_time,
            mean_exec_time,
            max_exec_time,
            stddev_exec_time,
            rows
        FROM pg_stat_statements
        WHERE mean_exec_time > 100  -- Queries slower than 100ms
        ORDER BY mean_exec_time DESC
        LIMIT 50;

        RAISE NOTICE '';
        RAISE NOTICE 'Performance monitoring view created: v_slow_queries';
        RAISE NOTICE 'Usage: SELECT * FROM v_slow_queries;';
    END IF;
END $$;

-- ============================================================================
-- FINAL SETUP SUMMARY
-- ============================================================================

DO $$
DECLARE
    ext_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO ext_count
    FROM pg_extension
    WHERE extname != 'plpgsql';

    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'EXTENSION INSTALLATION COMPLETE';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'Total extensions installed: %', ext_count;
    RAISE NOTICE '';
    RAISE NOTICE 'Next steps:';
    RAISE NOTICE '1. Run database/advanced_search_setup.sql for search configuration';
    RAISE NOTICE '2. Run database/create_indexes.sql for performance optimization';
    RAISE NOTICE '3. Monitor query performance with: SELECT * FROM v_slow_queries;';
    RAISE NOTICE '';
    RAISE NOTICE 'For Railway deployment:';
    RAISE NOTICE '  - Extensions are installed via PostgreSQL Extensions UI';
    RAISE NOTICE '  - This script verifies installation and provides fallbacks';
    RAISE NOTICE '============================================================================';
END $$;
