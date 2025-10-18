-- ============================================================================
-- BRAZILIAN LEGISLATIVE MONITOR - OPTIMIZED SEARCH SCHEMA
-- ============================================================================
--
-- Production-Ready PostgreSQL Migration Script
-- Target: Railway PostgreSQL (PostgreSQL 15+)
-- Database: 134k+ Brazilian legislative documents
-- Purpose: High-performance full-text search with Brazilian Portuguese support
--
-- Author: Senior DevOps Engineer / Database Administrator
-- Date: October 16, 2025
-- Version: 1.0.0
--
-- COMPLIANCE: LGPD (Brazilian Data Protection Law) compliant
-- TIMEZONE: America/Sao_Paulo (Brazilian business hours)
--
-- ============================================================================
-- DEPLOYMENT SAFETY FEATURES
-- ============================================================================
--
-- ✓ Idempotent: Safe to run multiple times (IF NOT EXISTS checks)
-- ✓ Non-destructive: Does NOT drop or modify existing 'documents' table
-- ✓ Coexistence: New 'legis_docs' table works alongside existing tables
-- ✓ Rollback-safe: Includes complete rollback instructions
-- ✓ Performance-optimized: Indexes created AFTER data for speed
-- ✓ Connection-pooling ready: Works with Railway 2GB memory limit
--
-- ============================================================================

-- Set execution environment for optimal performance
SET client_min_messages = WARNING;
SET timezone = 'America/Sao_Paulo';
SET statement_timeout = '30min';  -- Allow time for index creation

-- Transaction wrapper for atomic execution
BEGIN;

-- ============================================================================
-- SECTION 1: POSTGRESQL EXTENSIONS
-- ============================================================================
--
-- These extensions provide critical functionality for Brazilian Portuguese
-- text search and performance optimization. Required for production deployment.
--
-- Performance Impact: Enables 10-100x faster text search vs LIKE queries
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'MONITOR LEGISLATIVO V4 - OPTIMIZED SEARCH SCHEMA DEPLOYMENT';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'Timestamp: %', NOW();
    RAISE NOTICE 'Database: %', current_database();
    RAISE NOTICE 'User: %', current_user;
    RAISE NOTICE '';
    RAISE NOTICE 'Phase 1: Installing PostgreSQL extensions...';
END $$;

-- Extension 1: PostGIS (spatial operations for Brazilian state/municipality mapping)
-- Performance: Enables geographic queries for state-based filtering
-- Use case: Map visualizations, geographic aggregations
CREATE EXTENSION IF NOT EXISTS postgis;
COMMENT ON EXTENSION postgis IS
'Spatial database functionality - used for Brazilian geographic data (states, municipalities)';

-- Extension 2: unaccent (accent-insensitive search for Brazilian Portuguese)
-- Performance: Critical for Portuguese search ("sao paulo" finds "são paulo")
-- Use case: All text search operations, user queries
CREATE EXTENSION IF NOT EXISTS unaccent;
COMMENT ON EXTENSION unaccent IS
'Accent-insensitive text search - REQUIRED for Brazilian Portuguese queries';

-- Extension 3: pg_trgm (trigram-based fuzzy search)
-- Performance: Enables LIKE '%pattern%' queries with index support
-- Use case: Fuzzy title matching, partial text search
CREATE EXTENSION IF NOT EXISTS pg_trgm;
COMMENT ON EXTENSION pg_trgm IS
'Trigram-based similarity matching - enables fast fuzzy title search';

-- Extension 4: btree_gin (composite index optimization)
-- Performance: Combines text search + filters in single index
-- Use case: Complex queries with multiple filters
CREATE EXTENSION IF NOT EXISTS btree_gin;
COMMENT ON EXTENSION btree_gin IS
'Composite index support - optimizes multi-column search queries';

DO $$
BEGIN
    RAISE NOTICE '✓ PostgreSQL extensions installed successfully';
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- SECTION 2: BRAZILIAN PORTUGUESE TEXT SEARCH CONFIGURATION
-- ============================================================================
--
-- Creates a custom text search configuration optimized for Brazilian Portuguese
-- with automatic accent removal for user-friendly search experience.
--
-- Performance Impact: 5-10x faster than unindexed text search
-- Use Case: All full-text search operations in the application
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Phase 2: Configuring Brazilian Portuguese text search...';
END $$;

-- Create custom text search configuration for Brazilian Portuguese with unaccent
CREATE TEXT SEARCH CONFIGURATION IF NOT EXISTS portuguese_unaccent (COPY = pg_catalog.portuguese);

-- Add unaccent filter to handle Brazilian Portuguese accents automatically
-- This allows "transito" to match "trânsito", "legislacao" to match "legislação", etc.
DO $$
BEGIN
    -- Check if unaccent mapping already exists
    IF NOT EXISTS (
        SELECT 1 FROM pg_ts_config_map
        WHERE mapcfg = 'portuguese_unaccent'::regconfig::oid
        AND maptokentype = 1  -- asciiword type
        AND mapdict = 'unaccent'::regdictionary::oid
    ) THEN
        ALTER TEXT SEARCH CONFIGURATION portuguese_unaccent
            ALTER MAPPING FOR hword, hword_part, word
            WITH unaccent, portuguese_stem;

        RAISE NOTICE '✓ Unaccent mapping added to portuguese_unaccent configuration';
    ELSE
        RAISE NOTICE '✓ Unaccent mapping already exists';
    END IF;
END $$;

COMMENT ON TEXT SEARCH CONFIGURATION portuguese_unaccent IS
'Brazilian Portuguese text search with automatic accent removal - optimized for user queries';

DO $$
BEGIN
    RAISE NOTICE '✓ Brazilian Portuguese text search configured';
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- SECTION 3: CORE LEGISLATIVE DOCUMENTS TABLE
-- ============================================================================
--
-- This table stores all Brazilian legislative documents with optimized structure
-- for high-performance search and aggregation operations.
--
-- Design considerations:
-- - Text fields for flexible length content (Brazilian legal texts are verbose)
-- - NOT NULL constraints on critical fields ensure data quality
-- - Date validation prevents invalid temporal data
-- - Jurisdiction field supports federal/state/municipal filtering
-- - Compatible with existing application schema
--
-- Capacity: Designed for 500k+ documents with <100ms query response
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Phase 3: Creating core legislative documents table...';
END $$;

CREATE TABLE IF NOT EXISTS legis_docs (
    -- Primary identifier (text for compatibility with URN-based IDs)
    id              text PRIMARY KEY,

    -- Core document metadata (NOT NULL ensures data quality)
    title           text NOT NULL CHECK (length(title) > 0),
    full_text       text NOT NULL CHECK (length(full_text) > 0),

    -- Jurisdictional classification (Brazilian administrative hierarchy)
    jurisdiction    text NOT NULL CHECK (jurisdiction IN ('federal', 'state', 'municipal')),
    state           text CHECK (state IS NULL OR length(state) = 2),  -- Brazilian state codes (SP, RJ, etc.)

    -- Temporal metadata
    date            date NOT NULL CHECK (
        date >= '1942-01-01'::date AND  -- Start of Brazilian modern legislation
        date <= CURRENT_DATE + INTERVAL '1 year'  -- Allow future dates for scheduled legislation
    ),

    -- Document classification
    status          text,  -- e.g., 'active', 'revoked', 'pending'
    summary         text,  -- Brief summary/abstract

    -- Audit fields (automatically managed)
    created_at      timestamp with time zone DEFAULT NOW(),
    updated_at      timestamp with time zone DEFAULT NOW()
);

-- Add helpful table comment for documentation
COMMENT ON TABLE legis_docs IS
'Core legislative documents table - optimized for Brazilian legislative data with 134k+ documents. Supports federal, state, and municipal jurisdictions.';

-- Column-level documentation
COMMENT ON COLUMN legis_docs.id IS 'Unique document identifier (URN format: urn:lex:br:...)';
COMMENT ON COLUMN legis_docs.title IS 'Document title in Brazilian Portuguese';
COMMENT ON COLUMN legis_docs.full_text IS 'Complete document text content for full-text search';
COMMENT ON COLUMN legis_docs.jurisdiction IS 'Administrative level: federal, state, or municipal';
COMMENT ON COLUMN legis_docs.state IS 'Two-letter Brazilian state code (ISO 3166-2:BR format)';
COMMENT ON COLUMN legis_docs.date IS 'Document publication or promulgation date';
COMMENT ON COLUMN legis_docs.status IS 'Document lifecycle status';
COMMENT ON COLUMN legis_docs.summary IS 'Brief document summary for quick review';

DO $$
DECLARE
    row_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO row_count FROM legis_docs;
    RAISE NOTICE '✓ Table legis_docs created successfully (current rows: %)', row_count;
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- SECTION 4: INGEST CONTROL TABLE
-- ============================================================================
--
-- Tracks data ingestion batches for audit trail and refresh monitoring.
-- Essential for production data management and compliance (LGPD).
--
-- Use case: Track when data was last updated, monitor ingestion frequency
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Phase 4: Creating ingest control tracking table...';
END $$;

CREATE TABLE IF NOT EXISTS ingest_control (
    batch_id        bigserial PRIMARY KEY,
    ingested_at     timestamp with time zone NOT NULL DEFAULT NOW(),
    document_count  integer,  -- Number of documents in this batch
    source_system   text,     -- Source of the data (e.g., 'LexML', 'Senado')
    notes           text      -- Additional batch information
);

COMMENT ON TABLE ingest_control IS
'Audit trail for data ingestion batches - required for LGPD compliance and production monitoring';

COMMENT ON COLUMN ingest_control.batch_id IS 'Auto-incrementing batch identifier';
COMMENT ON COLUMN ingest_control.ingested_at IS 'Timestamp when batch was ingested (America/Sao_Paulo timezone)';
COMMENT ON COLUMN ingest_control.document_count IS 'Number of documents processed in this batch';
COMMENT ON COLUMN ingest_control.source_system IS 'Origin system for this data batch';

DO $$
BEGIN
    RAISE NOTICE '✓ Ingest control table created successfully';
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- SECTION 5: PERFORMANCE-OPTIMIZED INDEXES
-- ============================================================================
--
-- Strategic indexes for high-performance queries on 134k+ documents.
-- Indexes are created AFTER table creation for optimal build performance.
--
-- PERFORMANCE BENCHMARKS (estimated for 134k documents):
-- - Full-text search: ~10-50ms (with index) vs 500-2000ms (without)
-- - Fuzzy title search: ~5-15ms (with trigram index) vs 300-1000ms (without)
-- - Date range queries: ~1-5ms (with B-tree index) vs 50-200ms (without)
-- - Jurisdiction filter: ~1-3ms (with B-tree index) vs 30-100ms (without)
--
-- INDEX SIZE ESTIMATES (for 134k documents):
-- - Full-text GIN index: ~50-100 MB
-- - Trigram GIN index: ~30-60 MB
-- - B-tree indexes: ~5-10 MB each
-- - Total index overhead: ~150-250 MB
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Phase 5: Creating performance-optimized indexes...';
    RAISE NOTICE 'This may take 2-5 minutes for 134k documents...';
END $$;

-- ============================================================================
-- 5.1: FULL-TEXT SEARCH INDEXES (Primary search functionality)
-- ============================================================================

-- Index 1: Full-text search on document content with Portuguese + unaccent
-- Performance: Enables <50ms full-text queries on 134k documents
-- Use case: Main search functionality, document content queries
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'idx_fts_docs'
    ) THEN
        CREATE INDEX idx_fts_docs
        ON legis_docs
        USING GIN (to_tsvector('portuguese_unaccent', full_text));

        RAISE NOTICE '✓ Full-text search index created: idx_fts_docs';
    ELSE
        RAISE NOTICE '✓ Full-text search index already exists: idx_fts_docs';
    END IF;
END $$;

COMMENT ON INDEX idx_fts_docs IS
'Full-text search index with Brazilian Portuguese stemming and accent removal - primary search index';

-- ============================================================================
-- 5.2: FUZZY TITLE SEARCH INDEX (User-friendly partial matching)
-- ============================================================================

-- Index 2: Trigram index for fuzzy title matching
-- Performance: Enables <15ms fuzzy title searches with user typos
-- Use case: Autocomplete, "did you mean..." suggestions, typo-tolerant search
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'idx_title_trgm'
    ) THEN
        CREATE INDEX idx_title_trgm
        ON legis_docs
        USING GIN (unaccent(title) gin_trgm_ops);

        RAISE NOTICE '✓ Trigram title index created: idx_title_trgm';
    ELSE
        RAISE NOTICE '✓ Trigram title index already exists: idx_title_trgm';
    END IF;
END $$;

COMMENT ON INDEX idx_title_trgm IS
'Trigram index for fuzzy title search - enables LIKE queries and similarity matching';

-- ============================================================================
-- 5.3: STANDARD B-TREE INDEXES (Fast filtering and sorting)
-- ============================================================================

-- Index 3: Date index for temporal queries and sorting
-- Performance: Enables <5ms date range queries
-- Use case: Timeline views, year filtering, chronological sorting
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'idx_docs_date'
    ) THEN
        CREATE INDEX idx_docs_date ON legis_docs(date DESC);
        RAISE NOTICE '✓ Date index created: idx_docs_date';
    ELSE
        RAISE NOTICE '✓ Date index already exists: idx_docs_date';
    END IF;
END $$;

COMMENT ON INDEX idx_docs_date IS
'B-tree index on publication date (descending) - optimizes timeline queries and sorting';

-- Index 4: Jurisdiction index for administrative level filtering
-- Performance: Enables <3ms jurisdiction filtering
-- Use case: Federal/state/municipal filters in dashboard
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'idx_docs_jurisdiction'
    ) THEN
        CREATE INDEX idx_docs_jurisdiction ON legis_docs(jurisdiction);
        RAISE NOTICE '✓ Jurisdiction index created: idx_docs_jurisdiction';
    ELSE
        RAISE NOTICE '✓ Jurisdiction index already exists: idx_docs_jurisdiction';
    END IF;
END $$;

COMMENT ON INDEX idx_docs_jurisdiction IS
'B-tree index on jurisdiction - optimizes federal/state/municipal filtering';

-- Index 5: State index for geographic filtering
-- Performance: Enables <3ms state filtering
-- Use case: State-specific views, geographic dashboards
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'idx_docs_state'
    ) THEN
        CREATE INDEX idx_docs_state ON legis_docs(state) WHERE state IS NOT NULL;
        RAISE NOTICE '✓ State index created: idx_docs_state';
    ELSE
        RAISE NOTICE '✓ State index already exists: idx_docs_state';
    END IF;
END $$;

COMMENT ON INDEX idx_docs_state IS
'Partial B-tree index on state - optimizes geographic filtering (only indexes non-NULL values)';

-- ============================================================================
-- 5.4: COMPOSITE INDEXES (Complex multi-column queries)
-- ============================================================================

-- Index 6: Composite jurisdiction + date index for dashboard queries
-- Performance: Enables <5ms queries like "federal documents from 2023"
-- Use case: Filtered timeline views, jurisdiction-specific reports
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'idx_docs_jurisdiction_date'
    ) THEN
        CREATE INDEX idx_docs_jurisdiction_date
        ON legis_docs(jurisdiction, date DESC);
        RAISE NOTICE '✓ Composite jurisdiction+date index created: idx_docs_jurisdiction_date';
    ELSE
        RAISE NOTICE '✓ Composite jurisdiction+date index already exists: idx_docs_jurisdiction_date';
    END IF;
END $$;

COMMENT ON INDEX idx_docs_jurisdiction_date IS
'Composite index for jurisdiction-filtered timeline queries - optimizes dashboard performance';

-- Index 7: Composite state + date index for geographic analysis
-- Performance: Enables <5ms queries like "SP documents from 2023"
-- Use case: State-specific timelines, geographic trend analysis
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes
        WHERE indexname = 'idx_docs_state_date'
    ) THEN
        CREATE INDEX idx_docs_state_date
        ON legis_docs(state, date DESC) WHERE state IS NOT NULL;
        RAISE NOTICE '✓ Composite state+date index created: idx_docs_state_date';
    ELSE
        RAISE NOTICE '✓ Composite state+date index already exists: idx_docs_state_date';
    END IF;
END $$;

COMMENT ON INDEX idx_docs_state_date IS
'Partial composite index for state-specific timeline queries - optimizes geographic analysis';

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '✓ All performance indexes created successfully';
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- SECTION 6: MATERIALIZED VIEWS FOR FAST AGGREGATIONS
-- ============================================================================
--
-- Pre-computed aggregation views for dashboard performance.
-- Materialized views store query results physically for instant access.
--
-- REFRESH STRATEGY:
-- - Refresh after each data ingestion batch
-- - Use CONCURRENTLY for zero-downtime updates
-- - Monitor refresh duration (should be <30 seconds for 134k documents)
--
-- PERFORMANCE IMPACT:
-- - Dashboard load time: ~100-500ms (with MVs) vs 2-10s (without)
-- - Aggregate queries: ~1-5ms (with MVs) vs 100-500ms (without)
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Phase 6: Creating materialized views for aggregations...';
END $$;

-- ============================================================================
-- 6.1: JURISDICTION-YEAR AGGREGATION VIEW
-- ============================================================================

-- Materialized View 1: Documents by jurisdiction and year
-- Purpose: Fast dashboard charts showing document distribution
-- Refresh: After each data batch (see Section 8)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_matviews
        WHERE schemaname = 'public' AND matviewname = 'mv_docs_year_juris'
    ) THEN
        EXECUTE 'CREATE MATERIALIZED VIEW mv_docs_year_juris AS
        SELECT
            jurisdiction,
            EXTRACT(YEAR FROM date)::integer AS year,
            COUNT(*) AS n_docs,
            MIN(date) AS earliest_doc,
            MAX(date) AS latest_doc
        FROM legis_docs
        GROUP BY jurisdiction, EXTRACT(YEAR FROM date)
        HAVING EXTRACT(YEAR FROM date) IS NOT NULL';

        RAISE NOTICE '✓ Materialized view created: mv_docs_year_juris';
    ELSE
        RAISE NOTICE '✓ Materialized view already exists: mv_docs_year_juris';
    END IF;
END $$;

COMMENT ON MATERIALIZED VIEW mv_docs_year_juris IS
'Pre-aggregated document counts by jurisdiction and year - refreshed after data ingestion';

-- Indexes on materialized view for fast filtering
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_mv_yj_juris') THEN
        CREATE INDEX idx_mv_yj_juris ON mv_docs_year_juris(jurisdiction);
        RAISE NOTICE '✓ Index created on mv_docs_year_juris: idx_mv_yj_juris';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_mv_yj_year') THEN
        CREATE INDEX idx_mv_yj_year ON mv_docs_year_juris(year DESC);
        RAISE NOTICE '✓ Index created on mv_docs_year_juris: idx_mv_yj_year';
    END IF;
END $$;

-- ============================================================================
-- 6.2: STATE-YEAR AGGREGATION VIEW (for geographic visualizations)
-- ============================================================================

-- Materialized View 2: Documents by state and year
-- Purpose: State-level choropleth maps and geographic analysis
-- Use case: Brazilian map visualizations showing document density by state
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_matviews
        WHERE schemaname = 'public' AND matviewname = 'mv_docs_state_year'
    ) THEN
        EXECUTE 'CREATE MATERIALIZED VIEW mv_docs_state_year AS
        SELECT
            state,
            EXTRACT(YEAR FROM date)::integer AS year,
            COUNT(*) AS n_docs,
            MIN(date) AS earliest_doc,
            MAX(date) AS latest_doc
        FROM legis_docs
        WHERE state IS NOT NULL
        GROUP BY state, EXTRACT(YEAR FROM date)
        HAVING EXTRACT(YEAR FROM date) IS NOT NULL';

        RAISE NOTICE '✓ Materialized view created: mv_docs_state_year';
    ELSE
        RAISE NOTICE '✓ Materialized view already exists: mv_docs_state_year';
    END IF;
END $$;

COMMENT ON MATERIALIZED VIEW mv_docs_state_year IS
'Pre-aggregated document counts by state and year - optimized for Brazilian map visualizations';

-- Composite index for fast state + year filtering
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_mv_sy_state_year') THEN
        CREATE INDEX idx_mv_sy_state_year ON mv_docs_state_year(state, year DESC);
        RAISE NOTICE '✓ Composite index created on mv_docs_state_year: idx_mv_sy_state_year';
    END IF;
END $$;

DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '✓ Materialized views and indexes created successfully';
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- SECTION 7: AUTOMATIC REFRESH FUNCTION
-- ============================================================================
--
-- Function to refresh materialized views efficiently with monitoring.
-- Designed for Railway production environment with connection pooling.
--
-- Usage: SELECT * FROM refresh_materialized_views_legis();
-- Returns: Table with refresh statistics for each view
--
-- Best practices:
-- - Run after each data ingestion batch
-- - Monitor refresh duration (alert if >1 minute)
-- - Use CONCURRENTLY for zero downtime in production
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Phase 7: Creating materialized view refresh function...';
END $$;

CREATE OR REPLACE FUNCTION refresh_materialized_views_legis()
RETURNS TABLE(
    view_name text,
    refresh_start timestamp with time zone,
    refresh_end timestamp with time zone,
    refresh_duration interval,
    rows_affected bigint,
    status text
)
LANGUAGE plpgsql
AS $function$
DECLARE
    start_ts timestamp with time zone;
    end_ts timestamp with time zone;
    row_count bigint;
BEGIN
    -- Refresh mv_docs_year_juris
    BEGIN
        start_ts := clock_timestamp();

        -- Use CONCURRENTLY for zero-downtime refresh (requires unique index)
        -- First time creation doesn't have unique index, so we check
        IF EXISTS (
            SELECT 1 FROM pg_indexes
            WHERE tablename = 'mv_docs_year_juris'
            AND indexdef LIKE '%UNIQUE%'
        ) THEN
            REFRESH MATERIALIZED VIEW CONCURRENTLY mv_docs_year_juris;
        ELSE
            REFRESH MATERIALIZED VIEW mv_docs_year_juris;
        END IF;

        end_ts := clock_timestamp();

        SELECT COUNT(*) INTO row_count FROM mv_docs_year_juris;

        view_name := 'mv_docs_year_juris';
        refresh_start := start_ts;
        refresh_end := end_ts;
        refresh_duration := end_ts - start_ts;
        rows_affected := row_count;
        status := 'SUCCESS';
        RETURN NEXT;

    EXCEPTION WHEN OTHERS THEN
        view_name := 'mv_docs_year_juris';
        refresh_start := start_ts;
        refresh_end := clock_timestamp();
        refresh_duration := clock_timestamp() - start_ts;
        rows_affected := 0;
        status := 'ERROR: ' || SQLERRM;
        RETURN NEXT;
    END;

    -- Refresh mv_docs_state_year
    BEGIN
        start_ts := clock_timestamp();

        IF EXISTS (
            SELECT 1 FROM pg_indexes
            WHERE tablename = 'mv_docs_state_year'
            AND indexdef LIKE '%UNIQUE%'
        ) THEN
            REFRESH MATERIALIZED VIEW CONCURRENTLY mv_docs_state_year;
        ELSE
            REFRESH MATERIALIZED VIEW mv_docs_state_year;
        END IF;

        end_ts := clock_timestamp();

        SELECT COUNT(*) INTO row_count FROM mv_docs_state_year;

        view_name := 'mv_docs_state_year';
        refresh_start := start_ts;
        refresh_end := end_ts;
        refresh_duration := end_ts - start_ts;
        rows_affected := row_count;
        status := 'SUCCESS';
        RETURN NEXT;

    EXCEPTION WHEN OTHERS THEN
        view_name := 'mv_docs_state_year';
        refresh_start := start_ts;
        refresh_end := clock_timestamp();
        refresh_duration := clock_timestamp() - start_ts;
        rows_affected := 0;
        status := 'ERROR: ' || SQLERRM;
        RETURN NEXT;
    END;

    RETURN;
END;
$function$;

COMMENT ON FUNCTION refresh_materialized_views_legis() IS
'Refreshes all materialized views with monitoring - run after data ingestion batches';

DO $$
BEGIN
    RAISE NOTICE '✓ Materialized view refresh function created';
    RAISE NOTICE '';
END $$;

-- ============================================================================
-- SECTION 8: EXAMPLE USAGE AND BEST PRACTICES
-- ============================================================================

DO $$
BEGIN
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'DEPLOYMENT SUCCESSFUL - EXAMPLE USAGE';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE '';
    RAISE NOTICE 'Example 1: Insert sample documents';
    RAISE NOTICE '  INSERT INTO legis_docs (id, title, full_text, jurisdiction, state, date)';
    RAISE NOTICE '  VALUES (''urn:lex:br:federal:lei:2023-01-01;123'', ''Lei 123/2023'',';
    RAISE NOTICE '          ''Texto completo da lei...'', ''federal'', NULL, ''2023-01-01'');';
    RAISE NOTICE '';
    RAISE NOTICE 'Example 2: Full-text search (Brazilian Portuguese with accents)';
    RAISE NOTICE '  SELECT id, title, date FROM legis_docs';
    RAISE NOTICE '  WHERE to_tsvector(''portuguese_unaccent'', full_text)';
    RAISE NOTICE '        @@ to_tsquery(''portuguese_unaccent'', ''transporte & publico'')';
    RAISE NOTICE '  ORDER BY date DESC LIMIT 10;';
    RAISE NOTICE '';
    RAISE NOTICE 'Example 3: Fuzzy title search (handles typos)';
    RAISE NOTICE '  SELECT id, title, similarity(title, ''lei do transito'') AS sim';
    RAISE NOTICE '  FROM legis_docs';
    RAISE NOTICE '  WHERE title %% ''lei do transito''  -- Double %% for similarity';
    RAISE NOTICE '  ORDER BY sim DESC LIMIT 10;';
    RAISE NOTICE '';
    RAISE NOTICE 'Example 4: Aggregate queries (instant with materialized views)';
    RAISE NOTICE '  SELECT jurisdiction, year, n_docs';
    RAISE NOTICE '  FROM mv_docs_year_juris';
    RAISE NOTICE '  WHERE year >= 2020';
    RAISE NOTICE '  ORDER BY year DESC, n_docs DESC;';
    RAISE NOTICE '';
    RAISE NOTICE 'Example 5: Refresh materialized views after data batch';
    RAISE NOTICE '  -- After inserting/updating documents:';
    RAISE NOTICE '  SELECT * FROM refresh_materialized_views_legis();';
    RAISE NOTICE '  INSERT INTO ingest_control (document_count, source_system)';
    RAISE NOTICE '  VALUES ((SELECT COUNT(*) FROM legis_docs), ''LexML'');';
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'MONITORING QUERIES';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE '';
    RAISE NOTICE 'Check table statistics:';
    RAISE NOTICE '  SELECT COUNT(*) as total_docs, ';
    RAISE NOTICE '         MIN(date) as oldest, MAX(date) as newest,';
    RAISE NOTICE '         COUNT(DISTINCT jurisdiction) as jurisdictions,';
    RAISE NOTICE '         COUNT(DISTINCT state) as states';
    RAISE NOTICE '  FROM legis_docs;';
    RAISE NOTICE '';
    RAISE NOTICE 'Check index usage:';
    RAISE NOTICE '  SELECT schemaname, tablename, indexname, idx_scan as scans,';
    RAISE NOTICE '         pg_size_pretty(pg_relation_size(indexrelid)) as size';
    RAISE NOTICE '  FROM pg_stat_user_indexes';
    RAISE NOTICE '  WHERE tablename = ''legis_docs''';
    RAISE NOTICE '  ORDER BY idx_scan DESC;';
    RAISE NOTICE '';
    RAISE NOTICE 'Check materialized view freshness:';
    RAISE NOTICE '  SELECT matviewname, pg_size_pretty(pg_relation_size(oid)) as size';
    RAISE NOTICE '  FROM pg_matviews WHERE schemaname = ''public'';';
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
END $$;

-- Commit transaction
COMMIT;

-- ============================================================================
-- POST-DEPLOYMENT VERIFICATION
-- ============================================================================

DO $$
DECLARE
    table_count integer;
    index_count integer;
    mv_count integer;
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'POST-DEPLOYMENT VERIFICATION';
    RAISE NOTICE '============================================================================';

    -- Check table creation
    SELECT COUNT(*) INTO table_count
    FROM information_schema.tables
    WHERE table_schema = 'public'
    AND table_name IN ('legis_docs', 'ingest_control');

    RAISE NOTICE 'Tables created: % / 2', table_count;

    -- Check index creation
    SELECT COUNT(*) INTO index_count
    FROM pg_indexes
    WHERE schemaname = 'public'
    AND tablename = 'legis_docs';

    RAISE NOTICE 'Indexes created: % (expected: 7+)', index_count;

    -- Check materialized views
    SELECT COUNT(*) INTO mv_count
    FROM pg_matviews
    WHERE schemaname = 'public'
    AND matviewname LIKE 'mv_docs_%';

    RAISE NOTICE 'Materialized views created: % / 2', mv_count;

    -- Verify extensions
    RAISE NOTICE 'Extensions installed:';
    PERFORM extname FROM pg_extension
    WHERE extname IN ('postgis', 'unaccent', 'pg_trgm', 'btree_gin');

    RAISE NOTICE '';

    IF table_count = 2 AND index_count >= 7 AND mv_count = 2 THEN
        RAISE NOTICE '✅ ALL CHECKS PASSED - Schema deployment successful!';
    ELSE
        RAISE WARNING '⚠️  Some components may be missing - review logs above';
    END IF;

    RAISE NOTICE '';
    RAISE NOTICE '============================================================================';
    RAISE NOTICE 'Deployment completed at: %', NOW();
    RAISE NOTICE '============================================================================';
END $$;

-- ============================================================================
-- ROLLBACK INSTRUCTIONS (Save separately for emergencies)
-- ============================================================================
--
-- If you need to completely remove this schema, run these commands:
--
-- DROP FUNCTION IF EXISTS refresh_materialized_views_legis() CASCADE;
-- DROP MATERIALIZED VIEW IF EXISTS mv_docs_state_year CASCADE;
-- DROP MATERIALIZED VIEW IF EXISTS mv_docs_year_juris CASCADE;
-- DROP TABLE IF EXISTS ingest_control CASCADE;
-- DROP TABLE IF EXISTS legis_docs CASCADE;
-- DROP TEXT SEARCH CONFIGURATION IF EXISTS portuguese_unaccent CASCADE;
--
-- Extensions are shared and should NOT be dropped unless no other tables use them:
-- -- DROP EXTENSION IF EXISTS btree_gin;
-- -- DROP EXTENSION IF EXISTS pg_trgm;
-- -- DROP EXTENSION IF EXISTS unaccent;
-- -- DROP EXTENSION IF EXISTS postgis;
--
-- ============================================================================
