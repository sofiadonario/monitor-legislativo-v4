-- ============================================================================
-- HIGH-PERFORMANCE LEGISLATIVE SEARCH SCHEMA
-- ============================================================================
-- Optimized for Railway PostgreSQL with 32GB RAM / 32GB vCPU
-- Target: 134k+ Brazilian legislative documents with sub-second search
-- Author: DevOps/DBA Team
-- Date: 2025-10-16
-- ============================================================================

-- ============================================================================
-- STEP 1: INSTALL REQUIRED EXTENSIONS
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '=== Installing PostgreSQL Extensions ===';
END $$;

-- PostGIS for spatial operations (state/municipality mapping)
CREATE EXTENSION IF NOT EXISTS postgis;
COMMENT ON EXTENSION postgis IS 'Spatial database operations for Brazilian geographic data';

-- Unaccent for Portuguese text normalization
CREATE EXTENSION IF NOT EXISTS unaccent;
COMMENT ON EXTENSION unaccent IS 'Remove accents from Portuguese text (são paulo → sao paulo)';

-- pg_trgm for trigram-based fuzzy search
CREATE EXTENSION IF NOT EXISTS pg_trgm;
COMMENT ON EXTENSION pg_trgm IS 'Trigram matching for fuzzy text search and LIKE optimization';

-- btree_gin for composite GIN indexes (text + filters)
CREATE EXTENSION IF NOT EXISTS btree_gin;
COMMENT ON EXTENSION btree_gin IS 'Combine text search with B-tree columns in single GIN index';

-- pg_stat_statements for query performance monitoring
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
COMMENT ON EXTENSION pg_stat_statements IS 'Track query execution statistics for optimization';

DO $$
BEGIN
    RAISE NOTICE '✓ All extensions installed successfully';
END $$;

-- ============================================================================
-- STEP 2: CONFIGURE POSTGRESQL FOR HIGH PERFORMANCE
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '=== Configuring PostgreSQL Performance Settings ===';
END $$;

-- Set Portuguese as default text search config
ALTER DATABASE railway SET default_text_search_config = 'portuguese';

-- High-performance settings for 32GB RAM environment
-- Note: These are session-level; for permanent changes, update postgresql.conf
SET work_mem = '512MB';                  -- Memory for sort/hash operations (32GB/64 = 512MB per worker)
SET maintenance_work_mem = '2GB';        -- Memory for CREATE INDEX, VACUUM
SET effective_cache_size = '24GB';       -- OS cache hint (75% of 32GB)
SET shared_buffers = '8GB';              -- PostgreSQL shared memory (25% of 32GB)
SET random_page_cost = 1.1;              -- SSD optimization (Railway uses NVMe)
SET effective_io_concurrency = 200;      -- Parallel I/O for SSDs
SET max_parallel_workers_per_gather = 8; -- Parallel query workers (32 vCPU available)
SET max_parallel_workers = 16;           -- Total parallel workers
SET max_worker_processes = 16;           -- Background worker processes

DO $$
BEGIN
    RAISE NOTICE '✓ Performance settings configured';
END $$;

-- ============================================================================
-- STEP 3: CORE LEGISLATIVE DOCUMENTS TABLE
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '=== Creating Core Legislative Documents Table ===';
END $$;

CREATE TABLE IF NOT EXISTS legis_docs (
    -- Primary identifier (URN or generated ID)
    id              TEXT PRIMARY KEY,

    -- Core document fields
    title           TEXT NOT NULL,
    full_text       TEXT NOT NULL,
    summary         TEXT,

    -- Jurisdiction classification
    jurisdiction    TEXT NOT NULL CHECK (jurisdiction IN ('federal', 'state', 'municipal')),
    state           TEXT,                -- 2-letter state code: 'SP', 'RJ', 'MG', etc.
    municipality    TEXT,                -- Municipality name

    -- Temporal data
    date            DATE NOT NULL,
    year            INTEGER GENERATED ALWAYS AS (EXTRACT(YEAR FROM date)) STORED,

    -- Document metadata
    status          TEXT,
    document_type   TEXT,                -- 'lei', 'decreto', 'portaria', etc.
    source          TEXT,                -- 'lexml', 'senado', 'camara', etc.
    url             TEXT,

    -- Additional metadata as JSONB for flexibility
    metadata        JSONB DEFAULT '{}'::jsonb,

    -- Computed tsvector for full-text search (stored for performance)
    search_vector   TSVECTOR GENERATED ALWAYS AS (
        to_tsvector('portuguese',
            unaccent(COALESCE(title, '')) || ' ' ||
            unaccent(COALESCE(full_text, '')) || ' ' ||
            unaccent(COALESCE(summary, ''))
        )
    ) STORED,

    -- Audit fields
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE legis_docs IS 'High-performance legislative documents table optimized for Brazilian legal corpus (134k+ documents)';
COMMENT ON COLUMN legis_docs.id IS 'Primary key - typically LexML URN or generated UUID';
COMMENT ON COLUMN legis_docs.search_vector IS 'Pre-computed tsvector for instant full-text search (Portuguese + unaccent)';
COMMENT ON COLUMN legis_docs.year IS 'Auto-generated year from date for fast temporal filtering';

DO $$
BEGIN
    RAISE NOTICE '✓ legis_docs table created';
END $$;

-- ============================================================================
-- STEP 4: INGEST CONTROL TABLE (Batch Tracking)
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '=== Creating Ingest Control Table ===';
END $$;

CREATE TABLE IF NOT EXISTS ingest_control (
    batch_id        BIGSERIAL PRIMARY KEY,
    batch_name      TEXT,
    source          TEXT,                -- 'lexml', 'senado', 'manual', etc.
    documents_count INTEGER DEFAULT 0,
    status          TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    error_message   TEXT,
    ingested_at     TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMP WITH TIME ZONE
);

COMMENT ON TABLE ingest_control IS 'Track data ingest batches for audit and rollback capability';

CREATE INDEX IF NOT EXISTS idx_ingest_control_status ON ingest_control(status);
CREATE INDEX IF NOT EXISTS idx_ingest_control_date ON ingest_control(ingested_at);

DO $$
BEGIN
    RAISE NOTICE '✓ ingest_control table created';
END $$;

-- ============================================================================
-- STEP 5: HIGH-PERFORMANCE INDEXES
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '=== Creating High-Performance Indexes ===';
END $$;

-- 5.1: GIN index for full-text search (uses pre-computed search_vector)
CREATE INDEX IF NOT EXISTS idx_fts_docs
    ON legis_docs USING GIN (search_vector);
COMMENT ON INDEX idx_fts_docs IS 'Full-text search index (Portuguese + unaccent) - primary search mechanism';

-- 5.2: Trigram index for fuzzy title search (handles typos and partial matches)
CREATE INDEX IF NOT EXISTS idx_title_trgm
    ON legis_docs USING GIN (unaccent(title) gin_trgm_ops);
COMMENT ON INDEX idx_title_trgm IS 'Trigram fuzzy search on titles - handles LIKE queries and typos';

-- 5.3: B-tree indexes for exact filtering
CREATE INDEX IF NOT EXISTS idx_docs_date
    ON legis_docs(date DESC);
COMMENT ON INDEX idx_docs_date IS 'Date filtering and sorting - DESC for recent-first queries';

CREATE INDEX IF NOT EXISTS idx_docs_year
    ON legis_docs(year DESC);
COMMENT ON INDEX idx_docs_year IS 'Year-based filtering for temporal analysis';

CREATE INDEX IF NOT EXISTS idx_docs_jurisdiction
    ON legis_docs(jurisdiction);
COMMENT ON INDEX idx_docs_jurisdiction IS 'Filter by federal/state/municipal jurisdiction';

CREATE INDEX IF NOT EXISTS idx_docs_state
    ON legis_docs(state);
COMMENT ON INDEX idx_docs_state IS 'Filter by Brazilian state (SP, RJ, MG, etc.)';

-- 5.4: Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_docs_jurisdiction_year
    ON legis_docs(jurisdiction, year DESC);
COMMENT ON INDEX idx_docs_jurisdiction_year IS 'Combined filter: jurisdiction + temporal sorting';

CREATE INDEX IF NOT EXISTS idx_docs_state_year
    ON legis_docs(state, year DESC) WHERE state IS NOT NULL;
COMMENT ON INDEX idx_docs_state_year IS 'State-level temporal analysis (partial index excludes nulls)';

-- 5.5: JSONB index for flexible metadata queries
CREATE INDEX IF NOT EXISTS idx_docs_metadata
    ON legis_docs USING GIN (metadata);
COMMENT ON INDEX idx_docs_metadata IS 'Query nested metadata fields using jsonb operators';

-- 5.6: Covering index for common SELECT queries (index-only scans)
CREATE INDEX IF NOT EXISTS idx_docs_covering
    ON legis_docs(jurisdiction, state, year DESC)
    INCLUDE (title, date, document_type);
COMMENT ON INDEX idx_docs_covering IS 'Covering index for dashboard queries - enables index-only scans';

DO $$
BEGIN
    RAISE NOTICE '✓ All indexes created successfully';
END $$;

-- ============================================================================
-- STEP 6: MATERIALIZED VIEWS FOR FAST AGGREGATIONS
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '=== Creating Materialized Views for Analytics ===';
END $$;

-- 6.1: Documents by jurisdiction and year
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_docs_year_juris AS
SELECT
    jurisdiction,
    year,
    COUNT(*) AS n_docs,
    COUNT(DISTINCT state) AS n_states,
    MIN(date) AS earliest_doc,
    MAX(date) AS latest_doc
FROM legis_docs
GROUP BY jurisdiction, year;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_yj_pk
    ON mv_docs_year_juris(jurisdiction, year);
CREATE INDEX IF NOT EXISTS idx_mv_yj_juris
    ON mv_docs_year_juris(jurisdiction);
CREATE INDEX IF NOT EXISTS idx_mv_yj_year
    ON mv_docs_year_juris(year DESC);

COMMENT ON MATERIALIZED VIEW mv_docs_year_juris IS 'Pre-aggregated document counts by jurisdiction and year - refresh after ingest';

-- 6.2: Documents by state and year (for geographic visualization)
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_docs_state_year AS
SELECT
    state,
    year,
    COUNT(*) AS n_docs,
    COUNT(DISTINCT document_type) AS n_document_types,
    array_agg(DISTINCT document_type) AS document_types
FROM legis_docs
WHERE state IS NOT NULL
GROUP BY state, year;

CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_sy_pk
    ON mv_docs_state_year(state, year);
CREATE INDEX IF NOT EXISTS idx_mv_sy_state
    ON mv_docs_state_year(state);
CREATE INDEX IF NOT EXISTS idx_mv_sy_year
    ON mv_docs_state_year(year DESC);

COMMENT ON MATERIALIZED VIEW mv_docs_state_year IS 'State-level document statistics - used for choropleth maps';

-- 6.3: Document type distribution
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_docs_by_type AS
SELECT
    document_type,
    jurisdiction,
    COUNT(*) AS n_docs,
    COUNT(DISTINCT state) AS n_states,
    MIN(date) AS earliest_doc,
    MAX(date) AS latest_doc,
    ROUND(AVG(LENGTH(full_text))) AS avg_text_length
FROM legis_docs
WHERE document_type IS NOT NULL
GROUP BY document_type, jurisdiction
ORDER BY n_docs DESC;

CREATE INDEX IF NOT EXISTS idx_mv_type_jurisdiction
    ON mv_docs_by_type(jurisdiction, document_type);

COMMENT ON MATERIALIZED VIEW mv_docs_by_type IS 'Document type analysis - lei, decreto, portaria distribution';

DO $$
BEGIN
    RAISE NOTICE '✓ Materialized views created successfully';
END $$;

-- ============================================================================
-- STEP 7: AUTO-UPDATE TRIGGER FOR updated_at
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '=== Creating Automatic Timestamp Trigger ===';
END $$;

CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_legis_docs_modtime ON legis_docs;
CREATE TRIGGER update_legis_docs_modtime
    BEFORE UPDATE ON legis_docs
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();

COMMENT ON FUNCTION update_modified_column() IS 'Auto-update updated_at timestamp on row modification';

DO $$
BEGIN
    RAISE NOTICE '✓ Auto-update trigger installed';
END $$;

-- ============================================================================
-- STEP 8: UTILITY FUNCTIONS FOR MATERIALIZED VIEW REFRESH
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '=== Creating Utility Functions ===';
END $$;

-- Function to refresh all materialized views
CREATE OR REPLACE FUNCTION refresh_all_mv()
RETURNS TABLE(view_name TEXT, refresh_time INTERVAL) AS $$
DECLARE
    start_time TIMESTAMP;
    end_time TIMESTAMP;
BEGIN
    -- Refresh mv_docs_year_juris
    start_time := clock_timestamp();
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_docs_year_juris;
    end_time := clock_timestamp();
    view_name := 'mv_docs_year_juris';
    refresh_time := end_time - start_time;
    RETURN NEXT;

    -- Refresh mv_docs_state_year
    start_time := clock_timestamp();
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_docs_state_year;
    end_time := clock_timestamp();
    view_name := 'mv_docs_state_year';
    refresh_time := end_time - start_time;
    RETURN NEXT;

    -- Refresh mv_docs_by_type
    start_time := clock_timestamp();
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_docs_by_type;
    end_time := clock_timestamp();
    view_name := 'mv_docs_by_type';
    refresh_time := end_time - start_time;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION refresh_all_mv() IS 'Refresh all materialized views and report timing - run after ingest';

-- Function to record ingest batch completion
CREATE OR REPLACE FUNCTION complete_ingest_batch(p_batch_id BIGINT, p_doc_count INTEGER)
RETURNS VOID AS $$
BEGIN
    UPDATE ingest_control
    SET status = 'completed',
        documents_count = p_doc_count,
        completed_at = NOW()
    WHERE batch_id = p_batch_id;

    -- Auto-refresh materialized views after successful ingest
    PERFORM refresh_all_mv();
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION complete_ingest_batch(BIGINT, INTEGER) IS 'Mark batch complete and auto-refresh analytics';

DO $$
BEGIN
    RAISE NOTICE '✓ Utility functions created';
END $$;

-- ============================================================================
-- STEP 9: QUERY PERFORMANCE VIEWS
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '=== Creating Performance Monitoring Views ===';
END $$;

-- View to monitor slow queries
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

COMMENT ON VIEW v_slow_queries IS 'Monitor queries slower than 100ms - use for optimization';

-- View for table size monitoring
CREATE OR REPLACE VIEW v_table_sizes AS
SELECT
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) AS total_size,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) AS table_size,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename) - pg_relation_size(schemaname||'.'||tablename)) AS index_size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

COMMENT ON VIEW v_table_sizes IS 'Monitor table and index sizes';

DO $$
BEGIN
    RAISE NOTICE '✓ Performance monitoring views created';
END $$;

-- ============================================================================
-- STEP 10: EXAMPLE QUERIES AND USAGE PATTERNS
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '';
    RAISE NOTICE '==========================================================';
    RAISE NOTICE 'HIGH-PERFORMANCE SCHEMA INSTALLATION COMPLETE';
    RAISE NOTICE '==========================================================';
    RAISE NOTICE '';
    RAISE NOTICE 'USAGE EXAMPLES:';
    RAISE NOTICE '';
    RAISE NOTICE '1. Full-Text Search (sub-second on 134k docs):';
    RAISE NOTICE '   SELECT id, title, date FROM legis_docs';
    RAISE NOTICE '   WHERE search_vector @@ to_tsquery(''portuguese'', ''transporte & urbano'')';
    RAISE NOTICE '   ORDER BY date DESC LIMIT 100;';
    RAISE NOTICE '';
    RAISE NOTICE '2. Fuzzy Title Search:';
    RAISE NOTICE '   SELECT id, title FROM legis_docs';
    RAISE NOTICE '   WHERE unaccent(title) ILIKE unaccent(''%mobilidade%'')';
    RAISE NOTICE '   LIMIT 100;';
    RAISE NOTICE '';
    RAISE NOTICE '3. State + Year Filter (uses composite index):';
    RAISE NOTICE '   SELECT * FROM legis_docs';
    RAISE NOTICE '   WHERE state = ''SP'' AND year = 2024';
    RAISE NOTICE '   ORDER BY date DESC;';
    RAISE NOTICE '';
    RAISE NOTICE '4. Fast Aggregations (using materialized views):';
    RAISE NOTICE '   SELECT * FROM mv_docs_state_year';
    RAISE NOTICE '   WHERE state = ''RJ'' AND year BETWEEN 2020 AND 2024;';
    RAISE NOTICE '';
    RAISE NOTICE '5. Refresh Analytics After Ingest:';
    RAISE NOTICE '   SELECT * FROM refresh_all_mv();';
    RAISE NOTICE '   -- or --';
    RAISE NOTICE '   SELECT complete_ingest_batch(123, 5000);';
    RAISE NOTICE '';
    RAISE NOTICE 'PERFORMANCE MONITORING:';
    RAISE NOTICE '   SELECT * FROM v_slow_queries;';
    RAISE NOTICE '   SELECT * FROM v_table_sizes;';
    RAISE NOTICE '';
    RAISE NOTICE '==========================================================';
END $$;

-- ============================================================================
-- ROLLBACK INSTRUCTIONS (in case of issues)
-- ============================================================================
/*
-- ROLLBACK SCRIPT (run only if needed):

DROP MATERIALIZED VIEW IF EXISTS mv_docs_by_type CASCADE;
DROP MATERIALIZED VIEW IF EXISTS mv_docs_state_year CASCADE;
DROP MATERIALIZED VIEW IF EXISTS mv_docs_year_juris CASCADE;
DROP TABLE IF EXISTS ingest_control CASCADE;
DROP TABLE IF EXISTS legis_docs CASCADE;
DROP FUNCTION IF EXISTS refresh_all_mv() CASCADE;
DROP FUNCTION IF EXISTS complete_ingest_batch(BIGINT, INTEGER) CASCADE;
DROP FUNCTION IF EXISTS update_modified_column() CASCADE;
DROP VIEW IF EXISTS v_slow_queries;
DROP VIEW IF EXISTS v_table_sizes;

-- Note: Extensions are NOT dropped during rollback to avoid breaking other tables
*/
