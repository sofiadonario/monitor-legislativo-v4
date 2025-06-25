-- Database Schema Optimization for Monitor Legislativo v4
-- Phase 4 Week 14: Query optimization, indexes, and performance tuning
-- PostgreSQL 15+ optimized schema with performance enhancements

-- =============================================================================
-- Index Strategy & Performance Optimization
-- =============================================================================

-- Drop existing indexes if they exist (for migrations)
DROP INDEX IF EXISTS idx_documents_urn;
DROP INDEX IF EXISTS idx_documents_type;
DROP INDEX IF EXISTS idx_documents_collected;
DROP INDEX IF EXISTS idx_documents_updated;
DROP INDEX IF EXISTS idx_documents_source;
DROP INDEX IF EXISTS idx_documents_state;
DROP INDEX IF EXISTS idx_documents_municipality;
DROP INDEX IF EXISTS gin_content_search;
DROP INDEX IF EXISTS gin_metadata;
DROP INDEX IF EXISTS gin_title_search;
DROP INDEX IF EXISTS idx_search_terms_active;
DROP INDEX IF EXISTS idx_collection_logs_status;
DROP INDEX IF EXISTS idx_collection_logs_date;

-- =============================================================================
-- Primary Table Indexes (Core Performance)
-- =============================================================================

-- Legislative documents table - core indexes
CREATE INDEX CONCURRENTLY idx_documents_urn 
    ON legislative_documents(urn) 
    WHERE urn IS NOT NULL;

CREATE INDEX CONCURRENTLY idx_documents_type 
    ON legislative_documents(document_type) 
    WHERE document_type IS NOT NULL;

CREATE INDEX CONCURRENTLY idx_documents_collected 
    ON legislative_documents(collected_at DESC)
    WHERE collected_at IS NOT NULL;

CREATE INDEX CONCURRENTLY idx_documents_updated 
    ON legislative_documents(updated_at DESC)
    WHERE updated_at IS NOT NULL;

-- Composite index for common query patterns
CREATE INDEX CONCURRENTLY idx_documents_type_date 
    ON legislative_documents(document_type, collected_at DESC)
    WHERE document_type IS NOT NULL AND collected_at IS NOT NULL;

-- Source and location indexes
CREATE INDEX CONCURRENTLY idx_documents_source 
    ON legislative_documents(source)
    WHERE source IS NOT NULL;

-- Extract state and municipality from metadata for better performance
CREATE INDEX CONCURRENTLY idx_documents_state 
    ON legislative_documents((metadata->>'state'))
    WHERE metadata->>'state' IS NOT NULL;

CREATE INDEX CONCURRENTLY idx_documents_municipality 
    ON legislative_documents((metadata->>'municipality'))
    WHERE metadata->>'municipality' IS NOT NULL;

-- =============================================================================
-- Full-Text Search Indexes (Portuguese Language)
-- =============================================================================

-- Install Portuguese text search extension if not exists
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gin;

-- Full-text search on content (Portuguese)
CREATE INDEX CONCURRENTLY gin_content_search 
    ON legislative_documents 
    USING GIN (to_tsvector('portuguese', content))
    WHERE content IS NOT NULL AND length(content) > 0;

-- Full-text search on title (Portuguese)
CREATE INDEX CONCURRENTLY gin_title_search 
    ON legislative_documents 
    USING GIN (to_tsvector('portuguese', title))
    WHERE title IS NOT NULL AND length(title) > 0;

-- Trigram search for fuzzy matching
CREATE INDEX CONCURRENTLY trgm_title_idx 
    ON legislative_documents 
    USING GIN (title gin_trgm_ops)
    WHERE title IS NOT NULL;

CREATE INDEX CONCURRENTLY trgm_content_idx 
    ON legislative_documents 
    USING GIN (content gin_trgm_ops)
    WHERE content IS NOT NULL AND length(content) > 0;

-- =============================================================================
-- JSONB Metadata Indexes (Optimized for Brazilian Government Data)
-- =============================================================================

-- General JSONB index for metadata
CREATE INDEX CONCURRENTLY gin_metadata 
    ON legislative_documents 
    USING GIN (metadata)
    WHERE metadata IS NOT NULL;

-- Specific indexes for commonly queried metadata fields
CREATE INDEX CONCURRENTLY idx_metadata_orgao 
    ON legislative_documents((metadata->>'orgao'))
    WHERE metadata->>'orgao' IS NOT NULL;

CREATE INDEX CONCURRENTLY idx_metadata_ano 
    ON legislative_documents((metadata->>'ano'))
    WHERE metadata->>'ano' IS NOT NULL;

CREATE INDEX CONCURRENTLY idx_metadata_numero 
    ON legislative_documents((metadata->>'numero'))
    WHERE metadata->>'numero' IS NOT NULL;

-- Transport-specific metadata indexes
CREATE INDEX CONCURRENTLY idx_metadata_modal_transporte 
    ON legislative_documents((metadata->>'modal_transporte'))
    WHERE metadata->>'modal_transporte' IS NOT NULL;

CREATE INDEX CONCURRENTLY idx_metadata_categoria 
    ON legislative_documents((metadata->>'categoria'))
    WHERE metadata->>'categoria' IS NOT NULL;

-- =============================================================================
-- Supporting Table Indexes
-- =============================================================================

-- Search terms table
CREATE INDEX CONCURRENTLY idx_search_terms_active 
    ON search_terms(active)
    WHERE active = true;

CREATE INDEX CONCURRENTLY idx_search_terms_frequency 
    ON search_terms(collection_frequency);

CREATE INDEX CONCURRENTLY idx_search_terms_priority 
    ON search_terms(priority DESC);

-- Collection logs table
CREATE INDEX CONCURRENTLY idx_collection_logs_status 
    ON collection_logs(status);

CREATE INDEX CONCURRENTLY idx_collection_logs_date 
    ON collection_logs(started_at DESC);

CREATE INDEX CONCURRENTLY idx_collection_logs_term 
    ON collection_logs(search_term_id);

-- Composite index for collection monitoring
CREATE INDEX CONCURRENTLY idx_collection_logs_monitoring 
    ON collection_logs(search_term_id, started_at DESC, status)
    WHERE started_at IS NOT NULL;

-- =============================================================================
-- Materialized Views for Performance
-- =============================================================================

-- Document statistics by type and date
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_document_statistics AS
SELECT 
    document_type,
    DATE_TRUNC('month', collected_at) as month,
    metadata->>'state' as state,
    COUNT(*) as document_count,
    AVG(LENGTH(content)) as avg_content_length,
    MAX(collected_at) as latest_collection,
    MIN(collected_at) as earliest_collection
FROM legislative_documents 
WHERE collected_at IS NOT NULL
GROUP BY document_type, DATE_TRUNC('month', collected_at), metadata->>'state';

-- Create index on materialized view
CREATE INDEX idx_mv_doc_stats_type_month 
    ON mv_document_statistics(document_type, month DESC);

CREATE INDEX idx_mv_doc_stats_state 
    ON mv_document_statistics(state)
    WHERE state IS NOT NULL;

-- Transport legislation summary view
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_transport_summary AS
SELECT 
    metadata->>'modal_transporte' as transport_modal,
    metadata->>'state' as state,
    document_type,
    COUNT(*) as document_count,
    STRING_AGG(DISTINCT metadata->>'orgao', ', ') as source_organs,
    MAX(collected_at) as latest_update,
    AVG(LENGTH(content)) as avg_content_length
FROM legislative_documents 
WHERE metadata->>'modal_transporte' IS NOT NULL
GROUP BY metadata->>'modal_transporte', metadata->>'state', document_type;

-- Create index on transport summary
CREATE INDEX idx_mv_transport_modal 
    ON mv_transport_summary(transport_modal);

CREATE INDEX idx_mv_transport_state 
    ON mv_transport_summary(state)
    WHERE state IS NOT NULL;

-- Collection performance view
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_collection_performance AS
SELECT 
    st.term,
    st.category,
    COUNT(cl.id) as total_collections,
    COUNT(CASE WHEN cl.status = 'success' THEN 1 END) as successful_collections,
    COUNT(CASE WHEN cl.status = 'error' THEN 1 END) as failed_collections,
    AVG(cl.execution_time_ms) as avg_execution_time,
    AVG(cl.records_collected) as avg_records_collected,
    MAX(cl.completed_at) as last_collection,
    SUM(cl.records_collected) as total_records_collected
FROM search_terms st
LEFT JOIN collection_logs cl ON st.id = cl.search_term_id
WHERE st.active = true
GROUP BY st.id, st.term, st.category;

-- Create index on collection performance
CREATE INDEX idx_mv_collection_perf_term 
    ON mv_collection_performance(term);

-- =============================================================================
-- Query Optimization Functions
-- =============================================================================

-- Function to refresh all materialized views
CREATE OR REPLACE FUNCTION refresh_all_materialized_views()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_document_statistics;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_transport_summary;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_collection_performance;
    
    -- Log refresh operation
    INSERT INTO system_logs (operation, status, message, created_at)
    VALUES ('mv_refresh', 'success', 'All materialized views refreshed', NOW());
    
EXCEPTION WHEN OTHERS THEN
    -- Log error
    INSERT INTO system_logs (operation, status, message, error_details, created_at)
    VALUES ('mv_refresh', 'error', 'Failed to refresh materialized views', SQLERRM, NOW());
    RAISE;
END;
$$;

-- Function for intelligent document search with ranking
CREATE OR REPLACE FUNCTION search_documents_ranked(
    search_query TEXT,
    doc_types TEXT[] DEFAULT NULL,
    states TEXT[] DEFAULT NULL,
    limit_count INTEGER DEFAULT 50,
    offset_count INTEGER DEFAULT 0
)
RETURNS TABLE (
    id BIGINT,
    urn VARCHAR(255),
    title TEXT,
    document_type VARCHAR(50),
    metadata JSONB,
    collected_at TIMESTAMP,
    rank REAL,
    headline TEXT
)
LANGUAGE plpgsql
AS $$
DECLARE
    ts_query tsquery;
BEGIN
    -- Create text search query
    ts_query := plainto_tsquery('portuguese', search_query);
    
    RETURN QUERY
    SELECT 
        ld.id,
        ld.urn,
        ld.title,
        ld.document_type,
        ld.metadata,
        ld.collected_at,
        -- Ranking based on title and content relevance
        (
            ts_rank(to_tsvector('portuguese', ld.title), ts_query) * 2.0 +
            ts_rank(to_tsvector('portuguese', ld.content), ts_query)
        ) as rank,
        -- Generate headline for search results
        ts_headline('portuguese', ld.title, ts_query, 'MaxWords=20, MinWords=5') as headline
    FROM legislative_documents ld
    WHERE 
        (ts_query @@ to_tsvector('portuguese', ld.title) OR 
         ts_query @@ to_tsvector('portuguese', ld.content))
        AND (doc_types IS NULL OR ld.document_type = ANY(doc_types))
        AND (states IS NULL OR ld.metadata->>'state' = ANY(states))
    ORDER BY rank DESC, ld.collected_at DESC
    LIMIT limit_count
    OFFSET offset_count;
END;
$$;

-- Function for geographic document distribution
CREATE OR REPLACE FUNCTION get_document_distribution_by_state()
RETURNS TABLE (
    state TEXT,
    document_count BIGINT,
    latest_document TIMESTAMP,
    document_types BIGINT,
    transport_related BIGINT
)
LANGUAGE sql
STABLE
AS $$
    SELECT 
        metadata->>'state' as state,
        COUNT(*) as document_count,
        MAX(collected_at) as latest_document,
        COUNT(DISTINCT document_type) as document_types,
        COUNT(CASE WHEN metadata->>'modal_transporte' IS NOT NULL THEN 1 END) as transport_related
    FROM legislative_documents 
    WHERE metadata->>'state' IS NOT NULL
    GROUP BY metadata->>'state'
    ORDER BY document_count DESC;
$$;

-- Function for collection health monitoring
CREATE OR REPLACE FUNCTION get_collection_health_status()
RETURNS TABLE (
    search_term TEXT,
    last_success TIMESTAMP,
    last_failure TIMESTAMP,
    success_rate NUMERIC,
    avg_execution_time NUMERIC,
    health_status TEXT
)
LANGUAGE sql
STABLE
AS $$
    WITH collection_stats AS (
        SELECT 
            st.term,
            MAX(CASE WHEN cl.status = 'success' THEN cl.completed_at END) as last_success,
            MAX(CASE WHEN cl.status = 'error' THEN cl.completed_at END) as last_failure,
            COUNT(CASE WHEN cl.status = 'success' THEN 1 END)::NUMERIC / 
                NULLIF(COUNT(cl.id), 0) as success_rate,
            AVG(cl.execution_time_ms) as avg_execution_time
        FROM search_terms st
        LEFT JOIN collection_logs cl ON st.id = cl.search_term_id
        WHERE st.active = true 
        AND cl.started_at >= NOW() - INTERVAL '30 days'
        GROUP BY st.id, st.term
    )
    SELECT 
        term as search_term,
        last_success,
        last_failure,
        ROUND(success_rate * 100, 2) as success_rate,
        ROUND(avg_execution_time, 2) as avg_execution_time,
        CASE 
            WHEN success_rate >= 0.95 THEN 'healthy'
            WHEN success_rate >= 0.80 THEN 'warning'
            ELSE 'critical'
        END as health_status
    FROM collection_stats
    ORDER BY success_rate ASC, term;
$$;

-- =============================================================================
-- Performance Monitoring Views
-- =============================================================================

-- Slow query monitoring view
CREATE OR REPLACE VIEW v_slow_queries AS
SELECT 
    query,
    calls,
    total_time,
    mean_time,
    min_time,
    max_time,
    stddev_time,
    rows as total_rows,
    100.0 * shared_blks_hit / nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
FROM pg_stat_statements 
WHERE total_time > 1000  -- Queries taking more than 1 second total
ORDER BY total_time DESC;

-- Index usage statistics
CREATE OR REPLACE VIEW v_index_usage AS
SELECT 
    schemaname,
    tablename,
    indexname,
    idx_tup_read,
    idx_tup_fetch,
    idx_scan,
    CASE 
        WHEN idx_scan = 0 THEN 'unused'
        WHEN idx_scan < 10 THEN 'rarely_used'
        ELSE 'active'
    END as usage_status
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC, idx_tup_read DESC;

-- Table size and bloat monitoring
CREATE OR REPLACE VIEW v_table_sizes AS
SELECT 
    schemaname,
    tablename,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as total_size,
    pg_size_pretty(pg_relation_size(schemaname||'.'||tablename)) as table_size,
    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename) - pg_relation_size(schemaname||'.'||tablename)) as index_size,
    n_tup_ins + n_tup_upd + n_tup_del as total_modifications,
    n_live_tup,
    n_dead_tup,
    CASE 
        WHEN n_live_tup > 0 THEN 
            ROUND(n_dead_tup::NUMERIC / n_live_tup, 4) * 100
        ELSE 0 
    END as dead_tuple_percent
FROM pg_stat_user_tables
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- =============================================================================
-- Maintenance and Cleanup Procedures
-- =============================================================================

-- Automated VACUUM and ANALYZE procedure
CREATE OR REPLACE FUNCTION maintain_database_health()
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    table_record RECORD;
    vacuum_command TEXT;
BEGIN
    -- VACUUM and ANALYZE tables with high modification rates
    FOR table_record IN 
        SELECT tablename, n_tup_ins + n_tup_upd + n_tup_del as modifications
        FROM pg_stat_user_tables 
        WHERE (n_tup_ins + n_tup_upd + n_tup_del) > 1000
        OR (n_dead_tup::FLOAT / GREATEST(n_live_tup, 1)) > 0.1
    LOOP
        vacuum_command := 'VACUUM (ANALYZE, VERBOSE) ' || quote_ident(table_record.tablename);
        EXECUTE vacuum_command;
        
        -- Log maintenance operation
        INSERT INTO system_logs (operation, status, message, created_at)
        VALUES ('maintenance', 'success', 
                'VACUUM ANALYZE completed for ' || table_record.tablename, NOW());
    END LOOP;
    
    -- Update table statistics
    ANALYZE;
    
    -- Refresh materialized views if they're stale
    PERFORM refresh_all_materialized_views();
    
EXCEPTION WHEN OTHERS THEN
    INSERT INTO system_logs (operation, status, message, error_details, created_at)
    VALUES ('maintenance', 'error', 'Database maintenance failed', SQLERRM, NOW());
    RAISE;
END;
$$;

-- Cleanup old log entries
CREATE OR REPLACE FUNCTION cleanup_old_logs(retention_days INTEGER DEFAULT 90)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Delete old collection logs
    DELETE FROM collection_logs 
    WHERE completed_at < NOW() - (retention_days || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Delete old system logs
    DELETE FROM system_logs 
    WHERE created_at < NOW() - (retention_days || ' days')::INTERVAL;
    
    -- Log cleanup operation
    INSERT INTO system_logs (operation, status, message, created_at)
    VALUES ('cleanup', 'success', 
            'Cleaned up ' || deleted_count || ' old log entries', NOW());
    
    RETURN deleted_count;
END;
$$;

-- =============================================================================
-- Database Statistics and Monitoring
-- =============================================================================

-- Create system logs table if not exists
CREATE TABLE IF NOT EXISTS system_logs (
    id BIGSERIAL PRIMARY KEY,
    operation VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL,
    message TEXT,
    error_details TEXT,
    execution_time_ms INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for system logs
CREATE INDEX IF NOT EXISTS idx_system_logs_operation 
    ON system_logs(operation, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_system_logs_status 
    ON system_logs(status, created_at DESC);

-- =============================================================================
-- Query Performance Optimization Settings
-- =============================================================================

-- Update PostgreSQL configuration for optimal performance
-- These should be applied in postgresql.conf

/*
Recommended PostgreSQL configuration settings for Monitor Legislativo v4:

# Memory settings
shared_buffers = 256MB                    # 25% of total RAM
effective_cache_size = 1GB               # 75% of total RAM
work_mem = 4MB                           # Per query operation
maintenance_work_mem = 128MB             # For maintenance operations

# Checkpoint settings
checkpoint_completion_target = 0.7
wal_buffers = 16MB
checkpoint_timeout = 10min

# Connection settings
max_connections = 100
shared_preload_libraries = 'pg_stat_statements'

# Query planner settings
default_statistics_target = 100
random_page_cost = 1.1                  # For SSD storage
effective_io_concurrency = 200          # For SSD storage

# Full-text search settings
default_text_search_config = 'portuguese'

# Logging settings
log_min_duration_statement = 1000       # Log queries > 1 second
log_checkpoints = on
log_connections = on
log_disconnections = on
log_lock_waits = on

# Auto vacuum settings
autovacuum = on
autovacuum_max_workers = 3
autovacuum_naptime = 1min
autovacuum_vacuum_threshold = 50
autovacuum_analyze_threshold = 50
autovacuum_vacuum_scale_factor = 0.1
autovacuum_analyze_scale_factor = 0.05
*/

-- =============================================================================
-- Performance Testing Queries
-- =============================================================================

-- Test query performance for common operations
/*
-- 1. Full-text search performance test
EXPLAIN (ANALYZE, BUFFERS) 
SELECT * FROM search_documents_ranked('transporte público', NULL, NULL, 20, 0);

-- 2. Geographic aggregation performance test
EXPLAIN (ANALYZE, BUFFERS)
SELECT * FROM get_document_distribution_by_state();

-- 3. Recent documents query performance test
EXPLAIN (ANALYZE, BUFFERS)
SELECT id, title, document_type, metadata->>'state', collected_at
FROM legislative_documents 
WHERE collected_at >= NOW() - INTERVAL '30 days'
ORDER BY collected_at DESC
LIMIT 100;

-- 4. Complex metadata query performance test
EXPLAIN (ANALYZE, BUFFERS)
SELECT document_type, COUNT(*), metadata->>'orgao'
FROM legislative_documents 
WHERE metadata->>'modal_transporte' IS NOT NULL
  AND metadata->>'state' IN ('SP', 'RJ', 'MG')
  AND collected_at >= '2024-01-01'
GROUP BY document_type, metadata->>'orgao'
ORDER BY COUNT(*) DESC;
*/

-- =============================================================================
-- Completion Message
-- =============================================================================

DO $$
BEGIN
    RAISE NOTICE 'Database schema optimization completed successfully!';
    RAISE NOTICE 'Created % indexes for performance optimization', 
        (SELECT COUNT(*) FROM pg_indexes WHERE schemaname = 'public');
    RAISE NOTICE 'Created % materialized views for query acceleration', 
        (SELECT COUNT(*) FROM pg_matviews WHERE schemaname = 'public');
    RAISE NOTICE 'Performance monitoring and maintenance procedures are now active.';
END
$$;