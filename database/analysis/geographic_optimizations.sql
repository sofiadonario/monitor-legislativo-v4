-- Geographic Analysis Database Optimizations
-- Implements PRD specifications for handling 134k+ documents efficiently

-- Create extension for advanced text search if not exists
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- Create extension for cron jobs (for scheduled refreshes)
-- Note: Requires pg_cron extension to be installed
-- CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Drop existing materialized view if exists
DROP MATERIALIZED VIEW IF EXISTS mv_geographic_stats CASCADE;

-- Create materialized view for geographic aggregations
CREATE MATERIALIZED VIEW mv_geographic_stats AS
SELECT 
    estado,
    municipio,
    categoria_original,
    tipo,
    COUNT(*) as doc_count,
    COUNT(DISTINCT DATE(data_documento)) as active_days,
    MIN(data_documento) as first_doc,
    MAX(data_documento) as last_doc,
    AVG(CASE 
        WHEN LENGTH(conteudo) > 0 THEN LENGTH(conteudo) 
        ELSE NULL 
    END) as avg_content_length,
    -- Add temporal metrics
    EXTRACT(YEAR FROM MAX(data_documento)) as latest_year,
    EXTRACT(MONTH FROM MAX(data_documento)) as latest_month,
    -- Add document freshness indicator
    CASE 
        WHEN MAX(data_documento) >= CURRENT_DATE - INTERVAL '7 days' THEN 'very_fresh'
        WHEN MAX(data_documento) >= CURRENT_DATE - INTERVAL '30 days' THEN 'fresh'
        WHEN MAX(data_documento) >= CURRENT_DATE - INTERVAL '90 days' THEN 'recent'
        WHEN MAX(data_documento) >= CURRENT_DATE - INTERVAL '365 days' THEN 'dated'
        ELSE 'old'
    END as freshness_category
FROM documents
WHERE estado IS NOT NULL AND estado != ''
GROUP BY estado, municipio, categoria_original, tipo
WITH DATA;

-- Create indexes on materialized view
CREATE INDEX idx_mv_geo_estado ON mv_geographic_stats(estado);
CREATE INDEX idx_mv_geo_municipio ON mv_geographic_stats(municipio);
CREATE INDEX idx_mv_geo_categoria ON mv_geographic_stats(categoria_original);
CREATE INDEX idx_mv_geo_tipo ON mv_geographic_stats(tipo);
CREATE INDEX idx_mv_geo_doc_count ON mv_geographic_stats(doc_count DESC);
CREATE INDEX idx_mv_geo_latest_doc ON mv_geographic_stats(last_doc DESC);
CREATE INDEX idx_mv_geo_freshness ON mv_geographic_stats(freshness_category);

-- Create composite indexes for common query patterns
CREATE INDEX idx_mv_geo_estado_categoria ON mv_geographic_stats(estado, categoria_original);
CREATE INDEX idx_mv_geo_estado_tipo ON mv_geographic_stats(estado, tipo);
CREATE INDEX idx_mv_geo_estado_freshness ON mv_geographic_stats(estado, freshness_category);

-- Create state-level summary view
DROP MATERIALIZED VIEW IF EXISTS mv_state_summary CASCADE;

CREATE MATERIALIZED VIEW mv_state_summary AS
SELECT 
    estado,
    SUM(doc_count) as total_documents,
    COUNT(DISTINCT municipio) as municipality_count,
    COUNT(DISTINCT categoria_original) as category_count,
    COUNT(DISTINCT tipo) as type_count,
    MIN(first_doc) as earliest_document,
    MAX(last_doc) as latest_document,
    AVG(avg_content_length) as avg_document_length,
    -- Calculate document distribution metrics
    STDDEV(doc_count) as doc_count_stddev,
    -- Temporal coverage
    MAX(last_doc) - MIN(first_doc) as temporal_span_days,
    -- Activity score based on recent documents
    SUM(CASE 
        WHEN freshness_category IN ('very_fresh', 'fresh') 
        THEN doc_count 
        ELSE 0 
    END)::FLOAT / NULLIF(SUM(doc_count), 0) as activity_score
FROM mv_geographic_stats
GROUP BY estado
WITH DATA;

-- Create indexes on state summary
CREATE INDEX idx_state_summary_estado ON mv_state_summary(estado);
CREATE INDEX idx_state_summary_total_docs ON mv_state_summary(total_documents DESC);
CREATE INDEX idx_state_summary_activity ON mv_state_summary(activity_score DESC);

-- Create municipality-level summary view
DROP MATERIALIZED VIEW IF EXISTS mv_municipality_summary CASCADE;

CREATE MATERIALIZED VIEW mv_municipality_summary AS
SELECT 
    estado,
    municipio,
    SUM(doc_count) as total_documents,
    COUNT(DISTINCT categoria_original) as category_count,
    COUNT(DISTINCT tipo) as type_count,
    MIN(first_doc) as earliest_document,
    MAX(last_doc) as latest_document,
    -- Ranking within state
    RANK() OVER (PARTITION BY estado ORDER BY SUM(doc_count) DESC) as rank_in_state
FROM mv_geographic_stats
WHERE municipio IS NOT NULL AND municipio != ''
GROUP BY estado, municipio
WITH DATA;

-- Create indexes on municipality summary
CREATE INDEX idx_municipality_summary_estado_municipio ON mv_municipality_summary(estado, municipio);
CREATE INDEX idx_municipality_summary_rank ON mv_municipality_summary(estado, rank_in_state);

-- Create function to refresh all geographic materialized views
CREATE OR REPLACE FUNCTION refresh_geographic_stats()
RETURNS void AS $$
BEGIN
    -- Refresh with CONCURRENTLY to avoid locking
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_geographic_stats;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_state_summary;
    REFRESH MATERIALIZED VIEW CONCURRENTLY mv_municipality_summary;
    
    -- Log the refresh
    INSERT INTO system_logs (log_type, message, created_at)
    VALUES ('geographic_refresh', 'Geographic materialized views refreshed', NOW());
END;
$$ LANGUAGE plpgsql;

-- Create table for caching geographic queries (if not exists)
CREATE TABLE IF NOT EXISTS geographic_query_cache (
    query_hash VARCHAR(64) PRIMARY KEY,
    query_params JSONB,
    result_data JSONB,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    hit_count INTEGER DEFAULT 0
);

-- Create indexes on cache table
CREATE INDEX idx_geo_cache_expires ON geographic_query_cache(expires_at);
CREATE INDEX idx_geo_cache_created ON geographic_query_cache(created_at DESC);

-- Function to clean expired cache entries
CREATE OR REPLACE FUNCTION clean_geographic_cache()
RETURNS void AS $$
BEGIN
    DELETE FROM geographic_query_cache 
    WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Optimize main documents table for geographic queries
-- Add indexes if they don't exist
DO $$
BEGIN
    -- Check and create estado index
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_documents_estado') THEN
        CREATE INDEX idx_documents_estado ON documents(estado) WHERE estado IS NOT NULL;
    END IF;
    
    -- Check and create municipio index
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_documents_municipio') THEN
        CREATE INDEX idx_documents_municipio ON documents(municipio) WHERE municipio IS NOT NULL;
    END IF;
    
    -- Check and create composite index for geographic filtering
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_documents_geo_composite') THEN
        CREATE INDEX idx_documents_geo_composite ON documents(estado, municipio, data_documento DESC) 
        WHERE estado IS NOT NULL;
    END IF;
    
    -- Check and create GIN index for text search on municipality names
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE indexname = 'idx_documents_municipio_gin') THEN
        CREATE INDEX idx_documents_municipio_gin ON documents USING gin(municipio gin_trgm_ops)
        WHERE municipio IS NOT NULL;
    END IF;
END $$;

-- Create helper function for geographic sampling
CREATE OR REPLACE FUNCTION sample_documents_by_state(
    sample_size INTEGER DEFAULT 5000,
    category_filter TEXT DEFAULT NULL
)
RETURNS TABLE (
    id INTEGER,
    titulo TEXT,
    estado VARCHAR(2),
    municipio TEXT,
    categoria_original TEXT,
    tipo TEXT,
    data_documento DATE,
    sample_weight NUMERIC
) AS $$
DECLARE
    total_count INTEGER;
    state_sample_size INTEGER;
BEGIN
    -- Get total count
    SELECT COUNT(*) INTO total_count 
    FROM documents 
    WHERE estado IS NOT NULL 
    AND (category_filter IS NULL OR categoria_original = category_filter);
    
    -- Calculate sample weight
    IF total_count <= sample_size THEN
        -- Return all documents if under sample size
        RETURN QUERY
        SELECT 
            d.id,
            d.titulo,
            d.estado,
            d.municipio,
            d.categoria_original,
            d.tipo,
            d.data_documento,
            1.0::NUMERIC as sample_weight
        FROM documents d
        WHERE d.estado IS NOT NULL
        AND (category_filter IS NULL OR d.categoria_original = category_filter);
    ELSE
        -- Stratified sampling by state
        RETURN QUERY
        WITH state_counts AS (
            SELECT 
                estado,
                COUNT(*) as state_total,
                COUNT(*)::FLOAT / total_count as state_proportion
            FROM documents
            WHERE estado IS NOT NULL
            AND (category_filter IS NULL OR categoria_original = category_filter)
            GROUP BY estado
        ),
        state_samples AS (
            SELECT 
                estado,
                GREATEST(3, ROUND(sample_size * state_proportion)) as target_sample
            FROM state_counts
        )
        SELECT 
            d.id,
            d.titulo,
            d.estado,
            d.municipio,
            d.categoria_original,
            d.tipo,
            d.data_documento,
            (sc.state_total::NUMERIC / ss.target_sample::NUMERIC) as sample_weight
        FROM documents d
        JOIN state_counts sc ON d.estado = sc.estado
        JOIN state_samples ss ON d.estado = ss.estado
        WHERE d.estado IS NOT NULL
        AND (category_filter IS NULL OR d.categoria_original = category_filter)
        AND d.id IN (
            SELECT id FROM (
                SELECT 
                    id,
                    ROW_NUMBER() OVER (PARTITION BY estado ORDER BY RANDOM()) as rn
                FROM documents
                WHERE estado IS NOT NULL
                AND (category_filter IS NULL OR categoria_original = category_filter)
            ) sampled
            WHERE sampled.rn <= (
                SELECT target_sample 
                FROM state_samples 
                WHERE estado = sampled.estado
            )
        );
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Create view for real-time geographic statistics
CREATE OR REPLACE VIEW v_geographic_realtime AS
SELECT 
    estado,
    COUNT(*) as document_count,
    COUNT(DISTINCT municipio) as municipality_count,
    MAX(data_documento) as latest_document,
    COUNT(CASE 
        WHEN data_documento >= CURRENT_DATE - INTERVAL '7 days' 
        THEN 1 
    END) as documents_last_week,
    COUNT(CASE 
        WHEN data_documento >= CURRENT_DATE - INTERVAL '30 days' 
        THEN 1 
    END) as documents_last_month
FROM documents
WHERE estado IS NOT NULL AND estado != ''
GROUP BY estado;

-- Add comment documentation
COMMENT ON MATERIALIZED VIEW mv_geographic_stats IS 
'Pre-aggregated geographic statistics for efficient querying of 134k+ documents';

COMMENT ON MATERIALIZED VIEW mv_state_summary IS 
'State-level summary statistics with activity scores and temporal metrics';

COMMENT ON MATERIALIZED VIEW mv_municipality_summary IS 
'Municipality-level statistics with state rankings';

COMMENT ON FUNCTION refresh_geographic_stats() IS 
'Refreshes all geographic materialized views - should be called hourly';

COMMENT ON FUNCTION sample_documents_by_state(INTEGER, TEXT) IS 
'Returns stratified sample of documents by state with sampling weights';

-- Schedule refresh (requires pg_cron extension)
-- Uncomment if pg_cron is available:
-- SELECT cron.schedule('refresh-geo-stats', '0 * * * *', 'SELECT refresh_geographic_stats();');

-- Initial refresh
SELECT refresh_geographic_stats();