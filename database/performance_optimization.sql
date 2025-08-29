-- PERFORMANCE OPTIMIZATION FOR BRAZILIAN LEGISLATIVE MONITOR
-- ===========================================================
-- Database indexing and optimization strategies for 134k+ documents
-- Target: Sub-2 second query response times with concurrent users

-- ============================================================================
-- 1. PRIMARY INDEXES FOR CORE FILTERING
-- ============================================================================

-- Category index (most common filter - 40.7% Jurisprudência, 38.1% Legislação)
CREATE INDEX IF NOT EXISTS idx_documents_categoria 
ON documents(categoria_original, categoria);

-- Geographic index (SP: 8,234 docs, MG: 6,739 docs are top states)
CREATE INDEX IF NOT EXISTS idx_documents_geographic 
ON documents(estado, municipio);

-- Temporal index for date-based filtering and sorting
CREATE INDEX IF NOT EXISTS idx_documents_temporal 
ON documents(data_documento DESC NULLS LAST);

-- Compound index for most common filter combinations
CREATE INDEX IF NOT EXISTS idx_documents_category_state_date 
ON documents(categoria_original, estado, data_documento DESC);

-- URN index for direct document lookups and references
CREATE INDEX IF NOT EXISTS idx_documents_urn_hash 
ON documents USING hash(urn);

-- Document type index for faceted filtering
CREATE INDEX IF NOT EXISTS idx_documents_tipo 
ON documents(tipo_documento) 
WHERE tipo_documento IS NOT NULL;

-- ============================================================================
-- 2. FULL-TEXT SEARCH OPTIMIZATION
-- ============================================================================

-- Full-text search index with Portuguese language support
CREATE INDEX IF NOT EXISTS idx_documents_fulltext 
ON documents USING gin(
  to_tsvector('portuguese', 
    COALESCE(title, '') || ' ' || 
    COALESCE(ementa, '') || ' ' ||
    COALESCE(categoria_original, '') || ' ' ||
    COALESCE(tipo_documento, '')
  )
);

-- Separate index for title search (most important field)
CREATE INDEX IF NOT EXISTS idx_documents_title_search 
ON documents USING gin(to_tsvector('portuguese', COALESCE(title, '')));

-- URN pattern search for exact references
CREATE INDEX IF NOT EXISTS idx_documents_urn_pattern 
ON documents USING gin(urn gin_trgm_ops);

-- ============================================================================
-- 3. SPECIALIZED INDEXES FOR ADVANCED FEATURES
-- ============================================================================

-- Tribunal identification for jurisprudence documents
CREATE INDEX IF NOT EXISTS idx_documents_tribunal 
ON documents(
  CASE 
    WHEN urn ILIKE '%supremo.tribunal.federal%' THEN 'STF'
    WHEN urn ILIKE '%superior.tribunal.justica%' THEN 'STJ'
    WHEN urn ILIKE '%tribunal.superior.trabalho%' THEN 'TST'
    WHEN urn ILIKE '%tribunal.regional.federal%' THEN 'TRF'
    WHEN urn ILIKE '%tribunal.regional.trabalho%' THEN 'TRT'
    WHEN urn ILIKE '%tribunal.justica%' THEN 'TJ'
    ELSE 'OTHER'
  END
) WHERE categoria_original = 'Jurisprudência';

-- Authority level index for relevance ranking
CREATE INDEX IF NOT EXISTS idx_documents_authority_level 
ON documents(nivel_federativo, estado);

-- Recent documents index for trending analysis
CREATE INDEX IF NOT EXISTS idx_documents_recent 
ON documents(data_documento DESC) 
WHERE data_documento >= CURRENT_DATE - INTERVAL '1 year';

-- ============================================================================
-- 4. PERFORMANCE-OPTIMIZED VIEWS
-- ============================================================================

-- Pre-computed category statistics view
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_category_statistics AS
SELECT 
  COALESCE(categoria_original, categoria, 'Unknown') as categoria,
  COUNT(*) as document_count,
  ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 2) as percentage,
  MIN(data_documento) as earliest_date,
  MAX(data_documento) as latest_date,
  COUNT(DISTINCT estado) as states_covered
FROM documents 
WHERE categoria_original IS NOT NULL OR categoria IS NOT NULL
GROUP BY COALESCE(categoria_original, categoria, 'Unknown')
ORDER BY document_count DESC;

-- Create unique index on materialized view
CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_category_statistics_categoria 
ON mv_category_statistics(categoria);

-- Geographic distribution statistics
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_geographic_statistics AS
SELECT 
  estado,
  COUNT(*) as document_count,
  COUNT(DISTINCT COALESCE(categoria_original, categoria)) as categories_count,
  COUNT(DISTINCT tipo_documento) as document_types_count,
  MIN(data_documento) as earliest_date,
  MAX(data_documento) as latest_date
FROM documents 
WHERE estado IS NOT NULL AND estado != ''
GROUP BY estado
ORDER BY document_count DESC;

-- Create unique index on geographic view
CREATE UNIQUE INDEX IF NOT EXISTS idx_mv_geographic_statistics_estado 
ON mv_geographic_statistics(estado);

-- Monthly document trends for analytics
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_monthly_trends AS
SELECT 
  DATE_TRUNC('month', data_documento) as month_year,
  COALESCE(categoria_original, categoria, 'Unknown') as categoria,
  COUNT(*) as document_count
FROM documents 
WHERE data_documento IS NOT NULL 
  AND data_documento >= CURRENT_DATE - INTERVAL '5 years'
GROUP BY DATE_TRUNC('month', data_documento), 
         COALESCE(categoria_original, categoria, 'Unknown')
ORDER BY month_year DESC, document_count DESC;

-- Create compound index on trends view
CREATE INDEX IF NOT EXISTS idx_mv_monthly_trends_month_categoria 
ON mv_monthly_trends(month_year DESC, categoria);

-- ============================================================================
-- 5. SEARCH OPTIMIZATION FUNCTIONS
-- ============================================================================

-- Function to refresh materialized views (call daily)
CREATE OR REPLACE FUNCTION refresh_library_statistics()
RETURNS void AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY mv_category_statistics;
  REFRESH MATERIALIZED VIEW CONCURRENTLY mv_geographic_statistics;
  REFRESH MATERIALIZED VIEW CONCURRENTLY mv_monthly_trends;
END;
$$ LANGUAGE plpgsql;

-- Function for intelligent document search with ranking
CREATE OR REPLACE FUNCTION search_documents(
  search_query TEXT DEFAULT '',
  category_filter TEXT DEFAULT 'all',
  state_filter TEXT DEFAULT 'all',
  date_start DATE DEFAULT NULL,
  date_end DATE DEFAULT NULL,
  limit_results INTEGER DEFAULT 50,
  offset_results INTEGER DEFAULT 0
) 
RETURNS TABLE(
  id INTEGER,
  urn TEXT,
  title TEXT,
  categoria TEXT,
  estado TEXT,
  data_documento DATE,
  tipo_documento TEXT,
  relevance_score FLOAT,
  search_rank FLOAT
) AS $$
BEGIN
  RETURN QUERY
  SELECT 
    d.id,
    d.urn,
    d.title,
    COALESCE(d.categoria_original, d.categoria, 'Unknown') as categoria,
    d.estado,
    d.data_documento,
    d.tipo_documento,
    
    -- Relevance scoring based on multiple factors
    CASE 
      WHEN search_query != '' THEN
        ts_rank(
          to_tsvector('portuguese', COALESCE(d.title, '') || ' ' || COALESCE(d.ementa, '')),
          plainto_tsquery('portuguese', search_query)
        ) * 10 +
        CASE WHEN d.title ILIKE '%' || search_query || '%' THEN 5 ELSE 0 END +
        CASE WHEN d.urn ILIKE '%' || search_query || '%' THEN 3 ELSE 0 END
      ELSE 0
    END as relevance_score,
    
    -- Authority and recency ranking
    CASE 
      WHEN d.urn ILIKE '%supremo.tribunal.federal%' THEN 5.0
      WHEN d.urn ILIKE '%superior.tribunal.justica%' THEN 4.0
      WHEN d.urn ILIKE '%tribunal.superior.trabalho%' THEN 3.0
      WHEN d.nivel_federativo ILIKE '%federal%' THEN 2.0
      ELSE 1.0
    END +
    CASE 
      WHEN d.data_documento >= CURRENT_DATE - INTERVAL '1 year' THEN 2.0
      WHEN d.data_documento >= CURRENT_DATE - INTERVAL '5 years' THEN 1.0
      ELSE 0.0
    END as search_rank
    
  FROM documents d
  WHERE 
    (search_query = '' OR 
     to_tsvector('portuguese', COALESCE(d.title, '') || ' ' || COALESCE(d.ementa, '')) 
     @@ plainto_tsquery('portuguese', search_query) OR
     d.title ILIKE '%' || search_query || '%' OR
     d.urn ILIKE '%' || search_query || '%')
    
    AND (category_filter = 'all' OR 
         COALESCE(d.categoria_original, d.categoria, 'Unknown') = category_filter)
    
    AND (state_filter = 'all' OR d.estado = state_filter)
    
    AND (date_start IS NULL OR d.data_documento >= date_start)
    AND (date_end IS NULL OR d.data_documento <= date_end)
  
  ORDER BY 
    CASE WHEN search_query != '' THEN relevance_score ELSE 0 END DESC,
    search_rank DESC,
    d.data_documento DESC NULLS LAST
    
  LIMIT limit_results OFFSET offset_results;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 6. PERFORMANCE MONITORING SETUP
-- ============================================================================

-- Table for tracking query performance
CREATE TABLE IF NOT EXISTS query_performance_log (
  id SERIAL PRIMARY KEY,
  query_text TEXT,
  execution_time_ms INTEGER,
  result_count INTEGER,
  filters_applied JSONB,
  timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  user_session TEXT
);

-- Index for performance log analysis
CREATE INDEX IF NOT EXISTS idx_query_performance_timestamp 
ON query_performance_log(timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_query_performance_execution_time 
ON query_performance_log(execution_time_ms);

-- Function to log query performance
CREATE OR REPLACE FUNCTION log_query_performance(
  query_text TEXT,
  execution_time_ms INTEGER,
  result_count INTEGER,
  filters_applied JSONB DEFAULT NULL,
  user_session TEXT DEFAULT NULL
) 
RETURNS void AS $$
BEGIN
  INSERT INTO query_performance_log 
    (query_text, execution_time_ms, result_count, filters_applied, user_session)
  VALUES 
    (query_text, execution_time_ms, result_count, filters_applied, user_session);
    
  -- Clean up old logs (keep last 10,000 entries)
  DELETE FROM query_performance_log 
  WHERE id < (
    SELECT id FROM query_performance_log 
    ORDER BY timestamp DESC 
    LIMIT 1 OFFSET 10000
  );
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 7. CACHE OPTIMIZATION TABLES
-- ============================================================================

-- Search results cache table
CREATE TABLE IF NOT EXISTS search_cache (
  cache_key TEXT PRIMARY KEY,
  query_hash TEXT NOT NULL,
  results_data JSONB NOT NULL,
  result_count INTEGER NOT NULL,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  accessed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
  access_count INTEGER DEFAULT 1
);

-- Index for cache management
CREATE INDEX IF NOT EXISTS idx_search_cache_created 
ON search_cache(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_search_cache_accessed 
ON search_cache(accessed_at DESC);

-- Function to manage cache cleanup
CREATE OR REPLACE FUNCTION cleanup_search_cache()
RETURNS void AS $$
BEGIN
  -- Remove entries older than 1 hour
  DELETE FROM search_cache 
  WHERE created_at < CURRENT_TIMESTAMP - INTERVAL '1 hour';
  
  -- Remove least accessed entries if cache is too large (keep top 1000)
  DELETE FROM search_cache 
  WHERE cache_key NOT IN (
    SELECT cache_key FROM search_cache 
    ORDER BY access_count DESC, accessed_at DESC 
    LIMIT 1000
  );
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 8. REGULAR MAINTENANCE PROCEDURES
-- ============================================================================

-- Daily maintenance procedure
CREATE OR REPLACE FUNCTION daily_maintenance()
RETURNS void AS $$
BEGIN
  -- Refresh materialized views
  PERFORM refresh_library_statistics();
  
  -- Clean up cache
  PERFORM cleanup_search_cache();
  
  -- Update table statistics
  ANALYZE documents;
  ANALYZE mv_category_statistics;
  ANALYZE mv_geographic_statistics;
  ANALYZE mv_monthly_trends;
  
  -- Log maintenance completion
  INSERT INTO query_performance_log 
    (query_text, execution_time_ms, result_count, user_session)
  VALUES 
    ('DAILY_MAINTENANCE', 0, 0, 'system');
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 9. INITIAL DATA ANALYSIS AND VALIDATION
-- ============================================================================

-- Query to validate index effectiveness
-- Run this after creating indexes to ensure they're being used

-- Check index usage statistics
SELECT 
  schemaname,
  tablename,
  indexname,
  idx_tup_read,
  idx_tup_fetch,
  idx_scan
FROM pg_stat_user_indexes 
WHERE tablename = 'documents'
ORDER BY idx_scan DESC;

-- Check table statistics for query planning
SELECT 
  attname,
  n_distinct,
  most_common_vals,
  most_common_freqs
FROM pg_stats 
WHERE tablename = 'documents' 
  AND attname IN ('categoria_original', 'estado', 'tipo_documento');

-- Analyze query performance for common patterns
EXPLAIN (ANALYZE, BUFFERS) 
SELECT * FROM documents 
WHERE categoria_original = 'Jurisprudência' 
  AND estado = 'SP' 
  AND data_documento >= '2023-01-01'
ORDER BY data_documento DESC 
LIMIT 50;

-- ============================================================================
-- 10. DEPLOYMENT NOTES
-- ============================================================================

/*
DEPLOYMENT CHECKLIST:

1. Run this script during off-peak hours (index creation can be intensive)
2. Monitor index creation progress with:
   SELECT * FROM pg_stat_progress_create_index;

3. After deployment, refresh materialized views:
   SELECT refresh_library_statistics();

4. Set up daily maintenance cron job:
   0 2 * * * psql -d database_name -c "SELECT daily_maintenance();"

5. Monitor performance with:
   - Query execution times should be <200ms for most searches
   - Cache hit rate should be >80%
   - Index usage should show consistent idx_scan values

6. Expected improvements:
   - Category filtering: 90% faster (from 1s to <100ms)
   - Geographic filtering: 85% faster (from 800ms to <120ms)
   - Full-text search: 70% faster (from 2s to <600ms)
   - Combined filters: 95% faster (from 5s to <250ms)

7. Memory considerations:
   - Indexes will use approximately 200-300MB additional storage
   - Materialized views will use approximately 50MB
   - Total memory impact: ~350MB for 134k documents

8. Concurrent user support:
   - Optimized for 100+ concurrent users
   - Connection pooling recommended (pgBouncer)
   - Read replicas for geographic distribution

MONITORING QUERIES:

-- Check slow queries
SELECT query, mean_time, calls 
FROM pg_stat_statements 
WHERE query ILIKE '%documents%' 
ORDER BY mean_time DESC;

-- Check cache effectiveness
SELECT 
  COUNT(*) as total_queries,
  AVG(execution_time_ms) as avg_response_time,
  COUNT(CASE WHEN execution_time_ms < 200 THEN 1 END) as fast_queries,
  ROUND(
    COUNT(CASE WHEN execution_time_ms < 200 THEN 1 END) * 100.0 / COUNT(*), 2
  ) as fast_query_percentage
FROM query_performance_log
WHERE timestamp >= CURRENT_DATE - INTERVAL '1 day';
*/