-- =============================================================================
-- GEOGRAPHIC MATERIALIZED VIEWS FOR PERFORMANCE OPTIMIZATION
-- =============================================================================
-- Creates materialized views for fast geographic aggregations
-- Part of PRD Performance Requirements (P0-P1)
-- =============================================================================

-- Drop existing views if they exist
DROP MATERIALIZED VIEW IF EXISTS mv_geographic_stats CASCADE;
DROP MATERIALIZED VIEW IF EXISTS mv_state_summary CASCADE;
DROP MATERIALIZED VIEW IF EXISTS mv_municipality_summary CASCADE;

-- =============================================================================
-- 1. STATE-LEVEL GEOGRAPHIC STATS
-- =============================================================================
-- Pre-aggregates document counts by state for fast queries
-- Refreshes: Daily or on-demand
-- Expected speedup: 10-50x for state-level queries

CREATE MATERIALIZED VIEW mv_geographic_stats AS
SELECT
  estado,
  COUNT(*) as doc_count,
  COUNT(DISTINCT tipo) as tipo_count,
  COUNT(DISTINCT municipio) as municipio_count,
  COUNT(DISTINCT categoria_original) as categoria_count,
  MIN(data) as first_doc,
  MAX(data) as last_doc,
  AVG(CASE WHEN LENGTH(conteudo) > 0 THEN LENGTH(conteudo) END) as avg_content_length,
  COUNT(CASE WHEN data >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as recent_doc_count_30d,
  COUNT(CASE WHEN data >= CURRENT_DATE - INTERVAL '90 days' THEN 1 END) as recent_doc_count_90d,
  CURRENT_TIMESTAMP as last_updated
FROM lexml_documents
WHERE estado IS NOT NULL AND estado != ''
GROUP BY estado;

-- Create indexes on materialized view for fast lookups
CREATE INDEX idx_mv_geographic_stats_estado ON mv_geographic_stats(estado);
CREATE INDEX idx_mv_geographic_stats_doc_count ON mv_geographic_stats(doc_count DESC);
CREATE INDEX idx_mv_geographic_stats_last_updated ON mv_geographic_stats(last_updated);

-- =============================================================================
-- 2. DETAILED STATE SUMMARY
-- =============================================================================
-- Comprehensive state-level statistics with temporal breakdown

CREATE MATERIALIZED VIEW mv_state_summary AS
SELECT
  estado,
  -- Document counts
  COUNT(*) as total_documents,
  COUNT(DISTINCT tipo) as document_types,
  COUNT(DISTINCT municipio) as municipality_count,

  -- Temporal metrics
  MIN(data) as first_document_date,
  MAX(data) as last_document_date,
  EXTRACT(DAYS FROM (MAX(data) - MIN(data))) as time_span_days,

  -- Recent activity (last 30, 90, 180, 365 days)
  COUNT(CASE WHEN data >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as docs_last_30d,
  COUNT(CASE WHEN data >= CURRENT_DATE - INTERVAL '90 days' THEN 1 END) as docs_last_90d,
  COUNT(CASE WHEN data >= CURRENT_DATE - INTERVAL '180 days' THEN 1 END) as docs_last_180d,
  COUNT(CASE WHEN data >= CURRENT_DATE - INTERVAL '365 days' THEN 1 END) as docs_last_365d,

  -- Activity percentages
  ROUND(COUNT(CASE WHEN data >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END)::numeric /
        NULLIF(COUNT(*), 0) * 100, 2) as recent_activity_pct,

  -- Content statistics
  AVG(CASE WHEN LENGTH(conteudo) > 0 THEN LENGTH(conteudo) END) as avg_content_length,
  MAX(LENGTH(conteudo)) as max_content_length,

  -- Top document types (as array)
  ARRAY_AGG(DISTINCT tipo ORDER BY tipo) as document_types_array,

  -- Update timestamp
  CURRENT_TIMESTAMP as last_updated
FROM lexml_documents
WHERE estado IS NOT NULL AND estado != ''
GROUP BY estado;

-- Indexes for state summary
CREATE INDEX idx_mv_state_summary_estado ON mv_state_summary(estado);
CREATE INDEX idx_mv_state_summary_total_docs ON mv_state_summary(total_documents DESC);
CREATE INDEX idx_mv_state_summary_recent_activity ON mv_state_summary(recent_activity_pct DESC);

-- =============================================================================
-- 3. MUNICIPALITY-LEVEL SUMMARY (TOP 500)
-- =============================================================================
-- Pre-aggregates top municipalities for fast visualization
-- Limited to top 500 to manage view size

CREATE MATERIALIZED VIEW mv_municipality_summary AS
SELECT
  estado,
  municipio,
  CONCAT(estado, '_', UPPER(TRIM(municipio))) as estado_municipio,

  -- Document counts
  COUNT(*) as total_documents,
  COUNT(DISTINCT tipo) as document_types,

  -- Temporal metrics
  MIN(data) as first_document_date,
  MAX(data) as last_document_date,

  -- Recent activity
  COUNT(CASE WHEN data >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END) as docs_last_30d,
  COUNT(CASE WHEN data >= CURRENT_DATE - INTERVAL '90 days' THEN 1 END) as docs_last_90d,

  -- Activity score (recent docs / total docs)
  ROUND(COUNT(CASE WHEN data >= CURRENT_DATE - INTERVAL '30 days' THEN 1 END)::numeric /
        NULLIF(COUNT(*), 0) * 100, 2) as activity_score,

  -- Content statistics
  AVG(CASE WHEN LENGTH(conteudo) > 0 THEN LENGTH(conteudo) END) as avg_content_length,

  -- Update timestamp
  CURRENT_TIMESTAMP as last_updated
FROM lexml_documents
WHERE estado IS NOT NULL AND estado != ''
  AND municipio IS NOT NULL AND municipio != ''
GROUP BY estado, municipio
HAVING COUNT(*) >= 5  -- Minimum threshold for meaningful statistics
ORDER BY total_documents DESC
LIMIT 500;  -- Top 500 municipalities only

-- Indexes for municipality summary
CREATE INDEX idx_mv_municipality_summary_estado ON mv_municipality_summary(estado);
CREATE INDEX idx_mv_municipality_summary_municipio ON mv_municipality_summary(municipio);
CREATE INDEX idx_mv_municipality_summary_total_docs ON mv_municipality_summary(total_documents DESC);
CREATE INDEX idx_mv_municipality_summary_activity ON mv_municipality_summary(activity_score DESC);

-- =============================================================================
-- 4. REFRESH FUNCTIONS
-- =============================================================================
-- Functions to manually or automatically refresh materialized views

-- Function to refresh all geographic materialized views
CREATE OR REPLACE FUNCTION refresh_geographic_materialized_views()
RETURNS TEXT AS $$
DECLARE
  start_time TIMESTAMP;
  end_time TIMESTAMP;
  duration INTERVAL;
BEGIN
  start_time := clock_timestamp();

  -- Refresh views concurrently where possible
  REFRESH MATERIALIZED VIEW CONCURRENTLY mv_geographic_stats;
  REFRESH MATERIALIZED VIEW CONCURRENTLY mv_state_summary;
  REFRESH MATERIALIZED VIEW CONCURRENTLY mv_municipality_summary;

  end_time := clock_timestamp();
  duration := end_time - start_time;

  RETURN 'Geographic materialized views refreshed successfully in ' ||
         EXTRACT(EPOCH FROM duration)::TEXT || ' seconds';
EXCEPTION
  WHEN OTHERS THEN
    RETURN 'Error refreshing geographic materialized views: ' || SQLERRM;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- 5. AUTOMATIC REFRESH SCHEDULE (OPTIONAL)
-- =============================================================================
-- Create a scheduled job to refresh views daily
-- Requires pg_cron extension (available on Cloud SQL and many managed PostgreSQL services)

-- To enable automatic daily refresh at 2 AM:
-- SELECT cron.schedule('refresh-geographic-views', '0 2 * * *',
--   'SELECT refresh_geographic_materialized_views()');

-- To check existing cron jobs:
-- SELECT * FROM cron.job;

-- To remove the scheduled job:
-- SELECT cron.unschedule('refresh-geographic-views');

-- =============================================================================
-- 6. USAGE EXAMPLES
-- =============================================================================

-- Manual refresh of all geographic views:
-- SELECT refresh_geographic_materialized_views();

-- Query state statistics (fast):
-- SELECT * FROM mv_geographic_stats WHERE estado = 'SP';

-- Query top 10 states by document count:
-- SELECT estado, doc_count, recent_doc_count_30d
-- FROM mv_geographic_stats
-- ORDER BY doc_count DESC
-- LIMIT 10;

-- Query municipality details:
-- SELECT * FROM mv_municipality_summary
-- WHERE estado = 'SP'
-- ORDER BY total_documents DESC
-- LIMIT 20;

-- Compare recent activity across states:
-- SELECT estado, total_documents, docs_last_30d, recent_activity_pct
-- FROM mv_state_summary
-- ORDER BY recent_activity_pct DESC;

-- =============================================================================
-- 7. PERFORMANCE NOTES
-- =============================================================================
-- Expected performance improvements:
-- - State aggregation queries: 10-50x faster
-- - Municipality queries: 20-100x faster
-- - Geographic map rendering: 5-10x faster
-- - Export operations: 10-20x faster
--
-- View refresh time (typical):
-- - mv_geographic_stats: 1-5 seconds
-- - mv_state_summary: 2-10 seconds
-- - mv_municipality_summary: 5-15 seconds
-- Total: ~10-30 seconds for full refresh
--
-- Recommended refresh frequency:
-- - Production: Daily (2 AM local time)
-- - Development: On-demand or hourly
-- - After bulk data imports: Immediate
--
-- Storage impact:
-- - Estimated additional storage: 1-5 MB per view
-- - Total: ~5-15 MB for all geographic views
-- =============================================================================

-- Grant permissions to application user
GRANT SELECT ON mv_geographic_stats TO monitor_user;
GRANT SELECT ON mv_state_summary TO monitor_user;
GRANT SELECT ON mv_municipality_summary TO monitor_user;

-- Initial refresh
SELECT refresh_geographic_materialized_views();

-- Display completion message
SELECT
  'Geographic materialized views created successfully!' as status,
  'Run: SELECT refresh_geographic_materialized_views(); to refresh manually' as usage_note,
  'Views: mv_geographic_stats, mv_state_summary, mv_municipality_summary' as available_views;
