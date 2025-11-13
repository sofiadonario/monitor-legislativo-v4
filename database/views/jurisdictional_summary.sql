-- ==============================================================================
-- MATERIALIZED VIEW: JURISDICTIONAL SUMMARY
-- ==============================================================================
-- Pre-aggregated data for fast jurisdictional comparison queries
--
-- Purpose:
--   - Significantly improve query performance for jurisdictional analytics
--   - Reduce load on documents table (118k+ rows)
--   - Enable sub-second response times for dashboard queries
--
-- Update Strategy:
--   - Refresh nightly: REFRESH MATERIALIZED VIEW CONCURRENTLY jurisdictional_summary
--   - Or on-demand after bulk data imports
--
-- Author: Monitor Legislativo v4 - Data Science Team
-- Date: 2025-11-13
-- Expected Impact: 10-50x faster query performance
-- ==============================================================================

-- Drop existing view if it exists
DROP MATERIALIZED VIEW IF EXISTS jurisdictional_summary CASCADE;

-- Create the materialized view
CREATE MATERIALIZED VIEW jurisdictional_summary AS
SELECT
  -- Dimension keys
  COALESCE(nivel, 'Não Especificado') AS nivel,
  estado,
  COALESCE(poder, 'Não Especificado') AS poder,
  tipo,
  ano,
  mes,

  -- Aggregated metrics
  COUNT(*) AS doc_count,

  -- Text complexity metrics
  AVG(LENGTH(texto_completo)) AS avg_length,
  PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY LENGTH(texto_completo)) AS median_length,
  MAX(LENGTH(texto_completo)) AS max_length,

  -- Temporal metadata
  MIN(data) AS earliest_date,
  MAX(data) AS latest_date,

  -- Data quality indicators
  COUNT(*) FILTER (WHERE texto_completo IS NOT NULL AND LENGTH(texto_completo) > 100) AS complete_docs,
  COUNT(*) FILTER (WHERE titulo IS NOT NULL AND LENGTH(titulo) > 10) AS titled_docs

FROM documents

-- Filter out invalid/incomplete records
WHERE ano IS NOT NULL
  AND ano >= 2000  -- Focus on modern legislation
  AND ano <= EXTRACT(YEAR FROM CURRENT_DATE) + 1  -- Allow for future-dated docs

GROUP BY
  nivel,
  estado,
  poder,
  tipo,
  ano,
  mes;

-- ==============================================================================
-- INDEXES FOR OPTIMAL QUERY PERFORMANCE
-- ==============================================================================

-- Composite index for jurisdictional queries
CREATE INDEX idx_jurisdictional_summary_composite
  ON jurisdictional_summary(nivel, estado, ano);

-- Index for state-specific queries
CREATE INDEX idx_jurisdictional_summary_state
  ON jurisdictional_summary(estado, ano)
  WHERE estado IS NOT NULL;

-- Index for temporal queries
CREATE INDEX idx_jurisdictional_summary_temporal
  ON jurisdictional_summary(ano, mes, nivel);

-- Index for document type analysis
CREATE INDEX idx_jurisdictional_summary_tipo
  ON jurisdictional_summary(tipo, nivel)
  WHERE tipo IS NOT NULL;

-- Index for branch analysis (Executivo, Legislativo, Judiciário)
CREATE INDEX idx_jurisdictional_summary_poder
  ON jurisdictional_summary(poder, estado)
  WHERE poder IS NOT NULL;

-- ==============================================================================
-- ADDITIONAL ANALYTICAL VIEWS
-- ==============================================================================

-- View 1: State-Level Summary (pre-aggregated by state)
CREATE MATERIALIZED VIEW state_level_summary AS
SELECT
  estado,
  COUNT(DISTINCT ano) AS years_covered,
  SUM(doc_count) AS total_documents,
  ROUND(AVG(doc_count)::numeric, 2) AS avg_docs_per_period,
  COUNT(DISTINCT tipo) AS unique_types,
  COUNT(DISTINCT poder) AS unique_branches,
  ROUND(AVG(avg_length)::numeric, 0) AS overall_avg_length,
  MIN(ano) AS first_year,
  MAX(ano) AS last_year,

  -- Growth calculation
  (
    SELECT SUM(doc_count)
    FROM jurisdictional_summary js2
    WHERE js2.estado = js1.estado
      AND js2.ano = (SELECT MAX(ano) FROM jurisdictional_summary WHERE estado = js1.estado)
  ) AS last_year_volume,

  (
    SELECT SUM(doc_count)
    FROM jurisdictional_summary js2
    WHERE js2.estado = js1.estado
      AND js2.ano = (SELECT MIN(ano) FROM jurisdictional_summary WHERE estado = js1.estado AND ano >= 2015)
  ) AS first_tracked_year_volume

FROM jurisdictional_summary js1
WHERE estado IS NOT NULL
  AND estado NOT IN ('Federal', 'Nacional', 'Justiça Trabalho', 'Não Identificado')
  AND LENGTH(estado) = 2  -- Valid state codes only
GROUP BY estado;

CREATE INDEX idx_state_level_summary_estado ON state_level_summary(estado);

-- View 2: Jurisdiction-Level Summary (Federal, Estadual, Municipal)
CREATE MATERIALIZED VIEW jurisdiction_level_summary AS
SELECT
  nivel,
  COUNT(DISTINCT estado) AS states_count,
  SUM(doc_count) AS total_documents,
  ROUND(AVG(doc_count)::numeric, 2) AS avg_docs_per_period,
  COUNT(DISTINCT tipo) AS unique_types,
  ROUND(AVG(avg_length)::numeric, 0) AS overall_avg_length,
  MIN(ano) AS first_year,
  MAX(ano) AS last_year,

  -- Temporal metrics
  COUNT(DISTINCT ano || '-' || mes) AS total_months,
  ROUND(SUM(doc_count)::numeric / NULLIF(COUNT(DISTINCT ano || '-' || mes), 0), 2) AS docs_per_month

FROM jurisdictional_summary
WHERE nivel IS NOT NULL
GROUP BY nivel;

CREATE INDEX idx_jurisdiction_level_summary_nivel ON jurisdiction_level_summary(nivel);

-- View 3: Temporal Trends (monthly aggregation for time series)
CREATE MATERIALIZED VIEW temporal_trends_summary AS
SELECT
  nivel,
  estado,
  ano,
  mes,
  TO_DATE(ano || '-' || LPAD(mes::text, 2, '0') || '-01', 'YYYY-MM-DD') AS month_date,
  SUM(doc_count) AS monthly_docs,
  COUNT(DISTINCT tipo) AS monthly_types,
  ROUND(AVG(avg_length)::numeric, 0) AS monthly_avg_length

FROM jurisdictional_summary
WHERE mes IS NOT NULL
  AND ano >= 2015  -- Focus on recent trends
GROUP BY nivel, estado, ano, mes
ORDER BY ano, mes;

CREATE INDEX idx_temporal_trends_nivel_date ON temporal_trends_summary(nivel, month_date);
CREATE INDEX idx_temporal_trends_estado_date ON temporal_trends_summary(estado, month_date) WHERE estado IS NOT NULL;

-- ==============================================================================
-- UTILITY FUNCTIONS
-- ==============================================================================

-- Function to refresh all jurisdictional materialized views
CREATE OR REPLACE FUNCTION refresh_jurisdictional_views()
RETURNS void AS $$
BEGIN
  REFRESH MATERIALIZED VIEW CONCURRENTLY jurisdictional_summary;
  REFRESH MATERIALIZED VIEW CONCURRENTLY state_level_summary;
  REFRESH MATERIALIZED VIEW CONCURRENTLY jurisdiction_level_summary;
  REFRESH MATERIALIZED VIEW CONCURRENTLY temporal_trends_summary;

  RAISE NOTICE 'All jurisdictional materialized views refreshed successfully at %', NOW();
END;
$$ LANGUAGE plpgsql;

-- Grant permissions (adjust as needed for your user roles)
GRANT SELECT ON jurisdictional_summary TO PUBLIC;
GRANT SELECT ON state_level_summary TO PUBLIC;
GRANT SELECT ON jurisdiction_level_summary TO PUBLIC;
GRANT SELECT ON temporal_trends_summary TO PUBLIC;

-- ==============================================================================
-- MAINTENANCE NOTES
-- ==============================================================================

-- Manual refresh command (run as needed):
-- SELECT refresh_jurisdictional_views();

-- Schedule automatic refresh (add to cron or pg_cron):
-- SELECT cron.schedule('refresh-jurisdictional-views', '0 2 * * *',
--                      'SELECT refresh_jurisdictional_views()');

-- Check view freshness:
-- SELECT
--   schemaname,
--   matviewname,
--   pg_size_pretty(pg_total_relation_size(schemaname||'.'||matviewname)) as size
-- FROM pg_matviews
-- WHERE matviewname LIKE '%jurisdictional%';

-- Analyze for query optimization (run after refresh):
-- ANALYZE jurisdictional_summary;
-- ANALYZE state_level_summary;
-- ANALYZE jurisdiction_level_summary;
-- ANALYZE temporal_trends_summary;

-- ==============================================================================
-- PERFORMANCE VALIDATION QUERIES
-- ==============================================================================

/*
-- Test query 1: Jurisdiction-level comparison (should be < 100ms)
SELECT nivel, SUM(doc_count) as total_docs
FROM jurisdictional_summary
WHERE ano >= 2020
GROUP BY nivel;

-- Test query 2: State comparison (should be < 200ms)
SELECT estado, SUM(doc_count) as total_docs
FROM jurisdictional_summary
WHERE estado IN ('SP', 'RJ', 'MG')
  AND ano >= 2020
GROUP BY estado;

-- Test query 3: Temporal trends (should be < 300ms)
SELECT nivel, ano, mes, SUM(doc_count) as monthly_total
FROM jurisdictional_summary
WHERE ano >= 2020
GROUP BY nivel, ano, mes
ORDER BY ano, mes;

-- Test query 4: Document type diversity by jurisdiction (should be < 150ms)
SELECT nivel, COUNT(DISTINCT tipo) as type_diversity, SUM(doc_count) as total_docs
FROM jurisdictional_summary
WHERE ano >= 2020
  AND tipo IS NOT NULL
GROUP BY nivel;
*/
