-- ============================================================================
-- AMENDMENT PATTERN ANALYSIS - MATERIALIZED VIEWS
-- ============================================================================
--
-- Optimized views for amendment pattern analysis in Monitor Legislativo v4
-- Pre-computed aggregations for faster dashboard performance
--
-- Author: Monitor Legislativo Analytics Team
-- Date: 2025-01-13
-- Version: 1.0
--
-- ============================================================================

-- ============================================================================
-- DROP EXISTING VIEWS
-- ============================================================================

DROP MATERIALIZED VIEW IF EXISTS mv_amendment_summary CASCADE;
DROP MATERIALIZED VIEW IF EXISTS mv_amendment_hotspots CASCADE;
DROP MATERIALIZED VIEW IF EXISTS mv_amendment_velocity CASCADE;
DROP MATERIALIZED VIEW IF EXISTS mv_cross_jurisdiction_amendments CASCADE;
DROP MATERIALIZED VIEW IF EXISTS mv_amendment_networks CASCADE;

DROP INDEX IF EXISTS idx_mv_amendment_summary_year;
DROP INDEX IF EXISTS idx_mv_amendment_summary_tipo;
DROP INDEX IF EXISTS idx_mv_amendment_hotspots_count;
DROP INDEX IF EXISTS idx_mv_amendment_velocity_year;


-- ============================================================================
-- MV 1: AMENDMENT SUMMARY
-- ============================================================================
-- Main view identifying all amendment documents with their characteristics
-- ============================================================================

CREATE MATERIALIZED VIEW mv_amendment_summary AS
WITH amendment_keywords AS (
  -- Documents containing amendment language
  SELECT
    d.id,
    d.urn,
    d.titulo,
    d.tipo,
    d.ano,
    d.estado,
    d.nivel,
    d.municipio,
    d.data_publicacao,
    COALESCE(d.texto_completo, d.conteudo, '') AS texto,

    -- Amendment type flags
    (LOWER(COALESCE(d.texto_completo, d.conteudo, '')) ~ '(altera|modifica|altera dispositivos|altera a lei|altera o art)') AS is_modification,
    (LOWER(COALESCE(d.texto_completo, d.conteudo, '')) ~ '(revoga|revoga o art|revoga a lei|cancela|anula)') AS is_revocation,
    (LOWER(COALESCE(d.texto_completo, d.conteudo, '')) ~ '(acrescenta|inclui|adiciona|insere|acresce|introduz)') AS is_addition,
    (LOWER(COALESCE(d.texto_completo, d.conteudo, '')) ~ '(substitui|troca|muda|transforma)') AS is_substitution,

    -- Legal reference flags
    (COALESCE(d.texto_completo, d.conteudo, '') ~ 'Lei n[ºo°]|Decreto n[ºo°]|art\.|artigo|§|paragrafo|inciso') AS has_legal_ref,

    -- Extract referenced law numbers (simplified pattern)
    ARRAY(
      SELECT DISTINCT unnest(
        regexp_matches(
          COALESCE(d.texto_completo, d.conteudo, ''),
          'Lei n[ºo°]?\s*(\d+(?:[.,]\d+)?)',
          'gi'
        )
      )
    ) AS referenced_law_numbers

  FROM documents d
  WHERE d.ano >= 1820
    AND d.ano <= EXTRACT(YEAR FROM CURRENT_DATE)
)
SELECT
  id,
  urn,
  titulo,
  tipo,
  ano,
  estado,
  nivel,
  municipio,
  data_publicacao,

  -- Classification
  CASE
    WHEN is_revocation THEN 'Revogação'
    WHEN is_substitution THEN 'Substituição'
    WHEN is_addition THEN 'Adição'
    WHEN is_modification THEN 'Modificação'
    ELSE 'Outro'
  END AS amendment_type,

  -- Flags
  is_modification,
  is_revocation,
  is_addition,
  is_substitution,
  has_legal_ref,

  -- Overall amendment flag
  (
    (is_modification OR is_revocation OR is_addition OR is_substitution)
    AND has_legal_ref
  ) AS is_amendment,

  -- Referenced laws
  array_to_string(referenced_law_numbers, '; ') AS referenced_laws,
  array_length(referenced_law_numbers, 1) AS num_referenced_laws,

  -- Metadata
  CURRENT_TIMESTAMP AS computed_at

FROM amendment_keywords
WHERE (is_modification OR is_revocation OR is_addition OR is_substitution) AND has_legal_ref;

-- Indexes for performance
CREATE INDEX idx_mv_amendment_summary_year ON mv_amendment_summary(ano);
CREATE INDEX idx_mv_amendment_summary_tipo ON mv_amendment_summary(amendment_type);
CREATE INDEX idx_mv_amendment_summary_nivel ON mv_amendment_summary(nivel);
CREATE INDEX idx_mv_amendment_summary_is_amendment ON mv_amendment_summary(is_amendment);

COMMENT ON MATERIALIZED VIEW mv_amendment_summary IS
'Pre-computed summary of all amendment documents with classification and references';


-- ============================================================================
-- MV 2: AMENDMENT HOTSPOTS
-- ============================================================================
-- Most frequently amended laws
-- ============================================================================

CREATE MATERIALIZED VIEW mv_amendment_hotspots AS
WITH law_references AS (
  -- Explode referenced laws
  SELECT
    id,
    ano,
    nivel,
    unnest(string_to_array(referenced_laws, '; ')) AS law_ref
  FROM mv_amendment_summary
  WHERE referenced_laws IS NOT NULL
),
reference_counts AS (
  -- Count references per law
  SELECT
    law_ref,
    COUNT(*) AS amendment_count,
    MIN(ano) AS first_amendment_year,
    MAX(ano) AS last_amendment_year,
    MAX(ano) - MIN(ano) AS amendment_span_years,
    COUNT(DISTINCT nivel) AS jurisdictions_affected,
    ARRAY_AGG(DISTINCT nivel) AS affecting_jurisdictions
  FROM law_references
  GROUP BY law_ref
  HAVING COUNT(*) >= 2  -- At least 2 amendments to be a hotspot
)
SELECT
  ROW_NUMBER() OVER (ORDER BY amendment_count DESC) AS hotspot_rank,
  law_ref,
  amendment_count,
  first_amendment_year,
  last_amendment_year,
  amendment_span_years,
  CASE
    WHEN amendment_span_years > 0 THEN ROUND(amendment_count::numeric / amendment_span_years, 2)
    ELSE 0
  END AS amendment_frequency,
  jurisdictions_affected,
  affecting_jurisdictions,

  -- Hotspot category
  CASE
    WHEN amendment_count >= 10 THEN 'Muito Alto'
    WHEN amendment_count >= 5 THEN 'Alto'
    WHEN amendment_count >= 3 THEN 'Moderado'
    ELSE 'Baixo'
  END AS hotspot_category,

  -- Hotspot score (0-100)
  ROUND((amendment_count::numeric / MAX(amendment_count) OVER ()) * 100, 2) AS hotspot_score,

  CURRENT_TIMESTAMP AS computed_at

FROM reference_counts
ORDER BY amendment_count DESC;

CREATE INDEX idx_mv_amendment_hotspots_count ON mv_amendment_hotspots(amendment_count);
CREATE INDEX idx_mv_amendment_hotspots_rank ON mv_amendment_hotspots(hotspot_rank);
CREATE INDEX idx_mv_amendment_hotspots_category ON mv_amendment_hotspots(hotspot_category);

COMMENT ON MATERIALIZED VIEW mv_amendment_hotspots IS
'Laws that are frequently amended - legislative hotspots requiring monitoring';


-- ============================================================================
-- MV 3: AMENDMENT VELOCITY
-- ============================================================================
-- Rate of amendments over time
-- ============================================================================

CREATE MATERIALIZED VIEW mv_amendment_velocity AS
WITH yearly_counts AS (
  SELECT
    ano AS year,
    nivel AS jurisdiction,
    COUNT(*) AS amendment_count,
    COUNT(DISTINCT tipo) AS document_types,
    COUNT(DISTINCT estado) AS states_active
  FROM mv_amendment_summary
  WHERE is_amendment = TRUE
  GROUP BY ano, nivel
),
velocity_calc AS (
  SELECT
    year,
    jurisdiction,
    amendment_count,
    document_types,
    states_active,

    -- 3-year rolling average
    AVG(amendment_count) OVER (
      PARTITION BY jurisdiction
      ORDER BY year
      ROWS BETWEEN 2 PRECEDING AND CURRENT ROW
    ) AS rolling_avg_3y,

    -- Velocity (year-over-year change)
    amendment_count - LAG(amendment_count) OVER (
      PARTITION BY jurisdiction ORDER BY year
    ) AS velocity,

    -- Velocity percentage
    ROUND(
      ((amendment_count - LAG(amendment_count) OVER (PARTITION BY jurisdiction ORDER BY year))::numeric /
      NULLIF(LAG(amendment_count) OVER (PARTITION BY jurisdiction ORDER BY year), 0) * 100),
      2
    ) AS velocity_pct

  FROM yearly_counts
)
SELECT
  year,
  jurisdiction,
  amendment_count,
  document_types,
  states_active,
  ROUND(rolling_avg_3y, 2) AS rolling_avg_3y,
  velocity,
  velocity_pct,

  -- Acceleration (change in velocity)
  velocity - LAG(velocity) OVER (PARTITION BY jurisdiction ORDER BY year) AS acceleration,

  -- Trend classification
  CASE
    WHEN velocity IS NULL THEN 'Sem Dados'
    WHEN velocity > 0 AND (velocity - LAG(velocity) OVER (PARTITION BY jurisdiction ORDER BY year)) > 0
      THEN 'Aceleração Crescente'
    WHEN velocity > 0 AND (velocity - LAG(velocity) OVER (PARTITION BY jurisdiction ORDER BY year)) <= 0
      THEN 'Crescimento Desacelerando'
    WHEN velocity < 0 AND (velocity - LAG(velocity) OVER (PARTITION BY jurisdiction ORDER BY year)) < 0
      THEN 'Declínio Acelerando'
    WHEN velocity < 0 AND (velocity - LAG(velocity) OVER (PARTITION BY jurisdiction ORDER BY year)) >= 0
      THEN 'Declínio Desacelerando'
    ELSE 'Estável'
  END AS trend,

  CURRENT_TIMESTAMP AS computed_at

FROM velocity_calc
ORDER BY jurisdiction, year;

CREATE INDEX idx_mv_amendment_velocity_year ON mv_amendment_velocity(year);
CREATE INDEX idx_mv_amendment_velocity_jurisdiction ON mv_amendment_velocity(jurisdiction);
CREATE INDEX idx_mv_amendment_velocity_trend ON mv_amendment_velocity(trend);

COMMENT ON MATERIALIZED VIEW mv_amendment_velocity IS
'Temporal velocity and acceleration of amendments over time by jurisdiction';


-- ============================================================================
-- MV 4: CROSS-JURISDICTION AMENDMENTS
-- ============================================================================
-- Track amendment flows between Federal, State, and Municipal levels
-- ============================================================================

CREATE MATERIALIZED VIEW mv_cross_jurisdiction_amendments AS
WITH jurisdiction_flows AS (
  SELECT
    a1.nivel AS source_jurisdiction,
    a1.ano AS source_year,
    a1.referenced_laws,
    a2.nivel AS target_jurisdiction,
    a2.ano AS target_year,
    a2.id AS target_doc_id,
    a2.titulo AS target_doc_title,
    ABS(a2.ano - a1.ano) AS year_gap
  FROM mv_amendment_summary a1
  JOIN mv_amendment_summary a2
    ON a1.referenced_laws = a2.referenced_laws
    AND a1.nivel != a2.nivel  -- Cross-jurisdiction only
    AND a1.id != a2.id
  WHERE a1.is_amendment = TRUE
    AND a2.is_amendment = TRUE
)
SELECT
  source_jurisdiction,
  target_jurisdiction,
  source_jurisdiction || ' → ' || target_jurisdiction AS flow_pattern,
  COUNT(*) AS flow_count,
  MIN(source_year) AS earliest_flow_year,
  MAX(target_year) AS latest_flow_year,
  ROUND(AVG(year_gap), 1) AS avg_diffusion_time_years,

  -- Flow category
  CASE
    WHEN source_jurisdiction = 'Federal' AND target_jurisdiction = 'Estadual' THEN 'Federal→Estado'
    WHEN source_jurisdiction = 'Federal' AND target_jurisdiction = 'Municipal' THEN 'Federal→Municipal'
    WHEN source_jurisdiction = 'Estadual' AND target_jurisdiction = 'Municipal' THEN 'Estado→Municipal'
    WHEN source_jurisdiction = 'Estadual' AND target_jurisdiction = 'Federal' THEN 'Estado→Federal'
    WHEN source_jurisdiction = 'Municipal' AND target_jurisdiction = 'Estadual' THEN 'Municipal→Estado'
    WHEN source_jurisdiction = 'Municipal' AND target_jurisdiction = 'Federal' THEN 'Municipal→Federal'
    ELSE 'Outro'
  END AS flow_category,

  -- Diffusion speed (amendments per year)
  CASE
    WHEN MAX(target_year) - MIN(source_year) > 0 THEN
      ROUND(COUNT(*)::numeric / (MAX(target_year) - MIN(source_year)), 2)
    ELSE 0
  END AS diffusion_speed,

  CURRENT_TIMESTAMP AS computed_at

FROM jurisdiction_flows
GROUP BY source_jurisdiction, target_jurisdiction
HAVING COUNT(*) >= 2  -- At least 2 flows to be significant
ORDER BY flow_count DESC;

CREATE INDEX idx_mv_cross_jurisdiction_flow ON mv_cross_jurisdiction_amendments(flow_pattern);
CREATE INDEX idx_mv_cross_jurisdiction_category ON mv_cross_jurisdiction_amendments(flow_category);

COMMENT ON MATERIALIZED VIEW mv_cross_jurisdiction_amendments IS
'Cross-jurisdictional amendment flows showing how changes propagate between government levels';


-- ============================================================================
-- MV 5: AMENDMENT NETWORKS
-- ============================================================================
-- Network structure for graph visualization
-- ============================================================================

CREATE MATERIALIZED VIEW mv_amendment_networks AS
WITH amendment_edges AS (
  -- Create edges between amendments and referenced laws
  SELECT
    a.id AS amending_doc_id,
    a.titulo AS amending_doc_title,
    a.ano AS amending_year,
    a.nivel AS amending_jurisdiction,
    unnest(string_to_array(a.referenced_laws, '; ')) AS referenced_law,
    a.amendment_type
  FROM mv_amendment_summary a
  WHERE a.is_amendment = TRUE
    AND a.referenced_laws IS NOT NULL
)
SELECT
  amending_doc_id AS node_id,
  amending_doc_title AS node_label,
  amending_year AS node_year,
  amending_jurisdiction AS node_jurisdiction,
  'amendment' AS node_type,
  referenced_law AS edge_target,
  amendment_type AS edge_type,
  1 AS edge_weight,
  CURRENT_TIMESTAMP AS computed_at
FROM amendment_edges;

CREATE INDEX idx_mv_amendment_networks_node ON mv_amendment_networks(node_id);
CREATE INDEX idx_mv_amendment_networks_target ON mv_amendment_networks(edge_target);
CREATE INDEX idx_mv_amendment_networks_type ON mv_amendment_networks(node_type);

COMMENT ON MATERIALIZED VIEW mv_amendment_networks IS
'Network edges for visualization of amendment relationships';


-- ============================================================================
-- REFRESH FUNCTIONS
-- ============================================================================

-- Function to refresh all amendment views
CREATE OR REPLACE FUNCTION refresh_amendment_views()
RETURNS TEXT AS $$
DECLARE
  start_time TIMESTAMP;
  end_time TIMESTAMP;
  duration INTERVAL;
BEGIN
  start_time := clock_timestamp();

  RAISE NOTICE 'Refreshing amendment materialized views...';

  REFRESH MATERIALIZED VIEW CONCURRENTLY mv_amendment_summary;
  RAISE NOTICE '✓ mv_amendment_summary refreshed';

  REFRESH MATERIALIZED VIEW CONCURRENTLY mv_amendment_hotspots;
  RAISE NOTICE '✓ mv_amendment_hotspots refreshed';

  REFRESH MATERIALIZED VIEW CONCURRENTLY mv_amendment_velocity;
  RAISE NOTICE '✓ mv_amendment_velocity refreshed';

  REFRESH MATERIALIZED VIEW CONCURRENTLY mv_cross_jurisdiction_amendments;
  RAISE NOTICE '✓ mv_cross_jurisdiction_amendments refreshed';

  REFRESH MATERIALIZED VIEW CONCURRENTLY mv_amendment_networks;
  RAISE NOTICE '✓ mv_amendment_networks refreshed';

  end_time := clock_timestamp();
  duration := end_time - start_time;

  RAISE NOTICE 'All amendment views refreshed successfully in %', duration;

  RETURN format('Amendment views refreshed in %s', duration);
END;
$$ LANGUAGE plpgsql;

COMMENT ON FUNCTION refresh_amendment_views() IS
'Refresh all amendment pattern analysis materialized views';


-- ============================================================================
-- STATISTICS VIEW
-- ============================================================================

-- Quick statistics for dashboard
CREATE OR REPLACE VIEW v_amendment_statistics AS
SELECT
  (SELECT COUNT(*) FROM mv_amendment_summary WHERE is_amendment = TRUE) AS total_amendments,
  (SELECT COUNT(*) FROM mv_amendment_hotspots) AS total_hotspots,
  (SELECT MAX(amendment_count) FROM mv_amendment_hotspots) AS max_amendments_to_single_law,
  (SELECT AVG(amendment_count) FROM mv_amendment_hotspots) AS avg_amendments_per_hotspot,
  (SELECT COUNT(DISTINCT flow_pattern) FROM mv_cross_jurisdiction_amendments) AS total_flow_patterns,
  (SELECT AVG(diffusion_speed) FROM mv_cross_jurisdiction_amendments) AS avg_diffusion_speed,
  (SELECT MIN(computed_at) FROM mv_amendment_summary) AS last_refresh_time,
  (SELECT MAX(ano) FROM mv_amendment_summary) AS latest_amendment_year,
  (SELECT MIN(ano) FROM mv_amendment_summary) AS earliest_amendment_year,
  (SELECT COUNT(DISTINCT nivel) FROM mv_amendment_summary) AS jurisdictions_analyzed;

COMMENT ON VIEW v_amendment_statistics IS
'Quick statistics about amendment patterns for dashboard displays';


-- ============================================================================
-- INITIAL REFRESH
-- ============================================================================

-- Perform initial population
SELECT refresh_amendment_views();


-- ============================================================================
-- USAGE NOTES
-- ============================================================================

COMMENT ON SCHEMA public IS
'Amendment Pattern Analysis Views Usage:

1. mv_amendment_summary: Main view with all identified amendments
   - Use for overview statistics and filtering
   - Query by year, jurisdiction, or amendment type

2. mv_amendment_hotspots: Pre-computed frequently amended laws
   - Use for hotspot detection and ranking
   - Includes amendment frequency metrics

3. mv_amendment_velocity: Temporal velocity metrics
   - Use for time-series analysis
   - Includes trend classification and acceleration

4. mv_cross_jurisdiction_amendments: Flow patterns
   - Use for understanding how amendments propagate
   - Includes diffusion speed metrics

5. mv_amendment_networks: Network structure
   - Use for graph visualizations
   - Provides nodes and edges for network analysis

Refresh Recommendations:
- Daily: REFRESH MATERIALIZED VIEW CONCURRENTLY mv_amendment_summary
- Weekly: SELECT refresh_amendment_views()
- After bulk data updates: SELECT refresh_amendment_views()

Performance:
- All views have appropriate indexes
- CONCURRENT refresh allows queries during refresh
- Estimated refresh time: 1-5 minutes depending on data volume
';

-- ============================================================================
-- GRANT PERMISSIONS
-- ============================================================================

-- Grant read access to authenticated users
GRANT SELECT ON mv_amendment_summary TO authenticated;
GRANT SELECT ON mv_amendment_hotspots TO authenticated;
GRANT SELECT ON mv_amendment_velocity TO authenticated;
GRANT SELECT ON mv_cross_jurisdiction_amendments TO authenticated;
GRANT SELECT ON mv_amendment_networks TO authenticated;
GRANT SELECT ON v_amendment_statistics TO authenticated;

-- Grant refresh permission to service role
GRANT EXECUTE ON FUNCTION refresh_amendment_views() TO service_role;

-- ============================================================================
-- END OF FILE
-- ============================================================================

\echo '✅ Amendment pattern analysis materialized views created successfully'
\echo '📊 Views: mv_amendment_summary, mv_amendment_hotspots, mv_amendment_velocity,'
\echo '         mv_cross_jurisdiction_amendments, mv_amendment_networks'
\echo '🔄 Refresh function: refresh_amendment_views()'
\echo '📈 Statistics view: v_amendment_statistics'
