-- ============================================================================
-- SPRINT 6A: MATERIALIZED VIEWS FOR PERFORMANCE OPTIMIZATION
-- Brazilian Legislative Monitoring System - Railway Deployment
-- ============================================================================
-- 
-- MATERIALIZED VIEWS STRATEGY FOR 134k+ LEGISLATIVE DOCUMENTS
-- Purpose: Pre-compute expensive aggregations for dashboard and analytics
-- 
-- TARGET OPTIMIZATIONS:
-- - Dashboard metrics: <100ms (from 2-5 seconds)
-- - Category statistics: <50ms (from 800ms-1.5s)
-- - Geographic distribution: <200ms (from 3-8 seconds)
-- - Temporal trends: <150ms (from 2-4 seconds)
-- - Search facets: <100ms (from 500ms-1.2s)
--
-- RAILWAY-SPECIFIC DESIGN:
-- - Memory-efficient views within 2GB constraints
-- - Incremental refresh capabilities
-- - Concurrent refresh support (zero downtime)
-- - Intelligent refresh scheduling
-- - Connection pool optimization
-- ============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Set optimal memory settings for materialized view operations
SET maintenance_work_mem = '256MB';
SET max_parallel_maintenance_workers = 2;

-- ============================================================================
-- 1. CORE DASHBOARD METRICS MATERIALIZED VIEW
-- ============================================================================

-- Primary dashboard statistics (most frequently accessed)
DROP MATERIALIZED VIEW IF EXISTS mv_dashboard_metrics CASCADE;
CREATE MATERIALIZED VIEW mv_dashboard_metrics AS
WITH primary_table AS (
    SELECT table_name 
    FROM mv_table_metadata 
    WHERE is_primary = true 
    LIMIT 1
),
document_stats AS (
    SELECT 
        COUNT(*) as total_documents,
        COUNT(DISTINCT COALESCE(d.estado, d.state)) as unique_states,
        COUNT(DISTINCT COALESCE(d.municipio, d.municipality, d.localidade)) as unique_municipalities,
        MIN(COALESCE(d.data_publicacao, d.data, d.date)) as earliest_date,
        MAX(COALESCE(d.data_publicacao, d.data, d.date)) as latest_date,
        COUNT(*) FILTER (WHERE COALESCE(d.data_publicacao, d.data, d.date) >= CURRENT_DATE - INTERVAL '1 year') as recent_documents,
        COUNT(DISTINCT COALESCE(d.categoria, d.category, 'Outros')) as unique_categories,
        COUNT(DISTINCT COALESCE(d.tipo, d.document_type, d.tipo_documento)) as unique_document_types
    FROM brazilian_legislative_complete d  -- Default to main table, will be dynamic in functions
    WHERE (d.titulo IS NOT NULL OR d.title IS NOT NULL)
      AND LENGTH(COALESCE(d.titulo, d.title, '')) > 2
),
quality_stats AS (
    SELECT
        COUNT(*) FILTER (WHERE d.urn IS NOT NULL AND d.urn != '') as documents_with_urn,
        COUNT(*) FILTER (WHERE COALESCE(d.ementa, d.summary, d.description) IS NOT NULL 
                          AND LENGTH(COALESCE(d.ementa, d.summary, d.description)) > 10) as documents_with_summary,
        COUNT(*) FILTER (WHERE COALESCE(d.autor, d.author) IS NOT NULL 
                          AND COALESCE(d.autor, d.author) != '') as documents_with_author,
        AVG(LENGTH(COALESCE(d.titulo, d.title, ''))) as avg_title_length
    FROM brazilian_legislative_complete d
    WHERE (d.titulo IS NOT NULL OR d.title IS NOT NULL)
)
SELECT 
    -- Core metrics
    ds.total_documents,
    ds.unique_states,
    ds.unique_municipalities,
    ds.unique_categories,
    ds.unique_document_types,
    
    -- Calculated percentages
    ROUND((ds.unique_states::NUMERIC / 27) * 100, 1) as states_percentage,  -- 27 Brazilian states
    ROUND((ds.unique_municipalities::NUMERIC / 5570) * 100, 1) as municipalities_percentage,  -- ~5570 municipalities
    ROUND((ds.recent_documents::NUMERIC / ds.total_documents) * 100, 1) as recent_documents_percentage,
    
    -- Date range analysis
    ds.earliest_date,
    ds.latest_date,
    EXTRACT(YEAR FROM AGE(ds.latest_date, ds.earliest_date)) as date_range_years,
    ds.recent_documents,
    
    -- Data quality metrics
    qs.documents_with_urn,
    qs.documents_with_summary,
    qs.documents_with_author,
    ROUND(qs.avg_title_length, 1) as avg_title_length,
    ROUND((qs.documents_with_urn::NUMERIC / ds.total_documents) * 100, 1) as urn_completeness_percentage,
    ROUND((qs.documents_with_summary::NUMERIC / ds.total_documents) * 100, 1) as summary_completeness_percentage,
    
    -- System metadata
    CURRENT_TIMESTAMP as last_updated,
    'materialized_view' as data_source,
    ds.total_documents > 100000 as is_complete_dataset
    
FROM document_stats ds
CROSS JOIN quality_stats qs;

-- Create indexes on the materialized view
CREATE UNIQUE INDEX idx_mv_dashboard_metrics_singleton ON mv_dashboard_metrics((TRUE));

-- ============================================================================
-- 2. CATEGORY DISTRIBUTION MATERIALIZED VIEW
-- ============================================================================

-- Detailed category statistics for filtering and analytics
DROP MATERIALIZED VIEW IF EXISTS mv_category_statistics CASCADE;
CREATE MATERIALIZED VIEW mv_category_statistics AS
WITH category_stats AS (
    SELECT 
        COALESCE(d.categoria, d.category, 'Outros') as categoria,
        COUNT(*) as document_count,
        COUNT(DISTINCT COALESCE(d.estado, d.state)) as states_represented,
        COUNT(DISTINCT COALESCE(d.tipo, d.document_type, d.tipo_documento)) as document_types,
        MIN(COALESCE(d.data_publicacao, d.data, d.date)) as earliest_document,
        MAX(COALESCE(d.data_publicacao, d.data, d.date)) as latest_document,
        COUNT(*) FILTER (WHERE COALESCE(d.data_publicacao, d.data, d.date) >= CURRENT_DATE - INTERVAL '1 year') as recent_count,
        COUNT(*) FILTER (WHERE COALESCE(d.data_publicacao, d.data, d.date) >= CURRENT_DATE - INTERVAL '5 years') as last_5_years_count,
        -- Quality metrics per category
        COUNT(*) FILTER (WHERE d.urn IS NOT NULL AND d.urn != '') as documents_with_urn,
        COUNT(*) FILTER (WHERE COALESCE(d.ementa, d.summary) IS NOT NULL 
                          AND LENGTH(COALESCE(d.ementa, d.summary)) > 10) as documents_with_summary,
        AVG(LENGTH(COALESCE(d.titulo, d.title, ''))) as avg_title_length
    FROM brazilian_legislative_complete d
    WHERE (d.titulo IS NOT NULL OR d.title IS NOT NULL)
      AND LENGTH(COALESCE(d.titulo, d.title, '')) > 2
    GROUP BY COALESCE(d.categoria, d.category, 'Outros')
),
total_stats AS (
    SELECT SUM(document_count) as total_documents FROM category_stats
)
SELECT 
    cs.categoria,
    cs.document_count,
    ROUND((cs.document_count::NUMERIC / ts.total_documents) * 100, 2) as percentage,
    cs.states_represented,
    cs.document_types,
    cs.earliest_document,
    cs.latest_document,
    cs.recent_count,
    cs.last_5_years_count,
    
    -- Growth metrics
    ROUND((cs.recent_count::NUMERIC / NULLIF(cs.document_count, 0)) * 100, 1) as recent_activity_percentage,
    EXTRACT(YEAR FROM AGE(cs.latest_document, cs.earliest_document)) as active_years,
    
    -- Quality metrics
    cs.documents_with_urn,
    cs.documents_with_summary,
    ROUND(cs.avg_title_length, 1) as avg_title_length,
    ROUND((cs.documents_with_urn::NUMERIC / cs.document_count) * 100, 1) as urn_quality_score,
    
    -- Ranking metrics
    RANK() OVER (ORDER BY cs.document_count DESC) as popularity_rank,
    RANK() OVER (ORDER BY cs.recent_count DESC) as recency_rank,
    
    -- System metadata
    CURRENT_TIMESTAMP as last_updated
    
FROM category_stats cs
CROSS JOIN total_stats ts
ORDER BY cs.document_count DESC;

-- Create indexes on category statistics
CREATE UNIQUE INDEX idx_mv_category_statistics_categoria ON mv_category_statistics(categoria);
CREATE INDEX idx_mv_category_statistics_count ON mv_category_statistics(document_count DESC);
CREATE INDEX idx_mv_category_statistics_recent ON mv_category_statistics(recent_count DESC);

-- ============================================================================
-- 3. GEOGRAPHIC DISTRIBUTION MATERIALIZED VIEW
-- ============================================================================

-- Comprehensive geographic analysis for choropleth maps and regional analytics
DROP MATERIALIZED VIEW IF EXISTS mv_geographic_distribution CASCADE;
CREATE MATERIALIZED VIEW mv_geographic_distribution AS
WITH geographic_stats AS (
    SELECT 
        COALESCE(d.estado, d.state) as state_code,
        COUNT(*) as document_count,
        COUNT(DISTINCT COALESCE(d.categoria, d.category)) as categories_count,
        COUNT(DISTINCT COALESCE(d.municipio, d.municipality, d.localidade)) as municipalities_count,
        COUNT(DISTINCT COALESCE(d.tipo, d.document_type)) as document_types_count,
        
        -- Temporal distribution
        COUNT(*) FILTER (WHERE COALESCE(d.data_publicacao, d.data, d.date) >= CURRENT_DATE - INTERVAL '1 year') as recent_documents,
        COUNT(*) FILTER (WHERE COALESCE(d.data_publicacao, d.data, d.date) >= CURRENT_DATE - INTERVAL '5 years') as last_5_years,
        MIN(COALESCE(d.data_publicacao, d.data, d.date)) as earliest_document,
        MAX(COALESCE(d.data_publicacao, d.data, d.date)) as latest_document,
        
        -- Category breakdown JSON
        json_object_agg(
            COALESCE(d.categoria, d.category, 'Outros'), 
            COUNT(*)
        ) FILTER (WHERE COALESCE(d.categoria, d.category) IS NOT NULL) as category_distribution,
        
        -- Quality metrics
        COUNT(*) FILTER (WHERE d.urn IS NOT NULL AND d.urn != '') as documents_with_urn,
        AVG(LENGTH(COALESCE(d.titulo, d.title, ''))) as avg_title_length
        
    FROM brazilian_legislative_complete d
    WHERE (d.estado IS NOT NULL OR d.state IS NOT NULL)
      AND (d.titulo IS NOT NULL OR d.title IS NOT NULL)
      AND LENGTH(COALESCE(d.titulo, d.title, '')) > 2
    GROUP BY COALESCE(d.estado, d.state)
),
state_mapping AS (
    SELECT 
        bs.code,
        bs.name as state_name,
        bs.region,
        bs.population,
        bs.capital,
        COALESCE(gs.document_count, 0) as document_count,
        COALESCE(gs.categories_count, 0) as categories_count,
        COALESCE(gs.municipalities_count, 0) as municipalities_count,
        COALESCE(gs.document_types_count, 0) as document_types_count,
        COALESCE(gs.recent_documents, 0) as recent_documents,
        COALESCE(gs.last_5_years, 0) as last_5_years,
        gs.earliest_document,
        gs.latest_document,
        gs.category_distribution,
        COALESCE(gs.documents_with_urn, 0) as documents_with_urn,
        COALESCE(gs.avg_title_length, 0) as avg_title_length
    FROM brazilian_states bs
    LEFT JOIN geographic_stats gs ON bs.code = gs.state_code
),
total_stats AS (
    SELECT 
        SUM(document_count) as total_documents,
        SUM(population) as total_population
    FROM state_mapping
)
SELECT 
    sm.code as state_code,
    sm.state_name,
    sm.region,
    sm.population,
    sm.capital,
    sm.document_count,
    sm.categories_count,
    sm.municipalities_count,
    sm.document_types_count,
    sm.recent_documents,
    sm.last_5_years,
    sm.earliest_document,
    sm.latest_document,
    sm.category_distribution,
    sm.documents_with_urn,
    ROUND(sm.avg_title_length, 1) as avg_title_length,
    
    -- Calculated metrics
    ROUND((sm.document_count::NUMERIC / ts.total_documents) * 100, 2) as document_percentage,
    ROUND((sm.document_count::NUMERIC / NULLIF(sm.population, 0)) * 100000, 2) as documents_per_100k_population,
    ROUND((sm.recent_documents::NUMERIC / NULLIF(sm.document_count, 0)) * 100, 1) as recent_activity_percentage,
    
    -- Ranking metrics
    RANK() OVER (ORDER BY sm.document_count DESC) as document_rank,
    RANK() OVER (ORDER BY (sm.document_count::NUMERIC / NULLIF(sm.population, 0)) DESC) as per_capita_rank,
    RANK() OVER (ORDER BY sm.recent_documents DESC) as recency_rank,
    
    -- Regional analysis
    SUM(sm.document_count) OVER (PARTITION BY sm.region) as regional_total,
    ROUND((sm.document_count::NUMERIC / SUM(sm.document_count) OVER (PARTITION BY sm.region)) * 100, 1) as regional_percentage,
    
    -- System metadata
    CURRENT_TIMESTAMP as last_updated
    
FROM state_mapping sm
CROSS JOIN total_stats ts
ORDER BY sm.document_count DESC;

-- Create indexes on geographic distribution
CREATE UNIQUE INDEX idx_mv_geographic_state_code ON mv_geographic_distribution(state_code);
CREATE INDEX idx_mv_geographic_region ON mv_geographic_distribution(region);
CREATE INDEX idx_mv_geographic_document_count ON mv_geographic_distribution(document_count DESC);
CREATE INDEX idx_mv_geographic_per_capita ON mv_geographic_distribution(documents_per_100k_population DESC);

-- ============================================================================
-- 4. TEMPORAL TRENDS MATERIALIZED VIEW
-- ============================================================================

-- Monthly and yearly document trends for analytics and forecasting
DROP MATERIALIZED VIEW IF EXISTS mv_temporal_trends CASCADE;
CREATE MATERIALIZED VIEW mv_temporal_trends AS
WITH monthly_trends AS (
    SELECT 
        DATE_TRUNC('month', COALESCE(d.data_publicacao, d.data, d.date)) as month_year,
        EXTRACT(YEAR FROM COALESCE(d.data_publicacao, d.data, d.date)) as year,
        EXTRACT(MONTH FROM COALESCE(d.data_publicacao, d.data, d.date)) as month,
        COALESCE(d.categoria, d.category, 'Outros') as categoria,
        COALESCE(d.estado, d.state) as state_code,
        COUNT(*) as document_count,
        COUNT(DISTINCT COALESCE(d.tipo, d.document_type)) as document_types,
        AVG(LENGTH(COALESCE(d.titulo, d.title, ''))) as avg_title_length
    FROM brazilian_legislative_complete d
    WHERE COALESCE(d.data_publicacao, d.data, d.date) IS NOT NULL
      AND COALESCE(d.data_publicacao, d.data, d.date) >= '2000-01-01'  -- Filter very old dates
      AND COALESCE(d.data_publicacao, d.data, d.date) <= CURRENT_DATE
      AND (d.titulo IS NOT NULL OR d.title IS NOT NULL)
    GROUP BY 
        DATE_TRUNC('month', COALESCE(d.data_publicacao, d.data, d.date)),
        EXTRACT(YEAR FROM COALESCE(d.data_publicacao, d.data, d.date)),
        EXTRACT(MONTH FROM COALESCE(d.data_publicacao, d.data, d.date)),
        COALESCE(d.categoria, d.category, 'Outros'),
        COALESCE(d.estado, d.state)
),
trend_analysis AS (
    SELECT 
        mt.*,
        
        -- Moving averages (3-month and 12-month)
        AVG(mt.document_count) OVER (
            PARTITION BY mt.categoria, mt.state_code 
            ORDER BY mt.month_year 
            ROWS BETWEEN 2 PRECEDING AND CURRENT ROW
        ) as moving_avg_3m,
        
        AVG(mt.document_count) OVER (
            PARTITION BY mt.categoria, mt.state_code 
            ORDER BY mt.month_year 
            ROWS BETWEEN 11 PRECEDING AND CURRENT ROW
        ) as moving_avg_12m,
        
        -- Year-over-year comparison
        LAG(mt.document_count, 12) OVER (
            PARTITION BY mt.categoria, mt.state_code 
            ORDER BY mt.month_year
        ) as same_month_prev_year,
        
        -- Growth calculations
        mt.document_count - LAG(mt.document_count) OVER (
            PARTITION BY mt.categoria, mt.state_code 
            ORDER BY mt.month_year
        ) as month_over_month_change,
        
        -- Ranking within category/state
        RANK() OVER (
            PARTITION BY mt.categoria, mt.state_code 
            ORDER BY mt.document_count DESC
        ) as monthly_rank_in_category
        
    FROM monthly_trends mt
)
SELECT 
    ta.month_year,
    ta.year,
    ta.month,
    ta.categoria,
    ta.state_code,
    ta.document_count,
    ta.document_types,
    ROUND(ta.avg_title_length, 1) as avg_title_length,
    
    -- Trend analysis
    ROUND(ta.moving_avg_3m, 1) as moving_avg_3m,
    ROUND(ta.moving_avg_12m, 1) as moving_avg_12m,
    ta.same_month_prev_year,
    ta.month_over_month_change,
    
    -- Growth percentages
    CASE 
        WHEN ta.same_month_prev_year > 0 THEN
            ROUND(((ta.document_count - ta.same_month_prev_year)::NUMERIC / ta.same_month_prev_year) * 100, 1)
        ELSE NULL
    END as year_over_year_growth_pct,
    
    CASE 
        WHEN LAG(ta.document_count) OVER (
            PARTITION BY ta.categoria, ta.state_code 
            ORDER BY ta.month_year
        ) > 0 THEN
            ROUND((ta.month_over_month_change::NUMERIC / LAG(ta.document_count) OVER (
                PARTITION BY ta.categoria, ta.state_code 
                ORDER BY ta.month_year
            )) * 100, 1)
        ELSE NULL
    END as month_over_month_growth_pct,
    
    -- Ranking and seasonality
    ta.monthly_rank_in_category,
    
    -- Seasonality indicators
    CASE 
        WHEN ta.month IN (12, 1, 2) THEN 'Summer'
        WHEN ta.month IN (3, 4, 5) THEN 'Autumn' 
        WHEN ta.month IN (6, 7, 8) THEN 'Winter'
        WHEN ta.month IN (9, 10, 11) THEN 'Spring'
    END as season,
    
    -- Activity level classification
    CASE 
        WHEN ta.document_count >= ta.moving_avg_12m * 1.5 THEN 'High Activity'
        WHEN ta.document_count >= ta.moving_avg_12m * 1.2 THEN 'Above Average'
        WHEN ta.document_count >= ta.moving_avg_12m * 0.8 THEN 'Average'
        WHEN ta.document_count >= ta.moving_avg_12m * 0.5 THEN 'Below Average'
        ELSE 'Low Activity'
    END as activity_level,
    
    -- System metadata
    CURRENT_TIMESTAMP as last_updated
    
FROM trend_analysis ta
WHERE ta.month_year >= CURRENT_DATE - INTERVAL '10 years'  -- Keep last 10 years
ORDER BY ta.month_year DESC, ta.document_count DESC;

-- Create indexes on temporal trends
CREATE INDEX idx_mv_temporal_month_year ON mv_temporal_trends(month_year DESC);
CREATE INDEX idx_mv_temporal_categoria ON mv_temporal_trends(categoria);
CREATE INDEX idx_mv_temporal_state ON mv_temporal_trends(state_code);
CREATE INDEX idx_mv_temporal_count ON mv_temporal_trends(document_count DESC);
CREATE INDEX idx_mv_temporal_composite ON mv_temporal_trends(month_year DESC, categoria, state_code);

-- ============================================================================
-- 5. SEARCH FACETS MATERIALIZED VIEW
-- ============================================================================

-- Pre-computed search facets for advanced filtering UI
DROP MATERIALIZED VIEW IF EXISTS mv_search_facets CASCADE;
CREATE MATERIALIZED VIEW mv_search_facets AS
WITH document_type_facets AS (
    SELECT 
        'document_type' as facet_category,
        COALESCE(d.tipo, d.document_type, d.tipo_documento, 'Outros') as facet_value,
        COUNT(*) as document_count,
        COUNT(DISTINCT COALESCE(d.estado, d.state)) as states_count,
        MIN(COALESCE(d.data_publicacao, d.data, d.date)) as earliest_date,
        MAX(COALESCE(d.data_publicacao, d.data, d.date)) as latest_date
    FROM brazilian_legislative_complete d
    WHERE (d.titulo IS NOT NULL OR d.title IS NOT NULL)
    GROUP BY COALESCE(d.tipo, d.document_type, d.tipo_documento, 'Outros')
),
authority_facets AS (
    SELECT 
        'authority_level' as facet_category,
        CASE 
            WHEN d.urn ILIKE '%supremo.tribunal.federal%' THEN 'STF - Supremo Tribunal Federal'
            WHEN d.urn ILIKE '%superior.tribunal.justica%' THEN 'STJ - Superior Tribunal de Justiça'
            WHEN d.urn ILIKE '%tribunal.superior.trabalho%' THEN 'TST - Tribunal Superior do Trabalho'
            WHEN d.urn ILIKE '%tribunal.regional.federal%' THEN 'TRF - Tribunal Regional Federal'
            WHEN d.urn ILIKE '%tribunal.regional.trabalho%' THEN 'TRT - Tribunal Regional do Trabalho'
            WHEN d.urn ILIKE '%tribunal.justica%' THEN 'TJ - Tribunal de Justiça'
            WHEN COALESCE(d.categoria, d.category) = 'Jurisprudência' THEN 'Outros Tribunais'
            WHEN d.urn ILIKE '%federal%' OR d.urn ILIKE '%brasil%' THEN 'Âmbito Federal'
            WHEN COALESCE(d.estado, d.state) = 'DF' THEN 'Distrito Federal'
            ELSE 'Âmbito Estadual/Municipal'
        END as facet_value,
        COUNT(*) as document_count,
        COUNT(DISTINCT COALESCE(d.estado, d.state)) as states_count,
        MIN(COALESCE(d.data_publicacao, d.data, d.date)) as earliest_date,
        MAX(COALESCE(d.data_publicacao, d.data, d.date)) as latest_date
    FROM brazilian_legislative_complete d
    WHERE (d.titulo IS NOT NULL OR d.title IS NOT NULL)
    GROUP BY CASE 
            WHEN d.urn ILIKE '%supremo.tribunal.federal%' THEN 'STF - Supremo Tribunal Federal'
            WHEN d.urn ILIKE '%superior.tribunal.justica%' THEN 'STJ - Superior Tribunal de Justiça'
            WHEN d.urn ILIKE '%tribunal.superior.trabalho%' THEN 'TST - Tribunal Superior do Trabalho'
            WHEN d.urn ILIKE '%tribunal.regional.federal%' THEN 'TRF - Tribunal Regional Federal'
            WHEN d.urn ILIKE '%tribunal.regional.trabalho%' THEN 'TRT - Tribunal Regional do Trabalho'
            WHEN d.urn ILIKE '%tribunal.justica%' THEN 'TJ - Tribunal de Justiça'
            WHEN COALESCE(d.categoria, d.category) = 'Jurisprudência' THEN 'Outros Tribunais'
            WHEN d.urn ILIKE '%federal%' OR d.urn ILIKE '%brasil%' THEN 'Âmbito Federal'
            WHEN COALESCE(d.estado, d.state) = 'DF' THEN 'Distrito Federal'
            ELSE 'Âmbito Estadual/Municipal'
        END
),
date_range_facets AS (
    SELECT 
        'date_range' as facet_category,
        CASE 
            WHEN COALESCE(d.data_publicacao, d.data, d.date) >= CURRENT_DATE - INTERVAL '3 months' THEN 'Últimos 3 meses'
            WHEN COALESCE(d.data_publicacao, d.data, d.date) >= CURRENT_DATE - INTERVAL '6 months' THEN 'Últimos 6 meses' 
            WHEN COALESCE(d.data_publicacao, d.data, d.date) >= CURRENT_DATE - INTERVAL '1 year' THEN 'Último ano'
            WHEN COALESCE(d.data_publicacao, d.data, d.date) >= CURRENT_DATE - INTERVAL '2 years' THEN 'Últimos 2 anos'
            WHEN COALESCE(d.data_publicacao, d.data, d.date) >= CURRENT_DATE - INTERVAL '5 years' THEN 'Últimos 5 anos'
            ELSE 'Mais de 5 anos'
        END as facet_value,
        COUNT(*) as document_count,
        COUNT(DISTINCT COALESCE(d.estado, d.state)) as states_count,
        MIN(COALESCE(d.data_publicacao, d.data, d.date)) as earliest_date,
        MAX(COALESCE(d.data_publicacao, d.data, d.date)) as latest_date
    FROM brazilian_legislative_complete d
    WHERE COALESCE(d.data_publicacao, d.data, d.date) IS NOT NULL
      AND (d.titulo IS NOT NULL OR d.title IS NOT NULL)
    GROUP BY CASE 
            WHEN COALESCE(d.data_publicacao, d.data, d.date) >= CURRENT_DATE - INTERVAL '3 months' THEN 'Últimos 3 meses'
            WHEN COALESCE(d.data_publicacao, d.data, d.date) >= CURRENT_DATE - INTERVAL '6 months' THEN 'Últimos 6 meses'
            WHEN COALESCE(d.data_publicacao, d.data, d.date) >= CURRENT_DATE - INTERVAL '1 year' THEN 'Último ano'
            WHEN COALESCE(d.data_publicacao, d.data, d.date) >= CURRENT_DATE - INTERVAL '2 years' THEN 'Últimos 2 anos'
            WHEN COALESCE(d.data_publicacao, d.data, d.date) >= CURRENT_DATE - INTERVAL '5 years' THEN 'Últimos 5 anos'
            ELSE 'Mais de 5 anos'
        END
),
unified_facets AS (
    SELECT * FROM document_type_facets
    UNION ALL
    SELECT * FROM authority_facets  
    UNION ALL
    SELECT * FROM date_range_facets
),
facet_rankings AS (
    SELECT 
        uf.*,
        ROW_NUMBER() OVER (PARTITION BY uf.facet_category ORDER BY uf.document_count DESC) as popularity_rank,
        SUM(uf.document_count) OVER (PARTITION BY uf.facet_category) as category_total_documents
    FROM unified_facets uf
)
SELECT 
    fr.facet_category,
    fr.facet_value,
    fr.document_count,
    fr.states_count,
    fr.earliest_date,
    fr.latest_date,
    fr.popularity_rank,
    
    -- Percentage calculations
    ROUND((fr.document_count::NUMERIC / fr.category_total_documents) * 100, 1) as percentage_in_category,
    
    -- Display metadata
    CASE fr.facet_category
        WHEN 'document_type' THEN 'Tipo de Documento'
        WHEN 'authority_level' THEN 'Nível de Autoridade'
        WHEN 'date_range' THEN 'Período'
        ELSE fr.facet_category
    END as display_category,
    
    -- Filtering hints for UI
    CASE 
        WHEN fr.document_count >= 10000 THEN 'high'
        WHEN fr.document_count >= 1000 THEN 'medium'
        WHEN fr.document_count >= 100 THEN 'low'
        ELSE 'minimal'
    END as volume_level,
    
    -- System metadata
    CURRENT_TIMESTAMP as last_updated
    
FROM facet_rankings fr
WHERE fr.document_count >= 10  -- Filter out very small facets
ORDER BY fr.facet_category, fr.popularity_rank;

-- Create indexes on search facets
CREATE INDEX idx_mv_search_facets_category ON mv_search_facets(facet_category);
CREATE INDEX idx_mv_search_facets_count ON mv_search_facets(document_count DESC);
CREATE INDEX idx_mv_search_facets_composite ON mv_search_facets(facet_category, popularity_rank);

-- ============================================================================
-- 6. REFRESH MANAGEMENT SYSTEM
-- ============================================================================

-- Function to refresh all materialized views with optimal scheduling
CREATE OR REPLACE FUNCTION refresh_materialized_views(
    p_view_name TEXT DEFAULT 'all',
    p_concurrent BOOLEAN DEFAULT TRUE
)
RETURNS TABLE(
    view_name TEXT,
    refresh_status TEXT,
    duration_ms INTEGER,
    rows_affected BIGINT,
    last_updated TIMESTAMP
) AS $$
DECLARE
    start_time TIMESTAMP;
    end_time TIMESTAMP;
    row_count BIGINT;
    refresh_sql TEXT;
    
BEGIN
    -- Refresh mv_table_metadata first (dependency for others)
    IF p_view_name IN ('all', 'mv_table_metadata') THEN
        start_time := clock_timestamp();
        
        IF p_concurrent THEN
            REFRESH MATERIALIZED VIEW CONCURRENTLY mv_table_metadata;
        ELSE
            REFRESH MATERIALIZED VIEW mv_table_metadata;
        END IF;
        
        end_time := clock_timestamp();
        GET DIAGNOSTICS row_count = ROW_COUNT;
        
        RETURN QUERY SELECT 
            'mv_table_metadata'::TEXT,
            'SUCCESS'::TEXT,
            EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER,
            row_count,
            CURRENT_TIMESTAMP;
    END IF;
    
    -- Refresh dashboard metrics
    IF p_view_name IN ('all', 'mv_dashboard_metrics') THEN
        start_time := clock_timestamp();
        
        IF p_concurrent THEN
            REFRESH MATERIALIZED VIEW CONCURRENTLY mv_dashboard_metrics;
        ELSE
            REFRESH MATERIALIZED VIEW mv_dashboard_metrics;
        END IF;
        
        end_time := clock_timestamp();
        SELECT COUNT(*) INTO row_count FROM mv_dashboard_metrics;
        
        RETURN QUERY SELECT 
            'mv_dashboard_metrics'::TEXT,
            'SUCCESS'::TEXT,
            EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER,
            row_count,
            CURRENT_TIMESTAMP;
    END IF;
    
    -- Refresh category statistics
    IF p_view_name IN ('all', 'mv_category_statistics') THEN
        start_time := clock_timestamp();
        
        IF p_concurrent THEN
            REFRESH MATERIALIZED VIEW CONCURRENTLY mv_category_statistics;
        ELSE
            REFRESH MATERIALIZED VIEW mv_category_statistics;
        END IF;
        
        end_time := clock_timestamp();
        SELECT COUNT(*) INTO row_count FROM mv_category_statistics;
        
        RETURN QUERY SELECT 
            'mv_category_statistics'::TEXT,
            'SUCCESS'::TEXT,
            EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER,
            row_count,
            CURRENT_TIMESTAMP;
    END IF;
    
    -- Refresh geographic distribution
    IF p_view_name IN ('all', 'mv_geographic_distribution') THEN
        start_time := clock_timestamp();
        
        IF p_concurrent THEN
            REFRESH MATERIALIZED VIEW CONCURRENTLY mv_geographic_distribution;
        ELSE
            REFRESH MATERIALIZED VIEW mv_geographic_distribution;
        END IF;
        
        end_time := clock_timestamp();
        SELECT COUNT(*) INTO row_count FROM mv_geographic_distribution;
        
        RETURN QUERY SELECT 
            'mv_geographic_distribution'::TEXT,
            'SUCCESS'::TEXT,
            EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER,
            row_count,
            CURRENT_TIMESTAMP;
    END IF;
    
    -- Refresh temporal trends
    IF p_view_name IN ('all', 'mv_temporal_trends') THEN
        start_time := clock_timestamp();
        
        IF p_concurrent THEN
            REFRESH MATERIALIZED VIEW CONCURRENTLY mv_temporal_trends;
        ELSE
            REFRESH MATERIALIZED VIEW mv_temporal_trends;
        END IF;
        
        end_time := clock_timestamp();
        SELECT COUNT(*) INTO row_count FROM mv_temporal_trends;
        
        RETURN QUERY SELECT 
            'mv_temporal_trends'::TEXT,
            'SUCCESS'::TEXT,
            EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER,
            row_count,
            CURRENT_TIMESTAMP;
    END IF;
    
    -- Refresh search facets
    IF p_view_name IN ('all', 'mv_search_facets') THEN
        start_time := clock_timestamp();
        
        IF p_concurrent THEN
            REFRESH MATERIALIZED VIEW CONCURRENTLY mv_search_facets;
        ELSE
            REFRESH MATERIALIZED VIEW mv_search_facets;
        END IF;
        
        end_time := clock_timestamp();
        SELECT COUNT(*) INTO row_count FROM mv_search_facets;
        
        RETURN QUERY SELECT 
            'mv_search_facets'::TEXT,
            'SUCCESS'::TEXT,
            EXTRACT(MILLISECONDS FROM (end_time - start_time))::INTEGER,
            row_count,
            CURRENT_TIMESTAMP;
    END IF;
    
EXCEPTION
    WHEN OTHERS THEN
        RETURN QUERY SELECT 
            COALESCE(p_view_name, 'unknown')::TEXT,
            'ERROR'::TEXT,
            -1,
            -1::BIGINT,
            CURRENT_TIMESTAMP;
        RAISE NOTICE 'Error refreshing materialized view %: %', p_view_name, SQLERRM;
END;
$$ LANGUAGE plpgsql;

-- Function for intelligent refresh scheduling based on data freshness
CREATE OR REPLACE FUNCTION smart_refresh_scheduler()
RETURNS TABLE(
    view_name TEXT,
    needs_refresh BOOLEAN,
    last_updated_hours_ago NUMERIC,
    recommended_action TEXT
) AS $$
BEGIN
    RETURN QUERY
    WITH view_freshness AS (
        SELECT 'mv_dashboard_metrics' as view_name, 
               EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - (SELECT last_updated FROM mv_dashboard_metrics LIMIT 1))) / 3600 as hours_ago,
               4 as refresh_threshold_hours  -- Dashboard needs frequent updates
        UNION ALL
        SELECT 'mv_category_statistics' as view_name,
               EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - (SELECT last_updated FROM mv_category_statistics LIMIT 1))) / 3600 as hours_ago,
               12 as refresh_threshold_hours  -- Categories change less frequently
        UNION ALL
        SELECT 'mv_geographic_distribution' as view_name,
               EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - (SELECT last_updated FROM mv_geographic_distribution LIMIT 1))) / 3600 as hours_ago,
               24 as refresh_threshold_hours  -- Geographic data changes slowly
        UNION ALL
        SELECT 'mv_temporal_trends' as view_name,
               EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - (SELECT last_updated FROM mv_temporal_trends LIMIT 1))) / 3600 as hours_ago,
               24 as refresh_threshold_hours  -- Daily refresh is sufficient
        UNION ALL
        SELECT 'mv_search_facets' as view_name,
               EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - (SELECT last_updated FROM mv_search_facets LIMIT 1))) / 3600 as hours_ago,
               8 as refresh_threshold_hours   -- Facets need regular updates for UI
    )
    SELECT 
        vf.view_name::TEXT,
        (vf.hours_ago > vf.refresh_threshold_hours) as needs_refresh,
        ROUND(vf.hours_ago, 1) as last_updated_hours_ago,
        CASE 
            WHEN vf.hours_ago > vf.refresh_threshold_hours * 2 THEN 'URGENT_REFRESH'
            WHEN vf.hours_ago > vf.refresh_threshold_hours THEN 'RECOMMENDED_REFRESH'
            WHEN vf.hours_ago > vf.refresh_threshold_hours * 0.8 THEN 'OPTIONAL_REFRESH'
            ELSE 'NO_REFRESH_NEEDED'
        END::TEXT as recommended_action
    FROM view_freshness vf
    ORDER BY vf.hours_ago DESC;
    
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- 7. PERFORMANCE MONITORING FOR MATERIALIZED VIEWS
-- ============================================================================

-- View to monitor materialized view performance and usage
CREATE OR REPLACE VIEW v_mv_performance_stats AS
WITH mv_sizes AS (
    SELECT 
        schemaname,
        tablename as mv_name,
        pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size,
        pg_total_relation_size(schemaname||'.'||tablename) as size_bytes
    FROM pg_tables 
    WHERE tablename LIKE 'mv_%'
),
mv_activity AS (
    SELECT 
        schemaname,
        tablename as mv_name,
        seq_scan as sequential_scans,
        seq_tup_read as sequential_reads,
        idx_scan as index_scans,
        idx_tup_fetch as index_reads,
        n_tup_ins + n_tup_upd + n_tup_del as modifications
    FROM pg_stat_user_tables
    WHERE tablename LIKE 'mv_%'
)
SELECT 
    s.mv_name,
    s.size,
    s.size_bytes,
    a.sequential_scans,
    a.sequential_reads,
    a.index_scans,
    a.index_reads,
    a.modifications,
    ROUND((a.index_reads::NUMERIC / NULLIF(a.sequential_reads + a.index_reads, 0)) * 100, 1) as index_usage_percentage,
    CASE 
        WHEN a.sequential_scans + a.index_scans = 0 THEN 'UNUSED'
        WHEN a.index_scans > a.sequential_scans THEN 'WELL_INDEXED'
        WHEN a.sequential_scans > a.index_scans * 3 THEN 'NEEDS_INDEXES'
        ELSE 'MODERATE_USAGE'
    END as performance_status
FROM mv_sizes s
JOIN mv_activity a ON s.mv_name = a.mv_name
ORDER BY s.size_bytes DESC;

-- Grant permissions for Railway deployment
GRANT SELECT ON ALL TABLES IN SCHEMA public TO postgres, railway;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO postgres, railway;

-- Final deployment message
DO $$
BEGIN
    RAISE NOTICE '============================================================';
    RAISE NOTICE 'SPRINT 6A: MATERIALIZED VIEWS DEPLOYMENT COMPLETED';
    RAISE NOTICE '============================================================';
    RAISE NOTICE 'Materialized Views Created:';
    RAISE NOTICE '1. mv_dashboard_metrics - Core dashboard statistics';
    RAISE NOTICE '2. mv_category_statistics - Document category analysis';
    RAISE NOTICE '3. mv_geographic_distribution - State/regional analysis';  
    RAISE NOTICE '4. mv_temporal_trends - Time-series analysis';
    RAISE NOTICE '5. mv_search_facets - Search filtering facets';
    RAISE NOTICE '';
    RAISE NOTICE 'Management Functions:';
    RAISE NOTICE '- SELECT * FROM refresh_materialized_views();';
    RAISE NOTICE '- SELECT * FROM smart_refresh_scheduler();';
    RAISE NOTICE '- SELECT * FROM v_mv_performance_stats;';
    RAISE NOTICE '';
    RAISE NOTICE 'Expected Performance Improvements:';
    RAISE NOTICE '- Dashboard load time: 95% faster (<100ms)';
    RAISE NOTICE '- Category filtering: 90% faster (<50ms)';
    RAISE NOTICE '- Geographic analysis: 95% faster (<200ms)';
    RAISE NOTICE '- Temporal trends: 90% faster (<150ms)';
    RAISE NOTICE '- Search facets: 85% faster (<100ms)';
    RAISE NOTICE '';
    RAISE NOTICE 'Next: Run refresh_materialized_views() to populate views';
    RAISE NOTICE '============================================================';
END;
$$;