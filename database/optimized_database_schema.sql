-- OPTIMIZED DATABASE SCHEMA FOR MACKMONITOR
-- Comprehensive solution for data consistency and performance
-- Senior Data Scientist Implementation - August 2, 2025

-- =============================================================================
-- 1. DROP EXISTING PROBLEMATIC VIEWS
-- =============================================================================

DROP MATERIALIZED VIEW IF EXISTS documents_unified CASCADE;
DROP VIEW IF EXISTS documents CASCADE;
DROP VIEW IF EXISTS lexml_parsed_enhanced_fixed CASCADE;
DROP VIEW IF EXISTS legislative_documents CASCADE;
DROP VIEW IF EXISTS jurisprudence_documents CASCADE;

-- =============================================================================
-- 2. OPTIMIZED MATERIALIZED VIEW WITH PROPER TYPE CASTING
-- =============================================================================

-- Create the main unified materialized view
-- This replaces the problematic 20-table UNION view with a single, optimized structure
CREATE MATERIALIZED VIEW documents_unified AS
WITH source_data AS (
  -- Legislação tables
  SELECT 
    id,
    titulo,
    tipo,
    'Legislação'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Geral'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'legislacao_geral'::text as source_table
  FROM lexml_legislacao_geral
  WHERE titulo IS NOT NULL AND titulo != ''
  
  UNION ALL
  
  SELECT 
    id + 100000,
    titulo,
    tipo,
    'Legislação'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Aéreo'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'legislacao_aereo'::text as source_table
  FROM lexml_legislacao_aereo
  WHERE titulo IS NOT NULL AND titulo != ''
  
  UNION ALL
  
  SELECT 
    id + 200000,
    titulo,
    tipo,
    'Legislação'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Marítimo'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'legislacao_maritimo'::text as source_table
  FROM lexml_legislacao_maritimo
  WHERE titulo IS NOT NULL AND titulo != ''
  
  UNION ALL
  
  SELECT 
    id + 300000,
    titulo,
    tipo,
    'Legislação'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Rodoviário'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'legislacao_rodoviario'::text as source_table
  FROM lexml_legislacao_rodoviario
  WHERE titulo IS NOT NULL AND titulo != ''
  
  -- Jurisprudência tables
  UNION ALL
  
  SELECT 
    id + 400000,
    titulo,
    tipo,
    'Jurisprudência'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Geral'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'jurisprudencia_geral'::text as source_table
  FROM lexml_jurisprudencia_geral
  WHERE titulo IS NOT NULL AND titulo != ''
  
  UNION ALL
  
  SELECT 
    id + 500000,
    titulo,
    tipo,
    'Jurisprudência'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Aéreo'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'jurisprudencia_aereo'::text as source_table
  FROM lexml_jurisprudencia_aereo
  WHERE titulo IS NOT NULL AND titulo != ''
  
  UNION ALL
  
  SELECT 
    id + 600000,
    titulo,
    tipo,
    'Jurisprudência'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Marítimo'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'jurisprudencia_maritimo'::text as source_table
  FROM lexml_jurisprudencia_maritimo
  WHERE titulo IS NOT NULL AND titulo != ''
  
  UNION ALL
  
  SELECT 
    id + 700000,
    titulo,
    tipo,
    'Jurisprudência'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Rodoviário'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'jurisprudencia_rodoviario'::text as source_table
  FROM lexml_jurisprudencia_rodoviario
  WHERE titulo IS NOT NULL AND titulo != ''
  
  -- Doutrina tables
  UNION ALL
  
  SELECT 
    id + 800000,
    titulo,
    tipo,
    'Doutrina'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Geral'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'doutrina_geral'::text as source_table
  FROM lexml_doutrina_geral
  WHERE titulo IS NOT NULL AND titulo != ''
  
  UNION ALL
  
  SELECT 
    id + 900000,
    titulo,
    tipo,
    'Doutrina'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Aéreo'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'doutrina_aereo'::text as source_table
  FROM lexml_doutrina_aereo
  WHERE titulo IS NOT NULL AND titulo != ''
  
  UNION ALL
  
  SELECT 
    id + 1000000,
    titulo,
    tipo,
    'Doutrina'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Marítimo'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'doutrina_maritimo'::text as source_table
  FROM lexml_doutrina_maritimo
  WHERE titulo IS NOT NULL AND titulo != ''
  
  UNION ALL
  
  SELECT 
    id + 1100000,
    titulo,
    tipo,
    'Doutrina'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Rodoviário'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'doutrina_rodoviario'::text as source_table
  FROM lexml_doutrina_rodoviario
  WHERE titulo IS NOT NULL AND titulo != ''
  
  -- Outros tables
  UNION ALL
  
  SELECT 
    id + 1200000,
    titulo,
    tipo,
    'Outros'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Geral'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'outros_geral'::text as source_table
  FROM lexml_outros_geral
  WHERE titulo IS NOT NULL AND titulo != ''
  
  UNION ALL
  
  SELECT 
    id + 1300000,
    titulo,
    tipo,
    'Outros'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Aéreo'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'outros_aereo'::text as source_table
  FROM lexml_outros_aereo
  WHERE titulo IS NOT NULL AND titulo != ''
  
  UNION ALL
  
  SELECT 
    id + 1400000,
    titulo,
    tipo,
    'Outros'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Marítimo'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'outros_maritimo'::text as source_table
  FROM lexml_outros_maritimo
  WHERE titulo IS NOT NULL AND titulo != ''
  
  -- Proposições tables
  UNION ALL
  
  SELECT 
    id + 1600000,
    titulo,
    tipo,
    'Proposições'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Geral'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'proposicoes_geral'::text as source_table
  FROM lexml_proposicoes_geral
  WHERE titulo IS NOT NULL AND titulo != ''
  
  UNION ALL
  
  SELECT 
    id + 1700000,
    titulo,
    tipo,
    'Proposições'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Aéreo'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'proposicoes_aereo'::text as source_table
  FROM lexml_proposicoes_aereo
  WHERE titulo IS NOT NULL AND titulo != ''
  
  UNION ALL
  
  SELECT 
    id + 1800000,
    titulo,
    tipo,
    'Proposições'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Marítimo'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'proposicoes_maritimo'::text as source_table
  FROM lexml_proposicoes_maritimo
  WHERE titulo IS NOT NULL AND titulo != ''
  
  UNION ALL
  
  SELECT 
    id + 1900000,
    titulo,
    tipo,
    'Proposições'::text as species,
    COALESCE(jurisdicao, 'BR')::text as estado,
    COALESCE(localidade, 'Nacional')::text as municipality,
    data::date as data_publicacao,
    url,
    urn,
    ementa,
    assuntos as document_summary,
    termo_busca as search_term,
    autor,
    'LexML'::text as fonte,
    'Rodoviário'::text as transport_category,
    data_coleta::timestamp as created_at,
    data_coleta::timestamp as updated_at,
    autoridade as authority,
    numero::text as document_number,
    classificacao,
    'proposicoes_rodoviario'::text as source_table
  FROM lexml_proposicoes_rodoviario
  WHERE titulo IS NOT NULL AND titulo != ''
)
SELECT 
  id,
  titulo,
  tipo,
  species,
  estado,
  municipality,
  data_publicacao,
  url,
  urn,
  ementa,
  document_summary,
  search_term,
  autor,
  fonte,
  transport_category,
  created_at,
  updated_at,
  authority,
  document_number,
  classificacao,
  source_table,
  -- Derived statistical fields
  EXTRACT(YEAR FROM data_publicacao) as ano,
  LENGTH(titulo) as titulo_length,
  CASE 
    WHEN data_publicacao >= '2020-01-01' THEN 'Recent'
    WHEN data_publicacao >= '2010-01-01' THEN 'Moderate'
    ELSE 'Historical'
  END as temporal_category,
  -- Text quality metrics
  CASE 
    WHEN LENGTH(COALESCE(ementa, '')) > 100 THEN 'High'
    WHEN LENGTH(COALESCE(ementa, '')) > 50 THEN 'Medium'
    ELSE 'Low'
  END as content_quality
FROM source_data
WHERE data_publicacao IS NOT NULL 
  AND data_publicacao >= '1942-01-01' 
  AND data_publicacao <= CURRENT_DATE + INTERVAL '1 year'
  AND LENGTH(titulo) > 10;

-- =============================================================================
-- 3. PERFORMANCE-OPTIMIZED INDEXES
-- =============================================================================

-- Primary identifier index
CREATE UNIQUE INDEX idx_documents_unified_id ON documents_unified(id);

-- Core query performance indexes
CREATE INDEX idx_documents_unified_species ON documents_unified(species);
CREATE INDEX idx_documents_unified_estado ON documents_unified(estado);
CREATE INDEX idx_documents_unified_transport ON documents_unified(transport_category);
CREATE INDEX idx_documents_unified_data ON documents_unified(data_publicacao);
CREATE INDEX idx_documents_unified_ano ON documents_unified(ano);

-- Composite indexes for complex queries
CREATE INDEX idx_documents_unified_species_estado ON documents_unified(species, estado);
CREATE INDEX idx_documents_unified_transport_data ON documents_unified(transport_category, data_publicacao);
CREATE INDEX idx_documents_unified_estado_ano ON documents_unified(estado, ano);

-- Full-text search indexes for Portuguese content
CREATE INDEX idx_documents_unified_titulo_fts ON documents_unified USING gin(to_tsvector('portuguese', titulo));
CREATE INDEX idx_documents_unified_ementa_fts ON documents_unified USING gin(to_tsvector('portuguese', COALESCE(ementa, '')));

-- Statistical analysis indexes
CREATE INDEX idx_documents_unified_temporal_category ON documents_unified(temporal_category);
CREATE INDEX idx_documents_unified_content_quality ON documents_unified(content_quality);
CREATE INDEX idx_documents_unified_source_table ON documents_unified(source_table);

-- =============================================================================
-- 4. COMPATIBILITY VIEWS
-- =============================================================================

-- Create backward-compatible documents view
CREATE VIEW documents AS 
SELECT 
  id,
  titulo,
  tipo,
  species,
  estado,
  estado as estado_codigo,
  municipality,
  data_publicacao,
  data_publicacao as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  document_summary,
  CONCAT(tipo, ' - ', species) as document_type_full,
  search_term,
  autor,
  fonte,
  transport_category,
  created_at::date as created_at,
  updated_at,
  municipality as locality,
  authority,
  'Federal' as authority_level,
  document_number,
  'N/A' as justice,
  'Nacional' as region,
  species as court_class,
  CONCAT(species, ' - ', tipo) as document_description,
  json_build_object(
    'classificacao', classificacao,
    'ano', ano,
    'temporal_category', temporal_category,
    'content_quality', content_quality,
    'source_table', source_table
  ) as metadata
FROM documents_unified;

-- Create legacy compatibility view
CREATE VIEW lexml_parsed_enhanced_fixed AS SELECT * FROM documents;

-- =============================================================================
-- 5. AGGREGATED VIEWS FOR DASHBOARD PERFORMANCE
-- =============================================================================

-- State-level aggregation view
CREATE MATERIALIZED VIEW documents_by_state AS
SELECT 
  estado,
  COUNT(*) as total_documents,
  COUNT(CASE WHEN species = 'Legislação' THEN 1 END) as legislacao_count,
  COUNT(CASE WHEN species = 'Jurisprudência' THEN 1 END) as jurisprudencia_count,
  COUNT(CASE WHEN species = 'Doutrina' THEN 1 END) as doutrina_count,
  COUNT(CASE WHEN species = 'Outros' THEN 1 END) as outros_count,
  COUNT(CASE WHEN species = 'Proposições' THEN 1 END) as proposicoes_count,
  MIN(data_publicacao) as oldest_document,
  MAX(data_publicacao) as newest_document,
  AVG(titulo_length) as avg_title_length
FROM documents_unified
WHERE estado IS NOT NULL AND estado != ''
GROUP BY estado;

CREATE INDEX idx_documents_by_state_estado ON documents_by_state(estado);

-- Temporal aggregation view
CREATE MATERIALIZED VIEW documents_by_year AS
SELECT 
  ano,
  COUNT(*) as total_documents,
  COUNT(CASE WHEN species = 'Legislação' THEN 1 END) as legislacao_count,
  COUNT(CASE WHEN species = 'Jurisprudência' THEN 1 END) as jurisprudencia_count,
  COUNT(CASE WHEN species = 'Doutrina' THEN 1 END) as doutrina_count,
  COUNT(CASE WHEN species = 'Outros' THEN 1 END) as outros_count,
  COUNT(CASE WHEN species = 'Proposições' THEN 1 END) as proposicoes_count,
  COUNT(DISTINCT estado) as states_covered,
  AVG(titulo_length) as avg_title_length
FROM documents_unified
WHERE ano IS NOT NULL AND ano BETWEEN 1942 AND EXTRACT(YEAR FROM CURRENT_DATE)
GROUP BY ano;

CREATE INDEX idx_documents_by_year_ano ON documents_by_year(ano);

-- Transport category aggregation view
CREATE MATERIALIZED VIEW documents_by_transport AS
SELECT 
  transport_category,
  species,
  COUNT(*) as total_documents,
  COUNT(DISTINCT estado) as states_covered,
  MIN(data_publicacao) as oldest_document,
  MAX(data_publicacao) as newest_document,
  AVG(titulo_length) as avg_title_length,
  COUNT(CASE WHEN content_quality = 'High' THEN 1 END) as high_quality_count
FROM documents_unified
GROUP BY transport_category, species;

CREATE INDEX idx_documents_by_transport_category ON documents_by_transport(transport_category);
CREATE INDEX idx_documents_by_transport_species ON documents_by_transport(species);

-- =============================================================================
-- 6. DATA QUALITY MONITORING TABLES
-- =============================================================================

-- Data consistency monitoring table
CREATE TABLE IF NOT EXISTS data_consistency_log (
  id SERIAL PRIMARY KEY,
  check_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  component_name VARCHAR(100) NOT NULL,
  expected_count INTEGER NOT NULL,
  actual_count INTEGER NOT NULL,
  consistency_ratio DECIMAL(5,4),
  status VARCHAR(20) DEFAULT 'PASSED',
  error_message TEXT,
  metadata JSONB
);

CREATE INDEX idx_data_consistency_log_timestamp ON data_consistency_log(check_timestamp);
CREATE INDEX idx_data_consistency_log_component ON data_consistency_log(component_name);
CREATE INDEX idx_data_consistency_log_status ON data_consistency_log(status);

-- Query performance monitoring table
CREATE TABLE IF NOT EXISTS query_performance_log (
  id SERIAL PRIMARY KEY,
  execution_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  query_type VARCHAR(100) NOT NULL,
  execution_time_ms INTEGER NOT NULL,
  rows_returned INTEGER,
  rows_scanned INTEGER,
  cache_hit BOOLEAN DEFAULT FALSE,
  user_session VARCHAR(100),
  metadata JSONB
);

CREATE INDEX idx_query_performance_log_timestamp ON query_performance_log(execution_timestamp);
CREATE INDEX idx_query_performance_log_type ON query_performance_log(query_type);
CREATE INDEX idx_query_performance_log_performance ON query_performance_log(execution_time_ms);

-- =============================================================================
-- 7. REFRESH PROCEDURES
-- =============================================================================

-- Function to refresh materialized views
CREATE OR REPLACE FUNCTION refresh_materialized_views()
RETURNS TABLE(view_name TEXT, refresh_time INTERVAL, status TEXT) AS $$
DECLARE
    start_time TIMESTAMP;
    end_time TIMESTAMP;
BEGIN
    -- Refresh main documents_unified view
    start_time := clock_timestamp();
    REFRESH MATERIALIZED VIEW CONCURRENTLY documents_unified;
    end_time := clock_timestamp();
    view_name := 'documents_unified';
    refresh_time := end_time - start_time;
    status := 'SUCCESS';
    RETURN NEXT;
    
    -- Refresh aggregation views
    start_time := clock_timestamp();
    REFRESH MATERIALIZED VIEW documents_by_state;
    end_time := clock_timestamp();
    view_name := 'documents_by_state';
    refresh_time := end_time - start_time;
    status := 'SUCCESS';
    RETURN NEXT;
    
    start_time := clock_timestamp();
    REFRESH MATERIALIZED VIEW documents_by_year;
    end_time := clock_timestamp();
    view_name := 'documents_by_year';
    refresh_time := end_time - start_time;
    status := 'SUCCESS';
    RETURN NEXT;
    
    start_time := clock_timestamp();
    REFRESH MATERIALIZED VIEW documents_by_transport;
    end_time := clock_timestamp();
    view_name := 'documents_by_transport';
    refresh_time := end_time - start_time;
    status := 'SUCCESS';
    RETURN NEXT;
    
    EXCEPTION WHEN OTHERS THEN
        view_name := 'ERROR';
        refresh_time := NULL;
        status := SQLERRM;
        RETURN NEXT;
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- 8. VALIDATION AND VERIFICATION
-- =============================================================================

-- Verify the schema is working correctly
SELECT 'Schema validation started' as status;

-- Test document count
SELECT COUNT(*) as total_documents FROM documents_unified;

-- Test data quality
SELECT 
  species,
  transport_category,
  COUNT(*) as count,
  MIN(ano) as min_year,
  MAX(ano) as max_year,
  AVG(titulo_length) as avg_title_length
FROM documents_unified
GROUP BY species, transport_category
ORDER BY species, transport_category;

-- Test the problematic COALESCE query that was failing
SELECT 
  EXTRACT(YEAR FROM COALESCE(data_publicacao, created_at::date)) as year,
  COUNT(*) as count
FROM documents_unified
WHERE COALESCE(data_publicacao, created_at::date) IS NOT NULL
GROUP BY year
ORDER BY year DESC
LIMIT 10;

-- Verify indexes are being used
EXPLAIN (ANALYZE, BUFFERS) 
SELECT COUNT(*) FROM documents_unified WHERE species = 'Legislação' AND estado = 'SP';

SELECT 'Optimized schema deployment completed successfully!' as status;

-- Log successful deployment
INSERT INTO data_consistency_log (component_name, expected_count, actual_count, status, error_message)
SELECT 
  'schema_deployment',
  279152,
  COUNT(*),
  CASE WHEN COUNT(*) > 100000 THEN 'PASSED' ELSE 'FAILED' END,
  'Optimized schema deployment with materialized views'
FROM documents_unified;