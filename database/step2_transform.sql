-- ============================================================================
-- STEP 2: Transform and Load Data into Documents Table
-- ============================================================================
-- Run this SQL after the CSV import completes
-- Execute in: https://console.cloud.google.com/sql/instances/mackmonitor-db/query?project=mackmonitor
-- ============================================================================

-- Insert transformed data from temp table into documents
INSERT INTO documents (
  titulo, tipo, data_publicacao, urn, autor, assuntos, classificacao,
  jurisdicao, autoridade, ementa, url, localidade, numero, ano,
  termo_busca, data_coleta, fonte, categoria, modal, pais, estado,
  municipio, fontes_localizacao, metadata
)
SELECT
  titulo,
  tipo,
  -- Convert data string to DATE (handle YYYY-MM-DD format)
  CASE WHEN data ~ '^\d{4}-\d{2}-\d{2}$' THEN data::DATE ELSE NULL END,
  urn,
  autor,
  assuntos,
  classificacao,
  jurisdicao,
  autoridade,
  ementa,
  url,
  localidade,
  numero,
  ano,
  termo_busca,
  -- Convert data_coleta to TIMESTAMP
  CASE WHEN data_coleta ~ '^\d{4}-\d{2}-\d{2}' THEN data_coleta::TIMESTAMP ELSE NULL END,
  origem,  -- Maps to 'fonte' column
  categoria,
  modal,
  pais,
  estado,
  municipio,
  fontes_localizacao,
  -- Store additional metadata fields in JSONB
  jsonb_build_object(
    'source_file', source_file,
    'extracted_category', extracted_category,
    'extracted_transport_mode', extracted_transport_mode,
    'deduplication_source', deduplication_source,
    'original_count', original_count,
    'merged_categories', merged_categories,
    'merged_transport', merged_transport
  )
FROM temp_csv_import
WHERE titulo IS NOT NULL;  -- Only import rows with a title

-- Show the count of imported documents
SELECT COUNT(*) as "Total Documents Imported" FROM documents;

-- Clean up temp table
DROP TABLE temp_csv_import;

-- Create compatibility view for the R Shiny app
-- This maps the column names the app expects to the actual table columns
DROP VIEW IF EXISTS documents_app_view;
CREATE VIEW documents_app_view AS
SELECT
  id,
  titulo,
  tipo,
  data_publicacao as data,      -- App queries 'data', table has 'data_publicacao'
  urn,
  autor,
  assuntos,
  classificacao,
  jurisdicao,
  autoridade,
  ementa,
  url,
  localidade,
  numero,
  ano,
  termo_busca,
  data_coleta,
  fonte as origem,               -- App queries 'origem', table has 'fonte'
  categoria,
  modal,
  pais,
  estado,
  municipio,
  fontes_localizacao,
  metadata
FROM documents;

-- Verify the import with statistics
SELECT
  'Total Documents' as metric,
  COUNT(*)::text as value
FROM documents
UNION ALL
SELECT
  'Unique Document Types',
  COUNT(DISTINCT tipo)::text
FROM documents
UNION ALL
SELECT
  'Date Range',
  CONCAT(
    MIN(data_publicacao)::text,
    ' to ',
    MAX(data_publicacao)::text
  )
FROM documents
UNION ALL
SELECT
  'Documents with Ementa',
  COUNT(CASE WHEN ementa IS NOT NULL AND ementa != '' THEN 1 END)::text
FROM documents;

-- Sample recent documents to verify data quality
SELECT
  id,
  titulo,
  tipo,
  data_publicacao,
  fonte
FROM documents
ORDER BY data_publicacao DESC NULLS LAST
LIMIT 10;
