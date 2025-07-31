-- Update documents view to include new location columns
-- This provides proper municipality and state data for the dashboard

-- Drop existing views
DROP VIEW IF EXISTS documents CASCADE;
DROP VIEW IF EXISTS lexml_parsed_enhanced_fixed CASCADE;
DROP VIEW IF EXISTS legislative_documents CASCADE;
DROP VIEW IF EXISTS jurisprudence_documents CASCADE;

-- Create updated documents view with location data from lexml_documents table
CREATE VIEW documents AS
SELECT 
  id,
  titulo,
  tipo,
  categoria as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(municipio, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - ', categoria) as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  modal as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  categoria as court_class,
  CONCAT(categoria, ' - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano, 'origem', origem) as metadata,
  -- New location columns
  pais,
  estado_sigla,
  municipio as municipio_parsed
FROM lexml_documents;

-- Create compatibility view for existing joins
CREATE VIEW lexml_parsed_enhanced_fixed AS SELECT * FROM documents;

-- Create legislative documents view with location data
CREATE VIEW legislative_documents AS
SELECT 
  id,
  titulo,
  tipo,
  'Legislação' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(municipio, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Geral' as modal,
  pais,
  estado_sigla,
  municipio
FROM lexml_legislacao_geral

UNION ALL

SELECT 
  id + 100000,
  titulo,
  tipo,
  'Legislação' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(municipio, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Aéreo' as modal,
  pais,
  estado_sigla,
  municipio
FROM lexml_legislacao_aereo

UNION ALL

SELECT 
  id + 200000,
  titulo,
  tipo,
  'Legislação' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(municipio, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Marítimo' as modal,
  pais,
  estado_sigla,
  municipio
FROM lexml_legislacao_maritimo

UNION ALL

SELECT 
  id + 300000,
  titulo,
  tipo,
  'Legislação' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(municipio, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Rodoviário' as modal,
  pais,
  estado_sigla,
  municipio
FROM lexml_legislacao_rodoviario;

-- Create jurisprudence documents view with location data
CREATE VIEW jurisprudence_documents AS
SELECT 
  id,
  titulo,
  tipo,
  'Jurisprudência' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(municipio, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Geral' as modal,
  pais,
  estado_sigla,
  municipio
FROM lexml_jurisprudencia_geral

UNION ALL

SELECT 
  id + 100000,
  titulo,
  tipo,
  'Jurisprudência' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(municipio, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Aéreo' as modal,
  pais,
  estado_sigla,
  municipio
FROM lexml_jurisprudencia_aereo

UNION ALL

SELECT 
  id + 200000,
  titulo,
  tipo,
  'Jurisprudência' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(municipio, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Marítimo' as modal,  
  pais,
  estado_sigla,
  municipio
FROM lexml_jurisprudencia_maritimo

UNION ALL

SELECT 
  id + 300000,
  titulo,
  tipo,
  'Jurisprudência' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(municipio, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Rodoviário' as modal,
  pais,
  estado_sigla,
  municipio
FROM lexml_jurisprudencia_rodoviario;

-- Verify the updated views
SELECT 'Updated documents view with location columns' as status;
SELECT COUNT(*) as total_documents FROM documents;
SELECT COUNT(DISTINCT municipio_parsed) as unique_municipalities FROM documents WHERE municipio_parsed IS NOT NULL AND municipio_parsed != '';
SELECT COUNT(DISTINCT estado_sigla) as unique_state_codes FROM documents WHERE estado_sigla IS NOT NULL AND estado_sigla != '';

-- Sample of the new location data
SELECT pais, estado_sigla, municipio_parsed, COUNT(*) as count 
FROM documents 
WHERE municipio_parsed IS NOT NULL AND municipio_parsed != '' 
GROUP BY pais, estado_sigla, municipio_parsed 
ORDER BY count DESC 
LIMIT 10;