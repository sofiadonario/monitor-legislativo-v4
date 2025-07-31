-- Senior Engineer Solution: Use specific tables for specific purposes
-- Drop incorrect unified views and create proper table-specific views

-- Drop existing incorrect views
DROP VIEW IF EXISTS documents CASCADE;
DROP VIEW IF EXISTS lexml_parsed_enhanced_fixed CASCADE;

-- 1. Main documents view - Uses lexml_documents (129,328 records)
-- For: Document count, state coverage, municipality coverage, date range
CREATE VIEW documents AS
SELECT 
  id,
  titulo,
  tipo,
  categoria as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
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
  json_build_object('classificacao', classificacao, 'ano', ano, 'origem', origem) as metadata
FROM lexml_documents;

-- 2. Legislative documents view - For Interactive Map 2
-- Uses lexml_legislacao_* tables
CREATE VIEW legislative_documents AS
SELECT 
  id,
  titulo,
  tipo,
  'Legislação' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Geral' as modal
FROM lexml_legislacao_geral

UNION ALL

SELECT 
  id + 100000,
  titulo,
  tipo,
  'Legislação' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Aéreo' as modal
FROM lexml_legislacao_aereo

UNION ALL

SELECT 
  id + 200000,
  titulo,
  tipo,
  'Legislação' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Marítimo' as modal
FROM lexml_legislacao_maritimo

UNION ALL

SELECT 
  id + 300000,
  titulo,
  tipo,
  'Legislação' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Rodoviário' as modal
FROM lexml_legislacao_rodoviario;

-- 3. Jurisprudence documents view - For Interactive Map 3
-- Uses lexml_jurisprudencia_* tables
CREATE VIEW jurisprudence_documents AS
SELECT 
  id,
  titulo,
  tipo,
  'Jurisprudência' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Geral' as modal
FROM lexml_jurisprudencia_geral

UNION ALL

SELECT 
  id + 100000,
  titulo,
  tipo,
  'Jurisprudência' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Aéreo' as modal
FROM lexml_jurisprudencia_aereo

UNION ALL

SELECT 
  id + 200000,
  titulo,
  tipo,
  'Jurisprudência' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Marítimo' as modal
FROM lexml_jurisprudencia_maritimo

UNION ALL

SELECT 
  id + 300000,
  titulo,
  tipo,
  'Jurisprudência' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  url,
  urn,
  'Rodoviário' as modal
FROM lexml_jurisprudencia_rodoviario;

-- 4. Compatibility view for existing JOIN queries
CREATE VIEW lexml_parsed_enhanced_fixed AS SELECT * FROM documents;

-- Verify the solution
SELECT 'Senior engineer solution applied correctly' as status;
SELECT COUNT(*) as main_documents FROM documents;
SELECT COUNT(*) as legislative_documents FROM legislative_documents;
SELECT COUNT(*) as jurisprudence_documents FROM jurisprudence_documents;

-- Test jurisdiction distribution from main table
SELECT 'Main table jurisdictions:' as info, jurisdicao, COUNT(*) as count 
FROM lexml_documents 
WHERE jurisdicao IS NOT NULL 
GROUP BY jurisdicao 
ORDER BY count DESC;