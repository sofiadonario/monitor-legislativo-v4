-- Create proper documents view using actual lexml_* tables
-- Maps real column names to expected application schema

-- Drop existing incorrect views
DROP VIEW IF EXISTS documents CASCADE;
DROP VIEW IF EXISTS lexml_parsed_enhanced_fixed CASCADE;

-- Create unified documents view from all real lexml_* tables
CREATE VIEW documents AS
-- Legislação tables
SELECT 
  id,
  titulo,
  tipo,
  'Legislação' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,  -- Map for compatibility
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Legislação') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Geral' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Legislação' as court_class,
  CONCAT('Legislação - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_legislacao_geral

UNION ALL

SELECT 
  id + 100000, -- Offset IDs to avoid conflicts
  titulo,
  tipo,
  'Legislação' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Legislação Aéreo') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Aéreo' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Legislação' as court_class,
  CONCAT('Legislação Aéreo - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_legislacao_aereo

UNION ALL

-- Doutrina tables  
SELECT 
  id + 200000,
  titulo,
  tipo,
  'Doutrina' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Doutrina') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Geral' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Doutrina' as court_class,
  CONCAT('Doutrina - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_doutrina_geral

UNION ALL

-- Jurisprudência tables
SELECT 
  id + 300000,
  titulo,
  tipo,
  'Jurisprudência' as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data as data_publicacao,
  data as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - Jurisprudência') as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  'Geral' as transport_category,
  data_coleta as created_at,
  data_coleta as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Jurisprudência' as court_class,
  CONCAT('Jurisprudência - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano) as metadata
FROM lexml_jurisprudencia_geral;

-- Create compatibility view
CREATE VIEW lexml_parsed_enhanced_fixed AS SELECT * FROM documents;

-- Verify the views
SELECT 'Proper documents view created from real lexml_* tables' as status;
SELECT COUNT(*) as total_documents FROM documents;
SELECT DISTINCT species, COUNT(*) as count FROM documents GROUP BY species;
SELECT DISTINCT estado, COUNT(*) as count FROM documents WHERE estado IS NOT NULL GROUP BY estado;