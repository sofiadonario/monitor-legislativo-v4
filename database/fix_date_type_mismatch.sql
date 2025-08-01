-- Fix date type mismatch issue in documents view
-- This addresses the error: "COALESCE types text and date cannot be matched"

-- Drop existing views that may have incorrect type casting
DROP VIEW IF EXISTS documents CASCADE;
DROP VIEW IF EXISTS lexml_parsed_enhanced_fixed CASCADE;
DROP VIEW IF EXISTS legislative_documents CASCADE;
DROP VIEW IF EXISTS jurisprudence_documents CASCADE;

-- Recreate documents view with proper date type casting
-- This ensures all date fields are properly cast to DATE type for COALESCE operations
CREATE VIEW documents AS
SELECT 
  id,
  titulo,
  tipo,
  categoria as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  -- CRITICAL FIX: Ensure both date fields are cast to the same type (DATE)
  data::date as data_publicacao,
  data::date as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT(tipo, ' - ', categoria) as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  modal as transport_category,
  -- CRITICAL FIX: Cast timestamp to date for consistent type
  data_coleta::date as created_at,
  data_coleta::timestamp as updated_at,
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

-- Create compatibility view
CREATE VIEW lexml_parsed_enhanced_fixed AS SELECT * FROM documents;

-- Create legislative documents view with proper date casting
CREATE VIEW legislative_documents AS
SELECT 
  id,
  titulo,
  tipo,
  'Legislação' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  -- Proper date casting
  data::date as data_publicacao,
  data::date as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT('Legislação - ', tipo) as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  modal as transport_category,
  data_coleta::date as created_at,
  data_coleta::timestamp as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Legislação' as court_class,
  CONCAT('Legislação - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano, 'origem', origem) as metadata,
  'N/A' as modal
FROM lexml_legislacao_aereo
UNION ALL
SELECT 
  id,
  titulo,
  tipo,
  'Legislação' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data::date as data_publicacao,
  data::date as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT('Legislação - ', tipo) as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  modal as transport_category,
  data_coleta::date as created_at,
  data_coleta::timestamp as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Legislação' as court_class,
  CONCAT('Legislação - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano, 'origem', origem) as metadata,
  'Geral' as modal
FROM lexml_legislacao_geral
UNION ALL
SELECT 
  id,
  titulo,
  tipo,
  'Legislação' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data::date as data_publicacao,
  data::date as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT('Legislação - ', tipo) as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  modal as transport_category,
  data_coleta::date as created_at,
  data_coleta::timestamp as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Legislação' as court_class,
  CONCAT('Legislação - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano, 'origem', origem) as metadata,
  'Marítimo' as modal
FROM lexml_legislacao_maritimo
UNION ALL
SELECT 
  id,
  titulo,
  tipo,
  'Legislação' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data::date as data_publicacao,
  data::date as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT('Legislação - ', tipo) as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  modal as transport_category,
  data_coleta::date as created_at,
  data_coleta::timestamp as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Legislação' as court_class,
  CONCAT('Legislação - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano, 'origem', origem) as metadata,
  'Rodoviário' as modal
FROM lexml_legislacao_rodoviario;

-- Create jurisprudence documents view with proper date casting
CREATE VIEW jurisprudence_documents AS
SELECT 
  id,
  titulo,
  tipo,
  'Jurisprudência' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data::date as data_publicacao,
  data::date as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT('Jurisprudência - ', tipo) as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  modal as transport_category,
  data_coleta::date as created_at,
  data_coleta::timestamp as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Jurisprudência' as court_class,
  CONCAT('Jurisprudência - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano, 'origem', origem) as metadata,
  'Aéreo' as modal
FROM lexml_jurisprudencia_aereo
UNION ALL
SELECT 
  id,
  titulo,
  tipo,
  'Jurisprudência' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data::date as data_publicacao,
  data::date as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT('Jurisprudência - ', tipo) as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  modal as transport_category,
  data_coleta::date as created_at,
  data_coleta::timestamp as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Jurisprudência' as court_class,
  CONCAT('Jurisprudência - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano, 'origem', origem) as metadata,
  'Geral' as modal
FROM lexml_jurisprudencia_geral
UNION ALL
SELECT 
  id,
  titulo,
  tipo,
  'Jurisprudência' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data::date as data_publicacao,
  data::date as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT('Jurisprudência - ', tipo) as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  modal as transport_category,
  data_coleta::date as created_at,
  data_coleta::timestamp as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Jurisprudência' as court_class,
  CONCAT('Jurisprudência - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano, 'origem', origem) as metadata,
  'Marítimo' as modal
FROM lexml_jurisprudencia_maritimo
UNION ALL
SELECT 
  id,
  titulo,
  tipo,
  'Jurisprudência' as categoria,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  data::date as data_publicacao,
  data::date as promulgation_date,
  url,
  urn,
  ementa as conteudo,
  assuntos as document_summary,
  CONCAT('Jurisprudência - ', tipo) as document_type_full,
  termo_busca as search_term,
  autor,
  'LexML' as fonte,
  modal as transport_category,
  data_coleta::date as created_at,
  data_coleta::timestamp as updated_at,
  localidade as locality,
  autoridade as authority,
  'Federal' as authority_level,
  numero::text as document_number,
  'N/A' as justice,
  'Nacional' as region,
  'Jurisprudência' as court_class,
  CONCAT('Jurisprudência - ', tipo) as document_description,
  json_build_object('classificacao', classificacao, 'ano', ano, 'origem', origem) as metadata,
  'Rodoviário' as modal
FROM lexml_jurisprudencia_rodoviario;

-- Verify the fix by testing the problematic query
-- This query should now work without type mismatch errors
SELECT 'View fix validation' as status;
SELECT COUNT(*) as total_documents FROM documents;

-- Test the COALESCE operation that was failing
SELECT 
  EXTRACT(YEAR FROM COALESCE(data_publicacao, created_at)) as year, 
  COUNT(*) as count 
FROM documents 
WHERE COALESCE(data_publicacao, created_at) IS NOT NULL 
GROUP BY year 
ORDER BY year DESC
LIMIT 5;

-- Verify data types are now consistent
SELECT 
  pg_typeof(data_publicacao) as data_publicacao_type,
  pg_typeof(created_at) as created_at_type
FROM documents 
LIMIT 1;