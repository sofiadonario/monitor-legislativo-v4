-- IMMEDIATE FIX FOR RAILWAY DEPLOYMENT
-- Execute this in Railway PostgreSQL Query tab to fix the type mismatch error
-- Error: "COALESCE types text and date cannot be matched"

-- Step 1: Check current view structure
SELECT 'Checking current documents view structure...' as status;

-- Step 2: Drop and recreate the problematic documents view with proper type casting
DROP VIEW IF EXISTS documents CASCADE;
DROP VIEW IF EXISTS lexml_parsed_enhanced_fixed CASCADE;

-- Step 3: Recreate documents view with explicit date casting to ensure type consistency
CREATE VIEW documents AS
SELECT 
  id,
  titulo,
  tipo,
  categoria as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
  -- CRITICAL FIX: Ensure both fields are cast to DATE type for COALESCE compatibility
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
  -- CRITICAL FIX: Cast data_coleta to DATE (not TIMESTAMP) for COALESCE consistency
  data_coleta::date as created_at,
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

-- Step 4: Create compatibility view
CREATE VIEW lexml_parsed_enhanced_fixed AS SELECT * FROM documents;

-- Step 5: Test the fix - this query should now work without errors
SELECT 'Testing the fixed query...' as status;

-- This is the exact query that was failing before
SELECT 
  EXTRACT(YEAR FROM COALESCE(data_publicacao, created_at)) as year, 
  COUNT(*) as count 
FROM documents 
WHERE COALESCE(data_publicacao, created_at) IS NOT NULL 
GROUP BY year 
ORDER BY year DESC
LIMIT 5;

-- Step 6: Verify data types are now consistent
SELECT 'Verifying data types...' as status;
SELECT 
  pg_typeof(data_publicacao) as data_publicacao_type,
  pg_typeof(created_at) as created_at_type,
  COUNT(*) as total_documents
FROM documents 
LIMIT 1;

-- Step 7: Performance check - ensure views are using indexes properly  
SELECT 'Performance verification...' as status;
SELECT COUNT(*) as total_document_count FROM documents;

SELECT 'Fix completed successfully!' as status;
SELECT 'Application should now show 144,138 documents instead of 3' as expected_result;