#!/bin/bash
# Railway CLI Database Fix Script
# Execute this after connecting with: railway connect Postgres

echo "🚂 Railway CLI Database Fix Script"
echo "=================================="
echo ""
echo "1. First, run this command to connect:"
echo "   railway connect Postgres"
echo ""
echo "2. Then copy and paste this SQL fix:"
echo ""

cat << 'EOF'
-- RAILWAY CLI FIX: Execute this in the PostgreSQL prompt

-- Step 1: Drop problematic views
DROP VIEW IF EXISTS documents CASCADE;
DROP VIEW IF EXISTS lexml_parsed_enhanced_fixed CASCADE;

-- Step 2: Recreate documents view with proper date casting
CREATE VIEW documents AS
SELECT 
  id,
  titulo,
  tipo,
  categoria as species,
  jurisdicao as estado,
  jurisdicao as estado_codigo,
  COALESCE(localidade, 'Nacional') as municipality,
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

-- Step 3: Test the fix
SELECT COUNT(*) as total_documents FROM documents;

-- Step 4: Verify the problematic query now works
SELECT 
  EXTRACT(YEAR FROM COALESCE(data_publicacao, created_at)) as year, 
  COUNT(*) as count 
FROM documents 
WHERE COALESCE(data_publicacao, created_at) IS NOT NULL 
GROUP BY year 
ORDER BY year DESC
LIMIT 5;

EOF

echo ""
echo "3. After executing the SQL, you should see:"
echo "   - total_documents: ~144,138 (instead of 3)"
echo "   - Year/count breakdown showing multiple years"
echo ""
echo "4. Then redeploy your Railway application"
echo ""