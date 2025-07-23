-- Fix for missing lexml_parsed_enhanced_fixed table - Version 2
-- Create a proper compatibility view that includes the missing promulgation_date column

-- Drop the existing view first
DROP VIEW IF EXISTS lexml_parsed_enhanced_fixed;

-- Create the enhanced view with all expected columns including promulgation_date
CREATE OR REPLACE VIEW lexml_parsed_enhanced_fixed AS
SELECT 
  id,
  titulo,
  tipo,
  species,
  estado,
  municipality,
  data_publicacao,
  data_publicacao as promulgation_date,  -- Map data_publicacao to expected promulgation_date
  url,
  urn,
  conteudo,
  document_summary,
  document_type_full,
  search_term,
  autor,
  fonte,
  transport_category,
  created_at,
  updated_at,
  locality,
  authority,
  authority_level,
  document_number,
  justice,
  region,
  court_class,
  document_description,
  metadata
FROM documents;

-- Verify the view was created with promulgation_date column
SELECT 'lexml_parsed_enhanced_fixed view updated with promulgation_date column' as status;
SELECT COUNT(*) as total_records FROM lexml_parsed_enhanced_fixed;

-- Test the problematic query that was failing
SELECT 
  EXTRACT(YEAR FROM COALESCE(lpe.promulgation_date::date, d.data_publicacao)) as test_year,
  COUNT(*) as count
FROM documents d 
LEFT JOIN lexml_parsed_enhanced_fixed lpe ON d.urn = lpe.urn 
WHERE COALESCE(lpe.promulgation_date::date, d.data_publicacao) IS NOT NULL
GROUP BY EXTRACT(YEAR FROM COALESCE(lpe.promulgation_date::date, d.data_publicacao))
ORDER BY test_year DESC
LIMIT 5;