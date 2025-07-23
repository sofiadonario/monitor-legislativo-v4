-- Fix for missing lexml_parsed_enhanced_fixed table
-- Create a placeholder view that maps to documents table

-- This creates a compatibility layer for queries expecting lexml_parsed_enhanced_fixed
CREATE OR REPLACE VIEW lexml_parsed_enhanced_fixed AS
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

-- Verify the view was created
SELECT 'lexml_parsed_enhanced_fixed view created successfully' as status;
SELECT COUNT(*) as total_records FROM lexml_parsed_enhanced_fixed;