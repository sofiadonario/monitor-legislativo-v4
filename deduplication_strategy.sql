-- DEDUPLICATION STRATEGY FOR MACKMONITOR
-- This script identifies and resolves duplicate documents across LexML tables

-- Step 1: Analyze duplicate patterns
SELECT 'Analyzing duplicate patterns across tables...' as status;

-- Check for duplicates by URN (most reliable identifier)
WITH duplicate_analysis AS (
  SELECT 
    urn,
    titulo,
    COUNT(*) as occurrence_count,
    ARRAY_AGG(DISTINCT transport_category) as found_in_categories,
    ARRAY_AGG(DISTINCT species) as found_in_species,
    MIN(data_publicacao) as earliest_date,
    MAX(data_publicacao) as latest_date
  FROM documents 
  WHERE urn IS NOT NULL AND urn != ''
  GROUP BY urn, titulo
  HAVING COUNT(*) > 1
)
SELECT 
  'Duplicates by URN' as analysis_type,
  COUNT(*) as duplicate_groups,
  SUM(occurrence_count) as total_duplicate_rows,
  SUM(occurrence_count - 1) as excess_rows
FROM duplicate_analysis;

-- Check for duplicates by title (for documents without URN)
WITH title_duplicates AS (
  SELECT 
    titulo,
    data_publicacao,
    jurisdicao,
    COUNT(*) as occurrence_count,
    ARRAY_AGG(DISTINCT transport_category) as categories,
    ARRAY_AGG(DISTINCT species) as species_list
  FROM documents 
  WHERE (urn IS NULL OR urn = '') 
    AND titulo IS NOT NULL 
    AND titulo != ''
  GROUP BY titulo, data_publicacao, jurisdicao
  HAVING COUNT(*) > 1
)
SELECT 
  'Duplicates by Title' as analysis_type,
  COUNT(*) as duplicate_groups,
  SUM(occurrence_count) as total_duplicate_rows,
  SUM(occurrence_count - 1) as excess_rows
FROM title_duplicates;

-- Step 2: Create deduplicated view with preserved metadata
CREATE OR REPLACE VIEW documents_deduplicated AS
WITH ranked_documents AS (
  SELECT *,
    -- Rank documents by preference: prefer more complete records
    ROW_NUMBER() OVER (
      PARTITION BY 
        CASE 
          WHEN urn IS NOT NULL AND urn != '' THEN urn
          ELSE CONCAT(titulo, '|', COALESCE(data_publicacao::text, ''), '|', COALESCE(jurisdicao, ''))
        END
      ORDER BY 
        -- Prefer records with more complete metadata
        (CASE WHEN ementa IS NOT NULL AND LENGTH(ementa) > 100 THEN 1 ELSE 0 END) DESC,
        (CASE WHEN assuntos IS NOT NULL AND LENGTH(assuntos) > 50 THEN 1 ELSE 0 END) DESC,
        (CASE WHEN url IS NOT NULL AND url != '' THEN 1 ELSE 0 END) DESC,
        data_coleta DESC, -- Prefer more recent collections
        id ASC
    ) as rn,
    -- Aggregate categories and species for the deduplicated record
    STRING_AGG(DISTINCT transport_category, ', ') OVER (
      PARTITION BY 
        CASE 
          WHEN urn IS NOT NULL AND urn != '' THEN urn
          ELSE CONCAT(titulo, '|', COALESCE(data_publicacao::text, ''), '|', COALESCE(jurisdicao, ''))
        END
    ) as all_transport_categories,
    STRING_AGG(DISTINCT species, ', ') OVER (
      PARTITION BY 
        CASE 
          WHEN urn IS NOT NULL AND urn != '' THEN urn
          ELSE CONCAT(titulo, '|', COALESCE(data_publicacao::text, ''), '|', COALESCE(jurisdicao, ''))
        END
    ) as all_species
FROM documents
)
SELECT 
  id,
  titulo,
  tipo,
  -- Use aggregated species if multiple, otherwise original
  CASE 
    WHEN all_species LIKE '%,%' THEN all_species
    ELSE species
  END as species,
  estado,
  estado_codigo,
  municipality,
  data_publicacao,
  promulgation_date,
  url,
  urn,
  conteudo,
  document_summary,
  document_type_full,
  search_term,
  autor,
  fonte,
  -- Use aggregated transport categories
  CASE 
    WHEN all_transport_categories LIKE '%,%' THEN all_transport_categories
    ELSE transport_category
  END as transport_category,
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
  -- Add deduplication metadata
  jsonb_build_object(
    'original_metadata', metadata,
    'deduplication_info', jsonb_build_object(
      'all_categories', all_transport_categories,
      'all_species', all_species,
      'deduplicated_at', NOW()
    )
  ) as metadata
FROM ranked_documents 
WHERE rn = 1;

-- Step 3: Verification queries
SELECT 'Deduplication Results:' as status;

SELECT 
  'Original documents view' as view_name,
  COUNT(*) as document_count
FROM documents
UNION ALL
SELECT 
  'Deduplicated documents view' as view_name,
  COUNT(*) as document_count
FROM documents_deduplicated;

-- Show reduction by category
SELECT 
  species,
  transport_category,
  COUNT(*) as original_count
FROM documents 
GROUP BY species, transport_category
UNION ALL
SELECT 
  species || ' (deduplicated)' as species,
  transport_category,
  COUNT(*) as deduplicated_count
FROM documents_deduplicated 
GROUP BY species, transport_category
ORDER BY species, transport_category;

-- Step 4: Sample duplicate analysis
SELECT 'Sample duplicates found:' as status;

-- Show examples of deduplicated records
SELECT 
  titulo,
  transport_category,
  species,
  data_publicacao,
  jurisdicao
FROM documents_deduplicated 
WHERE transport_category LIKE '%,%' OR species LIKE '%,%'
LIMIT 10;

-- Step 5: Create backup before implementing deduplication
CREATE TABLE IF NOT EXISTS documents_backup_before_dedup AS 
SELECT * FROM documents LIMIT 0; -- Structure only, no data yet

SELECT 'Deduplication analysis complete. Review results before proceeding with implementation.' as status;