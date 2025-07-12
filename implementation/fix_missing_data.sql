-- Fix missing states, municipalities, URLs and document summaries
-- Update documents table with proper data mapping

-- First, let's check what we have in the source
SELECT 'Source data check' as status;
SELECT COUNT(*) as total_source FROM lexml_documents_corrected;
SELECT COUNT(*) as with_url FROM lexml_documents_corrected WHERE url IS NOT NULL;
SELECT COUNT(*) as with_summary FROM lexml_documents_corrected WHERE document_summary IS NOT NULL;

-- Current documents table status
SELECT 'Current documents table' as status;
SELECT COUNT(*) as total_docs FROM documents;
SELECT COUNT(*) as with_estado FROM documents WHERE estado IS NOT NULL;
SELECT COUNT(*) as with_url FROM documents WHERE url IS NOT NULL;
SELECT COUNT(*) as with_conteudo FROM documents WHERE conteudo IS NOT NULL;

-- Update documents table with correct mapping
UPDATE documents SET
  estado = CASE 
    -- Extract state from metadata if available
    WHEN metadata->>'country' = 'Brasil' AND metadata->>'municipality' IS NOT NULL THEN 
      CASE 
        WHEN metadata->>'municipality' LIKE '%SP%' OR metadata->>'municipality' LIKE '%São Paulo%' THEN 'São Paulo'
        WHEN metadata->>'municipality' LIKE '%RJ%' OR metadata->>'municipality' LIKE '%Rio de Janeiro%' THEN 'Rio de Janeiro'
        WHEN metadata->>'municipality' LIKE '%MG%' OR metadata->>'municipality' LIKE '%Minas Gerais%' THEN 'Minas Gerais'
        WHEN metadata->>'municipality' LIKE '%RS%' OR metadata->>'municipality' LIKE '%Rio Grande%' THEN 'Rio Grande do Sul'
        WHEN metadata->>'municipality' LIKE '%BA%' OR metadata->>'municipality' LIKE '%Bahia%' THEN 'Bahia'
        WHEN metadata->>'municipality' LIKE '%PR%' OR metadata->>'municipality' LIKE '%Paraná%' THEN 'Paraná'
        WHEN metadata->>'municipality' LIKE '%SC%' OR metadata->>'municipality' LIKE '%Santa Catarina%' THEN 'Santa Catarina'
        WHEN metadata->>'municipality' LIKE '%DF%' OR metadata->>'municipality' LIKE '%Distrito Federal%' THEN 'Distrito Federal'
        ELSE 'Federal'
      END
    -- Extract from URN pattern for state/municipal laws
    WHEN urn LIKE '%sao.paulo%' THEN 'São Paulo'
    WHEN urn LIKE '%rio.de.janeiro%' OR urn LIKE '%rio.janeiro%' THEN 'Rio de Janeiro'
    WHEN urn LIKE '%minas.gerais%' THEN 'Minas Gerais'
    WHEN urn LIKE '%rio.grande.sul%' THEN 'Rio Grande do Sul'
    WHEN urn LIKE '%bahia%' THEN 'Bahia'
    WHEN urn LIKE '%parana%' THEN 'Paraná'
    WHEN urn LIKE '%santa.catarina%' THEN 'Santa Catarina'
    WHEN urn LIKE '%distrito.federal%' THEN 'Distrito Federal'
    WHEN urn LIKE '%federal%' OR urn LIKE '%congresso.nacional%' OR urn LIKE '%senado.federal%' THEN 'Federal'
    ELSE 'Federal'
  END
WHERE id IN (
  SELECT d.id 
  FROM documents d 
  JOIN lexml_documents_corrected ldc ON d.urn = ldc.urn
);

-- Update missing URLs (they should all have URLs)
UPDATE documents SET
  url = ldc.url
FROM lexml_documents_corrected ldc
WHERE documents.urn = ldc.urn 
  AND (documents.url IS NULL OR documents.url = '');

-- Update missing content/summaries (ementa)
UPDATE documents SET
  conteudo = COALESCE(ldc.document_summary, ldc.document_description, documents.conteudo)
FROM lexml_documents_corrected ldc
WHERE documents.urn = ldc.urn 
  AND (documents.conteudo IS NULL OR documents.conteudo = '');

-- Update metadata with additional information
UPDATE documents SET
  metadata = documents.metadata || jsonb_build_object(
    'state_extracted', estado,
    'has_summary', CASE WHEN conteudo IS NOT NULL AND conteudo != '' THEN true ELSE false END,
    'has_url', CASE WHEN url IS NOT NULL AND url != '' THEN true ELSE false END,
    'data_quality', 'corrected_lexml_v2'
  )
WHERE id > 0;

-- Final verification
SELECT 'FINAL RESULTS' as status;

SELECT 
  'Documents with states' as metric,
  COUNT(*) as count,
  ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 1) || '%' as percentage
FROM documents 
WHERE estado IS NOT NULL AND estado != '';

SELECT 
  'Documents with URLs' as metric,
  COUNT(*) as count,
  ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 1) || '%' as percentage
FROM documents 
WHERE url IS NOT NULL AND url != '';

SELECT 
  'Documents with content/ementa' as metric,
  COUNT(*) as count,
  ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 1) || '%' as percentage
FROM documents 
WHERE conteudo IS NOT NULL AND conteudo != '';

-- State distribution
SELECT 'State distribution' as status;
SELECT estado, COUNT(*) as count 
FROM documents 
WHERE estado IS NOT NULL 
GROUP BY estado 
ORDER BY count DESC 
LIMIT 10;

COMMIT;