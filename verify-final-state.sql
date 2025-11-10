-- Verify Final State After Migration 003
-- ============================================================================

-- 1. Overall Column Population Rates
SELECT
    'municipio' as column_name,
    COUNT(*) as total_rows,
    COUNT(municipio) as non_null_rows,
    COUNT(CASE WHEN municipio != '' THEN 1 END) as non_empty_rows,
    ROUND(100.0 * COUNT(CASE WHEN municipio != '' THEN 1 END) / COUNT(*), 2) as pct_populated
FROM documents;

-- 2. Municipal Documents by State
SELECT
    estado,
    COUNT(*) as municipal_doc_count
FROM documents
WHERE (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
  AND municipio IS NOT NULL
  AND municipio != ''
GROUP BY estado
ORDER BY municipal_doc_count DESC;

-- 3. Verify No More Federal Municipal Docs
SELECT
    'Federal Municipal Docs' as issue,
    COUNT(*) as count
FROM documents
WHERE (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
  AND estado = 'Federal';

-- 4. Total Municipal Documents
SELECT
    'Total Municipal Documents' as metric,
    COUNT(*) as count,
    COUNT(CASE WHEN municipio IS NOT NULL AND municipio != '' THEN 1 END) as with_municipio,
    COUNT(CASE WHEN estado IS NOT NULL AND estado != '' THEN 1 END) as with_estado
FROM documents
WHERE urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%';

-- 5. Sample of Fixed Documents
SELECT
    estado,
    municipio,
    substring(urn from 1 for 80) as urn_preview
FROM documents
WHERE (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
  AND estado IN ('RJ', 'RS', 'ES', 'PR', 'GO')
ORDER BY estado, municipio
LIMIT 20;
