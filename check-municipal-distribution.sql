-- Check which states have municipal documents
SELECT
    estado,
    COUNT(*) as total_docs,
    COUNT(CASE WHEN municipio IS NOT NULL AND municipio != '' THEN 1 END) as municipal_docs,
    ROUND(100.0 * COUNT(CASE WHEN municipio IS NOT NULL AND municipio != '' THEN 1 END) / COUNT(*), 2) as pct_municipal,
    COUNT(CASE WHEN municipio IS NULL OR municipio = '' THEN 1 END) as state_level_docs
FROM documents
WHERE estado IS NOT NULL AND estado != ''
GROUP BY estado
HAVING COUNT(CASE WHEN municipio IS NOT NULL AND municipio != '' THEN 1 END) > 0
ORDER BY municipal_docs DESC;

-- Summary
SELECT
    'TOTAL' as category,
    COUNT(*) as documents,
    COUNT(CASE WHEN municipio IS NOT NULL AND municipio != '' THEN 1 END) as with_municipio,
    COUNT(CASE WHEN municipio IS NULL OR municipio = '' THEN 1 END) as without_municipio
FROM documents;
