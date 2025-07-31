-- Verify data integrity and generate summary report

-- Total records
SELECT 'Total Records' as metric, COUNT(*) as value FROM lexml_documents;

-- Records by category
SELECT 'By Category' as metric, categoria, COUNT(*) as count,
       ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM lexml_documents), 1) as percentage
FROM lexml_documents
GROUP BY categoria
ORDER BY COUNT(*) DESC;

-- Records by modal
SELECT 'By Modal' as metric, modal, COUNT(*) as count,
       ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM lexml_documents), 1) as percentage
FROM lexml_documents
GROUP BY modal
ORDER BY COUNT(*) DESC;

-- Records by jurisdiction
SELECT 'By Jurisdiction' as metric, jurisdicao, COUNT(*) as count
FROM lexml_documents
WHERE jurisdicao IS NOT NULL
GROUP BY jurisdicao
ORDER BY COUNT(*) DESC;

-- Date range
SELECT 'Date Range' as metric, 
       MIN(data)::text as min_date, 
       MAX(data)::text as max_date
FROM lexml_documents
WHERE data IS NOT NULL;

-- Top search terms
SELECT 'Top Search Terms' as metric, termo_busca, COUNT(*) as count
FROM lexml_documents
WHERE termo_busca IS NOT NULL
GROUP BY termo_busca
ORDER BY COUNT(*) DESC
LIMIT 10;

-- Data quality checks
SELECT 'Data Quality' as metric, 
       'Records with URN' as check_type,
       COUNT(CASE WHEN urn IS NOT NULL THEN 1 END) as count,
       ROUND(COUNT(CASE WHEN urn IS NOT NULL THEN 1 END) * 100.0 / COUNT(*), 1) as percentage
FROM lexml_documents
UNION ALL
SELECT 'Data Quality' as metric,
       'Records with Date' as check_type,
       COUNT(CASE WHEN data IS NOT NULL THEN 1 END) as count,
       ROUND(COUNT(CASE WHEN data IS NOT NULL THEN 1 END) * 100.0 / COUNT(*), 1) as percentage
FROM lexml_documents
UNION ALL
SELECT 'Data Quality' as metric,
       'Records with Ementa' as check_type,
       COUNT(CASE WHEN ementa IS NOT NULL THEN 1 END) as count,
       ROUND(COUNT(CASE WHEN ementa IS NOT NULL THEN 1 END) * 100.0 / COUNT(*), 1) as percentage
FROM lexml_documents;

-- Category x Modal matrix (top 10)
SELECT categoria, modal, COUNT(*) as count
FROM lexml_documents
GROUP BY categoria, modal
ORDER BY COUNT(*) DESC
LIMIT 10;