
-- LexML Corrected Database - Usage Examples
-- Generated: 2025-07-12T17:45:38.142617

-- 1. Basic Statistics
SELECT 
    COUNT(*) as total_documents,
    COUNT(DISTINCT urn) as unique_documents,
    COUNT(CASE WHEN enacting_date IS NOT NULL THEN 1 END) as documents_with_dates
FROM lexml_documents_corrected;

-- 2. Document Type Distribution
SELECT 
    urn_type,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM lexml_documents_corrected), 1) as percentage
FROM lexml_documents_corrected
GROUP BY urn_type
ORDER BY count DESC;

-- 3. Legislative Documents by Year
SELECT 
    substr(enacting_date, 1, 4) as year,
    COUNT(*) as legislation_count
FROM lexml_documents_corrected
WHERE urn_type = 'legislation' 
    AND enacting_date IS NOT NULL
GROUP BY substr(enacting_date, 1, 4)
ORDER BY year DESC;

-- 4. Most Productive Search Terms
SELECT 
    search_term,
    COUNT(*) as document_count,
    COUNT(CASE WHEN urn_type = 'legislation' THEN 1 END) as legislation_count
FROM lexml_documents_corrected
GROUP BY search_term
ORDER BY document_count DESC
LIMIT 20;

-- 5. Recent Legislative Activity (Last 5 Years)
SELECT 
    title,
    enacting_date,
    urn_type,
    search_term
FROM lexml_documents_corrected
WHERE urn_type = 'legislation'
    AND enacting_date >= '2019-01-01'
ORDER BY enacting_date DESC
LIMIT 50;

-- 6. Documents by Authority Type
SELECT 
    CASE 
        WHEN urn LIKE '%federal%' THEN 'Federal'
        WHEN urn LIKE '%estadual%' THEN 'State'
        WHEN urn LIKE '%municipal%' THEN 'Municipal'
        WHEN urn LIKE '%senado.federal%' THEN 'Senate'
        WHEN urn LIKE '%congresso.nacional%' THEN 'Congress'
        ELSE 'Other'
    END as authority_level,
    COUNT(*) as document_count
FROM lexml_documents_corrected
WHERE urn_type = 'legislation'
GROUP BY authority_level
ORDER BY document_count DESC;

-- 7. Transportation-Specific Legislation
SELECT 
    title,
    enacting_date,
    search_term
FROM lexml_documents_corrected
WHERE urn_type = 'legislation'
    AND (search_term LIKE '%transport%' 
         OR search_term LIKE '%caminhão%'
         OR search_term LIKE '%veículo%'
         OR search_term LIKE '%diesel%'
         OR search_term LIKE '%biodiesel%')
ORDER BY enacting_date DESC;

-- 8. Document Summary Analysis
SELECT 
    LENGTH(document_summary) as summary_length,
    COUNT(*) as count
FROM lexml_documents_corrected
WHERE document_summary IS NOT NULL
    AND document_summary != ''
GROUP BY LENGTH(document_summary) DIV 100 * 100
ORDER BY summary_length;

-- 9. Jurisprudence Analysis
SELECT 
    substr(enacting_date, 1, 4) as year,
    COUNT(*) as jurisprudence_count
FROM lexml_documents_corrected
WHERE urn_type = 'jurisprudence'
    AND enacting_date IS NOT NULL
GROUP BY substr(enacting_date, 1, 4)
ORDER BY year DESC;

-- 10. Data Quality Check
SELECT 
    'Total Records' as metric,
    COUNT(*) as value
FROM lexml_documents_corrected
UNION ALL
SELECT 
    'Records with Dates',
    COUNT(*)
FROM lexml_documents_corrected
WHERE enacting_date IS NOT NULL AND enacting_date != ''
UNION ALL
SELECT 
    'Records with Summaries',
    COUNT(*)
FROM lexml_documents_corrected
WHERE document_summary IS NOT NULL AND document_summary != ''
UNION ALL
SELECT 
    'Unique URNs',
    COUNT(DISTINCT urn)
FROM lexml_documents_corrected
WHERE urn IS NOT NULL;
