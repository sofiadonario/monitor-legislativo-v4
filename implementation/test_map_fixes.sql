-- Test script to validate map rendering fixes
-- This script tests the complete data pipeline for map functionality

-- 1. Test state standardization
SELECT 'TESTING STATE STANDARDIZATION' as test_name;

-- Check if estado_codigo column exists and is populated
SELECT 
    COUNT(*) as total_documents,
    COUNT(CASE WHEN estado_codigo IS NOT NULL THEN 1 END) as with_estado_codigo,
    ROUND(COUNT(CASE WHEN estado_codigo IS NOT NULL THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as coverage
FROM documents;

-- Test state code distribution
SELECT 'State code distribution' as metric;
SELECT 
    estado_codigo, 
    estado,
    COUNT(*) as document_count
FROM documents 
WHERE estado_codigo IS NOT NULL 
GROUP BY estado_codigo, estado 
ORDER BY document_count DESC;

-- 2. Test geographic data compatibility
SELECT 'TESTING GEOGRAPHIC DATA COMPATIBILITY' as test_name;

-- Check that all our state codes match standard Brazilian state codes
WITH expected_states AS (
    SELECT unnest(ARRAY['AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 
                         'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 
                         'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO']) as valid_code
),
document_states AS (
    SELECT DISTINCT estado_codigo 
    FROM documents 
    WHERE estado_codigo IS NOT NULL 
      AND estado_codigo != 'BR'
)
SELECT 
    'Valid state codes in documents' as metric,
    COUNT(*) as count
FROM document_states ds
INNER JOIN expected_states es ON ds.estado_codigo = es.valid_code;

-- Check for invalid state codes
WITH expected_states AS (
    SELECT unnest(ARRAY['AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 
                         'MT', 'MS', 'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 
                         'RS', 'RO', 'RR', 'SC', 'SP', 'SE', 'TO', 'BR']) as valid_code
),
document_states AS (
    SELECT DISTINCT estado_codigo 
    FROM documents 
    WHERE estado_codigo IS NOT NULL
)
SELECT 
    'Invalid state codes (need fixing)' as metric,
    ds.estado_codigo
FROM document_states ds
LEFT JOIN expected_states es ON ds.estado_codigo = es.valid_code
WHERE es.valid_code IS NULL;

-- 3. Test map data query (simulates what the app will use)
SELECT 'TESTING MAP DATA QUERY' as test_name;

-- Simulate the map data aggregation query
SELECT 
    'Map data query results' as metric,
    estado,
    estado_codigo,
    COUNT(*) as documento_count
FROM documents 
WHERE estado IS NOT NULL 
  AND estado != ''
  AND estado_codigo IS NOT NULL
  AND estado_codigo != ''
GROUP BY estado, estado_codigo 
ORDER BY documento_count DESC
LIMIT 10;

-- Check total documents available for mapping
SELECT 
    'Documents available for mapping' as metric,
    COUNT(*) as mappable_documents
FROM documents 
WHERE estado IS NOT NULL 
  AND estado != ''
  AND estado_codigo IS NOT NULL
  AND estado_codigo != '';

-- 4. Test specific problematic states (previously showing 0)
SELECT 'TESTING SPECIFIC STATES' as test_name;

-- Check specific states that were problematic
WITH test_states AS (
    SELECT unnest(ARRAY['AM', 'PA', 'SP', 'RJ', 'MG']) as test_code
)
SELECT 
    ts.test_code as state_code,
    COALESCE(COUNT(d.id), 0) as document_count,
    CASE 
        WHEN COUNT(d.id) > 0 THEN '✅ Fixed'
        ELSE '❌ Still broken'
    END as status
FROM test_states ts
LEFT JOIN documents d ON d.estado_codigo = ts.test_code
GROUP BY ts.test_code
ORDER BY document_count DESC;

-- 5. Test data completeness for map rendering
SELECT 'TESTING DATA COMPLETENESS' as test_name;

-- Check URL availability
SELECT 
    'URL availability' as metric,
    COUNT(*) as total,
    COUNT(CASE WHEN url IS NOT NULL AND url != '' THEN 1 END) as with_url,
    ROUND(COUNT(CASE WHEN url IS NOT NULL AND url != '' THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents;

-- Check title availability  
SELECT 
    'Title availability' as metric,
    COUNT(*) as total,
    COUNT(CASE WHEN titulo IS NOT NULL AND titulo != '' THEN 1 END) as with_title,
    ROUND(COUNT(CASE WHEN titulo IS NOT NULL AND titulo != '' THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents;

-- Check date availability
SELECT 
    'Date availability' as metric,
    COUNT(*) as total,
    COUNT(CASE WHEN data_publicacao IS NOT NULL THEN 1 END) as with_date,
    ROUND(COUNT(CASE WHEN data_publicacao IS NOT NULL THEN 1 END) * 100.0 / COUNT(*), 1) || '%' as percentage
FROM documents;

-- 6. Final validation summary
SELECT 'FINAL VALIDATION SUMMARY' as test_name;

-- Summary statistics for map rendering
SELECT 
    'Total documents' as metric,
    COUNT(*) as value
FROM documents
UNION ALL
SELECT 
    'Documents with valid estado_codigo' as metric,
    COUNT(*) as value
FROM documents 
WHERE estado_codigo IS NOT NULL AND estado_codigo != ''
UNION ALL
SELECT 
    'Unique states represented' as metric,
    COUNT(DISTINCT estado_codigo) as value
FROM documents 
WHERE estado_codigo IS NOT NULL AND estado_codigo != '' AND estado_codigo != 'BR'
UNION ALL
SELECT 
    'Documents ready for mapping' as metric,
    COUNT(*) as value
FROM documents 
WHERE estado_codigo IS NOT NULL 
  AND estado_codigo != '' 
  AND titulo IS NOT NULL 
  AND titulo != '';

-- Final test: simulate exact query the R Shiny app will use
SELECT 'SIMULATING R SHINY MAP QUERY' as test_name;

SELECT 
    estado,
    estado_codigo,
    COUNT(*) as documento_count
FROM documents 
WHERE estado IS NOT NULL 
  AND estado != ''
  AND estado_codigo IS NOT NULL  
  AND estado_codigo != ''
GROUP BY estado, estado_codigo 
ORDER BY documento_count DESC;