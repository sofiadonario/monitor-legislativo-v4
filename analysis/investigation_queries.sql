-- Query 2: Top 30 Municipalities by Document Count
\echo '=== QUERY 2: Top 30 Municipalities by Document Count ==='
SELECT
    estado,
    municipio,
    COUNT(*) as document_count
FROM documents
WHERE municipio IS NOT NULL AND municipio != ''
GROUP BY estado, municipio
ORDER BY document_count DESC
LIMIT 30;

-- Query 3: Sample Rows from DF
\echo ''
\echo '=== QUERY 3: Sample Rows from DF ==='
SELECT
    estado,
    municipio,
    urn,
    substring(ementa, 1, 80) as ementa_preview
FROM documents
WHERE municipio IS NOT NULL AND municipio != ''
LIMIT 5;

-- Query 4: Check Municipio Encoding
\echo ''
\echo '=== QUERY 4: Check Municipio Encoding ==='
SELECT
    estado,
    municipio,
    LENGTH(municipio) as municipio_length,
    ascii(substring(municipio, 1, 1)) as first_char_ascii,
    COUNT(*) as count
FROM documents
WHERE municipio IS NOT NULL AND municipio != ''
GROUP BY estado, municipio
ORDER BY count DESC
LIMIT 20;

-- Query 5: SP Municipal Analysis
\echo ''
\echo '=== QUERY 5: SP Municipal Analysis ==='
SELECT
    estado,
    COUNT(*) as total_docs,
    COUNT(CASE WHEN urn LIKE '%municipal%' OR urn LIKE '%municipio%' THEN 1 END) as urn_mentions_municipal,
    COUNT(CASE WHEN urn LIKE '%sp/%' THEN 1 END) as urn_contains_sp,
    COUNT(CASE WHEN lower(ementa) LIKE '%municipal%' OR lower(ementa) LIKE '%município%' THEN 1 END) as ementa_mentions_municipal
FROM documents
WHERE estado = 'SP'
GROUP BY estado;

-- Query 6: Sample SP Documents
\echo ''
\echo '=== QUERY 6: Sample SP Documents ==='
SELECT
    urn,
    substring(ementa, 1, 100) as ementa_preview,
    municipio,
    esfera_nivel
FROM documents
WHERE estado = 'SP'
LIMIT 10;

-- Query 7: Esfera Nivel Distribution
\echo ''
\echo '=== QUERY 7: Esfera Nivel Distribution ==='
SELECT
    estado,
    esfera_nivel,
    COUNT(*) as document_count
FROM documents
WHERE estado IN ('DF', 'SP', 'RJ', 'MG', 'RS')
GROUP BY estado, esfera_nivel
ORDER BY estado, esfera_nivel;

-- Query 8: DF Municipal URN Patterns
\echo ''
\echo '=== QUERY 8: DF Municipal URN Patterns ==='
SELECT
    urn,
    municipio,
    esfera_nivel
FROM documents
WHERE estado = 'DF' AND municipio IS NOT NULL AND municipio != ''
LIMIT 10;
