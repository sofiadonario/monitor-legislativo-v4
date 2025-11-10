-- Investigation of Municipal Document Distribution Across Brazilian States
-- Date: 2025-11-09
-- Purpose: Understand why initial analysis showed only DF had municipal documents

-- Query 1: Overall distribution by state (ALREADY EXECUTED - SHOWN ABOVE)
-- SELECT estado, COUNT(*) as total_documents, COUNT(DISTINCT municipio) as unique_municipalities,
--        COUNT(CASE WHEN municipio IS NOT NULL AND municipio != '' THEN 1 END) as docs_with_municipio
-- FROM documents GROUP BY estado ORDER BY docs_with_municipio DESC;

-- Query 2: Check for different variations of municipality data
SELECT
    estado,
    municipio,
    COUNT(*) as document_count
FROM documents
WHERE municipio IS NOT NULL AND municipio != ''
GROUP BY estado, municipio
ORDER BY document_count DESC
LIMIT 30;

-- Query 3: Sample rows from DF to understand data structure
SELECT
    estado,
    municipio,
    urn,
    ementa
FROM documents
WHERE municipio IS NOT NULL AND municipio != ''
LIMIT 5;

-- Query 4: Check for special characters or encoding issues in municipio
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

-- Query 5: Check if SP has ANY municipal-related data in URN or other fields
SELECT
    estado,
    COUNT(*) as total_docs,
    COUNT(CASE WHEN urn LIKE '%municipal%' OR urn LIKE '%municipio%' THEN 1 END) as urn_mentions_municipal,
    COUNT(CASE WHEN urn LIKE '%sp/%' THEN 1 END) as urn_contains_sp,
    COUNT(CASE WHEN lower(ementa) LIKE '%municipal%' OR lower(ementa) LIKE '%município%' THEN 1 END) as ementa_mentions_municipal
FROM documents
WHERE estado = 'SP'
GROUP BY estado;

-- Query 6: Sample SP documents to see structure
SELECT
    urn,
    ementa,
    municipio,
    esfera_nivel
FROM documents
WHERE estado = 'SP'
LIMIT 10;

-- Query 7: Check esfera_nivel distribution for all states
SELECT
    estado,
    esfera_nivel,
    COUNT(*) as document_count
FROM documents
GROUP BY estado, esfera_nivel
ORDER BY estado, esfera_nivel;

-- Query 8: Investigate URN patterns for DF municipal documents
SELECT
    urn,
    municipio,
    esfera_nivel
FROM documents
WHERE estado = 'DF' AND municipio IS NOT NULL AND municipio != ''
LIMIT 10;
