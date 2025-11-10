-- Check actual table schema
\echo '=== TABLE SCHEMA ==='
SELECT
    column_name,
    data_type,
    character_maximum_length
FROM information_schema.columns
WHERE table_name = 'documents'
ORDER BY ordinal_position;

-- Investigate SP URNs that mention municipal
\echo ''
\echo '=== SP URNs with Municipal Pattern (sample) ==='
SELECT
    urn,
    substring(ementa, 1, 100) as ementa_preview,
    municipio
FROM documents
WHERE estado = 'SP'
  AND (urn LIKE '%municipal%' OR urn LIKE '%municipio%')
LIMIT 10;

-- Check if there's a pattern in SP URNs
\echo ''
\echo '=== SP URN Patterns Analysis ==='
SELECT
    substring(urn FROM 'urn:lex:br;[^:]+') as urn_state_level,
    COUNT(*) as count
FROM documents
WHERE estado = 'SP'
  AND urn IS NOT NULL
  AND urn != ''
GROUP BY substring(urn FROM 'urn:lex:br;[^:]+')
ORDER BY count DESC
LIMIT 20;

-- Sample SP documents to see full structure
\echo ''
\echo '=== Sample SP Documents (All Columns) ==='
SELECT
    id,
    urn,
    substring(ementa, 1, 80) as ementa_preview,
    municipio,
    estado,
    categoria,
    data_publicacao
FROM documents
WHERE estado = 'SP'
LIMIT 5;

-- Check for city names in SP URNs
\echo ''
\echo '=== SP Municipality Names in URNs ==='
SELECT
    substring(urn FROM 'urn:lex:br;sao.paulo\\.([^:]+)') as possible_municipality,
    COUNT(*) as count
FROM documents
WHERE estado = 'SP'
  AND urn LIKE 'urn:lex:br;sao.paulo.%'
GROUP BY substring(urn FROM 'urn:lex:br;sao.paulo\\.([^:]+)')
ORDER BY count DESC
LIMIT 20;
