-- URN Pattern Analysis for Unidentified Geographic Documents
-- Date: 2025-11-11
-- Purpose: Investigate URN patterns to improve geographic extraction logic

\echo '============================================================='
\echo 'URN PATTERN ANALYSIS FOR UNIDENTIFIED GEOGRAPHIC DOCUMENTS'
\echo '============================================================='
\echo ''

-- Total documents in database
\echo 'Total documents in database:'
SELECT COUNT(*) as total_documents FROM documents;
\echo ''

-- ============================================================
-- 1. BREAKDOWN OF ALL UNIDENTIFIED CATEGORIES
-- ============================================================

\echo '==========================================================='
\echo '1. BREAKDOWN OF UNIDENTIFIED CATEGORIES'
\echo '==========================================================='
\echo ''

SELECT
    COALESCE(estado_mapeado, 'NULL') as category,
    COUNT(*) as count,
    ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER(), 2) as pct_of_unidentified,
    ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM documents)::numeric, 2) as pct_of_total
FROM documents
WHERE estado_mapeado IS NULL
   OR estado_mapeado = 'Nacional'
   OR estado_mapeado = 'Estadual'
   OR estado_mapeado = 'Não Identificado'
GROUP BY estado_mapeado
ORDER BY count DESC;

\echo ''
\echo 'Total Unidentified vs Total Database:'
SELECT
    SUM(CASE WHEN estado_mapeado IS NULL OR estado_mapeado IN ('Nacional', 'Estadual', 'Não Identificado') THEN 1 ELSE 0 END) as total_unidentified,
    COUNT(*) as total_documents,
    ROUND(100.0 * SUM(CASE WHEN estado_mapeado IS NULL OR estado_mapeado IN ('Nacional', 'Estadual', 'Não Identificado') THEN 1 ELSE 0 END) / COUNT(*), 2) as pct_unidentified
FROM documents;

\echo ''
\echo '==========================================================='
\echo '2. NACIONAL DOCUMENTS'
\echo '==========================================================='
\echo ''

\echo 'Total Nacional documents:'
SELECT COUNT(*) as nacional_count FROM documents WHERE estado_mapeado = 'Nacional';

\echo ''
\echo 'Sample URNs (first 30):'
\echo '------------------------'
SELECT urn FROM documents WHERE estado_mapeado = 'Nacional' LIMIT 30;

\echo ''
\echo '==========================================================='
\echo '3. ESTADUAL (GENERIC) DOCUMENTS'
\echo '==========================================================='
\echo ''

\echo 'Total Estadual documents:'
SELECT COUNT(*) as estadual_count FROM documents WHERE estado_mapeado = 'Estadual';

\echo ''
\echo 'Sample URNs (first 30):'
\echo '------------------------'
SELECT urn FROM documents WHERE estado_mapeado = 'Estadual' LIMIT 30;

\echo ''
\echo '==========================================================='
\echo '4. NULL ESTADO_MAPEADO DOCUMENTS'
\echo '==========================================================='
\echo ''

\echo 'Total NULL estado_mapeado:'
SELECT COUNT(*) as null_count FROM documents WHERE estado_mapeado IS NULL;

\echo ''
\echo 'Sample URNs (first 30):'
\echo '------------------------'
SELECT urn FROM documents WHERE estado_mapeado IS NULL LIMIT 30;

\echo ''
\echo '==========================================================='
\echo '5. NÃO IDENTIFICADO (EXPLICIT) DOCUMENTS'
\echo '==========================================================='
\echo ''

\echo 'Total Não Identificado:'
SELECT COUNT(*) as nao_identificado_count FROM documents WHERE estado_mapeado = 'Não Identificado';

\echo ''
\echo 'Sample URNs (first 30 if any exist):'
\echo '------------------------'
SELECT urn FROM documents WHERE estado_mapeado = 'Não Identificado' LIMIT 30;

\echo ''
\echo '==========================================================='
\echo '6. URN COMPONENT ANALYSIS - NACIONAL'
\echo '==========================================================='
\echo ''

\echo 'URN Component Patterns for Nacional:'
SELECT
    COUNT(*) as total,
    SUM(CASE WHEN urn LIKE '%:lex:%' THEN 1 ELSE 0 END) as has_lex,
    SUM(CASE WHEN urn LIKE '%:congresso.nacional:%' THEN 1 ELSE 0 END) as has_congresso,
    SUM(CASE WHEN urn LIKE '%:estado:%' THEN 1 ELSE 0 END) as has_estado,
    SUM(CASE WHEN urn LIKE '%:municipal:%' THEN 1 ELSE 0 END) as has_municipal,
    SUM(CASE WHEN urn LIKE '%:federal:%' THEN 1 ELSE 0 END) as has_federal,
    SUM(CASE WHEN urn ~ ':br:' THEN 1 ELSE 0 END) as has_br
FROM documents
WHERE estado_mapeado = 'Nacional';

\echo ''
\echo 'Top URN structure patterns for Nacional (first 100 URNs):'
SELECT
    substring(urn from 1 for position(':lei:' in urn) + 20) as urn_pattern,
    COUNT(*) as frequency
FROM (
    SELECT urn FROM documents WHERE estado_mapeado = 'Nacional' LIMIT 100
) sub
GROUP BY urn_pattern
ORDER BY frequency DESC
LIMIT 15;

\echo ''
\echo '==========================================================='
\echo '7. URN COMPONENT ANALYSIS - ESTADUAL (GENERIC)'
\echo '==========================================================='
\echo ''

\echo 'URN Component Patterns for Estadual:'
SELECT
    COUNT(*) as total,
    SUM(CASE WHEN urn LIKE '%:lex:%' THEN 1 ELSE 0 END) as has_lex,
    SUM(CASE WHEN urn LIKE '%:congresso.nacional:%' THEN 1 ELSE 0 END) as has_congresso,
    SUM(CASE WHEN urn LIKE '%:estado:%' THEN 1 ELSE 0 END) as has_estado,
    SUM(CASE WHEN urn LIKE '%:municipal:%' THEN 1 ELSE 0 END) as has_municipal,
    SUM(CASE WHEN urn LIKE '%:federal:%' THEN 1 ELSE 0 END) as has_federal,
    SUM(CASE WHEN urn ~ ':br:' THEN 1 ELSE 0 END) as has_br
FROM documents
WHERE estado_mapeado = 'Estadual';

\echo ''
\echo 'Looking for state codes in Estadual URNs (sample of 100):'
SELECT
    urn,
    CASE
        WHEN urn ~ ':(ac|al|ap|am|ba|ce|df|es|go|ma|mt|ms|mg|pa|pb|pr|pe|pi|rj|rn|rs|ro|rr|sc|sp|se|to):' THEN 'HAS_STATE_CODE'
        ELSE 'NO_STATE_CODE'
    END as has_state_code
FROM (
    SELECT urn FROM documents WHERE estado_mapeado = 'Estadual' LIMIT 100
) sub;

\echo ''
\echo '==========================================================='
\echo '8. URN COMPONENT ANALYSIS - NULL'
\echo '==========================================================='
\echo ''

\echo 'URN Component Patterns for NULL:'
SELECT
    COUNT(*) as total,
    SUM(CASE WHEN urn LIKE '%:lex:%' THEN 1 ELSE 0 END) as has_lex,
    SUM(CASE WHEN urn LIKE '%:congresso.nacional:%' THEN 1 ELSE 0 END) as has_congresso,
    SUM(CASE WHEN urn LIKE '%:estado:%' THEN 1 ELSE 0 END) as has_estado,
    SUM(CASE WHEN urn LIKE '%:municipal:%' THEN 1 ELSE 0 END) as has_municipal,
    SUM(CASE WHEN urn LIKE '%:federal:%' THEN 1 ELSE 0 END) as has_federal,
    SUM(CASE WHEN urn ~ ':br:' THEN 1 ELSE 0 END) as has_br
FROM documents
WHERE estado_mapeado IS NULL;

\echo ''
\echo 'Sample NULL URNs with geographic indicators:'
SELECT
    urn,
    CASE
        WHEN urn ~ ':(ac|al|ap|am|ba|ce|df|es|go|ma|mt|ms|mg|pa|pb|pr|pe|pi|rj|rn|rs|ro|rr|sc|sp|se|to):' THEN 'HAS_STATE_CODE'
        WHEN urn LIKE '%:estado:%' THEN 'HAS_ESTADO'
        WHEN urn LIKE '%:municipal:%' THEN 'HAS_MUNICIPAL'
        ELSE 'NO_OBVIOUS_GEO'
    END as geo_indicator
FROM (
    SELECT urn FROM documents WHERE estado_mapeado IS NULL LIMIT 50
) sub;

\echo ''
\echo '==========================================================='
\echo '9. DETAILED URN STRUCTURE FREQUENCY ANALYSIS'
\echo '==========================================================='
\echo ''

\echo 'Most common URN prefixes (first 4 components) for ALL unidentified:'
SELECT
    substring(urn from 1 for position((SELECT substring(urn from position(':' in substring(urn from position(':' in substring(urn from position(':' in urn) + 1)) + 1)) + position(':' in substring(urn from position(':' in substring(urn from position(':' in urn) + 1)) + 1)))) FROM '^[^:]*:[^:]*:[^:]*:[^:]*')) as urn_prefix,
    COUNT(*) as frequency
FROM documents
WHERE estado_mapeado IS NULL
   OR estado_mapeado = 'Nacional'
   OR estado_mapeado = 'Estadual'
   OR estado_mapeado = 'Não Identificado'
GROUP BY urn_prefix
ORDER BY frequency DESC
LIMIT 20;

\echo ''
\echo '==========================================================='
\echo 'ANALYSIS COMPLETE'
\echo '==========================================================='
