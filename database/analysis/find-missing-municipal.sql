-- Find Missing Municipal Documents and Legislative Assembly Issues
-- ============================================================================

-- 1. FIND MUNICIPAL DOCS MISSING MUNICIPIO FIELD
-- ============================================================================
SELECT
    '1. Missing Municipio Field' as issue,
    estado,
    COUNT(*) as missing_count,
    array_agg(DISTINCT substring(urn from 'urn:lex:br;[^;]+;([^:]+):') LIMIT 10) as sample_municipalities
FROM documents
WHERE (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
  AND (municipio IS NULL OR municipio = '')
GROUP BY estado
ORDER BY missing_count DESC;

-- Sample missing URNs
SELECT
    '1a. Sample Missing URNs' as issue,
    estado,
    urn,
    municipio
FROM documents
WHERE (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
  AND (municipio IS NULL OR municipio = '')
LIMIT 20;

-- ============================================================================
-- 2. FIND "CAMARA DOS VEREADORES" PATTERN (City Council)
-- ============================================================================
SELECT
    '2. Camara Vereadores Pattern' as issue,
    COUNT(*) as count,
    COUNT(CASE WHEN municipio IS NOT NULL AND municipio != '' THEN 1 END) as with_municipio
FROM documents
WHERE urn ILIKE '%vereador%';

-- Sample camara vereadores URNs
SELECT
    '2a. Sample Vereadores URNs' as issue,
    estado,
    urn,
    municipio
FROM documents
WHERE urn ILIKE '%vereador%'
LIMIT 20;

-- ============================================================================
-- 3. STATE LEGISLATIVE ASSEMBLY DOCUMENTS
-- ============================================================================
SELECT
    '3. Legislative Assembly Docs' as issue,
    estado,
    COUNT(*) as count
FROM documents
WHERE urn ILIKE '%assembleia.legislativa%'
   OR urn ILIKE '%legislativo%'
GROUP BY estado
ORDER BY count DESC;

-- Sample legislative assembly URNs
SELECT
    '3a. Sample Legislative URNs' as issue,
    estado,
    urn
FROM documents
WHERE urn ILIKE '%assembleia.legislativa%'
   OR urn ILIKE '%legislativo%'
LIMIT 20;

-- ============================================================================
-- 4. CHECK ESTADO FIELD FOR LEGISLATIVE DOCS
-- ============================================================================
SELECT
    '4. Estado Field Check' as issue,
    CASE
        WHEN estado IS NULL OR estado = '' THEN 'Missing estado'
        ELSE 'Has estado'
    END as estado_status,
    COUNT(*) as count
FROM documents
WHERE urn ILIKE '%assembleia.legislativa%'
   OR urn ILIKE '%legislativo%'
GROUP BY estado_status;

-- ============================================================================
-- 5. ALL MUNICIPAL PATTERNS COMPREHENSIVE CHECK
-- ============================================================================
SELECT
    '5. All Municipal Patterns' as issue,
    CASE
        WHEN urn LIKE '%:municipal:%' THEN 'municipal'
        WHEN urn LIKE '%camara.municipal%' THEN 'camara.municipal'
        WHEN urn ILIKE '%vereador%' THEN 'vereador'
        WHEN urn ILIKE '%prefeitura%' THEN 'prefeitura'
    END as pattern,
    COUNT(*) as total_docs,
    COUNT(CASE WHEN municipio IS NOT NULL AND municipio != '' THEN 1 END) as with_municipio,
    COUNT(CASE WHEN estado IS NOT NULL AND estado != '' THEN 1 END) as with_estado
FROM documents
WHERE urn LIKE '%:municipal:%'
   OR urn LIKE '%camara.municipal%'
   OR urn ILIKE '%vereador%'
   OR urn ILIKE '%prefeitura%'
GROUP BY pattern;

-- ============================================================================
-- 6. FIND STATES WITH MISSING ESTADO ON LEGISLATIVE DOCS
-- ============================================================================
SELECT
    '6. Legislative Docs Without Estado' as issue,
    COUNT(*) as count,
    array_agg(DISTINCT substring(urn from 'urn:lex:br;([^;:]+)') LIMIT 10) as states_in_urn
FROM documents
WHERE (urn ILIKE '%assembleia.legislativa%' OR urn ILIKE '%legislativo%')
  AND (estado IS NULL OR estado = '');

-- Sample URNs without estado
SELECT
    '6a. Sample Missing Estado' as issue,
    urn,
    estado
FROM documents
WHERE (urn ILIKE '%assembleia.legislativa%' OR urn ILIKE '%legislativo%')
  AND (estado IS NULL OR estado = '')
LIMIT 20;

-- ============================================================================
-- 7. EXTRACT STATE FROM URN FOR MISSING ESTADO
-- ============================================================================
SELECT
    '7. States Extractable from URN' as issue,
    substring(urn from 'urn:lex:br;([^;:]+)') as state_from_urn,
    COUNT(*) as docs_with_missing_estado
FROM documents
WHERE (estado IS NULL OR estado = '')
  AND urn IS NOT NULL
GROUP BY state_from_urn
ORDER BY docs_with_missing_estado DESC
LIMIT 20;
