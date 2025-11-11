-- Analyze URN Structure and Extractable Data
-- ============================================================================
-- URN Format: urn:lex:br;{state};{municipality}:{level}:{type}:{date};{number}
-- Example: urn:lex:br;rio.janeiro;nova.friburgo:municipal:lei:2017-10-02;4584
-- ============================================================================

-- 1. Current Column Population Rates
SELECT
    'Column Population Status' as analysis,
    '' as details;

SELECT
    column_name,
    COUNT(*) as total_rows,
    COUNT(CASE WHEN column_value IS NOT NULL AND column_value != '' THEN 1 END) as populated,
    ROUND(100.0 * COUNT(CASE WHEN column_value IS NOT NULL AND column_value != '' THEN 1 END) / COUNT(*), 2) as pct_populated
FROM (
    SELECT 'estado' as column_name, estado as column_value FROM documents
    UNION ALL SELECT 'municipio', municipio FROM documents
    UNION ALL SELECT 'tipo', tipo FROM documents
    UNION ALL SELECT 'data', data FROM documents
    UNION ALL SELECT 'ano', ano FROM documents
    UNION ALL SELECT 'numero', numero FROM documents
    UNION ALL SELECT 'urn', urn FROM documents
) sub
GROUP BY column_name
ORDER BY pct_populated DESC;

-- ============================================================================
-- 2. Extract Document Types from URN
-- ============================================================================
SELECT
    'Document Types in URN' as analysis,
    '' as details;

SELECT
    substring(urn from ':([^:]+):\d{4}-\d{2}-\d{2}') as tipo_from_urn,
    COUNT(*) as count,
    COUNT(CASE WHEN tipo IS NOT NULL AND tipo != '' THEN 1 END) as already_has_tipo,
    COUNT(CASE WHEN tipo IS NULL OR tipo = '' THEN 1 END) as missing_tipo
FROM documents
WHERE urn IS NOT NULL
GROUP BY tipo_from_urn
ORDER BY count DESC
LIMIT 20;

-- ============================================================================
-- 3. Extract Dates from URN
-- ============================================================================
SELECT
    'Dates in URN' as analysis,
    '' as details;

SELECT
    substring(urn from '(\d{4}-\d{2}-\d{2})') as data_from_urn,
    COUNT(*) as count,
    COUNT(CASE WHEN data IS NOT NULL AND data != '' THEN 1 END) as already_has_data,
    COUNT(CASE WHEN data IS NULL OR data = '' THEN 1 END) as missing_data
FROM documents
WHERE urn IS NOT NULL
  AND urn ~ '\d{4}-\d{2}-\d{2}'
GROUP BY data_from_urn
ORDER BY count DESC
LIMIT 10;

-- Summary of dates
SELECT
    'Date Summary' as metric,
    COUNT(*) as total_urns_with_dates,
    COUNT(CASE WHEN data IS NOT NULL AND data != '' THEN 1 END) as already_has_data,
    COUNT(CASE WHEN data IS NULL OR data = '' THEN 1 END) as could_populate_data
FROM documents
WHERE urn IS NOT NULL
  AND urn ~ '\d{4}-\d{2}-\d{2}';

-- ============================================================================
-- 4. Extract Years from URN
-- ============================================================================
SELECT
    'Years in URN' as analysis,
    '' as details;

SELECT
    substring(urn from '(\d{4})-\d{2}-\d{2}') as ano_from_urn,
    COUNT(*) as count,
    COUNT(CASE WHEN ano IS NOT NULL AND ano != '' THEN 1 END) as already_has_ano,
    COUNT(CASE WHEN ano IS NULL OR ano = '' THEN 1 END) as missing_ano
FROM documents
WHERE urn IS NOT NULL
  AND urn ~ '\d{4}-\d{2}-\d{2}'
GROUP BY ano_from_urn
ORDER BY ano_from_urn DESC
LIMIT 20;

-- ============================================================================
-- 5. Extract Document Numbers from URN
-- ============================================================================
SELECT
    'Document Numbers in URN' as analysis,
    '' as details;

SELECT
    COUNT(*) as total_urns,
    COUNT(CASE WHEN urn ~ ';\d+$' THEN 1 END) as urns_with_number,
    COUNT(CASE WHEN numero IS NOT NULL AND numero != '' THEN 1 END) as already_has_numero,
    COUNT(CASE WHEN (numero IS NULL OR numero = '') AND urn ~ ';\d+$' THEN 1 END) as could_populate_numero
FROM documents
WHERE urn IS NOT NULL;

-- Sample extraction
SELECT
    urn,
    numero,
    substring(urn from ';(\d+)$') as numero_from_urn
FROM documents
WHERE urn IS NOT NULL
  AND urn ~ ';\d+$'
LIMIT 10;

-- ============================================================================
-- 6. Extract Level (Federal/State/Municipal) from URN
-- ============================================================================
SELECT
    'Government Level in URN' as analysis,
    '' as details;

SELECT
    CASE
        WHEN urn LIKE '%:federal:%' THEN 'Federal'
        WHEN urn LIKE '%:estadual:%' THEN 'Estadual'
        WHEN urn LIKE '%:municipal:%' THEN 'Municipal'
        ELSE 'Other/Unknown'
    END as nivel,
    COUNT(*) as count
FROM documents
WHERE urn IS NOT NULL
GROUP BY nivel
ORDER BY count DESC;

-- ============================================================================
-- 7. Compare URN Data with Existing Column Data
-- ============================================================================
SELECT
    'Data Quality Check' as analysis,
    '' as details;

-- Check if existing 'data' matches URN dates
SELECT
    'Date Consistency' as metric,
    COUNT(*) as total,
    COUNT(CASE WHEN data = substring(urn from '(\d{4}-\d{2}-\d{2})') THEN 1 END) as matches,
    COUNT(CASE WHEN data != substring(urn from '(\d{4}-\d{2}-\d{2})') AND data IS NOT NULL THEN 1 END) as mismatches
FROM documents
WHERE urn IS NOT NULL
  AND urn ~ '\d{4}-\d{2}-\d{2}'
  AND data IS NOT NULL
  AND data != '';

-- Sample mismatches
SELECT
    'Sample Date Mismatches' as analysis,
    data as data_field,
    substring(urn from '(\d{4}-\d{2}-\d{2})') as data_from_urn,
    urn
FROM documents
WHERE urn IS NOT NULL
  AND urn ~ '\d{4}-\d{2}-\d{2}'
  AND data IS NOT NULL
  AND data != ''
  AND data != substring(urn from '(\d{4}-\d{2}-\d{2})')
LIMIT 10;

-- ============================================================================
-- 8. Summary: What Can Be Populated
-- ============================================================================
SELECT
    'SUMMARY: Populatable Columns from URN' as report,
    '' as details;

SELECT
    'tipo' as column_name,
    COUNT(CASE WHEN urn IS NOT NULL AND urn ~ ':([^:]+):\d{4}-\d{2}-\d{2}' THEN 1 END) as extractable_count,
    COUNT(CASE WHEN tipo IS NULL OR tipo = '' THEN 1 END) as empty_count,
    COUNT(CASE WHEN (tipo IS NULL OR tipo = '') AND urn IS NOT NULL THEN 1 END) as can_populate
FROM documents
UNION ALL
SELECT
    'data' as column_name,
    COUNT(CASE WHEN urn IS NOT NULL AND urn ~ '\d{4}-\d{2}-\d{2}' THEN 1 END) as extractable_count,
    COUNT(CASE WHEN data IS NULL OR data = '' THEN 1 END) as empty_count,
    COUNT(CASE WHEN (data IS NULL OR data = '') AND urn ~ '\d{4}-\d{2}-\d{2}' THEN 1 END) as can_populate
FROM documents
UNION ALL
SELECT
    'ano' as column_name,
    COUNT(CASE WHEN urn IS NOT NULL AND urn ~ '\d{4}-\d{2}-\d{2}' THEN 1 END) as extractable_count,
    COUNT(CASE WHEN ano IS NULL OR ano = '' THEN 1 END) as empty_count,
    COUNT(CASE WHEN (ano IS NULL OR ano = '') AND urn ~ '\d{4}-\d{2}-\d{2}' THEN 1 END) as can_populate
FROM documents
UNION ALL
SELECT
    'numero' as column_name,
    COUNT(CASE WHEN urn IS NOT NULL AND urn ~ ';\d+$' THEN 1 END) as extractable_count,
    COUNT(CASE WHEN numero IS NULL OR numero = '' THEN 1 END) as empty_count,
    COUNT(CASE WHEN (numero IS NULL OR numero = '') AND urn ~ ';\d+$' THEN 1 END) as can_populate
FROM documents;
