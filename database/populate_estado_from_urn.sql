-- ===============================================================
-- Populate estado field from URN for all Brazilian documents
-- ===============================================================
-- This script extracts state information from LexML URNs
-- URN Pattern: urn:lex:br[;STATE]:AUTHORITY:DOC_TYPE:DATE;NUMBER
-- Example: urn:lex:br;sao.paulo:assembleia.legislativa:lei:2020-01-15;17.293
-- ===============================================================

BEGIN;

-- Count before update
SELECT
    'BEFORE UPDATE' as status,
    COUNT(*) as total_documents,
    COUNT(CASE WHEN estado IS NOT NULL AND estado != '' THEN 1 END) as with_estado,
    COUNT(CASE WHEN estado IS NULL OR estado = '' THEN 1 END) as without_estado
FROM documents;

-- Extract estado from URN and update documents table
UPDATE documents
SET estado = CASE
    -- Extract from URN pattern (urn:lex:br;STATE:...)
    WHEN urn LIKE '%br;acre:%' THEN 'AC'
    WHEN urn LIKE '%br;alagoas:%' THEN 'AL'
    WHEN urn LIKE '%br;amapa:%' THEN 'AP'
    WHEN urn LIKE '%br;amazonas:%' THEN 'AM'
    WHEN urn LIKE '%br;bahia:%' THEN 'BA'
    WHEN urn LIKE '%br;ceara:%' THEN 'CE'
    WHEN urn LIKE '%br;distrito.federal:%' THEN 'DF'
    WHEN urn LIKE '%br;espirito.santo:%' THEN 'ES'
    WHEN urn LIKE '%br;goias:%' THEN 'GO'
    WHEN urn LIKE '%br;maranhao:%' THEN 'MA'
    WHEN urn LIKE '%br;mato.grosso.sul:%' OR urn LIKE '%br;mato.grosso:%sul%' THEN 'MS'
    WHEN urn LIKE '%br;mato.grosso:%' AND urn NOT LIKE '%sul%' THEN 'MT'
    WHEN urn LIKE '%br;minas.gerais:%' THEN 'MG'
    WHEN urn LIKE '%br;para:%' AND urn NOT LIKE '%parana%' AND urn NOT LIKE '%paraiba%' THEN 'PA'
    WHEN urn LIKE '%br;paraiba:%' THEN 'PB'
    WHEN urn LIKE '%br;parana:%' THEN 'PR'
    WHEN urn LIKE '%br;pernambuco:%' THEN 'PE'
    WHEN urn LIKE '%br;piaui:%' THEN 'PI'
    WHEN urn LIKE '%br;rio.de.janeiro:%' OR urn LIKE '%br;rio.janeiro:%' THEN 'RJ'
    WHEN urn LIKE '%br;rio.grande.norte:%' THEN 'RN'
    WHEN urn LIKE '%br;rio.grande.sul:%' OR urn LIKE '%br;rio.grande:%sul%' THEN 'RS'
    WHEN urn LIKE '%br;rondonia:%' THEN 'RO'
    WHEN urn LIKE '%br;roraima:%' THEN 'RR'
    WHEN urn LIKE '%br;santa.catarina:%' THEN 'SC'
    WHEN urn LIKE '%br;sao.paulo:%' THEN 'SP'
    WHEN urn LIKE '%br;sergipe:%' THEN 'SE'
    WHEN urn LIKE '%br;tocantins:%' THEN 'TO'

    -- Federal level documents (no state in URN)
    WHEN urn LIKE '%br:federal:%' OR
         urn LIKE '%congresso.nacional:%' OR
         urn LIKE '%senado.federal:%' OR
         urn LIKE '%camara.deputados:%' OR
         urn LIKE '%supremo.tribunal.federal:%' OR
         urn LIKE '%superior.tribunal.justica:%' OR
         urn LIKE '%tribunal.contas.uniao:%' OR
         urn LIKE '%ministerio%:%' THEN 'Federal'

    -- Keep existing estado if already set
    WHEN estado IS NOT NULL AND estado != '' THEN estado

    -- Default to Federal for documents without clear state indication
    ELSE 'Federal'
END
WHERE urn IS NOT NULL AND urn != '';

-- Update municipio where possible (extract from URN)
UPDATE documents
SET municipio = CASE
    WHEN urn ~* 'municipio\.([a-z]+(\.[a-z]+)*)' THEN
        INITCAP(REPLACE(SUBSTRING(urn FROM 'municipio\.([a-z]+(\.[a-z]+)*)'), '.', ' '))
    ELSE municipio
END
WHERE urn IS NOT NULL
  AND urn LIKE '%municipio%'
  AND (municipio IS NULL OR municipio = '');

-- Count after update
SELECT
    'AFTER UPDATE' as status,
    COUNT(*) as total_documents,
    COUNT(CASE WHEN estado IS NOT NULL AND estado != '' THEN 1 END) as with_estado,
    COUNT(CASE WHEN estado IS NULL OR estado = '' THEN 1 END) as without_estado
FROM documents;

-- Show estado distribution
SELECT
    'Estado Distribution' as report,
    estado,
    COUNT(*) as document_count,
    ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 2) as percentage
FROM documents
WHERE estado IS NOT NULL
GROUP BY estado
ORDER BY document_count DESC;

-- Verify specific states
SELECT
    'Sample URNs by Estado' as report,
    estado,
    COUNT(*) as count,
    MIN(urn) as sample_urn
FROM documents
WHERE estado IS NOT NULL
GROUP BY estado
ORDER BY estado;

COMMIT;

-- Final summary
SELECT
    '=== FINAL SUMMARY ===' as status,
    'Total documents: ' || COUNT(*) as metric
FROM documents
UNION ALL
SELECT
    'Documents with geographic info: ' as status,
    COUNT(*) || ' (' || ROUND(COUNT(*) * 100.0 / (SELECT COUNT(*) FROM documents), 1) || '%)' as metric
FROM documents
WHERE estado IS NOT NULL AND estado != '';
