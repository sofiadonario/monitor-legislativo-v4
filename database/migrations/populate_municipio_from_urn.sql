-- Migration Script: Populate municipio field from URN patterns
-- Purpose: Fix data quality issue where municipio field is unpopulated
--          for 7,554 municipal documents (71.6% of municipal docs)
-- Date: 2025-11-09
-- Impact: Updates municipio field for documents in SP, RS, MG, SC, and other states

-- ============================================================================
-- BACKUP EXISTING DATA FIRST
-- ============================================================================
CREATE TABLE IF NOT EXISTS municipio_backup_20251109 AS
SELECT id, municipio, urn, estado
FROM documents
WHERE municipio IS NOT NULL AND municipio != '';

-- ============================================================================
-- 1. SÃO PAULO MUNICIPALITIES
-- ============================================================================
-- Total to update: 3,177 documents across 13+ municipalities

UPDATE documents
SET municipio = CASE
    WHEN urn LIKE 'urn:lex:br;sao.paulo;campinas:%' THEN 'Campinas'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;hortolandia:%' THEN 'Hortolândia'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;bauru:%' THEN 'Bauru'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;mococa:%' THEN 'Mococa'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;catanduva:%' THEN 'Catanduva'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;sao.joao.boa.vista:%' THEN 'São João da Boa Vista'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;jundiai:%' THEN 'Jundiaí'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;birigui:%' THEN 'Birigui'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;bertioga:%' THEN 'Bertioga'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;adamantina:%' THEN 'Adamantina'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;itapolis:%' THEN 'Itápolis'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;indiapora:%' THEN 'Indiaporã'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;bofete:%' THEN 'Bofete'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;americana:%' THEN 'Americana'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;araraquara:%' THEN 'Araraquara'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;aracatuba:%' THEN 'Araçatuba'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;botucatu:%' THEN 'Botucatu'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;franca:%' THEN 'Franca'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;guarulhos:%' THEN 'Guarulhos'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;limeira:%' THEN 'Limeira'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;marilia:%' THEN 'Marília'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;osasco:%' THEN 'Osasco'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;piracicaba:%' THEN 'Piracicaba'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;presidente.prudente:%' THEN 'Presidente Prudente'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;ribeirao.preto:%' THEN 'Ribeirão Preto'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;santos:%' THEN 'Santos'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;sao.bernardo.campo:%' THEN 'São Bernardo do Campo'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;sao.jose.campos:%' THEN 'São José dos Campos'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;sao.jose.rio.preto:%' THEN 'São José do Rio Preto'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;sorocaba:%' THEN 'Sorocaba'
    WHEN urn LIKE 'urn:lex:br;sao.paulo;taubate:%' THEN 'Taubaté'
END
WHERE estado = 'SP'
  AND (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
  AND (municipio IS NULL OR municipio = '');

-- ============================================================================
-- 2. RIO GRANDE DO SUL MUNICIPALITIES
-- ============================================================================
-- Total to update: 4,542 documents
-- Note: RS has the highest number of municipal documents

-- Generic pattern for RS - extract municipality name from URN
UPDATE documents
SET municipio = CASE
    -- Extract municipality name between second and third colon
    -- Pattern: urn:lex:br;rio.grande.sul;{municipality}:municipal:...
    WHEN urn ~ 'urn:lex:br;rio\.grande\.sul;([^:]+):municipal:' THEN
        regexp_replace(
            regexp_replace(
                substring(urn from 'urn:lex:br;rio\.grande\.sul;([^:]+):'),
                '\.', ' ', 'g'
            ),
            '([a-z])([A-Z])', '\1 \2', 'g'
        )
END
WHERE estado = 'RS'
  AND urn LIKE '%:municipal:%'
  AND (municipio IS NULL OR municipio = '');

-- ============================================================================
-- 3. MINAS GERAIS MUNICIPALITIES
-- ============================================================================
-- Total to update: 1,768 documents

UPDATE documents
SET municipio = CASE
    WHEN urn ~ 'urn:lex:br;minas\.gerais;([^:]+):municipal:' THEN
        regexp_replace(
            regexp_replace(
                substring(urn from 'urn:lex:br;minas\.gerais;([^:]+):'),
                '\.', ' ', 'g'
            ),
            '([a-z])([A-Z])', '\1 \2', 'g'
        )
    WHEN urn ~ 'urn:lex:br;minas\.gerais;([^:]+):camara\.municipal:' THEN
        regexp_replace(
            regexp_replace(
                substring(urn from 'urn:lex:br;minas\.gerais;([^:]+):camara'),
                '\.', ' ', 'g'
            ),
            '([a-z])([A-Z])', '\1 \2', 'g'
        )
END
WHERE estado = 'MG'
  AND (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
  AND (municipio IS NULL OR municipio = '');

-- ============================================================================
-- 4. SANTA CATARINA MUNICIPALITIES
-- ============================================================================
-- Total to update: 88 documents

UPDATE documents
SET municipio = CASE
    WHEN urn ~ 'urn:lex:br;santa\.catarina;([^:]+):municipal:' THEN
        regexp_replace(
            regexp_replace(
                substring(urn from 'urn:lex:br;santa\.catarina;([^:]+):'),
                '\.', ' ', 'g'
            ),
            '([a-z])([A-Z])', '\1 \2', 'g'
        )
    WHEN urn ~ 'urn:lex:br;santa\.catarina;([^:]+):camara\.municipal:' THEN
        regexp_replace(
            regexp_replace(
                substring(urn from 'urn:lex:br;santa\.catarina;([^:]+):camara'),
                '\.', ' ', 'g'
            ),
            '([a-z])([A-Z])', '\1 \2', 'g'
        )
END
WHERE estado = 'SC'
  AND (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
  AND (municipio IS NULL OR municipio = '');

-- ============================================================================
-- 5. OTHER STATES (RR, SE, MT, etc.)
-- ============================================================================
-- Generic update for remaining states with municipal documents

UPDATE documents
SET municipio =
    regexp_replace(
        regexp_replace(
            -- Extract municipality name from URN pattern: urn:lex:br;{state};{municipality}:
            substring(urn from 'urn:lex:br;[^;]+;([^:]+):'),
            '\.', ' ', 'g'
        ),
        '([a-z])([A-Z])', '\1 \2', 'g'
    )
WHERE estado IN ('RR', 'SE', 'MT')
  AND (urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%')
  AND (municipio IS NULL OR municipio = '');

-- ============================================================================
-- 6. VERIFICATION QUERIES
-- ============================================================================

-- Check updates by state
SELECT
    estado,
    COUNT(*) as total_docs,
    COUNT(CASE WHEN municipio IS NOT NULL AND municipio != '' THEN 1 END) as with_municipio,
    COUNT(CASE WHEN urn LIKE '%:municipal:%' OR urn LIKE '%camara.municipal%' THEN 1 END) as municipal_urns
FROM documents
WHERE estado IN ('SP', 'RS', 'MG', 'SC', 'RR', 'SE', 'MT', 'DF')
GROUP BY estado
ORDER BY estado;

-- Sample updated records
SELECT
    estado,
    municipio,
    urn,
    substring(ementa, 1, 100) as ementa_preview
FROM documents
WHERE municipio IS NOT NULL
  AND municipio != ''
  AND estado IN ('SP', 'RS', 'MG')
ORDER BY estado, municipio
LIMIT 20;

-- Summary statistics
SELECT
    'Total documents updated' as metric,
    COUNT(*)::text as value
FROM documents
WHERE municipio IS NOT NULL
  AND municipio != ''
  AND id NOT IN (SELECT id FROM municipio_backup_20251109)
UNION ALL
SELECT
    'States with municipio data (before)',
    '1 (DF only)'
UNION ALL
SELECT
    'States with municipio data (after)',
    COUNT(DISTINCT estado)::text
FROM documents
WHERE municipio IS NOT NULL AND municipio != '';

-- ============================================================================
-- 7. ROLLBACK SCRIPT (if needed)
-- ============================================================================
-- To rollback this migration:
/*
UPDATE documents d
SET municipio = b.municipio
FROM municipio_backup_20251109 b
WHERE d.id = b.id;

UPDATE documents
SET municipio = NULL
WHERE id NOT IN (SELECT id FROM municipio_backup_20251109);

DROP TABLE municipio_backup_20251109;
*/
